"""Bounded, local-only ARP/TCP inventory and advisory Wi-Fi channel analysis."""
from __future__ import annotations

import ipaddress
import json
import platform
import re
import socket
import subprocess
import threading
import time
from dataclasses import dataclass
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from typing import Callable

from models import AccessPoint, Device, NetworkInfo, ScanResult
from netio import run_command

PORTS = (22, 53, 80, 139, 443, 445, 3389, 5357, 8000, 8080, 8443, 9100)
MAC_RE = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$", re.I)


@dataclass(frozen=True)
class ObservedAccessPoint(AccessPoint):
    source: str = ''
    observed_at: float = 0.0
    verification: str = 'protocol_claim'
    signal_percent: int | None = None
    signal_verification: str = 'measurement'
    evidence: str = ''
    observation_only: bool = True
    identity_verified: bool = False
    presence_verified: bool = False
    distance_m: None = None
    band_hint: str | None = None


@dataclass(frozen=True)
class ObservedDevice(Device):
    source: str = ''
    observed_at: float = 0.0
    verification: str = 'protocol_claim'
    evidence: str = ''
    observation_only: bool = True
    identity_verified: bool = False
    presence_verified: bool = False
    port_observations: tuple[dict, ...] = ()


class Observations(dict):
    """Keep per-result capture/check times without changing the mapping API."""
    def __init__(self):
        super().__init__()
        self.observed_at: dict = {}


def normalize_mac(value: str) -> str:
    value = value.strip().replace("-", ":").lower()
    return value if MAC_RE.fullmatch(value) else ""


def vendor_for_mac(mac: str) -> str:
    """Legacy name: returns an OUI assignee, never a verified device maker."""
    mac = normalize_mac(mac)
    if not mac:
        return "Sconosciuto"
    first = int(mac[:2], 16)
    if first & 1:
        return "Multicast"
    if first & 2:
        return "MAC locale / privato"
    try:
        from scapy.config import conf
        vendor = conf.manufdb._get_manuf(mac)
        return str(vendor) if vendor and vendor.lower() != mac.lower() else "OUI sconosciuto"
    except (ImportError, AttributeError, OSError):
        return "Database OUI non disponibile"


def mac_attribution(mac: str) -> dict:
    normalized = normalize_mac(mac)
    local = bool(normalized and int(normalized[:2], 16) & 2)
    multicast = bool(normalized and int(normalized[:2], 16) & 1)
    assignee = vendor_for_mac(normalized)
    known = assignee not in ('Sconosciuto', 'OUI sconosciuto', 'Database OUI non disponibile',
                            'MAC locale / privato', 'Multicast')
    return {'oui_assignee': assignee if known else None, 'source': 'Database OUI locale Scapy',
            'verification': 'database_attribution', 'manufacturer_verified': False,
            'locally_administered': local, 'multicast': multicast,
            'warning': ('MAC amministrato localmente/randomizzabile: assegnatario non attribuibile.' if local
                        else 'OUI: assegnatario del prefisso MAC, non produttore o identità verificati.')}


def scan_scope(network: NetworkInfo) -> tuple[ipaddress.IPv4Network, bool]:
    subnet = network.network
    if subnet.num_addresses > 1024:
        return ipaddress.IPv4Network(f"{network.address}/24", strict=False), True
    return subnet, False


def _band(freq_mhz: int) -> str:
    if 2400 <= freq_mhz <= 2500:
        return "2.4 GHz"
    if 4900 <= freq_mhz < 5925:
        return "5 GHz"
    if 5925 <= freq_mhz <= 7125:
        return "6 GHz"
    return "?"


def _signal_percent(value: str) -> int | None:
    match = re.search(r"\d+", value)
    return int(match[0]) if match and 0 <= int(match[0]) <= 100 else None


def parse_netsh(text: str) -> list[AccessPoint]:
    """Preserve netsh signal percentages; never manufacture dBm from quality."""
    result: list[AccessPoint] = []
    ssid, security = "", ""
    current: dict[str, str] = {}

    def flush() -> None:
        if not current:
            return
        channel = int(current.get("channel", "0"))
        band = current.get("band", "?")
        band_hint = None
        radio = current.get("radio", "").lower()
        if band == "?" and 1 <= channel <= 14 and any(x in radio for x in ("802.11b", "802.11g", "802.11n")):
            band_hint = "2.4 GHz"
        elif band == "?" and channel > 14 and ("802.11ac" in radio or radio == "802.11a"):
            band_hint = "5 GHz"
        mac = normalize_mac(current.get("bssid", ""))
        if mac:
            result.append(ObservedAccessPoint(ssid or "<nascosta>", mac, channel, band, None, security,
                source='netsh WLAN cache', observed_at=time.time(),
                signal_percent=_signal_percent(current.get('signal', '')), band_hint=band_hint,
                evidence='Elenco nella cache WLAN; istante di lettura, non conferma di presenza attuale. '
                         'SSID/BSSID/sicurezza annunciati, identità non autenticata; segnale in percentuale.'))

    for line in text.splitlines():
        ssid_match = re.match(r"\s*SSID\s+\d+\s*:\s?(.*)$", line, re.I)
        bssid_match = re.match(r"\s*BSSID\s+\d+\s*:\s*(.*)$", line, re.I)
        if ssid_match:
            flush()
            current = {}
            ssid, security = ssid_match[1].strip(), ""
        elif bssid_match:
            flush()
            current = {"bssid": bssid_match[1].strip()}
        elif ":" in line:
            key, value = (part.strip() for part in line.split(":", 1))
            key = key.lower()
            if key in ("authentication", "autenticazione"):
                security = value
            elif current:
                if key in ("signal", "segnale"):
                    current["signal"] = value
                elif key in ("channel", "canale") and value.isdigit():
                    current["channel"] = value
                elif key in ("radio type", "tipo frequenza radio", "tipo di radio", "tipo radio"):
                    current["radio"] = value
                elif key in ("band", "banda"):
                    match = re.search(r"(2[.,]4|5|6)\s*GHz", value, re.I)
                    if match:
                        current["band"] = match[1].replace(",", ".") + " GHz"
    flush()
    return result


def split_nmcli(line: str) -> list[str]:
    """Decode NetworkManager's escaped colon/backslash terse output."""
    fields, chars, escaped = [], [], False
    for char in line:
        if escaped:
            chars.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            fields.append("".join(chars))
            chars = []
        else:
            chars.append(char)
    if escaped:
        chars.append("\\")
    fields.append("".join(chars))
    return fields


def parse_nmcli(text: str) -> list[AccessPoint]:
    result = []
    for line in text.splitlines():
        fields = split_nmcli(line)
        if len(fields) != 7:
            continue
        ssid, bssid, channel, freq, quality, security, _in_use = fields
        try:
            frequency = int(re.search(r"\d+", freq)[0])
            channel_number = int(channel)
        except (ValueError, TypeError):
            continue
        mac = normalize_mac(bssid)
        if mac:
            result.append(ObservedAccessPoint(ssid or "<nascosta>", mac, channel_number,
                _band(frequency), None, security, source='NetworkManager nmcli scan',
                observed_at=time.time(), signal_percent=_signal_percent(quality),
                evidence='Dati riportati da NetworkManager; frequenza/canale e percentuale letti, '
                         'SSID/BSSID/sicurezza annunciati. Nessuna conversione percentuale→dBm.'))
    return result


def parse_iw(text: str) -> list[AccessPoint]:
    result = []
    blocks = re.split(r"(?m)^BSS\s+", text)[1:]
    for block in blocks:
        mac = normalize_mac(block[:17])
        freq_match = re.search(r"(?m)^\s*freq:\s*(\d+)", block)
        signal = re.search(r"(?m)^\s*signal:\s*(-?[\d.]+)\s*dBm", block)
        ssid = re.search(r"(?m)^[ \t]*SSID:[ \t]?(.*)$", block)
        if not mac or not freq_match:
            continue
        freq = int(freq_match[1])
        band = _band(freq)
        channel = (14 if freq == 2484 else (freq - 2407) // 5) if band == "2.4 GHz" else 0
        if band == "5 GHz":
            channel = (freq - (4000 if freq < 5000 else 5000)) // 5
        elif band == "6 GHz":
            channel = 2 if freq == 5935 else (freq - 5950) // 5
        security = "RSN/WPA" if re.search(r"(?m)^\s*(RSN|WPA):", block) else "Non specificata"
        result.append(ObservedAccessPoint(ssid[1] if ssid and ssid[1] else "<nascosta>", mac,
            channel, band, float(signal[1]) if signal else None, security,
            source='Linux iw scan', observed_at=time.time(),
            evidence='RSSI in dBm riportato dal driver al momento della scansione; '
                     'SSID/BSSID/sicurezza sono dati annunciati, non identità verificate.'))
    return result


def channel_summary(access_points: list[AccessPoint]) -> str:
    """Count observed BSSIDs by reported band/channel; no inferred interference."""
    points = list({ap.bssid: ap for ap in access_points}.values())
    other_bands = []
    for band in ("2.4 GHz", "5 GHz", "6 GHz"):
        counts: dict[int, int] = {}
        for ap in points:
            if ap.band == band and ap.channel > 0:
                counts[ap.channel] = counts.get(ap.channel, 0) + 1
        shared = ", ".join(f"{ch} ({count} BSSID)" for ch, count in sorted(counts.items()) if count > 1)
        other_bands.append(f"{band}: {sum(counts.values())} BSSID; canali condivisi: {shared or 'nessuno osservato'}")
    unknown = sum(ap.band not in ('2.4 GHz', '5 GHz', '6 GHz') for ap in points)
    return ('. '.join(other_bands) + f'. Banda ignota: {unknown}. '
            'Conteggi della scansione, non stato continuo. Non misura airtime, spettro o interferenze; '
            'larghezza di canale e causa delle perturbazioni non determinate.')


def scan_wifi(network: NetworkInfo) -> tuple[list[AccessPoint], list[str]]:
    warnings: list[str] = []
    if platform.system() == "Windows":
        output = run_command(["netsh", "wlan", "show", "networks", "mode=bssid",
                              f"interface={network.interface}"], timeout=7)
        points = parse_netsh(output)
        if not points and re.search(r"access.{0,12}denied|accesso.{0,12}negato|permission|autorizzaz|localizzaz|location", output, re.I):
            raise RuntimeError("Scansione Wi-Fi negata: verificare autorizzazione alla posizione e servizio WLAN. " + output.strip()[:180])
        warnings.append("Wi-Fi Windows: cache WLAN, presenza attuale non verificata; segnale percentuale mantenuto senza conversione in dBm.")
    else:
        try:
            output = run_command(["nmcli", "--terse", "--escape", "yes", "--fields",
                                  "SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY,IN-USE", "device", "wifi", "list",
                                  "--rescan", "no", "ifname", network.interface], timeout=8)
            points = parse_nmcli(output)
            warnings.append("Wi-Fi NetworkManager: segnale percentuale mantenuto; RSSI dBm non disponibile da questa sorgente.")
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
            warnings.append(f"NetworkManager non disponibile ({str(exc)[:100]}); uso iw.")
            output = run_command(["iw", "dev", network.interface, "scan", "freq",
                                  *[str(2412+5*i) for i in range(13)]], timeout=8)
            points = parse_iw(output)
    if not points:
        warnings.append("Nessun BSSID leggibile: radio spenta, permessi mancanti o formato non supportato.")
    other = sum(ap.band != '2.4 GHz' for ap in points)
    if other:
        warnings.append(f'{other} BSSID esclusi: banda diversa o non verificata. Inventario radio limitato a 2,4 GHz.')
    return list({ap.bssid: ap for ap in points if ap.band == '2.4 GHz'}.values()), warnings


def _neighbors(network: NetworkInfo) -> dict[str, str]:
    if platform.system() == "Windows":
        # A single-quoted PowerShell literal escapes apostrophes by doubling them.
        name = network.interface.replace("'", "''")
        script = ("[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new(); "
                  f"Get-NetNeighbor -InterfaceAlias '{name}' -AddressFamily IPv4 -ErrorAction Stop | "
                  "Select-Object IPAddress,LinkLayerAddress,State | ConvertTo-Json -Compress")
        raw = run_command(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], timeout=5)
        rows = json.loads(raw) if raw.strip() else []
        rows = rows if isinstance(rows, list) else [rows]
        return {row["IPAddress"]: normalize_mac(row.get("LinkLayerAddress", "")) for row in rows
                if normalize_mac(row.get("LinkLayerAddress", "")) not in ("", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff")}
    rows = json.loads(run_command(["ip", "-j", "neigh", "show", "dev", network.interface], timeout=3))
    return {row["dst"]: normalize_mac(row.get("lladdr", "")) for row in rows
            if normalize_mac(row.get("lladdr", ""))}


def _arp_scan(network: NetworkInfo, scope: ipaddress.IPv4Network,
              stop: threading.Event) -> dict[str, str]:
    if platform.system() == 'Windows':
        return _windows_arp(network, scope, stop)
    from scapy.all import ARP, Ether, conf, srp
    # Match the selected address, not conf.iface (which might be a VPN/Ethernet route).
    iface = next((item for item in conf.ifaces.values()
                  if network.address == getattr(item, "ip", "")
                  or network.address in getattr(item, "ips", {}).get(4, [])), None)
    if iface is None:
        raise RuntimeError("Interfaccia Scapy corrispondente all'IPv4 selezionato non trovata")
    source_mac = normalize_mac(network.mac) or normalize_mac(getattr(iface, "mac", ""))
    if not source_mac:
        raise RuntimeError("Indirizzo MAC dell'interfaccia selezionata non disponibile")
    hosts = [str(ip) for ip in scope.hosts() if str(ip) != network.address]
    found = Observations()
    # Chunking bounds cancellation latency; each srp has a finite receive timeout.
    for offset in range(0, len(hosts), 128):
        if stop.is_set():
            break
        packets = Ether(src=source_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
            pdst=hosts[offset:offset + 128], psrc=network.address, hwsrc=source_mac)
        answers, _ = srp(packets, iface=iface, timeout=1.0, inter=0.003, retry=0, verbose=False)
        for _, packet in answers:
            if packet.haslayer(ARP) and packet[ARP].op == 2:
                ip, mac = packet[ARP].psrc, normalize_mac(packet[ARP].hwsrc)
                if ipaddress.ip_address(ip) in scope and mac:
                    found[ip] = mac
                    found.observed_at[ip] = float(packet.time)
    return found


def _windows_arp(network, scope, stop):
    """Use the IP Helper API; no Npcap installation or raw packet driver."""
    import ctypes as C
    import struct
    api = C.WinDLL('iphlpapi', use_last_error=True)
    send = api.SendARP
    send.argtypes = [C.c_uint32, C.c_uint32, C.c_void_p, C.POINTER(C.c_uint32)]
    send.restype = C.c_uint32
    source = struct.unpack('=I', socket.inet_aton(network.address))[0]
    def probe(ip):
        if stop.is_set():
            return None
        target = struct.unpack('=I', socket.inet_aton(ip))[0]
        buffer, length = (C.c_ubyte*8)(), C.c_uint32(8)
        result = send(target, source, buffer, C.byref(length))
        if result == 0 and length.value == 6:
            return ':'.join(f'{b:02x}' for b in buffer[:6])
        if result in (5, 87):
            raise OSError(result, 'SendARP: permesso o indirizzo sorgente non valido')
        return None
    found = Observations()
    hosts = iter(str(ip) for ip in scope.hosts() if str(ip) != network.address)
    with ThreadPoolExecutor(max_workers=16, thread_name_prefix='native-arp') as pool:
        pending = {}
        while not stop.is_set():
            while len(pending) < 16:
                ip = next(hosts, None)
                if ip is None:
                    break
                pending[pool.submit(probe, ip)] = ip
            if not pending:
                break
            ready, _ = wait(pending, timeout=.1, return_when=FIRST_COMPLETED)
            for future in ready:
                ip = pending.pop(future)
                mac = future.result()
                if mac:
                    found[ip] = mac
                    found.observed_at[ip] = time.time()
    return found


def _populate_neighbors(network, scope, stop):
    """Source-bound TCP attempts let the OS resolve ARP without raw privileges."""
    hosts = iter(str(ip) for ip in scope.hosts() if str(ip) != network.address)
    with ThreadPoolExecutor(max_workers=16, thread_name_prefix='neighbor-probe') as pool:
        pending = set()
        while not stop.is_set():
            while len(pending) < 16:
                ip = next(hosts, None)
                if ip is None:
                    break
                pending.add(pool.submit(_tcp_open, network.address, ip, 80, stop))
            if not pending:
                break
            done, pending = wait(pending, timeout=.1, return_when=FIRST_COMPLETED)
            for future in done:
                future.result()


def _tcp_open(source: str, ip: str, port: int, stop: threading.Event) -> bool:
    if stop.is_set():
        return False
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.settimeout(0.30)
            connection.bind((source, 0))
            return connection.connect_ex((ip, port)) == 0
    except OSError:
        return False


def _ports_for_hosts(network: NetworkInfo, hosts: dict[str, str],
                     stop: threading.Event) -> dict[str, list[int]]:
    opened = Observations()
    opened.update({ip: [] for ip in hosts})
    jobs = iter((ip, port) for ip in hosts for port in PORTS)
    with ThreadPoolExecutor(max_workers=32, thread_name_prefix="tcp-scan") as pool:
        pending = {}
        while not stop.is_set():
            while len(pending) < 64:
                job = next(jobs, None)
                if job is None:
                    break
                ip, port = job
                pending[pool.submit(_tcp_open, network.address, ip, port, stop)] = job
            if not pending:
                break
            ready, _ = wait(pending, timeout=0.1, return_when=FIRST_COMPLETED)
            for future in ready:
                ip, port = pending.pop(future)
                if future.result():
                    opened[ip].append(port)
                    opened.observed_at[(ip, port)] = time.time()
        for future in pending:
            future.cancel()
    return opened


def scan_network(network: NetworkInfo, stop: threading.Event,
                 progress: Callable[[str], None] | None = None) -> ScanResult:
    report = progress or (lambda message: None)
    if stop.is_set():
        return ScanResult(warnings=("Scansione annullata.",), partial=True)
    scope, partial = scan_scope(network)
    warnings: list[str] = []
    if partial:
        warnings.append(f"Sottorete {network.network} troppo ampia: scansione limitata a {scope} (massimo 1024 indirizzi).")
    report(f"Scansione ARP {scope}")
    hosts: dict[str, str] = {}
    host_source = 'ARP reply'
    try:
        hosts = _arp_scan(network, scope, stop)
    except Exception as exc:
        host_source = 'OS neighbor cache'
        partial = True
        warnings.append(f"ARP raw non disponibile ({str(exc)[:150]}). Risoluzione vicini tramite TCP/OS senza privilegi raw; MAC dalla cache, non prova di presenza.")
        try:
            _populate_neighbors(network, scope, stop)
            hosts = _neighbors(network)
        except Exception as neighbor_exc:
            warnings.append(f"Cache vicini non disponibile: {str(neighbor_exc)[:140]}")
    host_times = getattr(hosts, 'observed_at', {})
    query_finished = time.time()
    hosts = {ip: mac for ip, mac in hosts.items() if _in_scope(ip, scope)}
    if network.mac:
        hosts[network.address] = normalize_mac(network.mac)
    if stop.is_set():
        return ScanResult(warnings=tuple(warnings + ["Scansione annullata."]), partial=True)
    report(f"Verifica di {len(PORTS)} porte TCP su {len(hosts)} host")
    opened = _ports_for_hosts(network, hosts, stop)
    devices = tuple(ObservedDevice(ip, mac, vendor_for_mac(mac), tuple(sorted(opened.get(ip, []))),
                           "Gateway" if ip == network.gateway else "Questo host" if ip == network.address else "Endpoint osservato",
                           source='OS interface configuration' if ip == network.address else host_source,
                           observed_at=host_times.get(ip, query_finished),
                           verification='measurement' if ip == network.address else 'protocol_claim',
                           evidence=('Configurazione dell\'interfaccia di questo host.' if ip == network.address else
                                     'Voce letta nella cache vicini: non prova una risposta recente né connessione attuale.'
                                     if host_source == 'OS neighbor cache' else
                                     'Risposta ARP osservata: associazione IP/MAC dichiarata, non identità autenticata.'),
                           port_observations=tuple({'port': port, 'protocol': 'TCP',
                               'observed_at': getattr(opened, 'observed_at', {}).get((ip, port), time.time()),
                               'source': 'TCP connect', 'verification': 'measurement',
                               'tcp_handshake_completed': True, 'service_identity_verified': False,
                               'evidence': 'Connessione TCP riuscita durante la verifica; stato successivo non garantito.'}
                               for port in sorted(opened.get(ip, []))))
                    for ip, mac in sorted(hosts.items(), key=lambda item: ipaddress.ip_address(item[0])))
    points: list[AccessPoint] = []
    if not stop.is_set():
        report("Analisi dei canali Wi-Fi vicini")
        try:
            points, wifi_warnings = scan_wifi(network)
            warnings.extend(wifi_warnings)
        except Exception as exc:
            partial = True
            warnings.append(f"Canali Wi-Fi non disponibili: {str(exc)[:220]}")
    if stop.is_set():
        warnings.append("Scansione annullata: risultati parziali.")
    return ScanResult(devices, tuple(points), tuple(warnings), channel_summary(points), partial or stop.is_set())


def _in_scope(address: str, scope: ipaddress.IPv4Network) -> bool:
    try:
        ip = ipaddress.ip_address(address)
        return (ip in scope and not ip.is_multicast and not ip.is_unspecified
                and (scope.prefixlen >= 31 or ip not in (scope.network_address, scope.broadcast_address)))
    except ValueError:
        return False
