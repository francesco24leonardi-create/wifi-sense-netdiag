"""Local discovery: ARP/TCP, Wi-Fi channels, mDNS, SSDP and BLE.

Only multicast/local targets are contacted. SSDP LOCATION URLs and advertised
hostnames are displayed as untrusted metadata, never fetched or DNS-resolved.
An IP/MAC inventory does not provide per-client Wi-Fi RSSI or an azimuth.
"""
from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
import ipaddress
import math
from queue import Empty, Full, Queue
import socket
import threading
import time
from typing import Callable

from models import NetworkInfo
import lan_scanner

LIMIT = 256
DISCOVERY_SECONDS = 5.0
MDNS_TYPES = (
    '_googlecast._tcp.local.', '_airplay._tcp.local.', '_raop._tcp.local.',
    '_http._tcp.local.', '_https._tcp.local.', '_workstation._tcp.local.',
    '_smb._tcp.local.', '_hap._tcp.local.', '_ipp._tcp.local.',
    '_ipps._tcp.local.', '_androidtvremote2._tcp.local.', '_companion-link._tcp.local.',
)
NO_DISTANCE = 'Distanza e azimut non misurati. RSSI non viene convertito in metri.'


def clean(value: object, limit: int = 200) -> str:
    if isinstance(value, bytes):
        value = value.decode('utf-8', errors='replace')
    return ''.join(c for c in str(value) if c.isprintable())[:limit]


def local_ip(value: str, network: NetworkInfo) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return (ip.version == 4 and ip in network.network and not ip.is_multicast
                and not ip.is_unspecified and not ip.is_loopback
                and (network.network.prefixlen >= 31 or ip not in
                     (network.network.network_address, network.network.broadcast_address)))
    except ValueError:
        return False


def classify(service: str, properties: dict | None = None) -> tuple[str, str]:
    """Classification is a service/model hint, never authenticated identity."""
    properties = properties or {}
    hint = ' '.join([service] + [f'{clean(k)} {clean(v)}' for k, v in properties.items()]).lower()
    if any(word in hint for word in ('iphone', 'ipad', 'pixel phone', 'galaxy phone', 'smartphone')):
        return 'smartphone', 'Indizio nel modello annunciato; tipo fisico e identità non verificati'
    if any(word in hint for word in ('androidtv', 'apple tv', 'appletv', 'smart tv', 'bravia', 'chromecast', 'television')):
        return 'tv', 'Indizio nel servizio/modello multimediale annunciato; tipo fisico non verificato'
    if any(word in hint for word in ('_workstation.', '_smb.', 'macbook', 'windows workstation', 'linux workstation')):
        return 'pc', 'Servizio workstation/SMB annunciato; tipo fisico non verificato'
    if any(word in hint for word in ('_hap.', '_ipp.', '_ipps.', 'mediarenderer', 'dial-multiscreen', 'hue', 'sonos', 'shelly')):
        return 'iot', 'Indizio nel servizio annunciato; tipo fisico non verificato'
    return 'unknown', 'Categoria non determinata dai servizi disponibili'


def device_record(ip: str = '', name: str = '', source: str = '', category: str = 'unknown') -> dict:
    observed_at = time.time()
    evidence = 'Osservazione puntuale; identità, tipo fisico e presenza attuale non verificati.'
    return {'id': f'ip:{ip}', 'name': name or ip or 'Dispositivo', 'category': 'unknown',
            'category_hint': category if category != 'unknown' else None,
            'category_verified': False, 'identity_verified': False, 'name_verified': False,
            'ip': ip, 'mac': '', 'vendor': None, 'oui_assignee': None, 'manufacturer_verified': False,
            'ports': [], 'services': [], 'transport': None,
            'source': source, 'observed_at': observed_at, 'verification': 'protocol_claim',
            'observation_only': True, 'presence_verified': False, 'evidence': [evidence],
            'observations': [{'source': source, 'observed_at': observed_at,
                              'verification': 'protocol_claim', 'evidence': evidence}],
            'sources': [source] if source else [], 'rssi_dbm': None, 'distance_m': None,
            'distance_note': NO_DISTANCE, 'details': {}}


def merge_devices(groups: list[list[dict]]) -> list[dict]:
    """Merge IP observations; BLE identities remain separate from LAN devices."""
    merged: dict[str, dict] = {}
    for group in groups:
        for entry in group:
            key = entry['id'] if entry['id'].startswith('ble:') else f"ip:{entry.get('ip', '')}"
            if key not in merged:
                if len(merged) >= LIMIT:
                    continue
                merged[key] = {**entry, 'ports': list(entry.get('ports', [])),
                               'services': list(entry.get('services', [])),
                               'sources': list(entry.get('sources', [])),
                               'evidence': list(entry.get('evidence', [])),
                               'observations': list(entry.get('observations', [])),
                               'details': dict(entry.get('details', {}))}
                continue
            current = merged[key]
            for field in ('mac', 'oui_assignee'):
                if entry.get(field) and current.get(field) in (None, '', 'Sconosciuto', 'OUI sconosciuto'):
                    current[field] = entry[field]
            if current['name'] in ('', current.get('ip'), 'Dispositivo') and entry.get('name'):
                current['name'] = entry['name']
            if not current.get('category_hint') and entry.get('category_hint'):
                current['category_hint'] = entry['category_hint']
            for field in ('ports', 'services', 'sources', 'evidence', 'observations'):
                for item in entry.get(field, []):
                    if item not in current[field] and len(current[field]) < 64:
                        current[field].append(item)
            current['details'].update(entry.get('details', {}))
            current['observed_at'] = max(current['observed_at'], entry['observed_at'])
            current['source'] = ', '.join(current['sources'])
    return list(merged.values())


def discover_mdns(network: NetworkInfo, stop: threading.Event,
                  duration: float = DISCOVERY_SECONDS) -> tuple[list[dict], list[str]]:
    if stop.is_set():
        return [], []
    from zeroconf import IPVersion, ServiceBrowser, Zeroconf

    pending: Queue[tuple[str, str]] = Queue(maxsize=LIMIT * 2)
    records: dict[tuple[str, str], list[dict]] = {}
    warnings = []

    class Listener:
        def add_service(self, zc, type_, name):
            if not stop.is_set():
                try:
                    pending.put_nowait((type_, name))
                except Full:
                    return

        def update_service(self, zc, type_, name):
            self.add_service(zc, type_, name)

        def remove_service(self, zc, type_, name):
            # A five-second observation remains an observation even if withdrawn.
            return None

    zc = Zeroconf(interfaces=[network.address], ip_version=IPVersion.V4Only)
    browser = None
    deadline = time.monotonic() + duration
    try:
        browser = ServiceBrowser(zc, list(MDNS_TYPES), listener=Listener())
        while not stop.is_set() and time.monotonic() < deadline:
            try:
                type_, name = pending.get(timeout=min(.1, max(.001, deadline - time.monotonic())))
            except Empty:
                continue
            if (type_, name) not in records and len(records) >= LIMIT:
                continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            info = zc.get_service_info(type_, name, timeout=max(1, int(min(.4, remaining) * 1000)))
            if info is None:
                continue
            properties = {clean(k, 64): clean(v, 256) for k, v in list(info.properties.items())[:32]}
            category, confidence = classify(type_, properties)
            friendly = properties.get('fn') or properties.get('name') or name.removesuffix(type_).rstrip('.')
            observations = []
            for address in info.parsed_addresses(IPVersion.V4Only)[:8]:
                if not local_ip(address, network):
                    continue
                entry = device_record(address, clean(friendly), 'mDNS', category)
                entry['services'] = [f'{type_} :{info.port}']
                entry['category_evidence'] = confidence
                entry['evidence'].append('Nome, indirizzo e servizi dichiarati tramite mDNS; non autenticati.')
                entry['details'] = {'category_hint_evidence': confidence,
                                    'mdns': {'service': clean(name), 'server': clean(info.server or ''),
                                             'port': info.port, 'txt': properties,
                                             'verification': 'protocol_claim',
                                             'observed_at': entry['observed_at']}}
                observations.append(entry)
            records[(type_, name)] = observations
    except Exception as exc:
        warnings.append(f'mDNS interrotto: {clean(exc, 250)}')
    finally:
        try:
            if browser is not None:
                browser.cancel()
        except Exception as exc:
            warnings.append(f'Arresto browser mDNS: {clean(exc, 250)}')
        finally:
            zc.close()
    entries = [entry for observations in records.values() for entry in observations]
    return entries[:LIMIT], warnings


def parse_ssdp(payload: bytes) -> dict[str, str]:
    text = payload[:8192].decode('utf-8', errors='replace')
    lines = text.splitlines()
    if not lines or not lines[0].strip().upper().startswith(('HTTP/1.1 200', 'HTTP/1.0 200')):
        return {}
    headers: dict[str, str] = {}
    for line in lines[1:65]:
        if ':' in line:
            key, value = line.split(':', 1)
            key = clean(key, 40).strip().lower()
            if key in ('st', 'usn', 'server', 'location', 'cache-control', 'date', 'ext'):
                headers[key] = clean(value.strip(), 512)
    return headers


def discover_ssdp(network: NetworkInfo, stop: threading.Event,
                  duration: float = DISCOVERY_SECONDS) -> tuple[list[dict], list[str]]:
    if stop.is_set():
        return [], []
    request = (b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n'
               b'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n')
    entries: dict[tuple[str, str], dict] = {}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(network.address))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.bind((network.address, 0))
        sock.settimeout(.2)
        sock.sendto(request, ('239.255.255.250', 1900))
        deadline = time.monotonic() + duration
        while not stop.is_set() and time.monotonic() < deadline and len(entries) < LIMIT:
            try:
                packet, sender = sock.recvfrom(8192)
            except socket.timeout:
                continue
            if not local_ip(sender[0], network):
                continue
            headers = parse_ssdp(packet)
            if not headers:
                continue
            category, confidence = classify(headers.get('st', ''), headers)
            # No HTTP requests to LOCATION: attacker-controlled URLs cannot cause SSRF.
            entry = device_record(sender[0], sender[0], 'SSDP', category)
            entry['services'] = [headers.get('st', 'SSDP')]
            entry['category_evidence'] = confidence
            entry['evidence'].append('Risposta SSDP ricevuta; descrizione del servizio auto-dichiarata, non autenticata.')
            entry['details'] = {'category_hint_evidence': confidence, 'ssdp': headers,
                                'ssdp_note': 'Descrizione XML non scaricata; URL LOCATION solo informativo.'}
            entries[(sender[0], headers.get('usn', headers.get('st', '')))] = entry
    return list(entries.values()), []


async def _ble_scan(stop: threading.Event, duration: float) -> tuple[list[dict], list[str]]:
    from bleak import BleakScanner

    records: dict[str, dict] = {}
    warnings = []

    def advertisement(device, data):
        address = clean(device.address, 100)
        if stop.is_set() or (address not in records and len(records) >= LIMIT):
            return
        entry = device_record(name=clean(data.local_name or device.name or address), source='BLE')
        rssi = float(data.rssi)
        rssi = rssi if math.isfinite(rssi) and -120 <= rssi <= -1 else None
        entry.update(id=f'ble:{address}', mac=lan_scanner.normalize_mac(address),
                     rssi_dbm=rssi, distance_m=None, transport='ble',
                     distance_note=NO_DISTANCE, rssi_verification='measurement')
        entry['evidence'].append('Annuncio Bluetooth LE osservato; RSSI letto dall\'adattatore. '
                                 'Nome e payload auto-dichiarati, tipo fisico sconosciuto.')
        entry['services'] = [clean(uuid, 80) for uuid in (data.service_uuids or [])[:32]]
        entry['details'] = {'ble_address': address, 'classification': 'Trasporto BLE osservato; tipo fisico non determinato',
                            'tx_power_dbm': data.tx_power,
                            'manufacturer_data': {str(key): bytes(value)[:64].hex()
                                                  for key, value in list(data.manufacturer_data.items())[:16]},
                            'service_data': {clean(key, 80): bytes(value)[:64].hex()
                                             for key, value in list(data.service_data.items())[:16]},
                            'rssi': {'value_dbm': rssi, 'source': 'Adattatore BLE',
                                     'observed_at': entry['observed_at'], 'verification': 'measurement'},
                            'advertisement_verification': 'protocol_claim'}
        records[address] = entry

    scanner = BleakScanner(detection_callback=advertisement, scanning_mode='active')
    try:
        await asyncio.wait_for(scanner.start(), timeout=4)
        deadline = time.monotonic() + duration
        while not stop.is_set() and time.monotonic() < deadline:
            await asyncio.sleep(.1)
    except Exception as exc:
        warnings.append(f'BLE interrotto: {clean(exc, 250)}')
    finally:
        try:
            await asyncio.wait_for(scanner.stop(), timeout=3)
        except Exception as exc:
            warnings.append(f'Arresto BLE: {clean(exc, 250)}')
    return list(records.values()), warnings


def discover_ble(network: NetworkInfo, stop: threading.Event,
                 duration: float = DISCOVERY_SECONDS) -> tuple[list[dict], list[str]]:
    if stop.is_set():
        return [], []
    return asyncio.run(_ble_scan(stop, duration))


def scan_all(network: NetworkInfo, stop: threading.Event,
             progress: Callable[[str], None] | None = None) -> dict:
    """Concurrent one-shot scan; failures remain visible and never erase successes."""
    result = {'devices': [], 'access_points': [], 'warnings': [], 'channel_summary': '', 'partial': False}
    if stop.is_set():
        result.update(partial=True, warnings=['Scansione annullata.'])
        return result
    report = progress or (lambda message: None)
    report('Scansione locale ARP/TCP, mDNS, SSDP e Bluetooth LE')
    groups: list[list[dict]] = []
    # Each discovery owns its sockets/event loop. Blocking libraries never run on Tk/ASGI.
    with ThreadPoolExecutor(max_workers=4, thread_name_prefix='local-discovery') as pool:
        pending = {pool.submit(lan_scanner.scan_network, network, stop, report): 'LAN',
                   pool.submit(discover_mdns, network, stop): 'mDNS',
                   pool.submit(discover_ssdp, network, stop): 'SSDP',
                   pool.submit(discover_ble, network, stop): 'BLE'}
        for future in as_completed(pending):
            source = pending[future]
            try:
                payload = future.result()
                if source == 'LAN':
                    entries = []
                    for item in payload.devices:
                        role = 'gateway' if item.ip == network.gateway else 'local_host' if item.ip == network.address else 'endpoint'
                        source = getattr(item, 'source', '') or 'Inventario LAN, sorgente non specificata'
                        entry = device_record(item.ip, 'Gateway configurato' if role == 'gateway' else
                                              'Questo host' if role == 'local_host' else item.ip, source)
                        attribution = lan_scanner.mac_attribution(item.mac)
                        observed_at = getattr(item, 'observed_at', None) or time.time()
                        verification = getattr(item, 'verification', 'protocol_claim')
                        evidence = getattr(item, 'evidence', '') or 'Osservazione LAN; identità e connessione attuale non verificate.'
                        entry.update(mac=item.mac, vendor=None, oui_assignee=attribution['oui_assignee'],
                                     ports=list(item.ports), observed_at=observed_at, verification=verification,
                                     role=role, evidence=[evidence, attribution['warning']],
                                     observations=[{'source': source, 'observed_at': observed_at,
                                                    'verification': verification, 'evidence': evidence}])
                        entry['details'] = {'role': item.role, 'classification': 'Tipo fisico sconosciuto',
                                            'mac_attribution': attribution,
                                            'tcp_observations': list(getattr(item, 'port_observations', ())),
                                            'ports_note': 'Porte TCP raggiunte al momento della verifica; stato corrente non garantito.'}
                        entries.append(entry)
                    groups.insert(0, entries)
                    result['access_points'] = [dict(asdict(point), **({} if hasattr(point, 'source') else {
                        'source': 'Inventario WLAN, sorgente non specificata', 'observed_at': time.time(),
                        'verification': 'protocol_claim', 'observation_only': True,
                        'identity_verified': False, 'presence_verified': False, 'distance_m': None}))
                        for point in payload.access_points]
                    result['channel_summary'] = payload.channel_summary
                    result['warnings'].extend(payload.warnings)
                    result['partial'] |= payload.partial
                else:
                    entries, warnings = payload
                    groups.append(entries)
                    result['warnings'].extend(warnings)
                    result['partial'] |= bool(warnings)
                report(f'{source}: osservazioni completate')
            except Exception as exc:
                result['partial'] = True
                result['warnings'].append(f'{source} non disponibile: {clean(exc, 300)}')
    result['devices'] = merge_devices(groups)
    if len(result['devices']) >= LIMIT:
        result['partial'] = True
        result['warnings'].append(f'Inventario limitato a {LIMIT} dispositivi.')
    if stop.is_set():
        result['partial'] = True
        result['warnings'].append('Scansione annullata: dati raccolti parziali.')
    return result
