"""Existing host sockets and optional passive IPv4 headers; never contact an IP.

A normal Wi-Fi client cannot see every other client's unicast traffic.
No packet payload is retained or inspected, and no DNS lookup is performed.
"""
from collections import OrderedDict
import ipaddress
import socket
import threading
import time

from models import NetworkInfo


def public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value.split('%', 1)[0])
        return ip.is_global and not any((ip.is_multicast, ip.is_reserved, ip.is_loopback,
                                        ip.is_unspecified, ip.is_link_local))
    except ValueError:
        return False


def host_connections(limit: int = 128) -> tuple[list[dict], list[str]]:
    """Read OS socket table. Results describe THIS host, never inferred peers."""
    import psutil
    records, names, warnings = [], {}, []
    try:
        sockets = psutil.net_connections(kind='inet')
    except (psutil.Error, OSError) as exc:
        return [], [f'Tabella connessioni del PC non disponibile: {exc}']
    for item in sockets:
        if not item.raddr or not public_ip(item.raddr.ip):
            continue
        if item.pid not in names:
            try:
                names[item.pid] = psutil.Process(item.pid).name() if item.pid else 'Non disponibile'
            except (psutil.Error, OSError):
                names[item.pid] = 'Non disponibile'
        protocol = 'TCP' if item.type == socket.SOCK_STREAM else 'UDP'
        local_ip = item.laddr.ip if item.laddr else ''
        local_port = item.laddr.port if item.laddr else 0
        ident = f'host:{protocol}:{local_ip}:{local_port}:{item.raddr.ip}:{item.raddr.port}'
        records.append(dict(id=ident, local_ip=local_ip, local_port=local_port,
            remote_ip=item.raddr.ip, remote_port=item.raddr.port, protocol=protocol,
            process=names[item.pid], pid=item.pid, state=item.status,
            scope='host', source='OS socket table', observed_at=time.time(),
            verification='measurement', observation_only=True, identity_verified=False,
            currently_active_verified=False,
            evidence='Voce nella tabella socket di questo PC al momento della lettura; '
                     'lo stato successivo e l\'identità del peer non sono verificati.'))
    records.sort(key=lambda row: (row['remote_ip'], row['remote_port'], row['id']))
    if len(records) > limit:
        warnings.append(f'Visualizzate {limit} delle {len(records)} connessioni del PC.')
    return records[:limit], warnings


class PassiveCapture:
    """Optional bounded capture; only what is actually visible on this NIC."""
    def __init__(self):
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._flows = OrderedDict()
        self._thread = None
        self.error = ''

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive() and not self._stop.is_set()

    def start(self, network: NetworkInfo) -> None:
        if self._thread is not None and self._thread.is_alive():
            if self._stop.is_set():
                # A timed-out stop must not clear the old worker's stop signal
                # or lose its handle by starting another capture thread.
                raise RuntimeError('La cattura precedente è ancora in arresto; attendere prima di riavviarla')
            return
        self._stop.clear()
        self.error = ''
        with self._lock:
            self._flows.clear()
        self._thread = threading.Thread(target=self._run, args=(network,),
                                        name='passive-ip-headers', daemon=False)
        self._thread.start()

    def _run(self, network: NetworkInfo) -> None:
        try:
            from scapy.all import IP, TCP, UDP, conf, sniff
            iface = next((item for item in conf.ifaces.values()
                          if network.address == getattr(item, 'ip', '')
                          or network.address in getattr(item, 'ips', {}).get(4, [])), None)
            if iface is None:
                raise RuntimeError('Interfaccia di cattura corrispondente non disponibile')
            subnet = network.network

            def received(packet):
                if not packet.haslayer(IP):
                    return
                layer = packet[IP]
                src, dst = layer.src, layer.dst
                if ipaddress.ip_address(src) in subnet and public_ip(dst):
                    local, remote, outgoing = src, dst, True
                elif ipaddress.ip_address(dst) in subnet and public_ip(src):
                    local, remote, outgoing = dst, src, False
                else:
                    return
                transport = packet[TCP] if packet.haslayer(TCP) else packet[UDP] if packet.haslayer(UDP) else None
                protocol = 'TCP' if packet.haslayer(TCP) else 'UDP' if packet.haslayer(UDP) else 'IP'
                local_port = int(transport.sport if outgoing else transport.dport) if transport else 0
                remote_port = int(transport.dport if outgoing else transport.sport) if transport else 0
                self.record(local, remote, local_port, remote_port, protocol, len(packet), outgoing)

            while not self._stop.is_set():
                # Each capture releases its socket within 0.5 s, even on an idle LAN.
                sniff(iface=iface, filter='ip', store=False, prn=received, timeout=0.5)
        except Exception as exc:
            self.error = f'Cattura passiva non disponibile: {exc}'

    def record(self, local: str, remote: str, local_port: int, remote_port: int,
               protocol: str, size: int, outgoing: bool) -> None:
        key = f'capture:{protocol}:{local}:{local_port}:{remote}:{remote_port}'
        with self._lock:
            previous = self._flows.pop(key, {})
            self._flows[key] = dict(id=key, local_ip=local, local_port=local_port,
                remote_ip=remote, remote_port=remote_port, protocol=protocol,
                process='Non attribuito', scope='capture', observed_at=time.time(),
                source='Passive IPv4 capture', verification='measurement', observation_only=True,
                identity_verified=False, currently_active_verified=False,
                packets=previous.get('packets', 0) + 1, bytes=previous.get('bytes', 0) + size,
                direction='uscita' if outgoing else 'ingresso',
                evidence='Header IPv4 osservato sulla NIC; indirizzi dichiarati nel pacchetto, '
                         'non identità autenticate. Non dimostra una connessione attualmente attiva.')
            while len(self._flows) > 256:
                self._flows.popitem(last=False)

    def snapshot(self, max_age: float = 60) -> list[dict]:
        cutoff = time.time() - max_age
        with self._lock:
            return [dict(value) for value in self._flows.values() if value['observed_at'] >= cutoff]

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
            if self._thread.is_alive():
                raise RuntimeError('La libreria di cattura non ha ancora rilasciato la NIC')
            self._thread = None
        with self._lock:
            self._flows.clear()
