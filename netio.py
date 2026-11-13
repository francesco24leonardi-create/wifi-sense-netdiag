"""OS adapters: route discovery, native RSSI and source-bound ICMP.

No shell interpolation, no elevation and no OS configuration changes.
All blocking calls belong in worker threads. IPv4 is intentional.
"""
from __future__ import annotations

import ctypes as C
import errno
import ipaddress
import json
import locale
import os
from pathlib import Path
import re
import select
import shutil
import socket
import struct
import subprocess
import sys
import time

from models import NetworkInfo


def run_command(args: list[str], timeout: float = 5) -> str:
    """Run a bounded command without a shell, hiding Windows console windows."""
    env = os.environ.copy()
    env.update({"LC_ALL": "C", "LANG": "C"})
    result = subprocess.run(
        args, capture_output=True, timeout=timeout, env=env,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    encoding = "oem" if os.name == "nt" else locale.getpreferredencoding(False)
    if args[0].lower().endswith(("powershell", "powershell.exe")):
        encoding = "utf-8"
    out = result.stdout.decode(encoding, errors="replace").strip().lstrip("\ufeff")
    if result.returncode:
        error = result.stderr.decode(encoding, errors="replace").strip()
        raise RuntimeError(f"{Path(args[0]).name}: {(error or out or str(result.returncode))[:600]}")
    return out


def _items(value: object) -> list:
    return value if isinstance(value, list) else [value] if value else []


def discover_network(interface: str | None = None) -> NetworkInfo:
    """Choose the lowest-metric default IPv4 route (or requested interface)."""
    if sys.platform == "win32":
        # Interface names are filtered in Python, never inserted into script code.
        script = r"""
        $ErrorActionPreference = 'Stop'
        [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
        @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' |
          Where-Object { $_.NextHop -ne '0.0.0.0' } | ForEach-Object {
            $route = $_
            $nic = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue
            $ipif = Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $route.InterfaceIndex
            Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $route.InterfaceIndex |
              Where-Object { $_.AddressState -eq 'Preferred' -and -not $_.SkipAsSource } |
              ForEach-Object {
                [pscustomobject]@{
                  interface=$route.InterfaceAlias; address=$_.IPAddress
                  prefix=$_.PrefixLength; gateway=$route.NextHop
                  metric=([int]$route.RouteMetric + [int]$ipif.InterfaceMetric)
                  mac=$nic.MacAddress; guid=[string]$nic.InterfaceGuid
                }
              }
          }) | ConvertTo-Json -Compress
        """
        rows = _items(json.loads(run_command(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script], 12
        ) or "[]"))
        if interface:
            rows = [r for r in rows if str(r["interface"]).casefold() == interface.casefold()]
        if not rows:
            raise RuntimeError("Nessuna interfaccia IPv4 con gateway predefinito disponibile.")
        row = min(rows, key=lambda r: int(r["metric"]))
        net = ipaddress.IPv4Network(f"0.0.0.0/{int(row['prefix'])}")
        return NetworkInfo(row["interface"], row["address"], str(net.netmask),
                           row["gateway"], (row.get("mac") or "").replace("-", ":"),
                           row.get("guid", ""))
    if sys.platform.startswith("linux"):
        routes = _items(json.loads(run_command(["ip", "-j", "-4", "route", "show", "default"])))
        routes = [r for r in routes if r.get("gateway") and r.get("dev")
                  and "linkdown" not in r.get("flags", [])
                  and (interface is None or r["dev"] == interface)]
        if not routes:
            raise RuntimeError("Nessuna rotta IPv4 predefinita; verificare iproute2 e connessione.")
        route = min(routes, key=lambda r: int(r.get("metric", 0)))
        adapters = _items(json.loads(run_command(["ip", "-j", "-4", "addr", "show", "dev", route["dev"]])))
        for adapter in adapters:
            addresses = [a for a in adapter.get("addr_info", [])
                         if a.get("family") == "inet" and a.get("scope") == "global"]
            addresses.sort(key=lambda a: a["local"] != route.get("prefsrc"))
            for address in addresses:
                net = ipaddress.IPv4Network(f"{address['local']}/{address['prefixlen']}", strict=False)
                if ipaddress.IPv4Address(route["gateway"]) in net:
                    return NetworkInfo(route["dev"], address["local"], str(net.netmask),
                                       route["gateway"], adapter.get("address", ""))
        raise RuntimeError("Nessun indirizzo IPv4 locale compatibile con il gateway.")
    raise RuntimeError("Sono supportati Windows e Linux; usare --demo sugli altri sistemi.")


class GUID(C.Structure):
    _fields_ = [("data1", C.c_uint32), ("data2", C.c_uint16),
                ("data3", C.c_uint16), ("data4", C.c_ubyte * 8)]

    def text(self) -> str:
        import uuid
        return str(uuid.UUID(bytes_le=bytes(self)))


class _WlanInterface(C.Structure):
    _fields_ = [("guid", GUID), ("description", C.c_wchar * 256), ("state", C.c_uint32)]


def _win_error(code: int, operation: str) -> OSError:
    hint = " Verificare i permessi di posizione Windows." if code == 5 and operation.startswith("Wlan") else ""
    return OSError(code, f"{operation}: {C.FormatError(code).strip()}.{hint}")


class WindowsRSSI:
    label = "WLAN API · RSSI dBm (cache driver)"

    def __init__(self, network: NetworkInfo):
        self.api = C.WinDLL("wlanapi", use_last_error=True)
        self.handle = C.c_void_p()
        self.api.WlanOpenHandle.argtypes = [C.c_uint32, C.c_void_p, C.POINTER(C.c_uint32), C.POINTER(C.c_void_p)]
        self.api.WlanOpenHandle.restype = C.c_uint32
        self.api.WlanEnumInterfaces.argtypes = [C.c_void_p, C.c_void_p, C.POINTER(C.c_void_p)]
        self.api.WlanEnumInterfaces.restype = C.c_uint32
        self.api.WlanQueryInterface.argtypes = [C.c_void_p, C.POINTER(GUID), C.c_uint32,
            C.c_void_p, C.POINTER(C.c_uint32), C.POINTER(C.c_void_p), C.POINTER(C.c_uint32)]
        self.api.WlanQueryInterface.restype = C.c_uint32
        self.api.WlanFreeMemory.argtypes = [C.c_void_p]
        self.api.WlanFreeMemory.restype = None
        self.api.WlanCloseHandle.argtypes = [C.c_void_p, C.c_void_p]
        self.api.WlanCloseHandle.restype = C.c_uint32
        version = C.c_uint32()
        code = self.api.WlanOpenHandle(2, None, C.byref(version), C.byref(self.handle))
        if code:
            raise _win_error(code, "WlanOpenHandle")
        pointer = C.c_void_p()
        try:
            code = self.api.WlanEnumInterfaces(self.handle, None, C.byref(pointer))
            if code:
                raise _win_error(code, "WlanEnumInterfaces")
            count = C.cast(pointer, C.POINTER(C.c_uint32))[0]
            interfaces = (_WlanInterface * count).from_address(pointer.value + 8)
            wanted = network.interface_id.strip("{}").lower()
            candidates = [entry for entry in interfaces if entry.state == 1 and
                          (entry.guid.text().lower() == wanted if wanted
                           else entry.description == network.interface)]
            if not candidates:
                raise RuntimeError("L'interfaccia selezionata non è Wi-Fi connessa. "
                                   "Specificarla con --interface; controllare WLAN AutoConfig.")
            self.guid = GUID.from_buffer_copy(candidates[0].guid)
        except Exception:
            self.close()
            raise
        finally:
            if pointer.value:
                self.api.WlanFreeMemory(pointer)

    def read(self) -> float | None:
        pointer, size, value_type = C.c_void_p(), C.c_uint32(), C.c_uint32()
        try:
            code = self.api.WlanQueryInterface(self.handle, C.byref(self.guid), 0x10000102,
                None, C.byref(size), C.byref(pointer), C.byref(value_type))
            if code:
                raise _win_error(code, "WlanQueryInterface RSSI")
            if size.value < 4 or not pointer.value:
                return None
            value = C.cast(pointer, C.POINTER(C.c_int32))[0]
            return float(value) if -120 <= value < 0 else None
        finally:
            if pointer.value:
                self.api.WlanFreeMemory(pointer)

    def close(self) -> None:
        if self.handle.value:
            self.api.WlanCloseHandle(self.handle, None)
            self.handle = C.c_void_p()


def parse_proc_rssi(text: str, interface: str) -> float | None:
    for line in text.splitlines():
        if ":" not in line:
            continue
        name, data = line.split(":", 1)
        if name.strip() != interface:
            continue
        parts = data.split()
        if len(parts) < 3:
            return None
        try:
            value = float(parts[2].rstrip("."))
        except ValueError:
            return None
        # Legacy WEXT may expose signed dBm as an unsigned byte. Positive
        # relative-quality units are NOT silently converted to dBm.
        if 128 <= value <= 255:
            value -= 256
        return value if -120 <= value < 0 else None
    return None


class LinuxRSSI:
    label = "/proc/net/wireless · RSSI dBm (cache driver)"

    def __init__(self, network: NetworkInfo):
        self.interface = network.interface
        self.command = (["iw", "dev", self.interface, "link"] if shutil.which("iw") else
                        ["iwconfig", self.interface] if shutil.which("iwconfig") else None)

    def read(self) -> float | None:
        try:
            value = parse_proc_rssi(Path("/proc/net/wireless").read_text(), self.interface)
            if value is not None:
                return value
        except OSError:
            pass
        if not self.command:
            raise RuntimeError("RSSI assente: installare iw o wireless-tools e collegare il Wi-Fi.")
        self.label = f"{self.command[0]} · RSSI dBm (frequenza effettiva da verificare)"
        out = run_command(self.command, timeout=0.5)
        match = re.search(r"(?:signal:\s*|Signal level[=:]\s*)(-?\d+(?:\.\d+)?)\s*dBm", out, re.I)
        if match:
            value = float(match.group(1))
            return value if -120 <= value < 0 else None
        return None

    def close(self) -> None:
        return None


class _EchoHeader(C.Structure):
    # Only the fixed leading fields are accessed; reserve ample buffer space
    # for the pointer-containing reply layout on both 32- and 64-bit Windows.
    _fields_ = [("address", C.c_uint32), ("status", C.c_uint32), ("rtt", C.c_uint32)]


class WindowsPinger:
    def __init__(self, network: NetworkInfo, timeout: float):
        self.api = C.WinDLL("iphlpapi", use_last_error=True)
        self.api.IcmpCreateFile.argtypes = []
        self.api.IcmpCreateFile.restype = C.c_void_p
        self.api.IcmpCloseHandle.argtypes = [C.c_void_p]
        self.api.IcmpCloseHandle.restype = C.c_int
        self.api.IcmpSendEcho2Ex.argtypes = [C.c_void_p, C.c_void_p, C.c_void_p, C.c_void_p,
            C.c_uint32, C.c_uint32, C.c_void_p, C.c_uint16, C.c_void_p,
            C.c_void_p, C.c_uint32, C.c_uint32]
        self.api.IcmpSendEcho2Ex.restype = C.c_uint32
        self.handle = self.api.IcmpCreateFile()
        if self.handle in (None, C.c_void_p(-1).value):
            raise _win_error(C.get_last_error(), "IcmpCreateFile")
        self.source = struct.unpack("=I", socket.inet_aton(network.address))[0]
        self.target = struct.unpack("=I", socket.inet_aton(network.gateway))[0]
        self.timeout_ms = max(1, int(timeout * 1000))
        self.data = C.create_string_buffer(b"WiFiSense-NetDiag")
        self.reply = C.create_string_buffer(1024)

    def ping(self) -> float | None:
        count = self.api.IcmpSendEcho2Ex(self.handle, None, None, None, self.source, self.target,
            self.data, len(self.data) - 1, None, self.reply, len(self.reply), self.timeout_ms)
        if not count:
            code = C.get_last_error()
            if code in (5, 6, 87):
                raise _win_error(code, "IcmpSendEcho2Ex")
            return None
        reply = _EchoHeader.from_buffer(self.reply)
        return float(reply.rtt) if reply.status == 0 else None

    def close(self) -> None:
        if self.handle:
            self.api.IcmpCloseHandle(self.handle)
            self.handle = None


def icmp_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


class LinuxPinger:
    def __init__(self, network: NetworkInfo, timeout: float):
        self.timeout, self.target = timeout, network.gateway
        self.raw = False
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
        except PermissionError:
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                self.raw = True
            except PermissionError as exc:
                raise PermissionError("ICMP non disponibile: verificare ping_group_range o CAP_NET_RAW.") from exc
        try:
            self.sock.bind((network.address, 0))
            self.sock.setblocking(False)
        except Exception:
            self.sock.close()
            raise
        self.identifier = (os.getpid() & 0xFFFF) if self.raw else self.sock.getsockname()[1]
        self.sequence = 0
        self.nonce = os.urandom(8)

    def ping(self) -> float | None:
        self.sequence = (self.sequence + 1) & 0xFFFF
        body = self.nonce + struct.pack("!d", time.monotonic())
        header = struct.pack("!BBHHH", 8, 0, 0, self.identifier, self.sequence)
        packet = struct.pack("!BBHHH", 8, 0, icmp_checksum(header + body),
                             self.identifier, self.sequence) + body
        started = time.monotonic()
        try:
            self.sock.sendto(packet, (self.target, 0))
            while True:
                remaining = self.timeout - (time.monotonic() - started)
                if remaining <= 0 or not select.select([self.sock], [], [], remaining)[0]:
                    return None
                received, sender = self.sock.recvfrom(4096)
                offset = ((received[0] & 15) * 4) if self.raw and received else 0
                echo = received[offset:]
                if sender[0] != self.target or len(echo) < 8:
                    continue
                kind, code, _, ident, seq = struct.unpack("!BBHHH", echo[:8])
                if (kind == 0 and code == 0 and ident == self.identifier and
                        seq == self.sequence and echo[8:] == body):
                    return (time.monotonic() - started) * 1000
        except OSError as exc:
            if isinstance(exc, (BlockingIOError, ConnectionRefusedError, TimeoutError)) or exc.errno in (
                    errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ENETDOWN, errno.EHOSTDOWN):
                return None
            raise

    def close(self) -> None:
        self.sock.close()


def create_rssi_source(network: NetworkInfo):
    if sys.platform == "win32":
        return WindowsRSSI(network)
    if sys.platform.startswith("linux"):
        return LinuxRSSI(network)
    raise RuntimeError("Acquisizione RSSI supportata su Windows e Linux.")


def create_pinger(network: NetworkInfo, timeout: float = 0.08):
    if not 0 < timeout <= 1:
        raise ValueError("Timeout ICMP fuori intervallo (0, 1].")
    if sys.platform == "win32":
        return WindowsPinger(network, timeout)
    if sys.platform.startswith("linux"):
        return LinuxPinger(network, timeout)
    raise RuntimeError("ICMP supportato su Windows e Linux.")
