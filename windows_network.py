"""IPv4 adapter discovery through IP Helper, without PowerShell/CIM."""
import ctypes as C
import ipaddress
import socket
from models import NetworkInfo


class SocketAddress(C.Structure):
    _fields_ = [('pointer', C.c_void_p), ('length', C.c_int)]


class Unicast(C.Structure):
    pass


Unicast._fields_ = [('alignment', C.c_uint64), ('next', C.POINTER(Unicast)),
    ('address', SocketAddress), ('prefix_origin', C.c_int), ('suffix_origin', C.c_int),
    ('dad_state', C.c_int), ('valid_lifetime', C.c_uint32), ('preferred_lifetime', C.c_uint32),
    ('lease_lifetime', C.c_uint32), ('prefix_length', C.c_ubyte)]


class Gateway(C.Structure):
    pass


Gateway._fields_ = [('alignment', C.c_uint64), ('next', C.POINTER(Gateway)), ('address', SocketAddress)]


class Adapter(C.Structure):
    pass


Adapter._fields_ = [('length', C.c_uint32), ('index', C.c_uint32), ('next', C.POINTER(Adapter)),
    ('adapter_name', C.c_char_p), ('unicast', C.POINTER(Unicast)),
    ('anycast', C.c_void_p), ('multicast', C.c_void_p), ('dns', C.c_void_p),
    ('dns_suffix', C.c_wchar_p), ('description', C.c_wchar_p), ('name', C.c_wchar_p),
    ('mac', C.c_ubyte*8), ('mac_length', C.c_uint32), ('flags', C.c_uint32),
    ('mtu', C.c_uint32), ('if_type', C.c_uint32), ('status', C.c_int),
    ('ipv6_index', C.c_uint32), ('zones', C.c_uint32*16), ('prefix', C.c_void_p),
    ('transmit_speed', C.c_uint64), ('receive_speed', C.c_uint64),
    ('wins', C.c_void_p), ('gateway', C.POINTER(Gateway)), ('metric', C.c_uint32)]


def ipv4(address):
    if not address.pointer or address.length < 8:
        return None
    raw = C.string_at(address.pointer, address.length)
    if int.from_bytes(raw[:2], 'little') != socket.AF_INET:
        return None
    return socket.inet_ntoa(raw[4:8])


def linked(pointer):
    count = 0
    while pointer and count < 1024:
        yield pointer.contents
        pointer = pointer.contents.next
        count += 1


def discover(interface=None):
    api = C.WinDLL('iphlpapi', use_last_error=True)
    get = api.GetAdaptersAddresses
    get.argtypes = [C.c_uint32, C.c_uint32, C.c_void_p, C.c_void_p, C.POINTER(C.c_uint32)]
    get.restype = C.c_uint32
    size = C.c_uint32(15000)
    for _ in range(3):
        buffer = C.create_string_buffer(size.value)
        code = get(socket.AF_INET, 2|4|8|128, None, buffer, C.byref(size))
        if code == 0:
            break
        if code != 111 or size.value > 16*1024*1024:
            raise OSError(code, 'GetAdaptersAddresses non disponibile')
    else:
        raise RuntimeError('Configurazione degli adattatori in cambiamento: riprovare')
    candidates = []
    for adapter in linked(C.cast(buffer, C.POINTER(Adapter))):
        if adapter.status != 1 or adapter.length < Adapter.metric.offset+4:
            continue
        name = adapter.name or ''
        if interface and name.casefold() != interface.casefold():
            continue
        for gateway in linked(adapter.gateway):
            target = ipv4(gateway.address)
            if not target or target == '0.0.0.0':
                continue
            for address in linked(adapter.unicast):
                ip = ipv4(address.address)
                if not ip or address.dad_state != 4 or not 1 <= address.prefix_length <= 32:
                    continue
                net = ipaddress.IPv4Network(f'{ip}/{address.prefix_length}', strict=False)
                if ipaddress.ip_address(target) not in net:
                    continue
                mac = ':'.join(f'{b:02x}' for b in adapter.mac[:min(adapter.mac_length, 8)])
                guid = (adapter.adapter_name or b'').decode('ascii', errors='replace')
                candidates.append((adapter.if_type != 71, adapter.metric,
                    NetworkInfo(name, ip, str(net.netmask), target, mac, guid)))
    if not candidates:
        raise RuntimeError('Nessun adattatore IPv4 con gateway connesso; collegare il Wi-Fi e riprovare.')
    return min(candidates, key=lambda row: row[:2])[2]
