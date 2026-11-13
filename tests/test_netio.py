"""Pure tests: no traffic and no privileged operations."""
import json
import errno
import struct
import unittest
from unittest.mock import MagicMock, patch

from models import NetworkInfo
from netio import GUID, LinuxPinger, discover_network, icmp_checksum, parse_proc_rssi


class NetIOTests(unittest.TestCase):
    def test_proc_selects_interface_and_rejects_relative_units(self):
        text = 'wlan0: 0000 55. -62. -256 0 0\nwlan1: 0000 20. 40. 0 0 0'
        self.assertEqual(parse_proc_rssi(text, 'wlan0'), -62)
        self.assertIsNone(parse_proc_rssi(text, 'wlan1'))
        self.assertIsNone(parse_proc_rssi(text, 'eth0'))
        self.assertEqual(parse_proc_rssi('wlan0: 0000 55. 194. 0', 'wlan0'), -62)

    def test_checksum_round_trip_odd_payload(self):
        packet = struct.pack('!BBHHH', 8, 0, 0, 123, 9) + b'hello'
        checksum = icmp_checksum(packet)
        packet = packet[:2] + struct.pack('!H', checksum) + packet[4:]
        self.assertEqual(icmp_checksum(packet), 0)

    def test_guid_windows_memory_layout(self):
        import uuid
        expected = uuid.UUID('6d080b63-b850-4b23-b2dd-6ee1f9113dbc')
        self.assertEqual(GUID.from_buffer_copy(expected.bytes_le).text(), str(expected))

    @patch('netio.sys.platform', 'linux')
    @patch('netio.run_command')
    def test_route_metric_and_source_selection(self, command):
        routes = [{'dev': 'down0', 'gateway': '10.0.0.1', 'metric': 1, 'flags': ['linkdown']},
                  {'dev': 'eth0', 'gateway': '10.0.0.1', 'metric': 200},
                  {'dev': 'wlan0', 'gateway': '192.168.8.1', 'metric': 20, 'prefsrc': '192.168.8.4'}]
        adapters = [{'address': '00:11:22:33:44:55', 'addr_info': [
            {'family': 'inet', 'scope': 'global', 'local': '192.168.8.5', 'prefixlen': 24},
            {'family': 'inet', 'scope': 'global', 'local': '192.168.8.4', 'prefixlen': 24}]}]
        command.side_effect = [json.dumps(routes), json.dumps(adapters)]
        info = discover_network()
        self.assertEqual(info.interface, 'wlan0')
        self.assertEqual(info.address, '192.168.8.4')
        self.assertEqual(str(info.network), '192.168.8.0/24')

    @patch('netio.sys.platform', 'win32')
    @patch('netio.run_command')
    def test_windows_explicit_interface_and_null_mac(self, command):
        command.return_value = json.dumps([
            {'interface': 'Ethernet', 'address': '10.0.0.5', 'prefix': 24,
             'gateway': '10.0.0.1', 'metric': 10},
            {'interface': 'Wi-Fi', 'address': '192.168.1.4', 'prefix': 24,
             'gateway': '192.168.1.1', 'metric': 50, 'mac': None, 'guid': 'abc'}])
        info = discover_network('wi-fi')
        self.assertEqual(info.interface_id, 'abc')
        self.assertEqual(info.mac, '')

    @patch('netio.select.select', return_value=([True], [], []))
    def test_transient_icmp_outage_recovers(self, select_mock):
        pinger = LinuxPinger.__new__(LinuxPinger)
        pinger.sock = MagicMock()
        pinger.timeout, pinger.target = .08, '192.168.1.1'
        pinger.sequence, pinger.identifier, pinger.raw = 0, 123, False
        pinger.nonce = b'01234567'
        pinger.sock.sendto.side_effect = [OSError(errno.ENETUNREACH, 'offline'), 24]
        pinger.sock.recvfrom.side_effect = lambda n: (
            b'\0' + pinger.sock.sendto.call_args.args[0][1:], (pinger.target, 0))
        self.assertIsNone(pinger.ping())
        self.assertIsNotNone(pinger.ping())


if __name__ == '__main__':
    unittest.main()
