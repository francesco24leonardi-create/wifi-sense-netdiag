"""Pure mocked connection/capture tests: no socket, DNS or packet capture."""
import socket
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from connections import PassiveCapture, host_connections, public_ip
from models import NetworkInfo


def connection(remote, port=443, pid=7, protocol=socket.SOCK_STREAM):
    return SimpleNamespace(raddr=SimpleNamespace(ip=remote, port=port),
                           laddr=SimpleNamespace(ip='192.168.3.10', port=41000),
                           pid=pid, type=protocol, status='ESTABLISHED')


class ConnectionsTests(unittest.TestCase):
    def test_remote_filter_excludes_multicast_reserved_and_local(self):
        for value in ('8.8.8.8', '2606:4700:4700::1111'):
            self.assertTrue(public_ip(value), value)
        for value in ('224.0.0.1', 'ff02::1', '255.255.255.255', '0.0.0.0', '127.0.0.1',
                      '192.168.3.1', '169.254.1.1', '100.64.0.1', '192.0.2.10', 'fe80::1%wlan0', 'bad'):
            self.assertFalse(public_ip(value), value)

    def test_host_records_are_labelled_host_filtered_and_bounded(self):
        fake = SimpleNamespace(Error=type('PSUtilError', (Exception,), {}),
                               net_connections=MagicMock(return_value=[
                                   connection('8.8.8.8'), connection('192.168.3.1'),
                                   connection('1.1.1.1', 53, protocol=socket.SOCK_DGRAM)]),
                               Process=MagicMock(return_value=SimpleNamespace(name=lambda: 'test-process')))
        with patch.dict('sys.modules', {'psutil': fake}):
            rows, warnings = host_connections(limit=1)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['remote_ip'], '1.1.1.1')
        self.assertEqual(rows[0]['protocol'], 'UDP')
        self.assertEqual(rows[0]['scope'], 'host')
        self.assertEqual(rows[0]['source'], 'OS socket table')
        self.assertEqual(rows[0]['verification'], 'measurement')
        self.assertFalse(rows[0]['currently_active_verified'])
        self.assertFalse(rows[0]['identity_verified'])
        self.assertEqual(rows[0]['process'], 'test-process')
        self.assertTrue(warnings)
        fake.net_connections.assert_called_once_with(kind='inet')
        fake.Process.assert_called_once_with(7)

    def test_socket_table_permission_failure_is_explicit(self):
        error = type('PSUtilError', (Exception,), {})
        fake = SimpleNamespace(Error=error, net_connections=MagicMock(side_effect=error('denied')))
        with patch.dict('sys.modules', {'psutil': fake}):
            rows, warnings = host_connections()
        self.assertEqual(rows, [])
        self.assertIn('denied', warnings[0])

    def test_process_name_permission_failure_retains_connection(self):
        error = type('PSUtilError', (Exception,), {})
        fake = SimpleNamespace(Error=error,
                               net_connections=MagicMock(return_value=[connection('8.8.8.8')]),
                               Process=MagicMock(side_effect=error('denied')))
        with patch.dict('sys.modules', {'psutil': fake}):
            rows, warnings = host_connections()
        self.assertEqual(rows[0]['process'], 'Non disponibile')
        self.assertEqual(rows[0]['scope'], 'host')

    def test_capture_records_aggregate_metadata_and_snapshot_copies(self):
        capture = PassiveCapture()
        with patch('connections.time.time', return_value=100):
            capture.record('192.168.3.2', '8.8.8.8', 12345, 443, 'TCP', 100, True)
            capture.record('192.168.3.2', '8.8.8.8', 12345, 443, 'TCP', 200, False)
            rows = capture.snapshot()
        self.assertEqual(rows[0]['packets'], 2)
        self.assertEqual(rows[0]['bytes'], 300)
        self.assertEqual(rows[0]['scope'], 'capture')
        self.assertEqual(rows[0]['source'], 'Passive IPv4 capture')
        self.assertTrue(rows[0]['observation_only'])
        self.assertFalse(rows[0]['identity_verified'])
        self.assertNotIn('payload', rows[0])
        rows[0]['packets'] = 0
        with patch('connections.time.time', return_value=100):
            self.assertEqual(capture.snapshot()[0]['packets'], 2)
        with patch('connections.time.time', return_value=161):
            self.assertEqual(capture.snapshot(), [])

    def test_capture_memory_bound_and_stop_cleanup(self):
        capture = PassiveCapture()
        for index in range(300):
            capture.record('192.168.3.2', '8.8.8.8', index, 443, 'TCP', 50, True)
        self.assertEqual(len(capture.snapshot()), 256)
        worker = MagicMock()
        worker.is_alive.return_value = False
        capture._thread = worker
        capture.stop()
        self.assertFalse(capture.running)
        self.assertEqual(capture.snapshot(), [])
        worker.join.assert_called_once_with(timeout=3)

    def test_timed_out_capture_stop_cannot_resurrect_or_replace_old_worker(self):
        capture = PassiveCapture()
        worker = MagicMock()
        worker.is_alive.return_value = True
        capture._thread = worker
        with self.assertRaises(RuntimeError):
            capture.stop()
        network = NetworkInfo('wlan0', '192.168.3.10', '255.255.255.0', '192.168.3.1')
        with patch('connections.threading.Thread') as new_thread:
            with self.assertRaisesRegex(RuntimeError, 'ancora in arresto'):
                capture.start(network)
        self.assertTrue(capture._stop.is_set())
        self.assertIs(capture._thread, worker)
        new_thread.assert_not_called()

    def test_passive_packet_scope_and_direction_without_network(self):
        ip_type, tcp_type, udp_type = object(), object(), object()
        capture = PassiveCapture()

        class Packet:
            def __init__(self, src, dst, sport, dport):
                self.layers = {ip_type: SimpleNamespace(src=src, dst=dst),
                               tcp_type: SimpleNamespace(sport=sport, dport=dport)}

            def haslayer(self, kind):
                return kind in self.layers

            def __getitem__(self, kind):
                return self.layers[kind]

            def __len__(self):
                return 100

        def sniff(**kwargs):
            for packet in (Packet('192.168.3.2', '8.8.8.8', 4000, 443),
                           Packet('8.8.8.8', '192.168.3.2', 443, 4000),
                           Packet('192.168.3.2', '224.0.0.1', 4000, 443),
                           Packet('9.9.9.9', '8.8.8.8', 4000, 443)):
                kwargs['prn'](packet)
            capture._stop.set()

        fake = SimpleNamespace(IP=ip_type, TCP=tcp_type, UDP=udp_type,
                               conf=SimpleNamespace(ifaces={'nic': SimpleNamespace(ip='192.168.3.10', ips={})}),
                               sniff=MagicMock(side_effect=sniff))
        network = NetworkInfo('wlan0', '192.168.3.10', '255.255.255.0', '192.168.3.1')
        with patch.dict('sys.modules', {'scapy.all': fake}):
            capture._run(network)
        rows = capture.snapshot()
        self.assertEqual(capture.error, '')
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['local_ip'], '192.168.3.2')
        self.assertEqual(rows[0]['remote_ip'], '8.8.8.8')
        self.assertEqual(rows[0]['packets'], 2)
        self.assertEqual(rows[0]['direction'], 'ingresso')
        self.assertFalse(fake.sniff.call_args.kwargs['store'])
        self.assertEqual(fake.sniff.call_args.kwargs['timeout'], .5)


if __name__ == '__main__':
    unittest.main()
