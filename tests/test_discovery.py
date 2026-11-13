"""Offline discovery tests: no real multicast, ARP or Bluetooth traffic."""
import math
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from models import AccessPoint, Device, NetworkInfo, ScanResult
from scanner import (_ble_scan, classify, clean, device_record, discover_mdns, local_ip,
                     merge_devices, parse_ssdp, scan_all)


NET = NetworkInfo('wlan0', '192.168.4.10', '255.255.255.0', '192.168.4.1', '02:00:00:00:00:10')


class DiscoveryTests(unittest.TestCase):
    def test_ssdp_header_parser_bounds_and_preserves_untrusted_url_as_text(self):
        result = parse_ssdp(b'HTTP/1.1 200 OK\r\nST: urn:schemas-upnp-org:device:MediaRenderer:1\r\n'
                            b'LOCATION: http://127.0.0.1/private\r\nSERVER: Linux/6 UPnP/1.0\r\n\r\n')
        self.assertEqual(result['location'], 'http://127.0.0.1/private')
        self.assertEqual(classify(result['st'], result)[0], 'iot')
        self.assertEqual(parse_ssdp(b'GET / HTTP/1.1\r\nlocation: x'), {})
        self.assertLessEqual(len(parse_ssdp(b'HTTP/1.1 200 OK\nSERVER: ' + b'x' * 9000)['server']), 512)

    def test_classification_requires_evidence_not_generic_http_or_vendor(self):
        self.assertEqual(classify('_http._tcp.local.', {'vendor': 'Apple'})[0], 'unknown')
        self.assertEqual(classify('_airplay._tcp.local.', {'model': 'iPhone'})[0], 'smartphone')
        self.assertEqual(classify('_googlecast._tcp.local.', {'md': 'Chromecast'})[0], 'tv')
        self.assertEqual(classify('_workstation._tcp.local.')[0], 'pc')
        self.assertEqual(classify('_hap._tcp.local.')[0], 'iot')

    def test_local_scope_rejects_outside_multicast_loopback_broadcast(self):
        self.assertTrue(local_ip('192.168.4.2', NET))
        for address in ('8.8.8.8', '239.255.255.250', '127.0.0.1', '192.168.4.255', '192.168.4.0', 'bad'):
            self.assertFalse(local_ip(address, NET))

    def test_merge_preserves_real_identity_and_does_not_invent_rssi(self):
        arp = device_record('192.168.4.3', source='ARP')
        arp.update(mac='aa:bb:cc:dd:ee:ff', vendor='Vendor', ports=[80])
        mdns = device_record('192.168.4.3', name='Living room TV', source='mDNS', category='tv')
        mdns['services'] = ['_googlecast._tcp.local. :8009']
        ble = device_record(name='Beacon', source='BLE', category='bluetooth')
        ble['id'] = 'ble:aa:bb:cc:dd:ee:ff'
        result = merge_devices([[arp], [mdns], [ble]])
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]['name'], 'Living room TV')
        self.assertEqual(result[0]['mac'], arp['mac'])
        self.assertEqual(result[0]['sources'], ['ARP', 'mDNS'])
        self.assertIsNone(result[0]['rssi_dbm'])
        self.assertIsNone(result[0]['distance_m'])
        self.assertEqual(result[0]['category'], 'unknown')
        self.assertEqual(result[0]['category_hint'], 'tv')
        self.assertEqual(result[1]['category'], 'unknown')
        self.assertFalse(result[0]['identity_verified'])
        self.assertGreater(result[0]['observed_at'], 0)
        self.assertEqual(result[0]['source'], 'ARP, mDNS')

    def test_category_parameter_is_only_a_hint_not_verified_physical_type(self):
        entry = device_record('192.168.4.3', 'TV announcement', 'mDNS', 'tv')
        self.assertEqual(entry['category'], 'unknown')
        self.assertEqual(entry['category_hint'], 'tv')
        self.assertFalse(entry['category_verified'])
        self.assertFalse(entry['presence_verified'])
        self.assertIsNone(entry['distance_m'])
        self.assertEqual(entry['verification'], 'protocol_claim')

    def test_untrusted_text_is_bounded_but_not_html_interpreted(self):
        self.assertEqual(clean(b'A\x00B'), 'AB')
        self.assertEqual(clean('<script>', 100), '<script>')  # frontend uses textContent
        self.assertEqual(len(clean('x' * 1000)), 200)

    def test_ble_partial_records_survive_stop_failure_and_no_pairing(self):
        class FakeScanner:
            def __init__(self, detection_callback, scanning_mode):
                self.callback = detection_callback

            async def start(self):
                self.callback(SimpleNamespace(address='00:11:22:33:44:55', name='Beacon'),
                              SimpleNamespace(local_name='Beacon', rssi=-59, tx_power=0,
                                              service_uuids=['abc'], manufacturer_data={1: b'hi'},
                                              service_data={}))

            async def stop(self):
                raise RuntimeError('stop failure')

        async def immediate_wait(awaitable, timeout):
            return await awaitable

        # No OS event loop/socketpair is needed to test synchronous fake coroutines.
        with patch.dict('sys.modules', {'bleak': SimpleNamespace(BleakScanner=FakeScanner)}), \
                patch('scanner.asyncio.wait_for', side_effect=immediate_wait):
            coroutine = _ble_scan(threading.Event(), 0)
            with self.assertRaises(StopIteration) as completed:
                coroutine.send(None)
            devices, warnings = completed.exception.value
        self.assertEqual(len(devices), 1)
        self.assertIsNone(devices[0]['distance_m'])
        self.assertEqual(devices[0]['rssi_dbm'], -59)
        self.assertEqual(devices[0]['category'], 'unknown')
        self.assertEqual(devices[0]['transport'], 'ble')
        self.assertEqual(devices[0]['details']['rssi']['verification'], 'measurement')
        self.assertGreater(devices[0]['observed_at'], 0)
        self.assertFalse(devices[0]['identity_verified'])
        self.assertEqual(devices[0]['details']['manufacturer_data'], {'1': '6869'})
        self.assertTrue(any('Arresto BLE' in text for text in warnings))

    def test_mdns_cancel_error_still_closes_zeroconf(self):
        zc, browser = MagicMock(), MagicMock()
        browser.cancel.side_effect = RuntimeError('cancel failure')
        fake = SimpleNamespace(IPVersion=SimpleNamespace(V4Only=1),
                               Zeroconf=MagicMock(return_value=zc),
                               ServiceBrowser=MagicMock(return_value=browser))
        with patch.dict('sys.modules', {'zeroconf': fake}):
            entries, warnings = discover_mdns(NET, threading.Event(), duration=0)
        self.assertEqual(entries, [])
        self.assertTrue(warnings)
        zc.close.assert_called_once()
        fake.Zeroconf.assert_called_once_with(interfaces=[NET.address], ip_version=1)

    @patch('scanner.discover_ble')
    @patch('scanner.discover_ssdp')
    @patch('scanner.discover_mdns')
    @patch('scanner.lan_scanner.scan_network')
    def test_pre_cancel_never_starts_any_discovery(self, lan, mdns, ssdp, ble):
        stop = threading.Event()
        stop.set()
        result = scan_all(NET, stop)
        self.assertTrue(result['partial'])
        for mocked in (lan, mdns, ssdp, ble):
            mocked.assert_not_called()

    @patch('scanner.discover_ble', side_effect=RuntimeError('Bluetooth disabled'))
    @patch('scanner.discover_ssdp', return_value=([], []))
    @patch('scanner.discover_mdns')
    @patch('scanner.lan_scanner.scan_network')
    def test_partial_ble_failure_does_not_erase_arp_and_mdns(self, lan, mdns, ssdp, ble):
        lan.return_value = ScanResult(devices=(Device('192.168.4.3', 'aa:bb:cc:dd:ee:ff', 'Vendor', (80,)),),
                                     access_points=(AccessPoint('Test', '00:11:22:33:44:55', 6, '2.4 GHz', -58),))
        mdns.return_value = ([device_record('192.168.4.3', 'Office', 'mDNS', 'pc')], [])
        result = scan_all(NET, threading.Event())
        self.assertTrue(result['partial'])
        self.assertEqual(result['devices'][0]['name'], 'Office')
        self.assertEqual(result['devices'][0]['ports'], [80])
        self.assertEqual(len(result['access_points']), 1)
        self.assertTrue(any('BLE' in warning for warning in result['warnings']))
        self.assertEqual(result['devices'][0]['category'], 'unknown')
        self.assertFalse(result['devices'][0]['manufacturer_verified'])
        self.assertEqual(result['access_points'][0]['verification'], 'protocol_claim')


if __name__ == '__main__':
    unittest.main()
