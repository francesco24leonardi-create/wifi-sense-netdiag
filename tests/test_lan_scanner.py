"""Offline fixtures: these tests never scan the local network."""
import threading
import ipaddress
import unittest
from unittest.mock import patch

from models import AccessPoint, NetworkInfo
from lan_scanner import (_in_scope, _neighbors, channel_summary, normalize_mac, parse_iw, parse_netsh,
                     parse_nmcli, scan_network, scan_scope, split_nmcli, vendor_for_mac)
from lan_scanner import mac_attribution


class ScannerTests(unittest.TestCase):
    def test_netsh_italian_multiple_bssids_and_ambiguous_ax(self):
        text = """
SSID 1 : Casa:Studio
    Autenticazione : WPA2-Personal
    BSSID 1 : 00:11:22:33:44:55
         Segnale : 80%
         Tipo frequenza radio : 802.11n
         Canale : 6
    BSSID 2 : 00:11:22:33:44:66
         Segnale : 50%
         Tipo frequenza radio : 802.11ax
         Canale : 37
SSID 2 :
    Authentication : WPA3-Personal
    BSSID 1 : 00:22:33:44:55:66
         Signal : 90%
         Band : 6 GHz
         Channel : 5
"""
        points = parse_netsh(text)
        self.assertEqual(len(points), 3)
        self.assertEqual(points[0].ssid, "Casa:Studio")
        self.assertEqual(points[0].band, "?")
        self.assertEqual(points[0].band_hint, "2.4 GHz")
        self.assertIsNone(points[0].rssi_dbm)
        self.assertEqual(points[0].signal_percent, 80)
        self.assertGreater(points[0].observed_at, 0)
        self.assertFalse(points[0].presence_verified)
        self.assertEqual(points[0].source, 'netsh WLAN cache')
        self.assertEqual(points[1].band, "?")
        self.assertEqual(points[2].band, "6 GHz")
        self.assertEqual(points[2].ssid, "<nascosta>")
        self.assertEqual(points[2].security, "WPA3-Personal")

    def test_nmcli_escaping_and_frequency_disambiguation(self):
        text = r"Studio\:Nord\\AP:00\:11\:22\:33\:44\:55:5:5975 MHz:72:WPA3:*"
        fields = split_nmcli(text)
        self.assertEqual(fields[0], "Studio:Nord\\AP")
        points = parse_nmcli(text)
        self.assertEqual(len(points), 1)
        self.assertEqual(points[0].band, "6 GHz")
        self.assertEqual(points[0].channel, 5)
        self.assertIsNone(points[0].rssi_dbm)
        self.assertEqual(points[0].signal_percent, 72)
        self.assertEqual(parse_nmcli("invalid:line"), [])

    def test_iw_actual_dbm_and_special_channel(self):
        points = parse_iw("""BSS 00:11:22:33:44:55(on wlan0)
        freq: 2484
        signal: -52.75 dBm
        SSID: Test
        RSN:
BSS 00:11:22:33:44:66(on wlan0)
        freq: 5935
        signal: -66.00 dBm
        SSID:
""")
        self.assertEqual([point.channel for point in points], [14, 2])
        self.assertEqual(points[0].rssi_dbm, -52.75)
        self.assertEqual(points[1].band, "6 GHz")
        self.assertEqual(points[0].source, 'Linux iw scan')
        self.assertEqual(points[0].signal_verification, 'measurement')
        self.assertFalse(points[0].identity_verified)

    def test_scope_is_connected_and_bounded(self):
        large = NetworkInfo("wlan0", "10.2.3.99", "255.0.0.0", "10.0.0.1")
        scope, partial = scan_scope(large)
        self.assertEqual(str(scope), "10.2.3.0/24")
        self.assertTrue(partial)
        small = NetworkInfo("wlan0", "192.168.1.34", "255.255.255.224", "192.168.1.33")
        self.assertEqual(str(scan_scope(small)[0]), "192.168.1.32/27")
        self.assertFalse(scan_scope(small)[1])

    def test_vendor_local_invalid_and_multicast(self):
        self.assertEqual(normalize_mac("AA-BB-CC-DD-EE-FF"), "aa:bb:cc:dd:ee:ff")
        self.assertEqual(normalize_mac("not-a-mac"), "")
        self.assertEqual(vendor_for_mac("02:11:22:33:44:55"), "MAC locale / privato")
        self.assertEqual(vendor_for_mac("01:00:5e:00:00:01"), "Multicast")
        self.assertEqual(vendor_for_mac("bad"), "Sconosciuto")
        attribution = mac_attribution('02:11:22:33:44:55')
        self.assertIsNone(attribution['oui_assignee'])
        self.assertFalse(attribution['manufacturer_verified'])
        self.assertTrue(attribution['locally_administered'])
        self.assertIn('randomizzabile', attribution['warning'])

    def test_channel_scores_dont_mix_bands_or_duplicate_bssids(self):
        ap = AccessPoint("WiFi", "00:11:22:33:44:55", 1, "2.4 GHz", -40)
        baseline = channel_summary([ap])
        self.assertEqual(channel_summary([ap, ap]), baseline)
        summary = channel_summary([ap, AccessPoint("Six", "00:11:22:33:44:66", 6, "6 GHz", -20)])
        self.assertIn("2.4 GHz: 1 BSSID", summary)
        self.assertIn("6 GHz: 1", summary)
        self.assertIn("Non misura airtime", summary)

    def test_cochannel_groups_separate_five_and_six_ghz(self):
        points = [AccessPoint("A", "00:11:22:33:44:55", 37, "5 GHz", -50),
                  AccessPoint("B", "00:11:22:33:44:66", 37, "5 GHz", -60),
                  AccessPoint("C", "00:11:22:33:44:77", 37, "6 GHz", -45)]
        result = channel_summary(points)
        self.assertIn("5 GHz: 2 BSSID; canali condivisi: 37 (2 BSSID)", result)
        self.assertIn("6 GHz: 1 BSSID; canali condivisi: nessuno osservato", result)

    def test_scope_rejects_broadcast_but_allows_point_to_point(self):
        subnet = ipaddress.IPv4Network("192.168.1.0/24")
        self.assertFalse(_in_scope("192.168.1.255", subnet))
        self.assertFalse(_in_scope("192.168.1.0", subnet))
        self.assertFalse(_in_scope("::1", subnet))
        self.assertTrue(_in_scope("192.168.1.0", ipaddress.IPv4Network("192.168.1.0/31")))

    def test_windows_neighbors_utf8_and_interface_literal(self):
        network = NetworkInfo("Wi-Fi ' Ufficio", "192.168.1.2", "255.255.255.0", "192.168.1.1")
        raw = '[{"IPAddress":"192.168.1.1","LinkLayerAddress":"00-11-22-33-44-55"}]'
        with patch("lan_scanner.platform.system", return_value="Windows"), patch("lan_scanner.run_command", return_value=raw) as run:
            found = _neighbors(network)
        self.assertEqual(found, {"192.168.1.1": "00:11:22:33:44:55"})
        script = run.call_args.args[0][-1]
        self.assertIn("UTF8Encoding", script)
        self.assertIn("'Wi-Fi '' Ufficio'", script)

    def test_arp_fallback_marked_partial_and_external_hosts_filtered(self):
        network = NetworkInfo("wlan0", "192.168.1.2", "255.255.255.0", "192.168.1.1")
        with patch("lan_scanner._arp_scan", side_effect=PermissionError("no raw socket")), \
             patch("lan_scanner._neighbors", return_value={"192.168.1.1": "02:00:00:00:00:01", "8.8.8.8": "02:00:00:00:00:02"}), \
             patch("lan_scanner._ports_for_hosts", return_value={"192.168.1.1": [80]}), \
             patch("lan_scanner.scan_wifi", return_value=([], [])):
            result = scan_network(network, threading.Event())
        self.assertTrue(result.partial)
        self.assertEqual(len(result.devices), 1)
        self.assertEqual(result.devices[0].role, "Gateway")
        self.assertEqual(result.devices[0].ports, (80,))
        self.assertTrue(any("cache" in warning for warning in result.warnings))
        self.assertEqual(result.devices[0].source, 'OS neighbor cache')
        self.assertFalse(result.devices[0].presence_verified)
        self.assertIn('non prova', result.devices[0].evidence)
        observation = result.devices[0].port_observations[0]
        self.assertEqual(observation['port'], 80)
        self.assertTrue(observation['tcp_handshake_completed'])
        self.assertFalse(observation['service_identity_verified'])
        self.assertGreater(observation['observed_at'], 0)

    def test_cancellation_stops_before_port_scan(self):
        stop = threading.Event()
        stop.set()
        network = NetworkInfo("wlan0", "192.168.1.2", "255.255.255.0", "192.168.1.1")
        with patch("lan_scanner._arp_scan") as arp, patch("lan_scanner._ports_for_hosts") as ports:
            result = scan_network(network, stop)
        self.assertTrue(result.partial)
        arp.assert_not_called()
        ports.assert_not_called()

    def test_cancellation_after_arp_stops_port_and_wifi_work(self):
        stop = threading.Event()
        network = NetworkInfo("wlan0", "192.168.1.2", "255.255.255.0", "192.168.1.1")

        def cancel_after_arp(*args):
            stop.set()
            return {"192.168.1.1": "02:00:00:00:00:01"}

        with patch("lan_scanner._arp_scan", side_effect=cancel_after_arp), \
             patch("lan_scanner._ports_for_hosts") as ports, patch("lan_scanner.scan_wifi") as wifi:
            result = scan_network(network, stop)
        self.assertTrue(result.partial)
        ports.assert_not_called()
        wifi.assert_not_called()


if __name__ == "__main__":
    unittest.main()

