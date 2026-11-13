import gzip
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from geoip import GeoIPStore, ThreatStore
from setup_offline import asset_path, build_database, install_asset, parse_drop_feed, refresh_threats


class GeoIPTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.world = self.root / 'world.geojson'
        self.world.write_text(json.dumps({'features': [{'properties': {
            'ISO_A2_EH': 'US', 'NAME_EN': 'United States', 'LABEL_X': -98.5, 'LABEL_Y': 39.8}}]}))

    def database(self):
        source = self.root / 'data.csv.gz'
        with gzip.open(source, 'wt', encoding='utf-8') as stream:
            stream.write('8.8.8.0,8.8.8.255,US\n2001:4860::,2001:4860:ffff:ffff:ffff:ffff:ffff:ffff,US\n')
        path = self.root / 'geo.sqlite'
        build_database(source, path, 'test-fixture', hashlib.sha256(source.read_bytes()).hexdigest())
        store = GeoIPStore(path, self.world)
        self.addCleanup(store.close)
        return store

    def test_ip_ranges_ipv4_ipv6_and_boundaries(self):
        store = self.database()
        self.assertEqual(store.lookup('8.8.8.0')['country_code'], 'US')
        self.assertEqual(store.lookup('8.8.8.255')['accuracy'], 'country attribution only')
        self.assertIsNone(store.lookup('8.8.9.0'))
        attributed = store.lookup('2001:4860:4860::8888')
        self.assertEqual(attributed['country'], 'United States')
        self.assertNotIn('lat', attributed)
        self.assertNotIn('lon', attributed)
        self.assertFalse(attributed['exact_location_verified'])
        self.assertFalse(attributed['current_country_verified'])
        self.assertEqual(attributed['verification'], 'database_attribution')
        self.assertEqual(attributed['release'], 'test-fixture')
        self.assertIsNone(store.lookup('2001:4861::1'))

    def test_private_unknown_and_invalid_not_geolocated(self):
        store = self.database()
        for address in ('192.168.1.1', '127.0.0.1', '192.0.2.1', 'fe80::1', '224.0.0.1', 'invalid', '1.2.3.4'):
            self.assertIsNone(store.lookup(address))

    def test_missing_database_degrades_honestly(self):
        store = GeoIPStore(self.root / 'absent.sqlite', self.world)
        self.assertIsNone(store.lookup('8.8.8.8'))
        self.assertIn('non disponibile', store.status())
        store.close()

    def test_threats_longest_prefix_and_simulation_isolation(self):
        path = self.root / 'threats.json'
        path.write_text(json.dumps({'indicators': [
            {'network': '8.8.8.0/24', 'label': 'Broad', 'severity': 'low'},
            {'network': '8.8.8.8', 'label': 'Specific', 'severity': 'high'},
            {'network': '192.0.2.0/24', 'label': 'Demo only', 'scope': 'demo'},
            {'network': '2001:4860::/32', 'label': 'IPv6 fixture'}]}))
        store = ThreatStore(path)
        self.assertEqual(store.lookup('8.8.8.8')['label'], 'Specific')
        self.assertEqual(store.lookup('8.8.8.9')['label'], 'Broad')
        self.assertIsNone(store.lookup('192.0.2.1'))
        self.assertTrue(store.lookup('192.0.2.1', mode='demo')['matched'])
        self.assertTrue(store.lookup('2001:4860::1')['matched'])
        self.assertIsNone(store.lookup('8.8.4.4'))
        match = store.lookup('8.8.8.8')
        self.assertTrue(match['reputation_match_only'])
        self.assertFalse(match['attack_verified'])
        self.assertFalse(match['current_reputation_verified'])
        self.assertIsNone(match['snapshot_age_days'])
        self.assertIsNone(match['snapshot_stale'])

    def test_invalid_threat_file_never_partially_applies(self):
        path = self.root / 'threats.json'
        path.write_text(json.dumps({'indicators': [{'network': '8.8.8.8'}, {'network': 'broken'}]}))
        store = ThreatStore(path)
        self.assertIsNone(store.lookup('8.8.8.8'))
        self.assertIn('non valida', store.warning)

    def test_offline_verification_never_opens_network(self):
        path = self.root / 'script.js'
        content = b'export const offline = true;'
        path.write_bytes(content)
        spec = {'path': 'script.js', 'sha256': hashlib.sha256(content).hexdigest()}
        with patch('setup_offline.urllib.request.urlopen', side_effect=AssertionError('network')):
            self.assertFalse(install_asset(spec, self.root, verify_only=True))
            path.write_bytes(b'tampered')
            with self.assertRaises(ValueError):
                install_asset(spec, self.root, verify_only=True)

    def test_asset_path_cannot_escape_project(self):
        with self.assertRaises(ValueError):
            asset_path(self.root, '../outside.js')

    @staticmethod
    def feed(network, timestamp=1794432000):
        return ('\n'.join(json.dumps(row) for row in [
            {'cidr': network, 'sblid': 'SBL-TEST'},
            {'type': 'metadata', 'timestamp': timestamp, 'copyright': 'Test fixture copyright'}]) + '\n').encode()

    def test_drop_feed_requires_correct_family_and_metadata(self):
        entries, source = parse_drop_feed(self.feed('192.0.2.0/24'), 4, 'https://example.invalid/drop')
        self.assertEqual(entries[0]['network'], '192.0.2.0/24')
        self.assertEqual(entries[0]['category'], 'reputation match only')
        self.assertEqual(source['metadata']['copyright'], 'Test fixture copyright')
        with self.assertRaises(ValueError):
            parse_drop_feed(self.feed('2001:db8::/32'), 4, 'https://example.invalid/drop')
        with self.assertRaises(ValueError):
            parse_drop_feed(b'{"cidr":"192.0.2.0/24","sblid":"TEST"}\n', 4, 'https://example.invalid/drop')

    def test_refresh_preserves_custom_iocs_replaces_managed_and_is_rate_limited(self):
        path = self.root / 'threats.json'
        personal = {'network': '203.0.113.9', 'label': 'My indicator', 'source': 'personal'}
        path.write_text(json.dumps({'indicators': [personal, {'network': '198.51.100.0/24', 'managed_source': 'spamhaus-drop'}]}))
        calls = []
        def downloader(url):
            calls.append(url)
            return self.feed('192.0.2.0/24' if 'v4' in url else '2001:db8::/32')
        now = datetime(2026, 11, 12, tzinfo=timezone.utc)
        self.assertEqual(refresh_threats(path, downloader=downloader, now=now), 2)
        stored = json.loads(path.read_text())
        self.assertIn(personal, stored['indicators'])
        self.assertEqual(len(stored['indicators']), 3)
        self.assertEqual(len(stored['spamhaus_sources']), 2)
        self.assertEqual(refresh_threats(path, downloader=downloader, now=now+timedelta(minutes=5)), 0)
        self.assertEqual(len(calls), 2)

    def test_failed_refresh_keeps_previous_file_and_old_snapshot_warns(self):
        path = self.root / 'threats.json'
        original = json.dumps({'indicators': [], 'spamhaus_sources': [{'metadata': {'timestamp': 1000000000}}]})
        path.write_text(original)
        with self.assertRaises(ValueError):
            refresh_threats(path, downloader=lambda url: b'not JSON')
        self.assertEqual(path.read_text(), original)
        self.assertIn('non è un feed live', ThreatStore(path).warning)

    def test_old_reputation_hit_is_dated_not_a_current_attack(self):
        path = self.root / 'threats.json'
        path.write_text(json.dumps({'updated_at': '2001-01-01', 'indicators': [
            {'network': '8.8.8.8', 'source_date': '2001-01-01', 'source': 'fixture'}]}))
        hit = ThreatStore(path).lookup('8.8.8.8')
        self.assertTrue(hit['snapshot_stale'])
        self.assertGreater(hit['snapshot_age_days'], 2)
        self.assertFalse(hit['attack_verified'])
        self.assertEqual(hit['verification'], 'database_attribution')


if __name__ == '__main__':
    unittest.main()
