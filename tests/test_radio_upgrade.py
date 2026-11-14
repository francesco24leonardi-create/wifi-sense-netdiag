import math
import threading
import time
import unittest
import asyncio
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace

from models import NetworkInfo
from radio import parse_link, band_for_frequency, link_status
from sensing import MotionDetector, RegularSampler, SensingEngine
from survey import Survey
from scanner import provider_error


class UpgradeTests(unittest.TestCase):
    def test_ble_scan_without_ipv4_network(self):
        from service import Controller
        async def exercise():
            root=Path(__file__).resolve().parents[1]
            controller=Controller(root,dict(interface=None,hz=10,capture=False))
            with patch('service.discover_ble',return_value=([],[])) as discover:
                controller.start_scan('ble')
                await controller._scan_task
                self.assertEqual(controller.scan['providers']['BLE']['status'],'completed')
                discover.assert_called_once()
            await controller.close()
        asyncio.run(exercise())

    def test_linux_frequency_and_connected_bssid(self):
        result = parse_link('Connected to aa:bb:cc:dd:ee:ff (on wlan0)\nSSID: casa\nfreq: 2437\nsignal: -56 dBm')
        self.assertEqual(result['band'], '2.4 GHz')
        self.assertEqual(result['bssid'], 'aa:bb:cc:dd:ee:ff')

    def test_windows_localized_band(self):
        self.assertEqual(parse_link('Banda : 2,4 GHz\nCanale : 6')['band'], '2.4 GHz')
        self.assertIsNone(parse_link('Canale : 6')['band'])

    def test_other_bands_not_accepted(self):
        self.assertEqual(band_for_frequency(5180), '5 GHz')
        network = NetworkInfo('wlan0', '192.0.2.2', '255.255.255.0', '192.0.2.1')
        with patch('radio.sys.platform', 'linux'), patch('radio.run_command', return_value='freq: 5180'):
            self.assertFalse(link_status(network)['eligible'])

    def test_jittered_sampling_calibrates_without_changing_raw_data(self):
        detector, regular = MotionDetector(10), RegularSampler(10)
        detector.calibrate()
        for i in range(200):
            t = i*.1 + (.015 if i%2 else 0)
            result = regular.update(detector, t, -60)
        self.assertIsNotNone(result.threshold)
        self.assertFalse(result.motion)

    def test_long_gap_cancels_calibration(self):
        detector, regular = MotionDetector(10), RegularSampler(10)
        detector.calibrate()
        for i in range(90):
            regular.update(detector, i*.1, -60)
        result = regular.update(detector, 20, -60)
        self.assertIsNone(result.threshold)
        self.assertFalse(detector.calibrating)

    def test_slow_driver_is_not_interpolated_into_valid_calibration(self):
        detector, regular = MotionDetector(10), RegularSampler(10)
        detector.calibrate()
        for i in range(200):
            result = regular.update(detector, i/5, -60)
        self.assertIsNone(result.threshold)

    def test_probe_pause_keeps_raw_rssi(self):
        source=SimpleNamespace(label='test',read=lambda:-60,close=lambda:None)
        pinger=SimpleNamespace(ping=lambda:2,close=lambda:None)
        net=NetworkInfo('test','192.0.2.2','255.255.255.0','192.0.2.1')
        with patch('netio.create_rssi_source',return_value=source),patch('netio.create_pinger',return_value=pinger):
            engine=SensingEngine(net)
            engine.set_paused(True)
            engine.start()
            try:
                sample=engine.output.get(timeout=1).payload
                self.assertEqual(sample.rssi_dbm,-60)
                self.assertIsNone(sample.rf_perturbation)
            finally:
                engine.stop()
                engine.join(1)
        self.assertFalse(engine.is_alive())

    def test_survey_rejects_stale_and_nonfinite_points(self):
        survey=Survey()
        with self.assertRaises(ValueError): survey.capture(0,0,'test',now=3)
        for i in range(30):
            survey.observe(dict(timestamp=i*.1,rssi_dbm=-60,rtt_ms=2),dict(eligible=True,bssid='ap',band='2.4 GHz'),'wlan0')
        point=survey.capture(1,2,'stanza',now=3)
        self.assertEqual(point['rssi_dbm'],-60)
        self.assertIsNone(point['position_accuracy_m'])
        with self.assertRaises(ValueError): survey.capture(math.nan,2,'bad',now=3)
        with self.assertRaises(ValueError): survey.capture(1,2,'old',now=10)

    def test_survey_context_change_clears_old_samples(self):
        survey=Survey()
        survey.observe(dict(timestamp=1,rssi_dbm=-60),dict(eligible=True,bssid='a',band='2.4 GHz'),'wlan0')
        survey.observe(dict(timestamp=2,rssi_dbm=-60),dict(eligible=False,bssid='b',band='5 GHz'),'wlan0')
        self.assertEqual(len(survey.samples),0)

    def test_provider_error_has_interface_and_recovery_information(self):
        net=NetworkInfo('wlan0','192.0.2.2','255.255.255.0','192.0.2.1')
        message=provider_error('mDNS',PermissionError('denied'),net)
        self.assertIn('wlan0',message)
        self.assertIn('5353',message)
        self.assertIn('PermissionError',message)
