"""Deterministic DSP tests; no real network, privileges or display required."""
import math
from queue import Empty
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import numpy as np

from sensing import MotionDetector, SensingEngine, bandpass_taps
from models import NetworkInfo


class DetectorTests(unittest.TestCase):
    def setUp(self):
        self.detector = MotionDetector()
        self.t = 0.0
        self.rng = np.random.default_rng(5)

    def feed(self, seconds, amplitude=0.0):
        result = None
        for _ in range(round(seconds * 10)):
            rssi = -60 + self.rng.normal(0, .1) + amplitude * math.sin(2 * math.pi * self.t)
            result = self.detector.update(self.t, rssi)
            self.t += .1
        return result

    def calibrate(self):
        self.detector.calibrate()
        result = self.feed(17)
        self.assertIsNotNone(result.threshold)
        self.assertFalse(result.motion)

    def test_filter_rejects_dc_and_high_frequencies(self):
        taps = bandpass_taps(10)
        n = np.arange(len(taps))
        gain = lambda f: abs(np.dot(taps, np.exp(-2j * np.pi * f * n / 10)))
        self.assertLess(gain(0), 1e-10)
        self.assertGreater(gain(1), .9)
        self.assertLess(gain(4), .02)

    def test_no_detection_before_calibration(self):
        result = self.feed(20, amplitude=4)
        self.assertFalse(result.motion)
        self.assertIsNone(result.threshold)

    def test_calibration_needs_warmup_plus_ten_seconds(self):
        self.detector.calibrate()
        result = self.feed(12)
        self.assertIsNone(result.threshold)
        self.assertGreater(result.calibration_progress, .5)
        result = self.feed(5)
        self.assertIsNotNone(result.threshold)

    def test_calibrated_movement_and_recovery(self):
        self.calibrate()
        threshold = self.detector.threshold
        result = self.feed(8, amplitude=3)
        self.assertTrue(result.motion)
        self.assertGreater(result.intensity, 90)
        result = self.feed(10)
        self.assertFalse(result.motion)
        self.assertEqual(threshold, self.detector.threshold)

    def test_missing_read_invalidates_calibration_and_never_implies_motion(self):
        self.detector.calibrate()
        self.feed(9)
        result = self.detector.update(self.t, None)
        self.t += .1
        self.assertFalse(self.detector.calibrating)
        self.assertIn("Calibrazione interrotta", result.warning)
        result = self.feed(20, amplitude=4)
        self.assertFalse(result.motion)
        self.assertIsNone(result.threshold)

    def test_long_gap_resets_warmup_preserves_baseline(self):
        self.calibrate()
        self.feed(7, amplitude=4)
        self.t += 1
        result = self.detector.update(self.t, -60)
        self.assertFalse(result.motion)
        self.assertIsNotNone(result.threshold)
        self.assertIn("Riscaldamento", result.state)

    def test_flat_quantized_baseline_has_nonzero_floor(self):
        detector = MotionDetector()
        detector.calibrate()
        for i in range(180):
            result = detector.update(i / 10, -60)
        self.assertEqual(result.threshold, .08)
        self.assertFalse(result.motion)

    def test_low_effective_rate_cannot_complete_calibration(self):
        detector = MotionDetector(fs=10)
        detector.calibrate()
        for i in range(170):
            result = detector.update(i / 7, -60)
        self.assertIsNone(result.threshold)
        self.assertFalse(detector.calibrating)
        self.assertIn("frequenza effettiva", result.warning)

    def test_missing_measurements_are_null_not_zero(self):
        with self.assertRaises(ValueError): SensingEngine(None)
        missing=self.detector.update(0,None)
        self.assertIsNone(missing.variance)
        self.assertIsNone(missing.intensity)
        self.assertIsNone(missing.motion)

    def test_slow_icmp_does_not_slow_rssi_and_resources_are_closed(self):
        closed = []
        source = SimpleNamespace(label="test", read=lambda: -60,
                                 close=lambda: closed.append("rssi"))

        def slow_ping():
            time.sleep(.2)
            return None

        pinger = SimpleNamespace(ping=slow_ping, close=lambda: closed.append("icmp"))
        fake_netio = SimpleNamespace(create_rssi_source=lambda _: source,
                                     create_pinger=lambda _, timeout: pinger)
        network = NetworkInfo("test", "192.0.2.2", "255.255.255.0", "192.0.2.1")
        with patch.dict("sys.modules", netio=fake_netio):
            engine = SensingEngine(network)
            engine.start()
            try:
                samples = []
                deadline = time.monotonic() + 2
                while len(samples) < 12 and time.monotonic() < deadline:
                    message = engine.output.get(timeout=.3)
                    if message.kind == "sample":
                        samples.append(message.payload)
                self.assertGreaterEqual(len(samples), 12)
                self.assertGreater(samples[-1].sample_hz, 9)
                self.assertEqual(samples[-1].loss_percent, 100)
            finally:
                engine.stop()
                engine.join(timeout=1)
        self.assertFalse(engine.is_alive())
        self.assertCountEqual(closed, ["rssi", "icmp"])


if __name__ == "__main__":
    unittest.main()
