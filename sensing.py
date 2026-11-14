"""Observed RSSI perturbations and independent, bounded ICMP sampling.

RSSI is a driver-level measurement, not CSI. A polling rate of 10 Hz cannot
force a device to publish fresh measurements at that rate. RTT contributes
only to network health: congestion must not be classified as human motion.
"""
from collections import deque
from dataclasses import dataclass
from queue import Empty, Full, Queue
import threading
import time

import numpy as np

from models import NetworkInfo, SensingSnapshot, WorkerMessage


def bandpass_taps(fs: float, low: float = 0.3, high: float = 3.0) -> np.ndarray:
    """Windowed-sinc FIR, zero DC gain and unit gain near the passband center."""
    if not 0 < low < high < fs / 2:
        raise ValueError("Serve 0 < frequenza minima < massima < Nyquist")
    size = int(round(fs * 3)) | 1
    n = np.arange(size, dtype=float) - (size - 1) / 2
    taps = (2 * high / fs * np.sinc(2 * high / fs * n)
            - 2 * low / fs * np.sinc(2 * low / fs * n)) * np.hamming(size)
    taps -= taps.mean()
    center = (low + high) / 2
    gain = abs(np.sum(taps * np.exp(-2j * np.pi * center * n / fs)))
    return taps / gain


@dataclass(frozen=True)
class Detection:
    filtered: float | None = None
    variance: float | None = None
    threshold: float | None = None
    intensity: float | None = None
    motion: bool | None = None
    state: str = "Da calibrare"
    calibration_progress: float = 0.0
    warning: str = ""


class MotionDetector:
    """Single-thread-owned DSP; timestamps prevent bridging acquisition gaps."""

    def __init__(self, fs: float = 10.0):
        if not 10 <= fs <= 100:
            raise ValueError("La frequenza deve essere compresa tra 10 e 100 Hz")
        self.fs = fs
        self.taps = bandpass_taps(fs)
        self.raw = deque(maxlen=len(self.taps))
        self.window = deque(maxlen=round(3 * fs))
        self.cadence = deque(maxlen=round(fs) + 1)
        self.threshold: float | None = None
        self.calibrating = False
        self.calibration: list[float] = []
        self.calibration_started: float | None = None
        self.last_time: float | None = None
        self.motion = False
        self.above = self.below = 0
        self.warning = ""

    def reset(self, cancel_calibration: bool = False) -> None:
        self.raw.clear()
        self.window.clear()
        self.cadence.clear()
        self.last_time = None
        self.motion = False
        self.above = self.below = 0
        if cancel_calibration and self.calibrating:
            self.calibrating = False
            self.calibration.clear()
            self.calibration_started = None
            self.warning = "Calibrazione interrotta: ripetere con dati continui."

    def calibrate(self) -> None:
        # Discard movement that occurred before the user declared the room empty.
        self.reset()
        self.threshold = None
        self.calibrating = True
        self.calibration = []
        self.calibration_started = None
        self.motion = False
        self.above = self.below = 0
        self.warning = ""

    def update(self, timestamp: float, rssi: float | None) -> Detection:
        valid = rssi is not None and np.isfinite(rssi) and -120 <= rssi <= -1
        gap = self.last_time is not None and (
            timestamp <= self.last_time or timestamp - self.last_time > 1.8 / self.fs)
        if not valid or gap:
            self.reset(cancel_calibration=True)
            message = self.warning or "RSSI assente o campionamento discontinuo."
            if not valid:
                return Detection(threshold=self.threshold, state="Segnale non disponibile",
                                 warning=message)
            self.warning = message
        self.last_time = timestamp
        self.cadence.append(timestamp)
        if len(self.cadence) == self.cadence.maxlen:
            rate = (len(self.cadence) - 1) / (self.cadence[-1] - self.cadence[0])
            if not 0.9 * self.fs <= rate <= 1.1 * self.fs:
                cancelled = self.calibrating
                self.reset(cancel_calibration=True)
                self.warning = ("Calibrazione interrotta: " if cancelled else "") + (
                    "frequenza effettiva non compatibile con il filtro; attendere dati regolari.")
                return Detection(threshold=self.threshold, state="Campionamento insufficiente",
                                 warning=self.warning)
        self.raw.append(float(rssi))
        if len(self.raw) < len(self.taps):
            state = "Calibrazione · riscaldamento filtro" if self.calibrating else "Riscaldamento filtro"
            return Detection(threshold=self.threshold, state=state,
                             warning=self.warning)
        filtered = float(np.dot(self.taps, np.asarray(self.raw)))
        self.window.append(filtered)
        if len(self.window) < self.window.maxlen:
            state = ("Calibrazione · riscaldamento finestra (3 s)" if self.calibrating
                     else "Riscaldamento finestra (3 s)")
            return Detection(filtered=filtered, threshold=self.threshold,
                             state=state, warning=self.warning)
        variance = float(np.var(np.asarray(self.window), ddof=0))
        if self.threshold is not None:
            self.warning = ""
        progress = 0.0
        if self.calibrating:
            if self.calibration_started is None:
                self.calibration_started = timestamp
            self.calibration.append(variance)
            elapsed = timestamp - self.calibration_started + 1 / self.fs
            progress = min(1.0, elapsed / 10)
            if elapsed >= 10 - 1e-6 and len(self.calibration) < round(9.5 * self.fs):
                self.calibrating = False
                self.warning = "Calibrazione fallita: frequenza effettiva insufficiente."
                return Detection(filtered, variance, state="Da calibrare", warning=self.warning)
            if elapsed >= 10 - 1e-6:
                values = np.asarray(self.calibration)
                median = float(np.median(values))
                mad = float(np.median(np.abs(values - median)))
                # A floor handles integer-quantized, perfectly flat RSSI drivers.
                self.threshold = max(0.08, median + 6 * 1.4826 * mad,
                                     float(np.quantile(values, 0.95)) * 1.8)
                self.calibrating = False
                self.warning = ""
            else:
                return Detection(filtered, variance, state="Calibrazione stanza vuota",
                                 calibration_progress=progress, warning=self.warning)
        if self.threshold is None:
            return Detection(filtered, variance, state="Da calibrare", warning=self.warning)
        self.above = self.above + 1 if variance > self.threshold else 0
        self.below = self.below + 1 if variance < self.threshold * 0.7 else 0
        if self.above >= max(2, round(0.3 * self.fs)):
            self.motion = True
        elif self.below >= max(3, round(0.5 * self.fs)):
            self.motion = False
        excess = max(0.0, variance / self.threshold - 1)
        intensity = float(100 * -np.expm1(-excess))
        state = "Varianza RSSI sopra soglia" if self.motion else "Varianza RSSI sotto soglia"
        return Detection(filtered, variance, self.threshold, intensity, self.motion,
                         state, progress, self.warning)


class RegularSampler:
    """Uniform DSP grid only: raw RSSI telemetry is never interpolated."""
    def __init__(self, fs):
        self.fs = fs
        self.clear()

    def clear(self):
        self.previous = self.next_time = None
        self.times = deque(maxlen=30)
        self.detection = Detection(state='Preparazione filtro temporale')

    def update(self, detector, timestamp, value):
        if value is None or not np.isfinite(value):
            self.clear()
            self.detection = detector.update(timestamp, None)
            return self.detection
        if self.previous is not None:
            dt = timestamp-self.previous[0]
            if dt <= 0 or dt > 2.5/self.fs:
                self.clear()
                detector.reset(cancel_calibration=True)
        self.times.append(timestamp)
        if len(self.times) >= 10 and (len(self.times)-1)/(self.times[-1]-self.times[0]) < .8*self.fs:
            self.clear()
            detector.reset(cancel_calibration=True)
            return Detection(state='Campionamento insufficiente', warning='Ridurre le letture richieste; il driver non mantiene la cadenza.')
        if self.previous is None:
            self.previous = (timestamp, value)
            self.next_time = timestamp + 1/self.fs
            self.detection = detector.update(timestamp, value)
            return self.detection
        old_time, old_value = self.previous
        while self.next_time <= timestamp + 1e-9:
            fraction = (self.next_time-old_time)/(timestamp-old_time)
            interpolated = old_value + min(1, max(0, fraction))*(value-old_value)
            self.detection = detector.update(self.next_time, interpolated)
            self.next_time += 1/self.fs
        self.previous = (timestamp, value)
        return self.detection


class SensingEngine(threading.Thread):
    """RSSI/DSP and ICMP workers; only observations, never synthetic fallbacks."""

    def __init__(self, network: NetworkInfo, fs: float = 10.0):
        super().__init__(name="wifi-sensing", daemon=False)
        if network is None:
            raise ValueError("Interfaccia di rete necessaria: nessun dato sostitutivo")
        self.network, self.fs = network, fs
        self.output: Queue[WorkerMessage] = Queue(maxsize=100)
        self._stop_event = threading.Event()
        self._calibrate_event = threading.Event()
        self._paused = threading.Event()
        self._reset_event = threading.Event()
        self._baseline_reset = threading.Event()
        self._lock = threading.Lock()
        self._pings: deque[tuple[float, float | None]] = deque(maxlen=round(fs * 30))
        self._ping_warning = ""
        self.detector = MotionDetector(fs)
        self.regular = RegularSampler(fs)

    def stop(self) -> None:
        self._stop_event.set()

    def request_calibration(self) -> None:
        self._calibrate_event.set()

    def request_baseline_reset(self) -> None:
        self._baseline_reset.set()

    @property
    def calibration_active(self) -> bool:
        return self._calibrate_event.is_set() or self.detector.calibrating

    def set_paused(self, paused: bool) -> None:
        # Preserve even a pause/resume pair shorter than one sampling period.
        self._reset_event.set()
        if paused:
            self._paused.set()
        else:
            self._paused.clear()

    def _emit(self, kind: str, payload: object) -> None:
        try:
            self.output.put_nowait(WorkerMessage(kind, payload))
        except Full:
            try:
                self.output.get_nowait()
            except Empty:
                pass
            try:
                self.output.put_nowait(WorkerMessage(kind, payload))
            except Full:
                pass

    def _ping_loop(self) -> None:
        from netio import create_pinger
        pinger = None
        try:
            # RTT sampling has an independent timeout: increasing RSSI polling
            # must not turn valid 20–200 ms replies into artificial loss.
            pinger = create_pinger(self.network, timeout=0.25)
            deadline = time.monotonic()
            while not self._stop_event.is_set():
                rtt = pinger.ping()
                with self._lock:
                    self._pings.append((time.monotonic(), rtt))
                deadline += 0.1
                now = time.monotonic()
                if deadline < now:
                    deadline = now
                self._stop_event.wait(max(0, deadline - now))
        except Exception as exc:
            with self._lock:
                self._ping_warning = f"ICMP non disponibile: {exc}"
        finally:
            if pinger is not None:
                pinger.close()

    def _health(self, now: float) -> tuple[float | None, float | None, float | None, str]:
        with self._lock:
            recent = [(t, rtt) for t, rtt in self._pings if now - t <= 3]
            warning = self._ping_warning
        if not recent:
            return None, None, None, warning or "In attesa delle misure ICMP."
        good = [rtt for _, rtt in recent if rtt is not None]
        loss = 100 * (1 - len(good) / len(recent))
        jitter = float(np.std(good)) if len(good) >= 2 else None
        latest_time, rtt = recent[-1]
        if now - latest_time > max(0.5, 3 / self.fs):
            warning = warning or "Misure ICMP non aggiornate."
            return None, None, None, warning
        return rtt, loss, jitter, warning

    def run(self) -> None:
        source = ping_thread = None
        times: deque[float] = deque(maxlen=round(5 * self.fs))
        values: deque[float] = deque(maxlen=round(5 * self.fs))
        source_warning = ""
        retry_at = 0.0
        try:
            from netio import create_rssi_source
            ping_thread = threading.Thread(target=self._ping_loop, name="gateway-icmp",
                                           daemon=False)
            ping_thread.start()
            try:
                source = create_rssi_source(self.network)
                label = source.label
            except Exception as exc:
                label = "RSSI non disponibile"
                source_warning = f"RSSI non disponibile: {exc}"
            deadline = time.monotonic()
            was_paused = False
            while not self._stop_event.is_set():
                now = time.monotonic()
                paused = self._paused.is_set()
                if self._baseline_reset.is_set():
                    self._baseline_reset.clear()
                    self.detector.threshold = None
                    self.detector.reset(cancel_calibration=True)
                    self.regular.clear()
                if self._reset_event.is_set() or paused != was_paused:
                    self._reset_event.clear()
                    self.detector.reset(cancel_calibration=True)
                    self.regular.clear()
                    times.clear()
                    values.clear()
                    was_paused = paused
                if self._calibrate_event.is_set() and not paused:
                    self.detector.calibrate()
                    self.regular.clear()
                    self._calibrate_event.clear()
                if source is None and now >= retry_at:
                    retry_at = now + 5
                    try:
                        source = create_rssi_source(self.network)
                        label, source_warning = source.label, ""
                    except Exception as exc:
                        source_warning = str(exc)
                warning = source_warning
                if paused:
                    try:
                        rssi = source.read() if source is not None else None
                    except Exception as exc:
                        rssi, warning = None, str(exc)
                    if rssi is not None and (not np.isfinite(rssi) or not -120 <= rssi <= -1):
                        rssi = None
                    now = time.monotonic()
                    if rssi is not None:
                        times.append(now)
                        values.append(float(rssi))
                    detection = Detection(threshold=self.detector.threshold,
                        state="RSSI live · analisi esclusa durante sonde o banda non verificata")
                else:
                    try:
                        rssi = source.read() if source is not None else None
                        if source is not None:
                            label = source.label
                        if rssi is not None and (not np.isfinite(rssi) or not -120 <= rssi <= -1):
                            rssi = None
                            warning = "RSSI fuori intervallo: misura scartata."
                    except Exception as exc:
                        rssi = None
                        warning = f"Lettura RSSI: {exc}"
                    now = time.monotonic()
                    detection = self.regular.update(self.detector, now, rssi)
                    if rssi is not None and np.isfinite(rssi) and -120 <= rssi <= -1:
                        times.append(now)
                        values.append(float(rssi))
                while times and now - times[0] > 5:
                    times.popleft()
                rate = ((len(times) - 1) / (times[-1] - times[0])
                        if len(times) > 1 and times[-1] > times[0] else None)
                rtt, loss, jitter, ping_warning = self._health(now)
                warnings = [warning, detection.warning, ping_warning]
                if not paused and len(values) == values.maxlen and np.ptp(values) == 0:
                    warnings.append("RSSI invariato: possibile quantizzazione/cache del driver.")
                if not paused and len(times) >= 10 and rate < 0.9 * self.fs:
                    warnings.append(f"Acquisizione {rate:.1f} Hz, inferiore al target {self.fs:g} Hz.")
                self._emit("sample", SensingSnapshot(
                    now, rssi, rtt, detection.filtered, detection.variance, detection.threshold,
                    detection.intensity, detection.motion, detection.state,
                    detection.calibration_progress, rate, loss, jitter, label,
                    " ".join(dict.fromkeys(w for w in warnings if w))))
                deadline += 1 / self.fs
                now = time.monotonic()
                if deadline < now:
                    deadline = now
                self._stop_event.wait(max(0, deadline - now))
        except Exception as exc:
            self._emit("error", f"Acquisizione arrestata: {exc}")
        finally:
            self._stop_event.set()
            if ping_thread is not None:
                ping_thread.join()
            if source is not None:
                source.close()
