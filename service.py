"""Application state, acquisition lifecycle and authenticated UI commands.

The asyncio server owns state. Blocking discovery and native APIs run in
workers; the renderer only receives JSON snapshots of the latest state.
"""
from __future__ import annotations
import asyncio
from collections import deque
from dataclasses import asdict
import json
import math
from pathlib import Path
from queue import Empty
import threading
import time

from connections import PassiveCapture, host_connections
from geoip import GeoIPStore, ThreatStore
from location import LocationManager
from netio import discover_network
from scanner import scan_all
from sensing import SensingEngine


def json_safe(value):
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, dict):
        return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(item) for item in value]
    return value


def load_settings(path: Path) -> dict:
    defaults = dict(interface=None, hz=10.0, mode='real', capture=False,
                    location_provider='system')
    if path.exists():
        data = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(data, dict):
            raise ValueError('settings.json deve contenere un oggetto JSON')
        defaults.update({key: data[key] for key in defaults if key in data})
    # Migrate older settings safely: simulation and typed coordinates are ignored.
    defaults['mode'] = 'real'
    hz = float(defaults['hz'])
    if not math.isfinite(hz) or not 10 <= hz <= 50:
        raise ValueError('hz deve essere tra 10 e 50')
    defaults['hz'] = hz
    if defaults['interface'] is not None and not isinstance(defaults['interface'], str):
        raise ValueError('interface deve essere una stringa o null')
    if defaults['location_provider'] not in ('system', 'gpsd'):
        raise ValueError('location_provider deve essere system oppure gpsd')
    if not isinstance(defaults['capture'], bool):
        raise ValueError('capture deve essere true oppure false')
    return defaults


class Controller:
    def __init__(self, root: Path, settings: dict):
        self.root, self.settings = root, dict(settings)
        self.geo = GeoIPStore(root / 'data/ipgeo.sqlite', root / 'static/world.geojson')
        self.threats = ThreatStore(root / 'data/threats.json')
        self.capture = PassiveCapture()
        self.network = self.engine = None
        self.mode = 'real'
        self.location = LocationManager(system_enabled=True)
        self.telemetry = None
        self.devices, self.access_points, self.connections = [], [], []
        self.scan = dict(running=False, phase='Pronto', warnings=[])
        self.warning_log = deque(maxlen=12)
        self._stop = asyncio.Event()
        self._mode_lock = asyncio.Lock()
        self._command_lock = asyncio.Lock()
        self._scan_stop = threading.Event()
        self._scan_task = None
        self._tasks = []
        self._close_task = None
        self._generation, self._sequence = 0, 0
        self._started = time.monotonic()
        self._telemetry_received = self._connections_received = self._inventory_received = None
        self._telemetry_observed_at = None

    def warn(self, message: str) -> None:
        if message and message not in self.warning_log:
            self.warning_log.append(str(message)[:600])

    async def start(self) -> None:
        await self.set_mode(self.mode)
        self._tasks = [asyncio.create_task(self._samples(), name='rss-queue'),
                       asyncio.create_task(self._connections(), name='existing-sockets')]

    async def _stop_scan(self) -> None:
        self._scan_stop.set()
        if self._scan_task is not None:
            await self._scan_task
            self._scan_task = None

    async def _stop_engine(self) -> None:
        if self.engine is not None:
            self.engine.stop()
            await asyncio.to_thread(self.engine.join, 3)
            if self.engine.is_alive():
                raise RuntimeError('Il driver RSSI non ha terminato la chiamata; riprovare la chiusura')
            self.engine = None

    async def set_mode(self, mode: str) -> None:
        if mode != 'real':
            raise ValueError('Sono consentite solo osservazioni reali; simulazione rimossa')
        async with self._mode_lock:
            self._generation += 1
            await self._stop_scan()
            await asyncio.to_thread(self.capture.stop)
            await self._stop_engine()
            self.mode = mode
            self.network, self.telemetry = None, None
            self.devices, self.access_points, self.connections = [], [], []
            self._telemetry_received = self._connections_received = self._inventory_received = None
            self.warning_log.clear()
            self.scan = dict(running=False, phase='Inizializzazione', warnings=[])
            self._started = time.monotonic()
            try:
                self.network = await asyncio.to_thread(discover_network, self.settings.get('interface'))
            except Exception as exc:
                self.warn(f'Interfaccia reale non disponibile: {exc}')
            self.scan['phase'] = 'Osservazioni reali · scansione manuale'
            self.warn('RSSI: valore riferito dal driver; nessuna identificazione o localizzazione di persone.')
            if self.threats.warning:
                self.warn(self.threats.warning)
            if self.network is not None:
                self.engine = SensingEngine(self.network, fs=self.settings['hz'])
                self.engine.start()
                if self.settings.get('capture'):
                    await asyncio.to_thread(self.capture.start, self.network)

    async def _samples(self) -> None:
        while not self._stop.is_set():
            engine = self.engine
            if engine is not None:
                for _ in range(100):
                    try:
                        message = engine.output.get_nowait()
                    except Empty:
                        break
                    if message.kind == 'sample':
                        self.telemetry = json_safe(asdict(message.payload))
                        self._telemetry_received = time.monotonic()
                        # Driver acquisition time is unknown; label this as poll time.
                        age = max(0, self._telemetry_received - self.telemetry['timestamp'])
                        self._telemetry_observed_at = time.time() - age
                    elif message.kind == 'error':
                        self.warn(str(message.payload))
            try:
                await asyncio.wait_for(self._stop.wait(), .05)
            except asyncio.TimeoutError:
                continue

    async def _connections(self) -> None:
        while not self._stop.is_set():
            generation = self._generation
            if self.mode == 'real' and not self._mode_lock.locked():
                try:
                    rows, warnings = await asyncio.to_thread(host_connections)
                    if self.mode == 'real' and generation == self._generation:
                        rows.extend(self.capture.snapshot())
                        for row in rows:
                            row['geo'] = self.geo.lookup(row['remote_ip'])
                            row['threat'] = self.threats.lookup(row['remote_ip'], mode='real')
                        self.connections = rows[:256]
                        self._connections_received = time.monotonic() if rows or not warnings else None
                        for warning in warnings:
                            self.warn(warning)
                        if self.capture.error:
                            self.warn(self.capture.error)
                except Exception as exc:
                    self.connections = []
                    self._connections_received = None
                    self.warn(f'Osservazione connessioni: {exc}')
            try:
                await asyncio.wait_for(self._stop.wait(), 2)
            except asyncio.TimeoutError:
                continue

    def start_scan(self) -> None:
        if self.scan['running'] or self._mode_lock.locked():
            raise ValueError('Operazione già in corso')
        if self.engine and self.engine.calibration_active:
            raise ValueError('Attendere la fine della calibrazione prima della scansione')
        if self.mode == 'real' and self.network is None:
            raise ValueError('Nessuna interfaccia IPv4 selezionata; configurare --interface e riavviare')
        self._scan_stop.clear()
        self.devices, self.access_points = [], []
        self._inventory_received = None
        self.scan = dict(running=True, phase='Scansione in corso', warnings=[])
        if self.engine:
            self.engine.set_paused(True)
        self._scan_task = asyncio.create_task(self._scan(), name='inventory')

    async def _scan(self) -> None:
        generation = self._generation
        loop = asyncio.get_running_loop()

        def phase(message):
            def update():
                if self._generation == generation:
                    self.scan['phase'] = str(message)[:200]
            loop.call_soon_threadsafe(update)

        try:
            result = await asyncio.to_thread(scan_all, self.network, self._scan_stop, phase)
            if generation == self._generation:
                self.devices = result['devices']
                self.access_points = result['access_points']
                self._inventory_received = time.monotonic()
                self.scan = dict(running=False, phase='Scansione parziale' if result['partial'] else 'Scansione completata',
                                 warnings=result['warnings'], channel_summary=result.get('channel_summary', ''),
                                 partial=result['partial'])
        except Exception as exc:
            self.scan = dict(running=False, phase='Errore scansione', warnings=[str(exc)])
        finally:
            self.scan['running'] = False
            if self.engine:
                self.engine.set_paused(False)

    async def command(self, message: dict) -> str:
        async with self._command_lock:
            if self._stop.is_set():
                raise ValueError('Applicazione in chiusura')
            return await self._command(message)

    async def _command(self, message: dict) -> str:
        action = message.get('action')
        if action == 'mode':
            await self.set_mode(message.get('value'))
        elif action == 'calibrate':
            if self._mode_lock.locked() or self.scan['running'] or self.engine is None:
                raise ValueError('Calibrazione non disponibile durante scansione/cambio rete')
            self.engine.request_calibration()
        elif action == 'scan':
            self.start_scan()
        elif action == 'location_start':
            await self.location.start(provider=self.settings.get('location_provider', 'system'))
        elif action == 'location_stop':
            await self.location.stop()
        elif action == 'origin':
            raise ValueError('Coordinate manuali non accettate: richiedere una misura al sistema')
        elif action == 'capture':
            value = message.get('value')
            if not isinstance(value, bool):
                raise ValueError('capture richiede un booleano')
            if self.mode != 'real' or self.network is None or self._mode_lock.locked():
                raise ValueError('Cattura disponibile solo con interfaccia reale')
            if value:
                await asyncio.to_thread(self.capture.start, self.network)
            else:
                await asyncio.to_thread(self.capture.stop)
            self.settings['capture'] = value
        else:
            raise ValueError('Comando non supportato')
        return action

    def snapshot(self) -> dict:
        self._sequence += 1
        now = time.monotonic()
        def age(stamp):
            return max(0.0, now - stamp) if stamp is not None else None
        telemetry_age = age(self.telemetry.get('timestamp')) if self.telemetry else None
        connection_age = age(self._connections_received)
        inventory_age = age(self._inventory_received)
        telemetry = dict(self.telemetry) if self.telemetry else None
        if telemetry:
            stale = telemetry_age is None or telemetry_age > 2
            telemetry.update(observed_at=self._telemetry_observed_at, age_s=telemetry_age,
                stale=stale, verification='driver_reported', source_updated_at=None,
                source_freshness='unknown', intensity_meaning='Indice matematico della varianza; non probabilità di presenza')
            if stale:
                for field in ('rssi_dbm', 'rtt_ms', 'filtered', 'variance', 'intensity',
                              'rf_perturbation', 'sample_hz', 'loss_percent', 'jitter_ms'):
                    telemetry[field] = None
                telemetry['state'] = 'Misure non aggiornate'
        events = []
        if telemetry and telemetry.get('rf_perturbation') is True:
            events = [dict(id='rf-link', kind='rf', label='Perturbazione RF · causa e posizione non determinate',
                           intensity=telemetry['intensity'], synthetic=False, position=None,
                           source=telemetry['source'], observed_at=telemetry['observed_at'],
                           verification='derived_from_rssi', identifies_people=False)]
        warnings = list(self.warning_log)
        if telemetry and telemetry.get('warning'):
            warnings.append(telemetry['warning'])
        if self.threats.warning and self.threats.warning not in warnings:
            warnings.append(self.threats.warning)
        # Discovery is an observation at a moment, not proof of continued presence.
        def observed_rows(rows):
            result = []
            for row in rows:
                copy = dict(row)
                stamp = copy.get('observed_at')
                row_age = max(0, time.time()-stamp) if isinstance(stamp, (int, float)) else inventory_age
                copy.update(age_s=row_age, stale=row_age is None or row_age > 60,
                            presence_verified=False)
                result.append(copy)
            return result
        return json_safe(dict(type='snapshot', version=1, seq=self._sequence, time=time.time(), mode=self.mode,
            network=asdict(self.network) if self.network else None,
            telemetry=telemetry, devices=observed_rows(self.devices), access_points=observed_rows(self.access_points),
            connections=self.connections if connection_age is not None and connection_age <= 10 else [],
            origin=self.location.origin(), location=self.location.snapshot(),
            freshness=dict(telemetry_age_s=telemetry_age, connections_age_s=connection_age, inventory_age_s=inventory_age),
            scan=self.scan, events=events, warnings=warnings,
            capabilities=dict(capture=self.capture.running,
                visibility='Connessioni di questo PC; altri client solo se realmente osservabili dalla NIC.',
                geo=self.geo.status(), threats=self.threats.status(), target_hz=self.settings['hz'])))

    async def close(self) -> None:
        if self._close_task is None:
            self._stop.set()
            if self.engine:
                self.engine.stop()
            self._scan_stop.set()
            self._close_task = asyncio.create_task(self._close_resources(), name='resource-cleanup')
        cancelled = False
        while True:
            try:
                # A cancellation of the caller must not cancel resource cleanup.
                await asyncio.shield(self._close_task)
                break
            except asyncio.CancelledError:
                cancelled = True
                if self._close_task.done():
                    break
            except Exception:
                break
        try:
            self._close_task.result()
        except Exception as exc:
            if cancelled:
                raise asyncio.CancelledError() from exc
            raise
        if cancelled:
            raise asyncio.CancelledError()

    async def _close_resources(self) -> None:
        failures = []
        async with self._command_lock:
            operations = [*self._tasks, self._stop_scan(),
                          self.location.stop(), asyncio.to_thread(self.capture.stop), self._stop_engine()]
            for operation in operations:
                try:
                    await operation
                except asyncio.CancelledError:
                    # An already-cancelled worker is finished; still close the rest.
                    continue
                except Exception as exc:
                    failures.append(str(exc))
            try:
                self.geo.close()
            except Exception as exc:
                failures.append(str(exc))
        if failures:
            raise RuntimeError('; '.join(failures))
