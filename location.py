"""Location from the local OS/GNSS, never from an application IP lookup.

Only the most recent fix is held in RAM. System services may contact their own
online providers, and therefore require explicit ``system_enabled=True``.
GPSD only connects to loopback; use a local GNSS receiver for strict offline use.

Windows consent must be initiated on the foreground UI thread. ``ui_dispatch``
is an async callable accepting a zero-argument synchronous callable: execute it
on the native window thread, and return its result without blocking that thread.
All manager methods belong to the backend asyncio loop.
"""
from __future__ import annotations

import asyncio
from contextlib import suppress
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
import json
import math
import sys
import threading
import time
from typing import Any, Awaitable, Callable, Protocol


class LocationUnavailable(RuntimeError):
    """Unavailable provider or denied system permission; never fabricate a fix."""


class InvalidFix(ValueError):
    """The provider has not supplied sufficient valid location evidence."""


def _number(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise InvalidFix(f"{name}: numero non disponibile")
    value = float(value)
    if not math.isfinite(value):
        raise InvalidFix(f"{name}: numero non finito")
    return value


def _datetime_timestamp(value: Any) -> float:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise InvalidFix("Timestamp del provider assente o privo di fuso orario")
    try:
        return value.timestamp()
    except (ValueError, OSError, OverflowError) as exc:
        raise InvalidFix("Timestamp del provider non valido") from exc


@dataclass(frozen=True)
class LocationFix:
    lat: float
    lon: float
    accuracy_m: float
    timestamp: float
    source: str
    position_source: str
    label: str
    accuracy_note: str = "Stima di accuratezza fornita dal sistema; non è una garanzia."

    def __post_init__(self) -> None:
        lat = _number(self.lat, "Latitudine")
        lon = _number(self.lon, "Longitudine")
        accuracy = _number(self.accuracy_m, "Accuratezza")
        stamp = _number(self.timestamp, "Timestamp")
        if not -90 <= lat <= 90 or not -180 <= lon <= 180:
            raise InvalidFix("Coordinate fuori intervallo")
        if accuracy <= 0 or stamp <= 0:
            raise InvalidFix("Accuratezza positiva e timestamp di misura sono obbligatori")
        if not self.source or not self.position_source:
            raise InvalidFix("Sorgente della misura assente")


def parse_gpsd_tpv(report: dict[str, Any]) -> LocationFix:
    """Parse an actual GPSD TPV, retaining its measurement time and uncertainty."""
    if report.get("class") != "TPV" or report.get("mode") not in (2, 3):
        raise InvalidFix("GNSS senza fix 2D/3D")
    stamp = report.get("time")
    if not isinstance(stamp, str):
        raise InvalidFix("GNSS senza timestamp della misura")
    try:
        measured = _datetime_timestamp(datetime.fromisoformat(stamp.replace("Z", "+00:00")))
    except ValueError as exc:
        raise InvalidFix("Timestamp GNSS non valido") from exc
    if "eph" in report:
        accuracy = _number(report["eph"], "Errore orizzontale GNSS")
        accuracy_note = "eph GPSD: errore orizzontale stimato; confidenza dipendente dal ricevitore."
    else:
        ex = _number(report.get("epx"), "Errore longitudinale GNSS")
        ey = _number(report.get("epy"), "Errore latitudinale GNSS")
        if ex <= 0 or ey <= 0:
            raise InvalidFix("GNSS senza stima positiva dell'errore orizzontale")
        accuracy = math.hypot(ex, ey)
        accuracy_note = "sqrt(epx² + epy²) GPSD: stima combinata, confidenza dipendente dal ricevitore."
    return LocationFix(report.get("lat"), report.get("lon"), accuracy, measured,
                       "GPSD / GNSS locale", "SATELLITE", "Posizione GNSS misurata", accuracy_note)


_WINDOWS_SOURCES = {0: "CELLULAR", 1: "SATELLITE", 2: "WIFI", 3: "IPADDRESS",
                    4: "UNKNOWN", 5: "DEFAULT", 6: "OBFUSCATED"}


def parse_windows_position(position: Any) -> LocationFix:
    coordinate = position.coordinate
    try:
        position_source = _WINDOWS_SOURCES.get(int(coordinate.position_source), "UNKNOWN")
    except (ValueError, TypeError, AttributeError):
        position_source = "UNKNOWN"
    # Windows DEFAULT is a manually configured fallback, not a measured fix.
    if position_source == "DEFAULT":
        raise InvalidFix("Windows ha restituito la posizione predefinita manuale: origine non verificata")
    point = coordinate.point.position
    return LocationFix(point.latitude, point.longitude, coordinate.accuracy,
                       _datetime_timestamp(coordinate.timestamp),
                       f"Windows Geolocation / {position_source}", position_source,
                       "Posizione fornita da Windows",
                       "Raggio di accuratezza dichiarato da Windows; sorgente indicata dal sistema.")


def parse_geoclue_location(properties: dict[str, Any]) -> LocationFix:
    def value(name: str) -> Any:
        item = properties.get(name)
        return getattr(item, "value", item)

    stamp = value("Timestamp")
    if not isinstance(stamp, (tuple, list)) or len(stamp) != 2:
        raise InvalidFix("GeoClue senza timestamp della misura")
    seconds = _number(stamp[0], "Secondi del timestamp")
    micros = _number(stamp[1], "Microsecondi del timestamp")
    if not seconds.is_integer() or not micros.is_integer() or not 0 <= micros < 1_000_000:
        raise InvalidFix("Timestamp GeoClue non valido")
    return LocationFix(value("Latitude"), value("Longitude"), value("Accuracy"),
                       seconds + micros / 1_000_000, "GeoClue2 / sistema", "UNKNOWN",
                       "Posizione fornita da GeoClue2",
                       "Accuratezza GeoClue; il protocollo non espone la sorgente fisica del fix.")


class LocationProvider(Protocol):
    async def start(self) -> None: ...
    async def read_fix(self) -> LocationFix: ...
    async def close(self) -> None: ...


class GPSDProvider:
    """Bounded JSON stream from the local gpsd daemon only."""

    def __init__(self) -> None:
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None

    async def start(self) -> None:
        self.reader, self.writer = await asyncio.open_connection("127.0.0.1", 2947, limit=65536)
        self.writer.write(b'?WATCH={"enable":true,"json":true};\n')
        await self.writer.drain()

    async def read_fix(self) -> LocationFix:
        if self.reader is None:
            raise LocationUnavailable("GPSD non avviato")
        while True:
            line = await self.reader.readline()
            if not line:
                raise LocationUnavailable("Connessione al ricevitore GPSD terminata")
            try:
                report = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if isinstance(report, dict) and report.get("class") == "TPV":
                return parse_gpsd_tpv(report)

    async def close(self) -> None:
        writer, self.writer = self.writer, None
        self.reader = None
        if writer is not None:
            writer.close()
            with suppress(OSError, asyncio.TimeoutError):
                await asyncio.wait_for(writer.wait_closed(), 2)


UIDispatch = Callable[[Callable[[], Any]], Awaitable[Any]]


class WindowsLocationProvider:
    def __init__(self, ui_dispatch: UIDispatch | None = None) -> None:
        self.ui_dispatch = ui_dispatch
        self.locator: Any = None
        self.pending: Any = None

    async def _await_operation(self, operation: Any) -> Any:
        self.pending = operation
        try:
            return await operation
        except asyncio.CancelledError:
            with suppress(Exception):
                operation.cancel()
            raise
        finally:
            self.pending = None
            with suppress(Exception):
                operation.close()

    async def start(self) -> None:
        try:
            from winrt.windows.devices.geolocation import Geolocator, GeolocationAccessStatus, PositionAccuracy
        except ImportError as exc:
            raise LocationUnavailable("Installare le dipendenze WinRT di requirements.txt per la posizione Windows") from exc
        if self.ui_dispatch is not None:
            operation = await self.ui_dispatch(Geolocator.request_access_async)
        elif threading.current_thread() is threading.main_thread():
            operation = Geolocator.request_access_async()
        else:
            raise LocationUnavailable("Consenso Windows richiede la finestra desktop e il suo thread UI")
        access = await self._await_operation(operation)
        if access != GeolocationAccessStatus.ALLOWED:
            raise LocationUnavailable("Posizione Windows non autorizzata: controllare Privacy e sicurezza > Posizione")
        self.locator = Geolocator()
        self.locator.desired_accuracy = PositionAccuracy.HIGH

    async def read_fix(self) -> LocationFix:
        if self.locator is None:
            raise LocationUnavailable("Provider Windows non avviato")
        # PyWinRT 3.x projects this overload separately; 4.x merges overloads.
        method = getattr(self.locator, "get_geoposition_async_with_age_and_timeout", None)
        if method is None:
            method = self.locator.get_geoposition_async
        operation = method(timedelta(seconds=0), timedelta(seconds=15))
        position = await self._await_operation(operation)
        return parse_windows_position(position)

    async def close(self) -> None:
        if self.pending is not None:
            with suppress(Exception):
                self.pending.cancel()
        self.pending = None
        self.locator = None


class GeoClueProvider:
    SERVICE = "org.freedesktop.GeoClue2"
    CLIENT = "org.freedesktop.GeoClue2.Client"
    PROPERTIES = "org.freedesktop.DBus.Properties"
    DESKTOP_ID = "wifi-sense-netdiag"

    def __init__(self) -> None:
        self.bus: Any = None
        self.client: Any = None
        self.client_properties: Any = None
        self._location_path = "/"
        self._updated = asyncio.Event()

    async def _object(self, path: str) -> Any:
        introspection = await self.bus.introspect(self.SERVICE, path)
        return self.bus.get_proxy_object(self.SERVICE, path, introspection)

    def _location_updated(self, _old: str, new: str) -> None:
        self._location_path = new
        self._updated.set()

    async def start(self) -> None:
        try:
            from dbus_fast import BusType, Variant
            from dbus_fast.aio import MessageBus
        except ImportError as exc:
            raise LocationUnavailable("Installare dbus-fast e il servizio di sistema GeoClue2") from exc
        self.bus = MessageBus(bus_type=BusType.SYSTEM)
        await self.bus.connect()
        manager = (await self._object("/org/freedesktop/GeoClue2/Manager")).get_interface(
            "org.freedesktop.GeoClue2.Manager")
        path = await manager.call_get_client()
        obj = await self._object(path)
        self.client = obj.get_interface(self.CLIENT)
        self.client_properties = obj.get_interface(self.PROPERTIES)
        await self.client_properties.call_set(self.CLIENT, "DesktopId", Variant("s", self.DESKTOP_ID))
        await self.client_properties.call_set(self.CLIENT, "RequestedAccuracyLevel", Variant("u", 8))
        self.client.on_location_updated(self._location_updated)
        await self.client.call_start()
        # A cached path is still validated by its measurement timestamp below.
        current = await self.client_properties.call_get(self.CLIENT, "Location")
        self._location_updated("/", current.value)

    async def read_fix(self) -> LocationFix:
        if self.client is None:
            raise LocationUnavailable("GeoClue non avviato")
        while True:
            await self._updated.wait()
            self._updated.clear()
            path = self._location_path
            if path == "/":
                continue
            active = await self.client_properties.call_get(self.CLIENT, "Active")
            if not active.value:
                raise LocationUnavailable("GeoClue disattivato dal sistema o autorizzazione revocata")
            obj = await self._object(path)
            properties = await obj.get_interface(self.PROPERTIES).call_get_all(
                "org.freedesktop.GeoClue2.Location")
            return parse_geoclue_location(properties)

    async def close(self) -> None:
        if self.client is not None:
            with suppress(Exception):
                self.client.off_location_updated(self._location_updated)
            with suppress(Exception):
                await asyncio.wait_for(self.client.call_stop(), 2)
        self.client = self.client_properties = None
        if self.bus is not None:
            self.bus.disconnect()
        self.bus = None
        self._location_path = "/"
        self._updated.clear()


class LocationManager:
    """Own one cancellable provider task and expose only a current validated fix.

    Inject ``provider_factory``, ``clock`` and ``monotonic`` for hardware-free
    tests. The factory receives the requested provider string (gpsd/system).
    """

    def __init__(self, *, system_enabled: bool = False, ttl_s: float = 60,
                 ui_dispatch: UIDispatch | None = None,
                 provider_factory: Callable[[str], LocationProvider] | None = None,
                 clock: Callable[[], float] = time.time,
                 monotonic: Callable[[], float] = time.monotonic,
                 poll_interval_s: float = 5, request_timeout_s: float = 20) -> None:
        if not math.isfinite(ttl_s) or not 0 < ttl_s <= 60:
            raise ValueError("ttl_s deve essere compreso tra 0 e 60 secondi")
        if not math.isfinite(poll_interval_s) or poll_interval_s < 0:
            raise ValueError("Intervallo di aggiornamento non valido")
        if not math.isfinite(request_timeout_s) or request_timeout_s <= 0:
            raise ValueError("Timeout non valido")
        self.system_enabled = system_enabled
        self.ttl_s = ttl_s
        self.ui_dispatch = ui_dispatch
        self._factory = provider_factory or self._make_provider
        self._clock, self._monotonic = clock, monotonic
        self._poll_interval = poll_interval_s
        self._request_timeout = request_timeout_s
        self._lock = asyncio.Lock()
        self._task: asyncio.Task | None = None
        self._fix: LocationFix | None = None
        self._received_mono = 0.0
        self._initial_age = 0.0
        self._provider_name: str | None = None
        self._status = "idle"
        self._message = "Posizione non richiesta"

    def _make_provider(self, provider: str) -> LocationProvider:
        if provider == "gpsd":
            return GPSDProvider()
        if sys.platform == "win32":
            return WindowsLocationProvider(self.ui_dispatch)
        if sys.platform.startswith("linux"):
            return GeoClueProvider()
        raise LocationUnavailable("Posizione di sistema implementata per Windows e Linux")

    async def start(self, provider: str = "gpsd") -> None:
        if provider not in ("gpsd", "system"):
            raise ValueError("Provider ammessi: gpsd, system")
        async with self._lock:
            if self._task is not None and not self._task.done() and provider == self._provider_name:
                return
            await self._stop_task()
            self._provider_name = provider
            self._fix = None
            if provider == "system" and not self.system_enabled:
                self._status = "unavailable"
                self._message = "Posizione di sistema disabilitata: può usare servizi Internet"
                return
            self._status = "requesting"
            self._message = "In attesa di consenso del sistema e di una misura valida" if provider == "system" else "In attesa del ricevitore GNSS locale"
            self._task = asyncio.create_task(self._run(provider), name="location-provider")

    async def _stop_task(self) -> None:
        task, self._task = self._task, None
        if task is not None:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task

    async def stop(self) -> None:
        async with self._lock:
            await self._stop_task()
            self._fix = None
            self._provider_name = None
            self._status = "idle"
            self._message = "Posizione disattivata; misura rimossa dalla memoria"

    def _age(self) -> float | None:
        if self._fix is None:
            return None
        wall_age = self._clock() - self._fix.timestamp
        if wall_age < 0:
            return float("inf")  # clock rollback must never prolong a fix
        return max(wall_age, self._initial_age + max(0, self._monotonic() - self._received_mono))

    def _accept(self, fix: LocationFix) -> None:
        if not isinstance(fix, LocationFix):
            raise InvalidFix("Il provider non ha restituito una misura validata")
        age = self._clock() - fix.timestamp
        if age < 0:
            raise InvalidFix("Timestamp della misura nel futuro: controllare l'orologio")
        if age > self.ttl_s:
            raise InvalidFix("Misura del provider scaduta; richiesta una posizione recente")
        self._fix = fix
        self._initial_age = age
        self._received_mono = self._monotonic()
        self._status = "active"
        self._message = "Posizione recente ricevuta dal provider"

    async def _run(self, provider_name: str) -> None:
        provider: LocationProvider | None = None
        try:
            provider = self._factory(provider_name)
            # Consent needs time for a human response; stop remains cancellable.
            await asyncio.wait_for(provider.start(), max(60, self._request_timeout))
            while True:
                try:
                    fix = await asyncio.wait_for(provider.read_fix(), self._request_timeout)
                    self._accept(fix)
                except InvalidFix as exc:
                    self._fix = None
                    self._status, self._message = "unavailable", str(exc)
                except asyncio.TimeoutError:
                    self._status = "stale" if self._fix is not None else "unavailable"
                    self._message = "Nessuna nuova misura disponibile; attesa del provider"
                await asyncio.sleep(self._poll_interval if provider_name == "system" else 0.1)
        except asyncio.CancelledError:
            raise
        except (LocationUnavailable, ImportError, PermissionError, ConnectionError, OSError, asyncio.TimeoutError) as exc:
            self._fix = None
            self._status = "unavailable"
            self._message = f"Provider non disponibile: {exc or type(exc).__name__}"
        except Exception as exc:
            self._fix = None
            self._status = "error"
            self._message = f"Errore del provider: {type(exc).__name__}: {exc}"
        finally:
            if provider is not None:
                with suppress(Exception):
                    await asyncio.wait_for(provider.close(), 3)

    def origin(self) -> dict[str, Any] | None:
        age = self._age()
        if self._fix is None or age is None or age > self.ttl_s:
            return None
        return asdict(self._fix)

    def snapshot(self) -> dict[str, Any]:
        age = self._age()
        fix = self._fix
        status, message = self._status, self._message
        if fix is not None:
            if age is not None and age <= self.ttl_s:
                status = "active"
            else:
                status, message = "stale", "Misura scaduta: origine nascosta fino a un nuovo fix"
        return {"status": status, "provider": self._provider_name,
                "running": self._task is not None and not self._task.done(),
                "source": fix.source if fix else None,
                "position_source": fix.position_source if fix else None,
                "accuracy_m": fix.accuracy_m if fix else None,
                "accuracy_note": fix.accuracy_note if fix else None,
                "timestamp": fix.timestamp if fix else None,
                "age_s": round(age, 1) if age is not None and math.isfinite(age) else None,
                "max_age_s": self.ttl_s, "system_enabled": self.system_enabled,
                "message": message}
