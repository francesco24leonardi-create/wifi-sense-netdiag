"""Immutable records shared by acquisition workers and the application service."""
from dataclasses import dataclass, field
from ipaddress import IPv4Network


@dataclass(frozen=True)
class NetworkInfo:
    interface: str
    address: str
    netmask: str
    gateway: str
    mac: str = ""
    interface_id: str = ""

    @property
    def network(self) -> IPv4Network:
        return IPv4Network(f"{self.address}/{self.netmask}", strict=False)


@dataclass(frozen=True)
class Device:
    ip: str
    mac: str
    vendor: str
    ports: tuple[int, ...] = ()
    role: str = "Dispositivo LAN"


@dataclass(frozen=True)
class AccessPoint:
    ssid: str
    bssid: str
    channel: int
    band: str
    rssi_dbm: float | None
    security: str = ""


@dataclass(frozen=True)
class ScanResult:
    devices: tuple[Device, ...] = ()
    access_points: tuple[AccessPoint, ...] = ()
    warnings: tuple[str, ...] = ()
    channel_summary: str = ""
    partial: bool = False


@dataclass(frozen=True)
class SensingSnapshot:
    timestamp: float
    rssi_dbm: float | None
    rtt_ms: float | None
    filtered: float | None
    variance: float | None
    threshold: float | None
    intensity: float | None
    rf_perturbation: bool | None
    state: str
    calibration_progress: float
    sample_hz: float | None
    loss_percent: float | None
    jitter_ms: float | None
    source: str
    warning: str = ""


@dataclass(frozen=True)
class WorkerMessage:
    kind: str
    payload: object = field(default=None)
