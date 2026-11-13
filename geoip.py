"""Offline IP-country attribution and local IOC matching; no network requests."""
from __future__ import annotations

from functools import lru_cache
from datetime import datetime, timezone
import ipaddress
import json
import math
from pathlib import Path
import sqlite3
import threading
import time


def country_names(world_path: Path) -> dict[str, dict]:
    """Read country labels only; a country centroid is never a server location."""
    result = {}
    world = json.loads(Path(world_path).read_text(encoding="utf-8"))
    if not isinstance(world, dict) or not isinstance(world.get("features"), list):
        raise ValueError("GeoJSON non valido: features assente")
    for feature in world.get("features", []):
        if not isinstance(feature, dict):
            continue
        properties = feature.get("properties", {})
        if not isinstance(properties, dict):
            continue
        code = properties.get("ISO_A2_EH") or properties.get("ISO_A2")
        if code == "-99":
            code = properties.get("ISO_A2")
        if not isinstance(code, str) or len(code) != 2:
            continue
        result[code.upper()] = {"country_code": code.upper(),
                                "country": properties.get("NAME_EN") or properties.get("ADMIN") or code}
    return result


class GeoIPStore:
    """Read-only SQLite DB-IP range lookup; unknown/private addresses remain unknown."""

    def __init__(self, path: Path, world_path: Path):
        self.path = Path(path)
        self._lock = threading.RLock()
        self._connection: sqlite3.Connection | None = None
        self._countries = {}
        self._status = "Database IP offline non disponibile: eseguire setup_offline.py."
        self._source = "DB-IP Country Lite"
        self._release = ''
        self._loaded_at = time.time()
        try:
            self._countries = country_names(Path(world_path))
            uri = self.path.resolve().as_uri() + "?mode=ro"
            self._connection = sqlite3.connect(uri, uri=True, check_same_thread=False)
            self._connection.execute("PRAGMA query_only=ON")
            metadata = dict(self._connection.execute("SELECT key, value FROM metadata"))
            if metadata.get("schema") != "1":
                raise ValueError("Schema IP offline non supportato")
            self._release = metadata.get('release', '')
            self._source = "DB-IP Country Lite " + self._release
            self._status = (f"{self._source}; {metadata.get('rows', '?')} intervalli IPv4/IPv6. "
                            "Attribuzione del paese da database; posizione esatta non disponibile.")
        except (OSError, ValueError, sqlite3.Error) as exc:
            if self._connection is not None:
                self._connection.close()
                self._connection = None
            self._status = f"Geolocalizzazione offline non disponibile: {exc}"

    @lru_cache(maxsize=4096)
    def lookup(self, address: str) -> dict | None:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return None
        if not ip.is_global or ip.is_multicast or ip.is_reserved:
            return None
        with self._lock:
            if self._connection is None:
                return None
            row = self._connection.execute(
                "SELECT end, country FROM ranges WHERE version=? AND start<=? ORDER BY start DESC LIMIT 1",
                (ip.version, ip.packed),
            ).fetchone()
        if row is None or ip.packed > row[0]:
            return None
        country = self._countries.get(row[1], {'country_code': row[1], 'country': row[1]})
        return {**country, 'accuracy': 'country attribution only', 'source': self._source,
                'release': self._release, 'verification': 'database_attribution',
                'observed_at': self._loaded_at, 'observation_only': True,
                'exact_location_verified': False, 'current_country_verified': False,
                'note': 'Paese attribuito dal database della release indicata; non è una misura della '
                        'posizione del server e può essere obsoleto. Nessuna coordinata lat/lon disponibile.'}

    def status(self) -> str:
        return self._status

    def close(self) -> None:
        with self._lock:
            if self._connection is not None:
                self._connection.close()
                self._connection = None
            self.lookup.cache_clear()


class ThreatStore:
    """A match is an IOC-list hit, not proof that an attack took place."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.indicators: list[tuple[object, dict]] = []
        self.updated_at: str | None = None
        self._warning = ""
        self._snapshot_times: list[float] = []
        self._loaded_at = time.time()
        try:
            if self.path.stat().st_size > 2 * 1024 * 1024:
                raise ValueError("threats.json supera il limite di 2 MiB")
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(data, dict) or not isinstance(data.get("indicators"), list):
                raise ValueError("Serve un oggetto JSON con una lista indicators")
            if len(data["indicators"]) > 10000:
                raise ValueError("Troppi indicatori: limite 10000")
            self.updated_at = str(data.get("updated_at") or "")[:80]
            for source in data.get("spamhaus_sources", []):
                if not isinstance(source, dict) or not isinstance(source.get("metadata"), dict):
                    raise ValueError("Metadati snapshot Spamhaus non validi")
                timestamp = source["metadata"].get("timestamp")
                if not isinstance(timestamp, (int, float)) or not math.isfinite(timestamp) or timestamp <= 0:
                    raise ValueError("Data snapshot Spamhaus non valida")
                self._snapshot_times.append(float(timestamp))
            for item in data["indicators"]:
                if not isinstance(item, dict):
                    raise ValueError("Indicatore non valido")
                value = item.get("network", item.get("ip", ""))
                if not isinstance(value, str):
                    raise ValueError("L'indirizzo/CIDR deve essere una stringa")
                network = ipaddress.ip_network(value, strict=False)
                severity = item.get("severity", "medium")
                if severity not in ("low", "medium", "high", "critical"):
                    raise ValueError("Severità non valida")
                scope = item.get("scope", "real")
                if scope not in ("real", "demo", "all"):
                    raise ValueError("Scope IOC non valido")
                result = {"matched": True, "network": str(network), "severity": severity,
                          "label": str(item.get("label", "IOC locale"))[:200],
                          "source": str(item.get("source", "Elenco locale dell'utente"))[:400],
                          "source_date": str(item.get("source_date", ""))[:80],
                          "sblid": str(item.get("sblid", ""))[:80],
                          "category": str(item.get("category", "reputation match only"))[:100],
                          "scope": scope, 'verification': 'database_attribution',
                          'observed_at': self._loaded_at, 'observation_only': True,
                          'reputation_match_only': True, 'attack_verified': False,
                          'current_reputation_verified': False,
                          'note': 'Corrispondenza con una lista di reputazione locale; non prova un attacco '
                                  'né attività malevola della connessione osservata.'}
                self.indicators.append((network, result))
            self.indicators.sort(key=lambda pair: pair[0].prefixlen, reverse=True)
        except (OSError, ValueError, TypeError) as exc:
            self.indicators.clear()
            self._warning = f"Lista IOC non disponibile o non valida: {exc}"

    @property
    def warning(self) -> str:
        if self._warning:
            return self._warning
        if self._snapshot_times:
            age = (datetime.now(timezone.utc).timestamp() - min(self._snapshot_times)) / 86400
            if age > 2:
                return (f"Snapshot Spamhaus vecchio di {age:.1f} giorni; non è un feed live. "
                        "Aggiornare esplicitamente con setup_offline.py --refresh-threats.")
        return ""

    def lookup(self, address: str, mode: str = "real") -> dict | None:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return None
        for network, details in self.indicators:
            if details["scope"] not in (mode, "all"):
                continue
            if ip.version == network.version and ip in network:
                result = dict(details)
                source_date = details.get('source_date') or self.updated_at
                timestamp = None
                if source_date:
                    try:
                        stamp = datetime.fromisoformat(source_date.replace('Z', '+00:00'))
                        timestamp = stamp.replace(tzinfo=timezone.utc).timestamp() if stamp.tzinfo is None else stamp.timestamp()
                    except (ValueError, TypeError):
                        pass
                if timestamp is None and self._snapshot_times:
                    timestamp = min(self._snapshot_times)
                age_days = max(0, (time.time() - timestamp) / 86400) if timestamp is not None else None
                result.update(source_date=source_date or None, snapshot_age_days=age_days,
                              snapshot_stale=age_days > 2 if age_days is not None else None,
                              staleness_note='Snapshot offline; la data mancante non implica dati aggiornati. '
                                             'Una corrispondenza storica non conferma reputazione attuale.')
                return result
        return None

    def status(self) -> str:
        if self._warning:
            return self._warning
        snapshot = ""
        if self._snapshot_times:
            stamp = datetime.fromtimestamp(min(self._snapshot_times), timezone.utc).date().isoformat()
            snapshot = f" Snapshot Spamhaus {stamp}, consultato offline; non feed live."
        return f"{len(self.indicators)} IOC locali; un match non conferma un attacco.{snapshot} {self.warning}".strip()
