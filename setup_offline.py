"""One-time verified downloads and offline country database construction.

The runtime never imports this module for downloads. Use --verify with no Internet.
Pinned URLs and SHA-256 values are recorded in asset_manifest.json.
"""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import gzip
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import sqlite3
import sys
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parent
DROP_URLS = {4: "https://www.spamhaus.org/drop/drop_v4.json",
             6: "https://www.spamhaus.org/drop/drop_v6.json"}
DROP_MANAGED_SOURCE = "spamhaus-drop"


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def asset_path(root: Path, value: str) -> Path:
    path = (root / value).resolve()
    if not path.is_relative_to(root.resolve()):
        raise ValueError("Percorso asset esterno alla cartella del progetto")
    return path


def validate_content(data: bytes, kind: str) -> None:
    if not data or data.lstrip().lower().startswith((b"<!doctype", b"<html")):
        raise ValueError("Download vuoto o pagina HTML al posto dell'asset")
    if kind == "gzip" and not data.startswith(b"\x1f\x8b"):
        raise ValueError("Il database scaricato non è gzip")
    if kind == "geojson":
        content = json.loads(data)
        if content.get("type") != "FeatureCollection" or len(content.get("features", [])) < 100:
            raise ValueError("GeoJSON geografico non valido")


def install_asset(spec: dict, root: Path = ROOT, verify_only: bool = False) -> bool:
    path = asset_path(root, spec["path"])
    if path.is_file() and digest(path) == spec["sha256"]:
        print(f"OK {spec['path']}")
        return False
    if verify_only:
        raise ValueError(f"Asset mancante o modificato: {spec['path']}")
    if urllib.parse.urlparse(spec["url"]).scheme != "https":
        raise ValueError("Sono ammessi solo download HTTPS")
    request = urllib.request.Request(spec["url"], headers={"User-Agent": "WiFi-Sense-Offline-Setup/1.0"})
    with urllib.request.urlopen(request, timeout=60) as response:
        if urllib.parse.urlparse(response.geturl()).scheme != "https":
            raise ValueError("Redirect non HTTPS rifiutato")
        data = response.read(80 * 1024 * 1024 + 1)
    if len(data) > 80 * 1024 * 1024:
        raise ValueError("Asset oltre il limite di 80 MiB")
    if hashlib.sha256(data).hexdigest() != spec["source_sha256"]:
        raise ValueError(f"SHA-256 sorgente inatteso: {spec['path']}; download non installato")
    validate_content(data, spec["kind"])
    if spec["kind"] == "orbit-local-import":
        data = data.replace(b"from 'three'", b"from './three.min.js'")
    if hashlib.sha256(data).hexdigest() != spec["sha256"]:
        raise ValueError(f"SHA-256 finale inatteso: {spec['path']}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".download")
    try:
        temporary.write_bytes(data)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    print(f"INSTALLATO {spec['path']}")
    return True


def database_valid(path: Path, source_sha256: str) -> bool:
    if not path.is_file():
        return False
    try:
        with sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True) as connection:
            metadata = dict(connection.execute("SELECT key, value FROM metadata"))
            return (metadata.get("schema") == "1" and metadata.get("source_sha256") == source_sha256
                    and int(metadata.get("rows", "0")) > 100000
                    and connection.execute("PRAGMA quick_check").fetchone()[0] == "ok")
    except (sqlite3.Error, ValueError):
        return False


def build_database(source: Path, destination: Path, release: str, source_sha256: str) -> int:
    """Compact indexed binary ranges support both IPv4 and IPv6 without floats."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".building")
    temporary.unlink(missing_ok=True)
    connection = sqlite3.connect(temporary)
    count = 0
    try:
        connection.execute("PRAGMA journal_mode=OFF")
        connection.execute("PRAGMA synchronous=OFF")
        connection.execute("CREATE TABLE ranges (version INTEGER NOT NULL, start BLOB NOT NULL, end BLOB NOT NULL, country TEXT NOT NULL, PRIMARY KEY(version,start)) WITHOUT ROWID")
        connection.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID")
        batch = []
        with gzip.open(source, "rt", encoding="utf-8", newline="") as stream:
            for row in csv.reader(stream):
                if len(row) != 3:
                    raise ValueError("Riga DB-IP inattesa")
                first, last = ipaddress.ip_address(row[0]), ipaddress.ip_address(row[1])
                country = row[2].upper()
                if first.version != last.version or int(first) > int(last) or len(country) != 2:
                    raise ValueError("Intervallo DB-IP non valido")
                batch.append((first.version, first.packed, last.packed, country))
                if len(batch) >= 10000:
                    connection.executemany("INSERT INTO ranges VALUES(?,?,?,?)", batch)
                    count += len(batch)
                    batch.clear()
            if batch:
                connection.executemany("INSERT INTO ranges VALUES(?,?,?,?)", batch)
                count += len(batch)
        metadata = {"schema": "1", "release": release, "source_sha256": source_sha256,
                    "source": "DB-IP Country Lite", "license": "CC BY 4.0", "rows": str(count)}
        connection.executemany("INSERT INTO metadata VALUES(?,?)", metadata.items())
        connection.commit()
        connection.execute("VACUUM")
        if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ValueError("Verifica integrità SQLite fallita")
        connection.close()
        os.replace(temporary, destination)
        return count
    finally:
        connection.close()
        temporary.unlink(missing_ok=True)


def parse_drop_feed(content: bytes, version: int, source_url: str) -> tuple[list[dict], dict]:
    """Validate newline-delimited official DROP JSON and retain source metadata."""
    if len(content) > 2 * 1024 * 1024:
        raise ValueError("Feed DROP oltre il limite di 2 MiB")
    records, metadata = [], None
    for line in content.decode("utf-8-sig").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if not isinstance(row, dict):
            raise ValueError("Record DROP non valido")
        if row.get("type") == "metadata":
            if metadata is not None:
                raise ValueError("Metadati DROP duplicati")
            metadata = row
            continue
        if metadata is not None:
            raise ValueError("I metadati DROP devono essere l'ultimo record")
        if not isinstance(row.get("cidr"), str) or not row.get("sblid"):
            raise ValueError("Record DROP senza CIDR o identificativo SBL")
        network = ipaddress.ip_network(row["cidr"], strict=True)
        if network.version != version:
            raise ValueError("Versione IP inattesa nel feed DROP")
        records.append((str(network), str(row["sblid"])[:80]))
        if len(records) > 10000:
            raise ValueError("Feed DROP con troppi indicatori")
    if not records or metadata is None or not isinstance(metadata.get("copyright"), str):
        raise ValueError("Feed DROP incompleto o senza attribuzione originale")
    timestamp = metadata.get("timestamp")
    if not isinstance(timestamp, (int, float)) or timestamp <= 0:
        raise ValueError("Timestamp DROP non valido")
    updated = datetime.fromtimestamp(timestamp, timezone.utc).isoformat()
    indicators = [{"network": network, "label": f"Spamhaus DROP · {sblid}", "severity": "high",
                   "source": "The Spamhaus Project · DROP", "source_date": updated,
                   "source_url": source_url, "sblid": sblid, "category": "reputation match only",
                   "managed_source": DROP_MANAGED_SOURCE, "scope": "real"}
                  for network, sblid in records]
    return indicators, {"url": source_url, "metadata": metadata,
                        "sha256": hashlib.sha256(content).hexdigest(), "records": len(indicators)}


def refresh_threats(path: Path = ROOT / "data" / "threats.json", downloader=None,
                    now: datetime | None = None) -> int:
    """Explicit setup-only refresh; preserve entries not managed by this feed."""
    now = now or datetime.now(timezone.utc)
    previous = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {"indicators": []}
    if not isinstance(previous, dict) or not isinstance(previous.get("indicators"), list):
        raise ValueError("threats.json non valido: correggerlo prima di aggiornare")
    last_refresh = previous.get("spamhaus_fetched_at")
    if last_refresh:
        try:
            elapsed = (now - datetime.fromisoformat(last_refresh)).total_seconds()
        except (TypeError, ValueError):
            raise ValueError("Data ultimo aggiornamento Spamhaus non valida")
        if elapsed < 3600:
            print("DROP già aggiornato nell'ultima ora: nessun download, per rispettare il fair use.")
            return 0

    def download(url):
        request = urllib.request.Request(url, headers={"User-Agent": "WiFi-Sense-Offline-Setup/1.0"})
        with urllib.request.urlopen(request, timeout=40) as response:
            if urllib.parse.urlparse(response.geturl()).scheme != "https":
                raise ValueError("Redirect DROP non HTTPS rifiutato")
            return response.read(2 * 1024 * 1024 + 1)

    retrieve = downloader or download
    incoming, sources = [], []
    for version, url in DROP_URLS.items():
        records, metadata = parse_drop_feed(retrieve(url), version, url)
        incoming.extend(records)
        sources.append(metadata)
    custom = [record for record in previous["indicators"]
              if not isinstance(record, dict) or record.get("managed_source") != DROP_MANAGED_SOURCE]
    combined = custom + incoming
    if len(combined) > 10000:
        raise ValueError("La lista combinata supera 10000 IOC; file precedente conservato")
    result = {**previous, "updated_at": now.isoformat(), "spamhaus_fetched_at": now.isoformat(),
              "description": "Snapshot locale Spamhaus DROP e IOC dell'utente. Nessun aggiornamento durante l'esecuzione. Un match reputazionale non dimostra un attacco.",
              "spamhaus_sources": sources, "indicators": combined}
    data = (json.dumps(result, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    if len(data) > 2 * 1024 * 1024:
        raise ValueError("La lista combinata supera 2 MiB; file precedente conservato")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".refresh")
    try:
        temporary.write_bytes(data)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    return len(incoming)


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepara asset e database per l'esecuzione offline.")
    parser.add_argument("--verify", action="store_true", help="Controlla asset e database senza connessioni di rete")
    parser.add_argument("--refresh-threats", action="store_true", help="Scarica esplicitamente gli snapshot Spamhaus DROP IPv4/IPv6; preserva gli IOC personali")
    args = parser.parse_args()
    if args.verify and args.refresh_threats:
        parser.error("--verify è offline e non può essere combinato con --refresh-threats")
    try:
        manifest = json.loads((ROOT / "asset_manifest.json").read_text(encoding="utf-8"))
        for spec in manifest["assets"]:
            install_asset(spec, verify_only=args.verify)
        database_spec = next(item for item in manifest["assets"] if item["kind"] == "gzip")
        database = ROOT / "data" / "ipgeo.sqlite"
        if not database_valid(database, database_spec["sha256"]):
            if args.verify:
                raise ValueError("Database SQLite mancante o incoerente: eseguire setup_offline.py")
            count = build_database(asset_path(ROOT, database_spec["path"]), database,
                                   manifest["geo_release"], database_spec["sha256"])
            print(f"DATABASE {count} intervalli IPv4/IPv6")
        if args.refresh_threats:
            count = refresh_threats()
            print(f"IOC: {count} indicatori Spamhaus importati; snapshot locale, non feed live.")
        print("ASSET LOCALI PRONTI. La posizione di sistema può richiedere Internet.")
    except (OSError, ValueError, KeyError, StopIteration, sqlite3.Error) as exc:
        print(f"Preparazione offline fallita: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
