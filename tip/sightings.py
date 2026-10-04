"""Internal sighting telemetry: import sensor hits and match them to tracked IOCs.

A SOC's most important question is "did we see this IOC?" - this module ingests
sightings from internal sensors (firewall, DNS, proxy, EDR, SIEM) as CSV or
JSON and stores them against the tracked IOC keys.

Accepted CSV columns (header required): value, type, sensor, asset,
first_seen, last_seen, count, note. JSON accepts the same keys per object.

Usage: ``python -m tip sightings <file.csv>`` then re-render with
``python -m tip site``; sightings surface in the explorer, drill-down pages and
the action queue, and become STIX Sighting objects in the exports.
"""
from __future__ import annotations

import csv
import io
import json
import logging
import pathlib

from .normalize import detect_type, refang
from .store import Store

log = logging.getLogger("tip.sightings")


def parse_records(path: str | pathlib.Path) -> list[dict]:
    path = pathlib.Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"sightings file not found: {path}")
    text = path.read_text(encoding="utf-8", errors="replace")
    if not text.strip():
        return []
    if text.lstrip().startswith("["):
        data = json.loads(text)
        return [item for item in data if isinstance(item, dict)]
    reader = csv.DictReader(io.StringIO(text))
    return [
        {(key or "").strip().lower(): (value or "").strip() for key, value in row.items()}
        for row in reader
    ]


def normalize_records(records: list[dict]) -> tuple[list[dict], int]:
    out: list[dict] = []
    skipped = 0
    for record in records:
        value = str(record.get("value") or record.get("ioc") or "").strip()
        real = refang(value)
        kind = str(record.get("type") or "").strip() or detect_type(real)
        if not real or not kind:
            skipped += 1
            continue
        out.append(
            {
                "key": f"{kind}:{real.lower()}",
                "sensor": str(record.get("sensor") or "unknown").strip() or "unknown",
                "asset": str(record.get("asset") or "").strip(),
                "first_seen": str(record.get("first_seen") or "").strip() or None,
                "last_seen": str(record.get("last_seen") or "").strip() or None,
                "count": int(record.get("count") or 1),
                "note": str(record.get("note") or "").strip() or None,
            }
        )
    return out, skipped


def import_sightings(data_dir, path: str | pathlib.Path) -> dict:
    normalized, skipped = normalize_records(parse_records(path))
    with Store(pathlib.Path(data_dir) / "iocs.sqlite") as store:
        stored = store.upsert_sightings(normalized)
    log.info("sightings: %d stored, %d skipped", stored, skipped)
    return {"records": stored, "skipped": skipped}


def sights_summary(data_dir) -> dict:
    with Store(pathlib.Path(data_dir) / "iocs.sqlite") as store:
        sightings = store.sightings_map()
    total = sum(entry["count"] for entry in sightings.values())
    sensors = sorted({sensor for entry in sightings.values() for sensor in entry["sensors"]})
    return {
        "indicators_with_sightings": len(sightings),
        "total_sightings": total,
        "sensors": sensors,
    }
