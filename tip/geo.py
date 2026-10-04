"""Approximate geolocation of attack infrastructure for the map page.

Provider: the free ip-api.com batch endpoint, cached forever in
``data/geo.json`` (committed) so every IP is looked up at most once.

Geolocation is approximate: VPN, hosting and cloud infrastructure regularly
misrepresents the operator's real location. Treat the map as "possible
origins", not attribution.
"""
from __future__ import annotations

import json
import logging
import pathlib
import time
from datetime import datetime, timezone

from .normalize import refang
from .pipeline import make_session
from .reportfeed import load_reports
from .store import Store

log = logging.getLogger("tip.geo")

GEO_URL = "http://ip-api.com/batch"
_FIELDS = "status,message,country,countryCode,city,lat,lon,query"


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def geo_path(data_dir) -> pathlib.Path:
    return pathlib.Path(data_dir) / "geo.json"


def _chunks(items: list, size: int):
    for index in range(0, len(items), size):
        yield items[index : index + size]


def _load(path: pathlib.Path) -> dict:
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _candidate_ips(config: dict, data_dir: pathlib.Path) -> dict[str, set[str]]:
    """ip -> set(sources): high-signal infra from the DB plus report IPs."""
    cfg = config.get("geo") or {}
    include = [str(s) for s in (cfg.get("include_sources") or ["threatfox", "feodo"])]
    max_ips = int(cfg.get("max_ips", 400))
    candidates: dict[str, set[str]] = {}

    db_path = data_dir / "iocs.sqlite"
    if db_path.is_file() and include:
        with Store(db_path) as store:
            placeholders = ",".join("?" for _ in include)
            rows = store.conn.execute(
                "SELECT i.value AS value, s.source AS source"
                " FROM iocs i JOIN ioc_sources s ON s.key = i.key"
                f" WHERE i.type = 'ipv4' AND s.source IN ({placeholders})"
                " ORDER BY i.confidence DESC LIMIT ?",
                (*include, max_ips * 4),
            ).fetchall()
        for row in rows:
            candidates.setdefault(row["value"], set()).add(row["source"])

    for report in load_reports(data_dir).get("reports") or []:
        for ioc in report.get("iocs") or []:
            if ioc.get("type") != "ipv4":
                continue
            ip = refang(str(ioc.get("value") or ""))
            if ip:
                candidates.setdefault(ip, set()).add("report")

    def rank(item):
        _ip, sources = item
        return (0 if "report" in sources else 1, -len(sources))

    return dict(sorted(candidates.items(), key=rank)[:max_ips])


def build_geo(config: dict, data_dir) -> dict:
    cfg = config.get("geo") or {}
    stats: dict = {
        "enabled": bool(cfg.get("enabled", True)),
        "selected": 0,
        "looked_up": 0,
        "cached": 0,
        "known": 0,
        "errors": {},
    }
    if not stats["enabled"]:
        return stats

    data_dir = pathlib.Path(data_dir)
    doc = _load(geo_path(data_dir))
    ips: dict = doc.get("ips") or {}

    selected = _candidate_ips(config, data_dir)
    stats["selected"] = len(selected)
    missing = [ip for ip in selected if ip not in ips]
    stats["cached"] = len(selected) - len(missing)

    if missing:
        session = make_session()
        for chunk in _chunks(missing, 100):
            try:
                response = session.post(
                    GEO_URL,
                    params={"fields": _FIELDS},
                    json=[{"query": ip} for ip in chunk],
                    timeout=60,
                )
                response.raise_for_status()
                for item in response.json():
                    ip = str(item.get("query") or "")
                    if not ip:
                        continue
                    if item.get("status") == "success":
                        ips[ip] = {
                            "cc": str(item.get("countryCode") or "").lower(),
                            "country": item.get("country") or "",
                            "city": item.get("city") or "",
                            "lat": item.get("lat"),
                            "lon": item.get("lon"),
                        }
                    else:
                        ips[ip] = None  # never retry failures
                stats["looked_up"] += len(chunk)
                time.sleep(1.5)  # free tier: max 15 batch requests/minute
            except Exception as exc:  # noqa: BLE001
                stats["errors"]["provider"] = f"{type(exc).__name__}: {exc}"
                log.warning("geo lookup failed: %s", exc)
                break

    geo_doc = {
        "generated_at": _utcnow(),
        "provider": "ip-api.com",
        "sources": sorted({source for sources in selected.values() for source in sources}),
        "ips": ips,
    }
    geo_path(data_dir).write_text(json.dumps(geo_doc, indent=2, sort_keys=True), encoding="utf-8")

    stats["known"] = sum(1 for value in ips.values() if value)
    log.info(
        "geo: %d selected, %d looked up, %d cached, %d known",
        stats["selected"], stats["looked_up"], stats["cached"], stats["known"],
    )
    return stats


def load_geo(data_dir) -> dict:
    return _load(geo_path(data_dir))
