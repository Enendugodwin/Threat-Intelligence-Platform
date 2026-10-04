"""Vulnerability intelligence: CISA KEV catalog + FIRST EPSS scoring.

KEV is the authoritative "exploited in the wild" list; EPSS adds exploit
probability. Results are cached in ``data/kev.json`` (committed) so CI stays
inside free-tier limits and the page survives provider outages.
"""
from __future__ import annotations

import json
import logging
import pathlib
import time
from datetime import datetime, timezone

from .pipeline import make_session

log = logging.getLogger("tip.vulnintel")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def kev_path(data_dir) -> pathlib.Path:
    return pathlib.Path(data_dir) / "kev.json"


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


def fetch_kev(config: dict, data_dir) -> dict:
    cfg = config.get("vulnintel") or {}
    stats: dict = {"enabled": bool(cfg.get("enabled", True)), "total": 0, "epss_fetched": 0, "errors": {}}
    if not stats["enabled"]:
        return stats

    data_dir = pathlib.Path(data_dir)
    existing = _load(kev_path(data_dir))
    epss_cache: dict[str, dict] = {
        str(entry.get("cve", "")).upper(): {
            "epss": entry.get("epss"),
            "percentile": entry.get("epss_percentile"),
        }
        for entry in existing.get("entries", [])
        if entry.get("cve")
    }

    session = make_session()
    try:
        response = session.get(KEV_URL, timeout=120)
        response.raise_for_status()
        catalog = response.json()
    except Exception as exc:  # noqa: BLE001
        stats["errors"]["kev"] = f"{type(exc).__name__}: {exc}"
        log.warning("KEV fetch failed: %s", exc)
        return stats

    max_entries = int(cfg.get("max_entries", 200))
    entries: list[dict] = []
    for item in catalog.get("vulnerabilities") or []:
        if not isinstance(item, dict):
            continue
        entries.append(
            {
                "cve": str(item.get("cveID") or "").upper(),
                "vendor": item.get("vendorProject") or "",
                "product": item.get("product") or "",
                "name": (item.get("vulnerabilityName") or "")[:200],
                "date_added": item.get("dateAdded") or "",
                "due_date": item.get("dueDate") or "",
                "ransomware": str(item.get("knownRansomwareCampaignUse") or "").lower() == "known",
                "description": (item.get("shortDescription") or "")[:280],
                "required_action": (item.get("requiredAction") or "")[:200],
            }
        )
    entries.sort(key=lambda entry: entry.get("date_added") or "", reverse=True)
    entries = entries[:max_entries]

    missing = [
        entry["cve"]
        for entry in entries
        if entry["cve"] and not (epss_cache.get(entry["cve"]) or {}).get("epss")
    ]
    for chunk in _chunks(missing, 100):
        try:
            response = session.get(EPSS_URL, params={"cve": ",".join(chunk)}, timeout=60)
            response.raise_for_status()
            for item in response.json().get("data") or []:
                epss_cache[str(item.get("cve", "")).upper()] = {
                    "epss": float(item.get("epss") or 0.0),
                    "percentile": float(item.get("percentile") or 0.0),
                }
            stats["epss_fetched"] += len(chunk)
            time.sleep(1.0)
        except Exception as exc:  # noqa: BLE001
            stats["errors"]["epss"] = f"{type(exc).__name__}: {exc}"
            log.warning("EPSS fetch failed: %s", exc)
            break

    for entry in entries:
        cached = epss_cache.get(entry["cve"]) or {}
        entry["epss"] = cached.get("epss")
        entry["epss_percentile"] = cached.get("percentile")

    doc = {
        "generated_at": _utcnow(),
        "catalog_version": catalog.get("catalogVersion") or "",
        "catalog_count": int(catalog.get("count") or len(entries)),
        "entries": entries,
    }
    kev_path(data_dir).write_text(json.dumps(doc, indent=2), encoding="utf-8")

    stats["total"] = len(entries)
    stats["catalog_version"] = doc["catalog_version"]
    log.info(
        "KEV: %d tracked (catalog %s), %d EPSS lookups",
        len(entries), doc["catalog_version"], stats["epss_fetched"],
    )
    return stats


def load_kev(data_dir) -> dict:
    return _load(kev_path(data_dir))


def summarize(doc: dict, today: str | None = None) -> dict:
    """Priority counts for the KEV page cards and the dashboard."""
    today = today or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    entries = [entry for entry in (doc.get("entries") or []) if isinstance(entry, dict)]
    return {
        "total": len(entries),
        "catalog_count": int(doc.get("catalog_count") or len(entries)),
        "ransomware": sum(1 for entry in entries if entry.get("ransomware")),
        "overdue": sum(
            1
            for entry in entries
            if str(entry.get("due_date") or "") and str(entry.get("due_date")) < today
        ),
        "epss_high": sum(1 for entry in entries if (entry.get("epss") or 0.0) >= 0.5),
    }
