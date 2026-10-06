"""Build the report context and render Markdown reports."""
from __future__ import annotations

import json
import pathlib
from datetime import datetime, timezone

from jinja2 import Environment, FileSystemLoader

from .attack import AttackMap
from .normalize import attack_url, defang, slugify, virustotal_url
from .scoring import ioc_risk, org_profile
from .store import Store

_FEED_LABELS = {
    "urlhaus": "URLhaus",
    "feodo": "Feodo Tracker",
    "threatfox": "ThreatFox",
    "malwarebazaar": "MalwareBazaar",
    "openphish": "OpenPhish",
    "circl": "CIRCL MISP",
    "tor": "Tor Project",
    "otx": "AlienVault OTX",
}


def _sources(row) -> list[str]:
    try:
        return [s for s in str(row["sources"] or "").split(",") if s]
    except (IndexError, KeyError):
        return []


def _feed_health(config: dict, last_run: dict | None, previous_run: dict | None = None) -> dict:
    section = config.get("feeds") or {}
    enabled = [name for name, opts in section.items() if (opts or {}).get("enabled")]
    inactive = [
        _FEED_LABELS.get(name, name)
        for name, opts in section.items()
        if not (opts or {}).get("enabled")
    ]
    stats = (last_run or {}).get("stats") or {}
    previous_stats = (previous_run or {}).get("stats") or {}
    counts = stats.get("feeds") or {}
    previous_counts = previous_stats.get("feeds") or {}
    durations = stats.get("durations") or {}
    errors = stats.get("errors") or {}
    feeds = []
    for name in enabled:
        count = counts.get(name)
        previous = previous_counts.get(name)
        delta = None if (count is None or previous is None) else int(count) - int(previous)
        feeds.append(
            {
                "name": name,
                "label": _FEED_LABELS.get(name, name),
                "count": count,
                "delta": delta,
                "duration": durations.get(name),
                "error": errors.get(name, ""),
            }
        )
    ok = sum(1 for feed in feeds if not feed["error"])
    return {
        "total": len(feeds),
        "ok": ok,
        "feeds": feeds,
        "inactive": inactive,
        "last_run_at": (last_run or {}).get("finished_at") or "",
    }


def build_context(store: Store, config: dict, attack: AttackMap) -> dict:
    """Collect everything the report/site templates need."""
    report_cfg = config.get("report") or {}
    export_cfg = config.get("exports") or {}
    window_days = int(report_cfg.get("window_days", 7))
    top_n = int(report_cfg.get("top_n", 25))

    all_rows = store.all_rows()
    export_rows = store.rows_for_export(
        int(export_cfg.get("window_days", 30)),
        int(export_cfg.get("max_rows", 30000)),
        int(export_cfg.get("min_confidence", 0)),
        exclude_sources=[str(source) for source in (export_cfg.get("exclude_sources") or [])],
    )
    export_rows = [
        {
            "value": row["value"],
            "type": row["type"],
            "malware": row["malware"] or "",
            "sources": row["sources"] or "",
            "confidence": row["confidence"] or 0,
            "first_seen": row["first_seen"] or "",
            "last_seen": row["last_seen"] or "",
            "reference": row["reference"] or "",
        }
        for row in export_rows
    ]
    new_rows = store.new_since(window_days)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    recent_runs = store.runs(2)
    last_run = recent_runs[0] if recent_runs else None
    previous_run = recent_runs[1] if len(recent_runs) > 1 else None
    run_stats = (last_run or {}).get("stats") or {}
    activity = store.activity(window_days)
    org = org_profile(config)
    evidence_map = store.sources_map()
    sightings = store.sightings_map()

    def _evidence(key: str) -> list[dict]:
        return evidence_map.get(str(key), [])

    def _risk(row, sources: list[str]) -> dict:
        last_seen = row["last_seen"] or None
        if not last_seen:
            try:
                last_seen = row["seen_at"]
            except (IndexError, KeyError):
                last_seen = None
        return ioc_risk(
            confidence=row["confidence"] or 0,
            sources=len(sources),
            last_seen=last_seen,
            has_malware=bool(row["malware"]),
            ioc_type=row["type"],
        )

    new_by_type: dict[str, int] = {}
    new_by_family: dict[str, int] = {}
    for row in new_rows:
        new_by_type[row["type"]] = new_by_type.get(row["type"], 0) + 1
        if row["malware"]:
            family = str(row["malware"]).strip().lower()
            new_by_family[family] = new_by_family.get(family, 0) + 1

    by_type = [
        {"type": ioc_type, "total": count, "new": new_by_type.get(ioc_type, 0)}
        for ioc_type, count in store.counts_by_type()
    ]

    families = []
    used_slugs: set[str] = set()
    for name, total in store.top_malware(limit=20):
        slug = slugify(name)
        base_slug = slug
        counter = 2
        while slug in used_slugs:
            slug = f"{base_slug}-{counter}"
            counter += 1
        used_slugs.add(slug)
        families.append(
            {
                "name": name,
                "slug": slug,
                "total": total,
                "new": new_by_family.get(name.lower(), 0),
                "techniques": attack.family_techniques(name),
            }
        )

    coverage = [{"id": tid, **info} for tid, info in attack.coverage(all_rows).items()]

    notable = [
        {
            "value": defang(row["value"]),
            "href": virustotal_url(row["type"], row["value"]),
            "risk": _risk(row, _sources(row)),
            "evidence": _evidence(row["key"])[:4],
            "hits": sightings.get(str(row["key"])) or None,
            "type": row["type"],
            "malware": row["malware"] or "",
            "sources": _sources(row),
            "first_seen": row["first_seen"] or "",
            "confidence": row["confidence"],
        }
        for row in new_rows[:top_n]
    ]

    tor_rows = store.source_rows("tor")
    tor_exits = 0
    for row in tor_rows:
        try:
            tags = json.loads(row["tags"] or "[]")
        except (TypeError, ValueError):
            tags = []
        if "tor-exit" in tags:
            tor_exits += 1
    tor_new = sum(1 for row in new_rows if "tor" in str(row["sources"] or "").split(","))
    tor_sample_size = int(report_cfg.get("tor_sample", 20))
    tor = {
        "total": len(tor_rows),
        "exits": tor_exits,
        "relays": len(tor_rows) - tor_exits,
        "new": tor_new,
        "sample": [defang(row["value"]) for row in tor_rows[:tor_sample_size]],
        "source": "Tor Project Onionoo",
    }

    # drill-down pages: per-type / per-family / per-technique IOC lists
    browse_cap = 300
    type_rows: dict[str, list] = {}
    family_rows_by_name: dict[str, list] = {}
    technique_rows: dict[str, list] = {}
    family_name_set = {f["name"] for f in families}
    for row in all_rows:
        type_rows.setdefault(row["type"], []).append(row)
        if row["malware"] and str(row["malware"]) in family_name_set:
            family_rows_by_name.setdefault(str(row["malware"]), []).append(row)
        try:
            row_tags = json.loads(row["tags"] or "[]")
        except (TypeError, ValueError):
            row_tags = []
        for technique in attack.techniques_for(row["malware"], row_tags, row["type"]):
            technique_rows.setdefault(technique, []).append(row)

    def _browse_entry(row) -> dict:
        sources = _sources(row)
        return {
            "value": defang(row["value"]),
            "href": virustotal_url(row["type"], row["value"]),
            "risk": _risk(row, sources),
            "evidence": _evidence(row["key"])[:4],
            "hits": sightings.get(str(row["key"])) or None,
            "type": row["type"],
            "malware": row["malware"] or "",
            "sources": sources,
            "confidence": row["confidence"],
            "first_seen": row["first_seen"] or "",
        }

    def _browse_rows(rows: list) -> tuple[list, int]:
        ordered = sorted(rows, key=lambda r: (-(r["confidence"] or 0), str(r["value"])))
        return [_browse_entry(r) for r in ordered[:browse_cap]], len(rows)

    browse_types = []
    for type_id, total in store.counts_by_type():
        rows, count = _browse_rows(type_rows.get(type_id, []))
        browse_types.append(
            {"id": type_id, "total": count, "rows": rows, "truncated": count > browse_cap}
        )

    browse_families = []
    for family in families:
        rows, count = _browse_rows(family_rows_by_name.get(family["name"], []))
        browse_families.append(
            {
                "id": family["slug"],
                "name": family["name"],
                "total": count,
                "rows": rows,
                "truncated": count > browse_cap,
            }
        )

    browse_techniques = []
    for item in coverage:
        rows, count = _browse_rows(technique_rows.get(item["id"], []))
        browse_techniques.append(
            {
                "id": item["id"],
                "name": item["name"],
                "tactics": item["tactics"],
                "total": count,
                "rows": rows,
                "truncated": count > browse_cap,
                "external": attack_url(item["id"]),
            }
        )

    # IOC explorer index: risk-ranked rows for the client-side search page
    scored = []
    for row in all_rows:
        sources = _sources(row)
        risk = _risk(row, sources)
        scored.append((risk["score"], risk["level"], row, sources))
    scored.sort(key=lambda item: (-item[0], str(item[2]["value"])))
    explorer_cap = 10000
    ioc_index = [
        {
            "v": defang(row["value"]),
            "t": row["type"],
            "r": score,
            "l": level,
            "c": row["confidence"],
            "m": row["malware"] or "",
            "s": ", ".join(sources),
            "e": " · ".join(
                f"{ev['source']}:{ev['confidence']}" if ev["confidence"] else ev["source"]
                for ev in _evidence(row["key"])[:4]
            ),
            "h": int((sightings.get(str(row["key"])) or {}).get("count") or 0),
            "f": (row["first_seen"] or "")[:10],
        }
        for score, level, row, sources in scored[:explorer_cap]
    ]

    return {
        "generated_at": now,
        "generated_date": now[:10],
        "window_days": window_days,
        "repo_url": report_cfg.get("repo_url", ""),
        "totals": {
            "total": store.total(),
            "new": len(new_rows),
            "new_run": int(run_stats.get("new") or 0),
            "updated_run": int(run_stats.get("updated") or 0),
            "pruned_run": int(run_stats.get("pruned") or 0),
            "high_confidence": store.count_confidence(80),
            "families": len(families),
            "coverage": len(coverage),
            "activity_new": activity["new"],
            "activity_updated": activity["updated"],
            "activity_pruned": activity["pruned"],
            "activity_runs": activity["runs"],
        },
        "activity": activity,
        "org": org,
        "sightings": {
            "map": sightings,
            "iocs": len(sightings),
            "total": sum(entry["count"] for entry in sightings.values()),
            "sensors": sorted(
                {sensor for entry in sightings.values() for sensor in entry["sensors"]}
            ),
        },
        "feed_health": _feed_health(config, last_run, previous_run),
        "export_rows": export_rows,
        "by_type": by_type,
        "by_source": [{"source": s, "count": c} for s, c in store.counts_by_source()],
        "families": families,
        "coverage": coverage,
        "notable": notable,
        "tor": tor,
        "browse": {"types": browse_types, "families": browse_families, "techniques": browse_techniques},
        "ioc_index": ioc_index,
        "ioc_index_total": store.total(),
        "ioc_index_truncated": store.total() > explorer_cap,
        "explorer_types": [item["type"] for item in by_type],
        "last_run": last_run,
    }


def render_markdown(context: dict, templates_dir: str | pathlib.Path) -> str:
    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        trim_blocks=True,
        lstrip_blocks=True,
        autoescape=False,
        keep_trailing_newline=True,
    )
    return env.get_template("report.md.j2").render(**context)


def write_report(
    context: dict, out_dir: str | pathlib.Path, templates_dir: str | pathlib.Path
) -> list[pathlib.Path]:
    out_dir = pathlib.Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    text = render_markdown(context, templates_dir)
    dated = out_dir / f"{context['generated_date']}.md"
    latest = out_dir / "latest.md"
    dated.write_text(text, encoding="utf-8")
    latest.write_text(text, encoding="utf-8")
    return [dated, latest]
