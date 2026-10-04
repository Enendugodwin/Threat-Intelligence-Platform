"""Build the static dashboard, report-feed, KEV and attack-origin pages."""
from __future__ import annotations

import pathlib
from collections import Counter
from datetime import datetime, timedelta, timezone

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .reportfeed import CATEGORY_LABELS, CATEGORY_ORDER

_TYPE_LABELS = {
    "sha256": "hash",
    "sha1": "hash",
    "md5": "hash",
    "url": "URL",
    "domain": "domain",
    "ipv4": "IP",
    "ipv6": "IP",
    "email": "email",
}
_PLURALS = {"hash": "hashes", "domain": "domains", "IP": "IPs", "URL": "URLs", "email": "emails"}


def _ioc_summary(iocs) -> str:
    counts = Counter(_TYPE_LABELS.get(i.get("type"), str(i.get("type"))) for i in (iocs or []))
    parts = []
    for label, count in counts.most_common():
        word = label if count == 1 else _PLURALS.get(label, label + "s")
        parts.append(f"{count} {word}")
    return " · ".join(parts)


def _attack_url(technique_id: str) -> str:
    base, _, sub = technique_id.partition(".")
    return f"https://attack.mitre.org/techniques/{base}/" + (f"{sub}/" if sub else "")


def _reports_view(doc: dict) -> dict:
    """View-model for the report feed templates."""
    items = []
    counts = {category: 0 for category in CATEGORY_ORDER}
    for raw in doc.get("reports") or []:
        category = raw.get("category") if raw.get("category") in CATEGORY_ORDER else "general"
        item = dict(raw)
        item["category"] = category
        item["label"] = CATEGORY_LABELS[category]
        item["ioc_summary"] = _ioc_summary(item.get("iocs"))
        item["technique_links"] = [
            {"id": tid, "url": _attack_url(tid)} for tid in (item.get("techniques") or [])[:4]
        ]
        items.append(item)
        counts[category] = counts.get(category, 0) + 1
    categories = [
        {"id": category, "label": CATEGORY_LABELS[category], "count": counts.get(category, 0)}
        for category in CATEGORY_ORDER
    ]
    return {
        "entries": items,
        "total": len(items),
        "categories": categories,
        "generated_at": doc.get("generated_at", ""),
    }


def _kev_view(doc: dict) -> dict:
    entries = [entry for entry in (doc.get("entries") or []) if isinstance(entry, dict)]
    cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d")
    return {
        "entries": entries,
        "catalog_version": doc.get("catalog_version") or "",
        "catalog_count": int(doc.get("catalog_count") or len(entries)),
        "ransomware": sum(1 for entry in entries if entry.get("ransomware")),
        "recent": sum(1 for entry in entries if str(entry.get("date_added") or "") >= cutoff),
        "generated_at": doc.get("generated_at") or "",
    }


def _geo_view(doc: dict) -> dict:
    buckets: dict[str, dict] = {}
    for ip, meta in (doc.get("ips") or {}).items():
        if not meta:
            continue
        cc = str(meta.get("cc") or "??").lower()
        bucket = buckets.setdefault(
            cc, {"cc": cc, "country": meta.get("country") or cc.upper(), "ips": [], "lat": 0.0, "lon": 0.0}
        )
        bucket["ips"].append(ip)
        bucket["lat"] += float(meta.get("lat") or 0.0)
        bucket["lon"] += float(meta.get("lon") or 0.0)
    points = []
    for bucket in buckets.values():
        count = len(bucket["ips"])
        points.append(
            {
                "cc": bucket["cc"],
                "country": bucket["country"],
                "count": count,
                "lat": round(bucket["lat"] / count, 3),
                "lon": round(bucket["lon"] / count, 3),
                "ips": sorted(bucket["ips"])[:8],
            }
        )
    points.sort(key=lambda point: -point["count"])
    return {
        "points": points,
        "countries": len(points),
        "ips_total": sum(point["count"] for point in points),
        "generated_at": doc.get("generated_at") or "",
        "sources": doc.get("sources") or [],
        "provider": doc.get("provider") or "ip-api.com",
    }


def build_site(
    context: dict,
    out_dir: str | pathlib.Path,
    templates_dir: str | pathlib.Path,
    reports: dict | None = None,
    kev: dict | None = None,
    geo: dict | None = None,
) -> list[pathlib.Path]:
    out_dir = pathlib.Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        trim_blocks=True,
        lstrip_blocks=True,
        autoescape=select_autoescape(enabled_extensions=("html", "htm", "xml", "j2")),
        keep_trailing_newline=True,
    )

    written: list[pathlib.Path] = []
    index_html = env.get_template("index.html.j2").render(**context)
    report_html = env.get_template("report.html.j2").render(**context)
    (out_dir / "index.html").write_text(index_html, encoding="utf-8")
    (out_dir / "report.html").write_text(report_html, encoding="utf-8")
    written += [out_dir / "index.html", out_dir / "report.html"]

    kev_cves: set[str] = set()
    if kev:
        kev_view = _kev_view(kev)
        kev_cves = {str(entry.get("cve") or "") for entry in kev_view["entries"] if entry.get("cve")}
        kev_html = env.get_template("kev.html.j2").render(**context, kev=kev_view)
        kev_file = out_dir / "kev.html"
        kev_file.write_text(kev_html, encoding="utf-8")
        written.append(kev_file)

    if reports:
        view = _reports_view(reports)
        feed_html = env.get_template("reports.html.j2").render(**context, reports=view)
        feed_path = out_dir / "reports.html"
        feed_path.write_text(feed_html, encoding="utf-8")
        written.append(feed_path)

        detail_template = env.get_template("report_detail.html.j2")
        for item in view["entries"]:
            page = detail_template.render(**context, report=item, reports=view, kev_cves=kev_cves)
            detail_path = out_dir / f"report-{item['id']}.html"
            detail_path.write_text(page, encoding="utf-8")
            written.append(detail_path)

    if geo:
        geo_view = _geo_view(geo)
        map_html = env.get_template("map.html.j2").render(**context, geo=geo_view)
        map_file = out_dir / "map.html"
        map_file.write_text(map_html, encoding="utf-8")
        written.append(map_file)

    return written
