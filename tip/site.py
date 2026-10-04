"""Build the static dashboard, report-feed, KEV and attack-origin pages."""
from __future__ import annotations

import pathlib
from collections import Counter
from datetime import datetime, timedelta, timezone

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .reportfeed import CATEGORY_LABELS, CATEGORY_ORDER
from .normalize import attack_url, virustotal_url
from .scoring import technology_matches
from .vulnintel import summarize as summarize_kev

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


def _reports_view(doc: dict, org: dict | None = None) -> dict:
    """View-model for the report feed templates."""
    org = org or {"enabled": False, "terms": []}
    items = []
    counts = {category: 0 for category in CATEGORY_ORDER}
    for raw in doc.get("reports") or []:
        category = raw.get("category") if raw.get("category") in CATEGORY_ORDER else "general"
        item = dict(raw)
        item["category"] = category
        item["label"] = CATEGORY_LABELS[category]
        if org.get("enabled"):
            item["org_matches"] = technology_matches(
                org.get("terms"),
                item.get("title"),
                item.get("summary"),
                " ".join(item.get("tags") or []),
            )
        else:
            item["org_matches"] = []
        item["ioc_summary"] = _ioc_summary(item.get("iocs"))
        item["iocs"] = [
            {**ioc, "href": virustotal_url(str(ioc.get("type") or ""), str(ioc.get("value") or ""))}
            for ioc in (item.get("iocs") or [])
        ]
        item["technique_links"] = [
            {"id": tid, "url": attack_url(tid)} for tid in (item.get("techniques") or [])[:4]
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


def _kev_view(doc: dict, reports_doc: dict | None = None, org: dict | None = None) -> dict:
    org = org or {"enabled": False, "terms": []}
    summary = summarize_kev(doc)
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    reports_by_cve: dict[str, list] = {}
    for report in (reports_doc or {}).get("reports") or []:
        for cve in report.get("cves") or []:
            reports_by_cve.setdefault(str(cve).upper(), []).append(
                {"id": str(report.get("id") or ""), "title": str(report.get("title") or "")[:120]}
            )
    entries = []
    for raw in doc.get("entries") or []:
        if not isinstance(raw, dict):
            continue
        entry = dict(raw)
        entry["reports"] = reports_by_cve.get(str(entry.get("cve") or "").upper(), [])[:3]
        entry["overdue"] = bool(entry.get("due_date")) and str(entry.get("due_date")) < today
        if org.get("enabled"):
            entry["matched"] = technology_matches(
                org.get("terms"), entry.get("vendor"), entry.get("product"), entry.get("name")
            )
        else:
            entry["matched"] = []
        entries.append(entry)
    cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d")
    return {
        "entries": entries,
        "catalog_version": doc.get("catalog_version") or "",
        "catalog_count": summary["catalog_count"],
        "ransomware": summary["ransomware"],
        "overdue": summary["overdue"],
        "epss_high": summary["epss_high"],
        "matches": sum(1 for entry in entries if entry.get("matched")),
        "org": {"enabled": bool(org.get("enabled")), "name": org.get("name") or ""},
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


def _action_queue(
    context: dict,
    kev_view: dict | None,
    reports_view: dict | None,
    org: dict,
) -> list[dict]:
    """Rank what to look at first: vulns, then indicators, then reports."""
    queue: list[dict] = []

    vuln_items = []
    for entry in (kev_view or {}).get("entries") or []:
        if not entry.get("overdue"):
            continue
        ransomware = bool(entry.get("ransomware"))
        epss = entry.get("epss") or 0.0
        if not (ransomware or epss >= 0.5):
            continue
        bits = ["known exploited", "overdue"]
        if ransomware:
            bits.append("ransomware-linked")
        if epss >= 0.5:
            bits.append(f"EPSS {epss * 100:.0f}%")
        matched = entry.get("matched") or []
        if matched:
            bits.append("affects your stack")
        vuln_items.append(
            {
                "kind": "vulnerability",
                "level": "critical" if (ransomware or matched) else "high",
                "title": f"{entry.get('cve')} — {entry.get('vendor')} {entry.get('product')}".strip(" —"),
                "why": " · ".join(bits),
                "href": f"kev.html#{entry.get('cve')}",
                "external": f"https://nvd.nist.gov/vuln/detail/{entry.get('cve')}",
            }
        )
    vuln_items.sort(key=lambda item: 0 if item["level"] == "critical" else 1)
    queue.extend(vuln_items[:3])

    indicator_count = 0
    for row in context.get("ioc_index") or []:
        if indicator_count >= 3:
            break
        if not (row.get("m") or "," in (row.get("s") or "")):
            continue
        indicator_count += 1
        queue.append(
            {
                "kind": "indicator",
                "level": row.get("l") or "high",
                "title": row.get("v") or "",
                "why": " · ".join(part for part in (row.get("m"), row.get("s"), row.get("e")) if part),
                "href": "explorer.html",
                "external": virustotal_url(str(row.get("t") or ""), str(row.get("v") or "")),
            }
        )

    kev_cves = {str(entry.get("cve")) for entry in (kev_view or {}).get("entries") or []}
    for report in (reports_view or {}).get("entries") or []:
        cves = [str(cve) for cve in (report.get("cves") or []) if str(cve) in kev_cves]
        tags = [str(tag).lower() for tag in (report.get("tags") or [])]
        if not (cves or "ransomware" in tags or report.get("org_matches")):
            continue
        bits = []
        if cves:
            bits.append("references " + ", ".join(cves[:2]))
        if "ransomware" in tags:
            bits.append("ransomware-related")
        if report.get("org_matches"):
            bits.append("affects your stack")
        queue.append(
            {
                "kind": "report",
                "level": "high" if (cves or report.get("org_matches")) else "medium",
                "title": str(report.get("title") or "")[:120],
                "why": " · ".join(bits),
                "href": f"report-{report.get('id')}.html",
                "external": report.get("url"),
            }
        )
        break  # one representative report is enough

    return queue[:6]


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
    org = context.get("org") or {"enabled": False, "terms": []}
    kev_view = _kev_view(kev, reports, org) if kev else None
    reports_view = _reports_view(reports, org) if reports else None
    action_queue = _action_queue(context, kev_view, reports_view, org)

    index_html = env.get_template("index.html.j2").render(**context, action_queue=action_queue)
    report_html = env.get_template("report.html.j2").render(**context)
    (out_dir / "index.html").write_text(index_html, encoding="utf-8")
    (out_dir / "report.html").write_text(report_html, encoding="utf-8")
    written += [out_dir / "index.html", out_dir / "report.html"]

    if "ioc_index" in context:
        explorer_html = env.get_template("explorer.html.j2").render(**context)
        explorer_file = out_dir / "explorer.html"
        explorer_file.write_text(explorer_html, encoding="utf-8")
        written.append(explorer_file)

    kev_cves: set[str] = set()
    if kev_view:
        kev_cves = {str(entry.get("cve") or "") for entry in kev_view["entries"] if entry.get("cve")}
        kev_html = env.get_template("kev.html.j2").render(**context, kev=kev_view)
        kev_file = out_dir / "kev.html"
        kev_file.write_text(kev_html, encoding="utf-8")
        written.append(kev_file)

    if reports_view:
        view = reports_view
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

    browse = context.get("browse") or {}
    if browse:
        browse_template = env.get_template("browse.html.j2")
        for item in browse.get("types") or []:
            page = browse_template.render(
                **context,
                browse_heading=f"Indicators by type: {item['id']}",
                browse_subtitle=f"{item['total']} indicator(s) with type {item['id']}",
                browse_rows=item["rows"],
                browse_truncated=item["truncated"],
                browse_external=None,
            )
            path = out_dir / f"iocs-{item['id']}.html"
            path.write_text(page, encoding="utf-8")
            written.append(path)
        for item in browse.get("families") or []:
            page = browse_template.render(
                **context,
                browse_heading=f"Malware family: {item['name']}",
                browse_subtitle=f"{item['total']} indicator(s) attributed to {item['name']}",
                browse_rows=item["rows"],
                browse_truncated=item["truncated"],
                browse_external=None,
            )
            path = out_dir / f"family-{item['id']}.html"
            path.write_text(page, encoding="utf-8")
            written.append(path)
        for item in browse.get("techniques") or []:
            page = browse_template.render(
                **context,
                browse_heading=f"ATT&CK {item['id']}: {item['name']}",
                browse_subtitle=f"{item['total']} indicator(s) mapped to this technique (heuristic mapping)",
                browse_rows=item["rows"],
                browse_truncated=item["truncated"],
                browse_external=item.get("external"),
            )
            path = out_dir / f"technique-{item['id']}.html"
            path.write_text(page, encoding="utf-8")
            written.append(path)

    if geo:
        geo_view = _geo_view(geo)
        map_html = env.get_template("map.html.j2").render(**context, geo=geo_view)
        map_file = out_dir / "map.html"
        map_file.write_text(map_html, encoding="utf-8")
        written.append(map_file)

    return written
