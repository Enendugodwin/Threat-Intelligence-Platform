"""Build the static dashboard, report-feed, KEV and attack-origin pages."""
from __future__ import annotations

import pathlib
import re
from collections import Counter
from datetime import datetime, timedelta, timezone

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .exports import csv_export, json_export
from .normalize import attack_url, refang, slugify, virustotal_url
from .reportfeed import CATEGORY_LABELS, CATEGORY_ORDER
from .scoring import technology_matches
from .vulnintel import summarize as summarize_kev

_ACTOR_TAG_RE = re.compile(
    r"^(?:APT\d{1,2}|UNC\d{3,6}|UAT-\d{4,5}|Storm-\d{4,5}|FIN\d{1,2}|TA\d{2,4}|G\d{4}"
    r"|Operation\s+.+)$",
    re.IGNORECASE,
)

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


def _threats_view(reports_view: dict | None, families) -> dict:
    """Aggregate actor tags from reports into actor pages (actor -> families, TTPs)."""
    family_slug = {family["name"]: family["slug"] for family in (families or [])}
    actors: dict[str, dict] = {}
    for report in (reports_view or {}).get("entries") or []:
        tags = [str(tag) for tag in report.get("tags") or []]
        actor_tags = [tag for tag in tags if _ACTOR_TAG_RE.match(tag)]
        if not actor_tags:
            continue
        families_seen = [
            {"name": tag, "slug": family_slug.get(tag, slugify(tag))}
            for tag in tags
            if tag in family_slug
        ]
        for actor in actor_tags:
            entry = actors.setdefault(
                actor,
                {
                    "name": actor,
                    "slug": slugify(actor),
                    "reports": [],
                    "techniques": set(),
                    "families": {},
                    "cves": set(),
                },
            )
            entry["reports"].append(report)
            entry["techniques"].update(report.get("techniques") or [])
            for family in families_seen:
                entry["families"][family["name"]] = family
            entry["cves"].update(report.get("cves") or [])
    items = []
    for entry in actors.values():
        items.append(
            {
                "name": entry["name"],
                "slug": entry["slug"],
                "reports_count": len(entry["reports"]),
                "latest": max(
                    (str(report.get("published") or "") for report in entry["reports"]),
                    default="",
                )[:10],
                "families": sorted(entry["families"].values(), key=lambda fam: fam["name"]),
                "techniques": sorted(entry["techniques"])[:10],
                "cves": sorted(entry["cves"])[:10],
                "reports": entry["reports"][:10],
            }
        )
    items.sort(key=lambda actor: (-actor["reports_count"], actor["name"]))
    return {"actors": items, "total": len(items)}


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
    pool = list(context.get("ioc_index") or [])
    pool.sort(key=lambda row: (0 if row.get("h") else 1, -int(row.get("r") or 0)))
    for row in pool:
        if indicator_count >= 3:
            break
        if not (row.get("m") or "," in (row.get("s") or "") or row.get("h")):
            continue
        indicator_count += 1
        hits = int(row.get("h") or 0)
        why_parts = [part for part in (row.get("m"), row.get("s"), row.get("e")) if part]
        if hits:
            why_parts.insert(0, f"{hits} internal sighting(s)")
        queue.append(
            {
                "kind": "indicator",
                "level": "critical" if hits else (row.get("l") or "high"),
                "title": row.get("v") or "",
                "why": " · ".join(why_parts),
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

    kev_cve_set = {str(entry.get("cve")) for entry in (kev_view or {}).get("entries") or []}
    reports_entries = (reports_view or {}).get("entries") or []
    if reports_view:
        sighting_map = (context.get("sightings") or {}).get("map") or {}
        for entry in reports_entries:
            cves = [str(cve) for cve in entry.get("cves") or []]
            kev_hits = [cve for cve in cves if cve in kev_cve_set]
            tags_lower = [str(tag).lower() for tag in entry.get("tags") or []]
            if entry.get("org_matches"):
                level = "critical"
            elif kev_hits or "ransomware" in tags_lower:
                level = "high"
            elif entry.get("iocs"):
                level = "medium"
            else:
                level = "info"
            entry["risk"] = {"level": level}
            entry["kev_hits"] = kev_hits
            entry["hits_total"] = sum(
                int(
                    (
                        sighting_map.get(f"{ioc.get('type')}:{refang(str(ioc.get('value') or '')).lower()}")
                        or {}
                    ).get("count")
                    or 0
                )
                for ioc in entry.get("iocs") or []
            )

    index_html = env.get_template("index.html.j2").render(**context, action_queue=action_queue)
    report_html = env.get_template("report.html.j2").render(**context)
    (out_dir / "index.html").write_text(index_html, encoding="utf-8")
    (out_dir / "report.html").write_text(report_html, encoding="utf-8")
    written += [out_dir / "index.html", out_dir / "report.html"]

    if "export_rows" in context:
        csv_path = csv_export.write_csv(context["export_rows"], out_dir / "iocs.csv")
        json_path = json_export.write_json(
            context["export_rows"], out_dir / "iocs.json", context.get("generated_at")
        )
        written += [json_path, csv_path]

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

    if reports_view:
        # family -> related reports (from tags/titles) for cross-linking
        fam_map: dict[str, list] = {}
        for entry in reports_entries:
            tags_lower = [str(tag).lower() for tag in entry.get("tags") or []]
            title_lower = str(entry.get("title") or "").lower()
            for family in context.get("families") or []:
                name_lower = family["name"].lower()
                if name_lower in tags_lower or name_lower in title_lower:
                    fam_map.setdefault(family["slug"], []).append(
                        {
                            "id": entry["id"],
                            "title": str(entry.get("title") or "")[:90],
                            "published": str(entry.get("published") or "")[:10],
                        }
                    )
        for family in (context.get("browse") or {}).get("families") or []:
            family["related_reports"] = fam_map.get(family["id"], [])[:6]

        threats_view = _threats_view(reports_view, context.get("families"))
        threats_html = env.get_template("threats.html.j2").render(**context, threats=threats_view)
        threats_file = out_dir / "threats.html"
        threats_file.write_text(threats_html, encoding="utf-8")
        written.append(threats_file)
        actor_template = env.get_template("actor.html.j2")
        for actor in threats_view["actors"]:
            page = actor_template.render(**context, actor=actor, kev_cves=kev_cve_set)
            actor_path = out_dir / f"actor-{actor['slug']}.html"
            actor_path.write_text(page, encoding="utf-8")
            written.append(actor_path)

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
                browse_related=[],
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
                browse_related=item.get("related_reports") or [],
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
                browse_related=[],
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
