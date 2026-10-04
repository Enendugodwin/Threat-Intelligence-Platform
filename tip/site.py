"""Build the static dashboard and report-feed pages published to GitHub Pages."""
from __future__ import annotations

import pathlib

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .reportfeed import CATEGORY_LABELS, CATEGORY_ORDER


def _reports_view(doc: dict) -> dict:
    """View-model for the report feed templates."""
    items = []
    counts = {category: 0 for category in CATEGORY_ORDER}
    for raw in doc.get("reports") or []:
        category = raw.get("category") if raw.get("category") in CATEGORY_ORDER else "general"
        item = dict(raw)
        item["category"] = category
        item["label"] = CATEGORY_LABELS[category]
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


def build_site(
    context: dict,
    out_dir: str | pathlib.Path,
    templates_dir: str | pathlib.Path,
    reports: dict | None = None,
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

    if reports:
        view = _reports_view(reports)
        feed_html = env.get_template("reports.html.j2").render(**context, reports=view)
        feed_path = out_dir / "reports.html"
        feed_path.write_text(feed_html, encoding="utf-8")
        written.append(feed_path)

        detail_template = env.get_template("report_detail.html.j2")
        for item in view["entries"]:
            page = detail_template.render(**context, report=item, reports=view)
            detail_path = out_dir / f"report-{item['id']}.html"
            detail_path.write_text(page, encoding="utf-8")
            written.append(detail_path)

    return written
