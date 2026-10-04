"""Build the report context and render Markdown reports."""
from __future__ import annotations

import pathlib
from datetime import datetime, timezone

from jinja2 import Environment, FileSystemLoader

from .attack import AttackMap
from .normalize import defang
from .store import Store


def _sources(row) -> list[str]:
    try:
        return [s for s in str(row["sources"] or "").split(",") if s]
    except (IndexError, KeyError):
        return []


def _feed_health(config: dict, last_run: dict | None) -> dict:
    enabled = [
        name for name, opts in (config.get("feeds") or {}).items() if (opts or {}).get("enabled")
    ]
    stats = (last_run or {}).get("stats") or {}
    counts = stats.get("feeds") or {}
    errors = stats.get("errors") or {}
    feeds = [
        {"name": name, "count": counts.get(name), "error": errors.get(name, "")}
        for name in enabled
    ]
    ok = sum(1 for feed in feeds if not feed["error"])
    return {"total": len(feeds), "ok": ok, "feeds": feeds}


def build_context(store: Store, config: dict, attack: AttackMap) -> dict:
    """Collect everything the report/site templates need."""
    report_cfg = config.get("report") or {}
    window_days = int(report_cfg.get("window_days", 7))
    top_n = int(report_cfg.get("top_n", 25))

    all_rows = store.all_rows()
    new_rows = store.new_since(window_days)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

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
    for name, total in store.top_malware(limit=20):
        families.append(
            {
                "name": name,
                "total": total,
                "new": new_by_family.get(name.lower(), 0),
                "techniques": attack.family_techniques(name),
            }
        )

    coverage = [{"id": tid, **info} for tid, info in attack.coverage(all_rows).items()]

    notable = [
        {
            "value": defang(row["value"]),
            "type": row["type"],
            "malware": row["malware"] or "",
            "sources": _sources(row),
            "first_seen": row["first_seen"] or "",
            "confidence": row["confidence"],
        }
        for row in new_rows[:top_n]
    ]

    last_run = store.last_run()
    return {
        "generated_at": now,
        "generated_date": now[:10],
        "window_days": window_days,
        "repo_url": report_cfg.get("repo_url", ""),
        "totals": {
            "total": store.total(),
            "new": len(new_rows),
            "families": len(families),
            "coverage": len(coverage),
        },
        "feed_health": _feed_health(config, last_run),
        "by_type": by_type,
        "by_source": [{"source": s, "count": c} for s, c in store.counts_by_source()],
        "families": families,
        "coverage": coverage,
        "notable": notable,
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
