"""Orchestration: fetch feeds -> normalize/merge -> store -> counters."""
from __future__ import annotations

import json
import logging
import pathlib

import yaml

from .feeds import build_feeds
from .store import Store, utcnow

log = logging.getLogger("tip.pipeline")

_USER_AGENT = "threat-intel-pipeline/0.1 (+https://github.com/Enendugodwin/Threat-Intelligence-Platform)"


def load_config(path: str | pathlib.Path) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def make_session():
    """requests session with retries for transient feed errors."""
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

    session = requests.Session()
    session.headers["User-Agent"] = _USER_AGENT
    retry = Retry(
        total=3,
        backoff_factor=1.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET",),
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def run_sync(config: dict, data_dir: str | pathlib.Path) -> dict:
    """Run one sync cycle.

    A feed failure is logged and recorded but does not abort the run unless
    *every* enabled feed fails (then ``stats['fatal']`` is True).
    """
    data_dir = pathlib.Path(data_dir)
    feeds = build_feeds(config)
    if not feeds:
        raise SystemExit("no feeds enabled in config")

    session = make_session()
    store = Store(data_dir / "iocs.sqlite")
    started = utcnow()
    collected = []
    feed_counts: dict[str, int] = {}
    errors: dict[str, str] = {}

    try:
        for feed in feeds:
            try:
                got = feed.fetch(session)
                collected.extend(got)
                feed_counts[feed.name] = len(got)
                log.info("feed %s: %d indicators", feed.name, len(got))
            except Exception as exc:  # noqa: BLE001 - isolate per-feed failures
                errors[feed.name] = f"{type(exc).__name__}: {exc}"
                log.warning("feed %s failed: %s", feed.name, exc)

        new, updated = store.upsert_many(collected)
        prune_days = int((config.get("storage") or {}).get("prune_after_days", 45))
        pruned = store.prune(prune_days) if prune_days > 0 else 0

        stats = {
            "started_at": started,
            "finished_at": utcnow(),
            "feeds": feed_counts,
            "errors": errors,
            "fetched": len(collected),
            "new": new,
            "updated": updated,
            "pruned": pruned,
            "total": store.total(),
        }
        store.record_run(stats)

        counters = {
            "generated_at": stats["finished_at"],
            **store.stats(),
            "latest_run": stats,
        }
        (data_dir / "counters.json").write_text(
            json.dumps(counters, indent=2, sort_keys=True), encoding="utf-8"
        )
    finally:
        store.close()

    if len(errors) == len(feeds):
        stats["fatal"] = True
        log.error("all feeds failed")

    log.info(
        "sync complete: fetched=%d new=%d updated=%d pruned=%d total=%d",
        stats["fetched"],
        stats["new"],
        stats["updated"],
        stats["pruned"],
        stats["total"],
    )
    return stats
