"""Optional MISP push connector.

Requires ``pip install pymisp`` and environment configuration:

    MISP_URL=https://misp.example.org
    MISP_API_KEY=...
    MISP_VERIFY_SSL=true

Usage: ``python -m tip push --misp [--days 7]``
"""
from __future__ import annotations

import os
from datetime import datetime, timezone

_TYPE_MAP = {
    "domain": "domain",
    "url": "url",
    "ipv4": "ip-dst",
    "ipv6": "ip-dst",
    "sha256": "sha256",
    "sha1": "sha1",
    "md5": "md5",
    "email": "email-src",
}


def push_new(rows, url: str | None = None, key: str | None = None,
             verify: bool | None = None, event_info: str | None = None) -> dict:
    """Push indicators into one MISP event. Returns a summary dict."""
    url = url or os.environ.get("MISP_URL", "")
    key = key or os.environ.get("MISP_API_KEY", "")
    if not url or not key:
        raise RuntimeError("MISP_URL and MISP_API_KEY must be set (environment or .env)")
    if verify is None:
        verify = os.environ.get("MISP_VERIFY_SSL", "true").lower() not in ("0", "false", "no")

    try:
        from pymisp import MISPEvent, PyMISP
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError("pymisp is not installed: pip install pymisp") from exc

    misp = PyMISP(url, key, ssl=verify)
    event = MISPEvent()
    event.info = event_info or (
        f"threat-intel-pipeline sync {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC"
    )
    event.distribution = 0  # your organisation only - widen deliberately
    event.threat_level_id = 3
    event.analysis = 1

    added = skipped = 0
    for row in rows:
        attribute_type = _TYPE_MAP.get(row["type"])
        if not attribute_type:
            skipped += 1
            continue
        tags = ["tlp:clear", "source:threat-intel-pipeline"]
        for source in str(row["sources"] or "").split(","):
            if source:
                tags.append(f"source:{source}")
        if row["malware"]:
            tags.append(f"malware:{str(row['malware']).strip()}")
        attribute = event.add_attribute(
            attribute_type,
            row["value"],
            to_ids=True,
            comment=row["reference"] or "",
            tags=tags,
        )
        if attribute:
            added += 1
        else:
            skipped += 1

    result = misp.add_event(event)
    return {"event_id": getattr(result, "id", None), "added": added, "skipped": skipped}
