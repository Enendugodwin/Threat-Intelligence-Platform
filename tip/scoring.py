"""Risk scoring for indicators.

Separates the concepts the review called out:

- **confidence** (how strongly the sources vouch for an IOC - stored per IOC)
- **risk** (how dangerous the IOC is, combining confidence, corroboration,
  recency, malware association and indicator type)

The output is a 0-100 score plus a CRITICAL/HIGH/MEDIUM/LOW/INFO level.
Environment relevance is a future input (see ``organization`` in config).
"""
from __future__ import annotations

from datetime import datetime, timezone

_LEVELS = ((85, "critical"), (70, "high"), (50, "medium"), (30, "low"), (0, "info"))

_TYPE_WEIGHT = {
    "sha256": 90,
    "sha1": 85,
    "md5": 80,
    "ipv4": 75,
    "ipv6": 75,
    "domain": 70,
    "url": 65,
    "email": 60,
}


def _days_since(timestamp) -> float | None:
    if not timestamp:
        return None
    try:
        dt = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return max(0.0, (datetime.now(timezone.utc) - dt).total_seconds() / 86400)


def ioc_risk(
    *,
    confidence: int = 50,
    sources: int = 1,
    last_seen=None,
    has_malware: bool = False,
    ioc_type: str = "domain",
) -> dict:
    """Return ``{"score": 0-100, "level": "critical|high|medium|low|info"}``."""
    days = _days_since(last_seen)
    if days is None:
        recency = 50.0
    elif days <= 1:
        recency = 100.0
    elif days <= 7:
        recency = 85.0
    elif days <= 30:
        recency = 65.0
    else:
        recency = 45.0

    multi_source = min(100.0, 40.0 + 30.0 * max(0, sources - 1))
    malware = 100.0 if has_malware else 40.0
    type_weight = _TYPE_WEIGHT.get(ioc_type, 60)

    score = round(
        0.30 * max(0, min(100, int(confidence or 0)))
        + 0.20 * recency
        + 0.20 * multi_source
        + 0.20 * malware
        + 0.10 * type_weight
    )
    level = next(level for threshold, level in _LEVELS if score >= threshold)
    return {"score": int(score), "level": level}


def technology_matches(terms, *fields) -> list[str]:
    """Case-insensitive substring matches of organization technology terms."""
    blob = " ".join(str(field or "") for field in fields).lower()
    matches: list[str] = []
    for term in terms or []:
        term = str(term).strip()
        if term and term.lower() in blob and term not in matches:
            matches.append(term)
    return matches


def org_profile(config: dict) -> dict:
    """Organization/asset profile used for environment matching."""
    org = (config or {}).get("organization") or {}
    terms = [str(term) for term in (org.get("technologies") or []) if str(term).strip()]
    return {
        "enabled": bool(org.get("enabled", False)) and bool(terms),
        "name": str(org.get("name") or ""),
        "terms": terms,
    }
