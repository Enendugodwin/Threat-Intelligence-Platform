"""JSON export of the normalized indicator set."""
from __future__ import annotations

import json
import pathlib
from datetime import datetime, timezone

COLUMNS = (
    "value",
    "type",
    "malware",
    "sources",
    "confidence",
    "first_seen",
    "last_seen",
    "reference",
)


def build_document(rows, generated_at: str | None = None) -> dict:
    """Build a portable JSON document with export metadata and IOC rows."""
    def value(row, column):
        try:
            return row[column]
        except (IndexError, KeyError, TypeError):
            return None

    indicators = [{column: value(row, column) for column in COLUMNS} for row in rows]
    return {
        "schema": "threat-intel-platform/iocs/v1",
        "generated_at": generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "count": len(indicators),
        "indicators": indicators,
    }


def write_json(rows, path: str | pathlib.Path, generated_at: str | None = None) -> pathlib.Path:
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(build_document(rows, generated_at), indent=2), encoding="utf-8")
    return path
