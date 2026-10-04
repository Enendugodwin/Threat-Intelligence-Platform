"""Plain CSV export of the indicator set."""
from __future__ import annotations

import csv
import pathlib

COLUMNS = [
    "value",
    "type",
    "malware",
    "sources",
    "confidence",
    "first_seen",
    "last_seen",
    "reference",
]


def write_csv(rows, path: str | pathlib.Path) -> pathlib.Path:
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(COLUMNS)
        for row in rows:
            writer.writerow(
                [
                    row["value"],
                    row["type"],
                    row["malware"] or "",
                    row["sources"] or "",
                    row["confidence"] or "",
                    row["first_seen"] or "",
                    row["last_seen"] or "",
                    row["reference"] or "",
                ]
            )
    return path
