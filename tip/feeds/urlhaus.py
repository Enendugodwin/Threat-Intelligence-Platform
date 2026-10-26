"""URLhaus (abuse.ch) recent malicious URLs.

Source: https://urlhaus.abuse.ch/api/  (database dump, Auth-Key required)

abuse.ch retired the keyless ``/downloads/csv_recent/`` dump in 2026 - it now
returns HTTP 410 Gone. The authenticated v2 export is used instead:
``https://urlhaus-api.abuse.ch/v2/files/exports/<AUTH_KEY>/recent.csv``
"""
from __future__ import annotations

import csv
import io

from ..models import IOC
from ..normalize import detect_type, host_from_url, make_ioc, norm_ts
from .base import Feed

# Positional fallback for the historical export layout.
_URLHAUS_COLUMNS = (
    "id",
    "dateadded",
    "url",
    "url_status",
    "last_online",
    "threat",
    "tags",
    "urlhaus_link",
    "reporter",
)


class URLhausFeed(Feed):
    name = "urlhaus"
    url = "https://urlhaus-api.abuse.ch/v2/files/exports/{auth_key}/recent.csv"
    requires_auth = True

    @staticmethod
    def _columns(row: list[str]) -> list[str] | None:
        """Return the column order if ``row`` looks like a CSV header."""
        if not row:
            return None
        first = row[0].strip().lower().lstrip("#").strip()
        if first in ("id", "dateadded") and len(row) >= 8:
            return [c.strip().lower().lstrip("#").strip() for c in row]
        return None

    def parse(self, raw: bytes | str) -> list[IOC]:
        text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else raw
        derive_domains = bool(self.options.get("derive_domains", True))
        max_records = int(self.options.get("max_records", 5000))
        out: list[IOC] = []
        columns: list[str] | None = None

        for row in csv.reader(io.StringIO(text)):
            if not row or not any(cell.strip() for cell in row):
                continue
            if row[0].lstrip().startswith("#"):
                # Header lines in the legacy dump are commented out.
                header = self._columns([cell.lstrip("#").strip() for cell in row])
                if header:
                    columns = header
                continue
            header = self._columns(row)
            if header:
                columns = header
                continue

            record = dict(zip(columns, row)) if columns else {}
            if not record:
                if len(row) < 8:
                    continue
                record = dict(zip(_URLHAUS_COLUMNS, row))

            url = (record.get("url") or "").strip()
            if not url:
                continue
            status = (record.get("url_status") or record.get("status") or "").strip()
            tags = (record.get("tags") or "").strip()
            threat = (record.get("threat") or "").strip()
            link = (record.get("urlhaus_link") or record.get("link") or "").strip()
            dateadded = (record.get("dateadded") or "").strip()
            last_online = (record.get("last_online") or "").strip()

            tag_list = [
                t.strip() for t in tags.split(",") if t.strip() and t.strip().lower() != "none"
            ]
            if threat:
                tag_list.append(f"threat:{threat}")

            ioc = make_ioc(
                url,
                self.name,
                first_seen=norm_ts(dateadded),
                last_seen=norm_ts(last_online),
                tags=tag_list,
                confidence=80 if status.lower() == "online" else 60,
                reference=link or None,
            )
            if ioc:
                out.append(ioc)
                if derive_domains:
                    host = host_from_url(ioc.value)
                    if host and detect_type(host) == "domain":
                        derived = make_ioc(
                            host,
                            self.name,
                            first_seen=norm_ts(dateadded),
                            last_seen=norm_ts(last_online),
                            tags=tag_list + ["derived:url-host"],
                            confidence=70 if status.lower() == "online" else 55,
                            reference=link or None,
                        )
                        if derived:
                            out.append(derived)
            if len(out) >= max_records:
                break
        return out
