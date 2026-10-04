"""URLhaus (abuse.ch) CSV feed - recent malicious URLs.

Source: https://urlhaus.abuse.ch/api/  (no API key required for CSV dumps)
"""
from __future__ import annotations

import csv
import io

from ..models import IOC
from ..normalize import detect_type, host_from_url, make_ioc, norm_ts
from .base import Feed


class URLhausFeed(Feed):
    name = "urlhaus"
    url = "https://urlhaus.abuse.ch/downloads/csv_recent/"

    def parse(self, raw: bytes | str) -> list[IOC]:
        text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else raw
        derive_domains = bool(self.options.get("derive_domains", True))
        max_records = int(self.options.get("max_records", 5000))
        out: list[IOC] = []

        for row in csv.reader(io.StringIO(text)):
            if not row or row[0].startswith("#") or len(row) < 8:
                continue
            _id, dateadded, url, status, last_online, threat, tags, link = row[:8]
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
                confidence=80 if str(status).lower() == "online" else 60,
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
                            confidence=70 if str(status).lower() == "online" else 55,
                            reference=link or None,
                        )
                        if derived:
                            out.append(derived)
            if len(out) >= max_records:
                break
        return out
