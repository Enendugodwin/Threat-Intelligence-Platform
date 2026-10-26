"""TweetFeed - community IOCs posted on X/Twitter (keyless).

Source: https://github.com/0xDanielLopez/TweetFeed

Used as a keyless substitute for the abuse.ch feeds (ThreatFox / MalwareBazaar)
when no ``ABUSECH_AUTH_KEY`` is configured. The weekly CSV contains domains,
URLs, IPs and hashes tagged with malware families / campaigns.

Columns: ``date,reporter,ioc_type,value,tags,tweet_url``
"""
from __future__ import annotations

import csv
import io

from ..models import IOC
from ..normalize import make_ioc, norm_ts
from .base import Feed

# Tags that describe a category rather than a malware family.
_GENERIC_TAGS = {
    "phishing",
    "malware",
    "malvertising",
    "c2",
    "ransomware",
    "scam",
    "apt",
    "trojan",
    "stealer",
    "rat",
    "android",
    "opendir",
    "botnet",
    "backdoor",
    "exploit",
}

_TYPE_MAP = {
    "domain": "domain",
    "url": "url",
    "email": "email",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "ip": None,  # let the normalizer decide ipv4 / ipv6
}


class TweetFeed(Feed):
    name = "tweetfeed"
    url = "https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/week.csv"

    def parse(self, raw: bytes | str) -> list[IOC]:
        text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else raw
        max_records = int(self.options.get("max_records", 4000))
        out: list[IOC] = []
        for row in csv.reader(io.StringIO(text)):
            if not row or len(row) < 5:
                continue
            date = row[0].strip()
            if not date or date.lower().startswith("date"):
                continue
            ioc_type = row[2].strip().lower()
            if ioc_type not in _TYPE_MAP:
                continue
            value = row[3].strip()
            if not value:
                continue
            tags = [
                tag.strip().lstrip("#")
                for tag in row[4].replace(",", " ").split()
                if tag.strip().lstrip("#")
            ]
            reference = row[5].strip() if len(row) > 5 else None
            family = next(
                (tag for tag in tags if tag.lower() not in _GENERIC_TAGS), None
            )
            ioc = make_ioc(
                value,
                self.name,
                ioc_type=_TYPE_MAP[ioc_type],
                first_seen=norm_ts(date),
                tags=tags,
                malware=family,
                confidence=55,
                reference=reference,
            )
            if ioc:
                out.append(ioc)
            if len(out) >= max_records:
                break
        return out
