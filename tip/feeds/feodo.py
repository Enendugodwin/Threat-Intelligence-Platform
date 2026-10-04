"""Feodo Tracker (abuse.ch) botnet C2 IP blocklist.

Source: https://feodotracker.abuse.ch/  (no API key required for the JSON dump)
"""
from __future__ import annotations

import json

from ..models import IOC
from ..normalize import make_ioc, norm_ts
from .base import Feed, FeedError


class FeodoFeed(Feed):
    name = "feodo"
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"

    def parse(self, raw: bytes | str) -> list[IOC]:
        text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else raw
        text = text.strip()
        if not text:
            return []
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise FeedError(f"{self.name}: invalid JSON: {exc}") from exc
        if not isinstance(data, list):
            raise FeedError(f"{self.name}: unexpected payload type {type(data).__name__}")

        out: list[IOC] = []
        for record in data:
            if not isinstance(record, dict):
                continue
            ip = record.get("ip_address")
            if not ip:
                continue
            tags = [
                str(t)
                for t in (
                    record.get("status"),
                    record.get("country"),
                    f"asn:{record['as_number']}" if record.get("as_number") else None,
                    f"port:{record['port']}" if record.get("port") else None,
                    f"as:{record['as_name']}" if record.get("as_name") else None,
                )
                if t
            ]
            ioc = make_ioc(
                ip,
                self.name,
                first_seen=norm_ts(record.get("first_seen")),
                last_seen=norm_ts(record.get("last_online")),
                tags=tags,
                malware=record.get("malware") or None,
                confidence=85,
                reference=f"https://feodotracker.abuse.ch/browse/host/{ip}/",
            )
            if ioc:
                out.append(ioc)
        return out
