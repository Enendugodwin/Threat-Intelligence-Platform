"""ThreatFox (abuse.ch) recent IOC export.

Source: https://threatfox.abuse.ch/export/  (JSON export, no API key required)
"""
from __future__ import annotations

import json

from ..models import IOC
from ..normalize import make_ioc, norm_ts
from .base import Feed, FeedError

_HASH_TYPES = {
    "sha256_hash": "sha256",
    "sha256": "sha256",
    "md5_hash": "md5",
    "md5": "md5",
    "sha1_hash": "sha1",
    "sha1": "sha1",
}


class ThreatFoxFeed(Feed):
    name = "threatfox"
    url = "https://threatfox.abuse.ch/export/json/recent/"

    def parse(self, raw: bytes | str) -> list[IOC]:
        text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else raw
        text = text.strip()
        if not text:
            return []
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise FeedError(f"{self.name}: invalid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise FeedError(f"{self.name}: unexpected payload type {type(data).__name__}")

        out: list[IOC] = []
        for entry_id, entries in data.items():
            if not isinstance(entries, list):
                continue
            for record in entries:
                if not isinstance(record, dict):
                    continue
                value = str(record.get("ioc_value") or "").strip()
                if not value:
                    continue
                ioc_type = str(record.get("ioc_type") or "").lower()

                tags = [
                    t.strip() for t in str(record.get("tags") or "").split(",") if t.strip()
                ]
                if record.get("malware_alias"):
                    tags.extend(
                        a.strip() for a in str(record["malware_alias"]).split(",") if a.strip()
                    )

                kind: str | None = None
                if ioc_type in ("domain", "url", "email"):
                    kind = ioc_type
                elif ioc_type.startswith("ip:"):
                    if ":" in value:
                        value, _, port = value.rpartition(":")
                        if port.isdigit():
                            tags.append(f"port:{port}")
                        else:
                            value = f"{value}:{port}"
                    kind = None  # detect ipv4/ipv6 from the bare address
                else:
                    kind = _HASH_TYPES.get(ioc_type)

                confidence = record.get("confidence_level")
                try:
                    confidence = int(confidence)
                except (TypeError, ValueError):
                    confidence = 70

                ioc = make_ioc(
                    value,
                    self.name,
                    ioc_type=kind,
                    first_seen=norm_ts(record.get("first_seen_utc")),
                    last_seen=norm_ts(record.get("last_seen_utc")),
                    tags=tags,
                    malware=record.get("malware_printable") or record.get("malware") or None,
                    confidence=confidence,
                    reference=f"https://threatfox.abuse.ch/ioc/{entry_id}/",
                )
                if ioc:
                    out.append(ioc)
        return out
