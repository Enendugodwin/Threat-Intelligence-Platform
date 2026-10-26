"""ThreatFox (abuse.ch) recent IOCs.

Source: https://threatfox.abuse.ch/api/  (Auth-Key required)

ThreatFox retired the keyless ``/export/json/recent/`` dump in 2026 (HTTP 410
Gone). The documented authenticated API is used instead:

    POST https://threatfox-api.abuse.ch/api/v1/
    {"query": "get_iocs", "days": 1}
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
    url = "https://threatfox-api.abuse.ch/api/v1/"
    method = "POST"
    requires_auth = True

    def __init__(self, options: dict | None = None):
        super().__init__(options)
        try:
            days = int(self.options.get("days", 1))
        except (TypeError, ValueError):
            days = 1
        # The API accepts 1..7 days.
        self.json_body = {"query": "get_iocs", "days": max(1, min(7, days))}

    @staticmethod
    def _tag_list(value) -> list[str]:
        if value is None:
            return []
        if isinstance(value, (list, tuple)):
            return [str(v).strip() for v in value if str(v).strip()]
        return [t.strip() for t in str(value).split(",") if t.strip()]

    @staticmethod
    def _records(data: dict) -> list[tuple[str | None, dict]]:
        """Yield ``(entry_id, record)`` pairs for both payload shapes.

        The authenticated API returns ``{"query_status": ..., "data": [...]}``;
        the historical export was ``{"<id>": [{...}, ...], ...}``.
        """
        if isinstance(data.get("data"), list):
            status = str(data.get("query_status") or "").lower()
            if status and status != "ok":
                raise FeedError(f"threatfox: query_status={status}")
            return [(None, rec) for rec in data["data"] if isinstance(rec, dict)]
        pairs: list[tuple[str | None, dict]] = []
        for entry_id, entries in data.items():
            if isinstance(entries, list):
                pairs.extend((str(entry_id), rec) for rec in entries if isinstance(rec, dict))
        return pairs

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
        for entry_id, record in self._records(data):
            value = str(record.get("ioc") or record.get("ioc_value") or "").strip()
            if not value:
                continue
            ioc_type = str(record.get("ioc_type") or "").lower()

            tags = self._tag_list(record.get("tags"))
            tags.extend(self._tag_list(record.get("malware_alias")))

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

            record_id = record.get("id") or entry_id
            reference = record.get("reference") or (
                f"https://threatfox.abuse.ch/ioc/{record_id}/" if record_id else None
            )

            ioc = make_ioc(
                value,
                self.name,
                ioc_type=kind,
                first_seen=norm_ts(record.get("first_seen_utc") or record.get("first_seen")),
                last_seen=norm_ts(record.get("last_seen_utc") or record.get("last_seen")),
                tags=tags,
                malware=record.get("malware_printable") or record.get("malware") or None,
                confidence=confidence,
                reference=reference,
            )
            if ioc:
                out.append(ioc)
        return out
