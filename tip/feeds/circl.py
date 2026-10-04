"""CIRCL MISP OSINT feed (public MISP feed, keyless).

Manifest: https://www.circl.lu/doc/misp/feed-osint/manifest.json
Events:   https://www.circl.lu/doc/misp/feed-osint/<uuid>.json

Only attributes flagged ``to_ids`` are imported - those are the indicators the
event's author intends for correlation/sharing.
"""
from __future__ import annotations

import json
import pathlib

from ..models import IOC
from ..normalize import make_ioc, norm_ts
from .base import Feed, FeedError

_EVENT_BASE = "https://www.circl.lu/doc/misp/feed-osint"


def _map_attribute_type(raw_type: str) -> str | None:
    """Map a MISP attribute type to an IOC type ('' = auto-detect, None = skip)."""
    kind = str(raw_type or "").split("|")[-1].strip().lower()  # filename|sha256 -> sha256
    if kind in ("domain", "hostname"):
        return "domain"
    if kind in ("ip-dst", "ip-src", "ip", "ipv4", "ipv6"):
        return ""
    if kind in ("url", "uri"):
        return "url"
    if kind in ("md5", "sha1", "sha256"):
        return kind
    if kind in ("email-src", "email-dst", "email"):
        return "email"
    return None


class CIRCLFeed(Feed):
    name = "circl"
    url = f"{_EVENT_BASE}/manifest.json"

    def fetch(self, session) -> list[IOC]:
        local = self.options.get("local_file")
        if local:
            path = pathlib.Path(local)
            if not path.is_file():
                raise FeedError(f"{self.name}: local_file not found: {local}")
            data = json.loads(path.read_bytes())
            manifest = data.get("manifest") or {}
            events = data.get("events") or {}

            def get_event(uuid: str) -> dict:
                event = events.get(uuid)
                if event is None:
                    raise FeedError(f"{self.name}: fixture has no event {uuid}")
                return event
        else:
            response = session.get(self.url, timeout=90)
            response.raise_for_status()
            manifest = response.json()
            if not isinstance(manifest, dict):
                raise FeedError(f"{self.name}: unexpected manifest type {type(manifest).__name__}")

            def get_event(uuid: str) -> dict:
                event_response = session.get(f"{_EVENT_BASE}/{uuid}.json", timeout=90)
                event_response.raise_for_status()
                return event_response.json()

        max_events = int(self.options.get("max_events", 8))
        max_attributes = int(self.options.get("max_attributes_per_event", 300))
        max_records = int(self.options.get("max_records", 3000))

        ordered = sorted(
            manifest.items(),
            key=lambda item: str((item[1] or {}).get("timestamp") or ""),
            reverse=True,
        )[:max_events]

        out: list[IOC] = []
        for uuid, meta in ordered:
            meta = meta or {}
            try:
                event = get_event(uuid)
            except Exception:  # noqa: BLE001 - one bad event must not kill the feed
                continue
            info = str(meta.get("info") or "")[:120]
            org = (meta.get("Orgc") or {}).get("name") if isinstance(meta.get("Orgc"), dict) else None
            tags = ["misp", "circl-osint"]
            if org:
                tags.append(f"org:{org}")
            first_seen = norm_ts(str(meta.get("date") or "") or None)
            reference = f"{_EVENT_BASE}/{uuid}.json"

            attributes = (event.get("Event") or {}).get("Attribute") or []
            count = 0
            for attribute in attributes:
                if count >= max_attributes or len(out) >= max_records:
                    break
                if not isinstance(attribute, dict) or not attribute.get("to_ids"):
                    continue
                kind = _map_attribute_type(str(attribute.get("type") or ""))
                if kind is None:
                    continue
                ioc = make_ioc(
                    str(attribute.get("value") or ""),
                    self.name,
                    ioc_type=kind or None,
                    first_seen=first_seen,
                    tags=tags + ([f"event:{info}"] if info else []),
                    confidence=65,
                    reference=reference,
                )
                if ioc is not None:
                    out.append(ioc)
                    count += 1
        return out

    def parse(self, raw) -> list[IOC]:  # pragma: no cover - fetch() handles everything
        raise NotImplementedError("CIRCL feed is parsed in fetch()")
