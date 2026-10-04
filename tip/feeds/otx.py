"""AlienVault OTX feed - subscribed pulses (requires a free API key).

Set ``OTX_API_KEY`` in the environment or in ``.env``. The feed is disabled
by default in ``config/config.yaml``.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone

from ..models import IOC
from ..normalize import make_ioc, norm_ts
from .base import Feed, FeedError

_OTX_TYPES = {
    "IPv4": "ipv4",
    "IPv6": "ipv6",
    "domain": "domain",
    "hostname": "domain",
    "URL": "url",
    "email": "email",
    "FileHash-SHA256": "sha256",
    "FileHash-MD5": "md5",
    "FileHash-SHA1": "sha1",
}


class OTXFeed(Feed):
    name = "otx"
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"

    def _load(self, session) -> bytes | str:
        local = self.options.get("local_file")
        if local:
            return super()._load(session)

        api_key = self.options.get("api_key") or os.environ.get("OTX_API_KEY", "")
        if not api_key:
            raise FeedError("otx: OTX_API_KEY is not set")
        days = int(self.options.get("modified_since_days", 2))
        since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
        params = {
            "limit": int(self.options.get("max_pulses", 20)),
            "modified_since": since,
        }
        response = session.get(
            self.url, params=params, headers={"X-OTX-API-KEY": api_key}, timeout=90
        )
        response.raise_for_status()
        return response.content

    def parse(self, raw: bytes | str) -> list[IOC]:
        text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else raw
        if not text.strip():
            return []
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise FeedError(f"{self.name}: invalid JSON: {exc}") from exc

        results = data.get("results") or []
        max_indicators = int(self.options.get("max_indicators_per_pulse", 500))
        out: list[IOC] = []

        for pulse in results:
            if not isinstance(pulse, dict):
                continue
            tags = [str(t) for t in (pulse.get("tags") or [])]
            families = pulse.get("malware_families") or []
            malware = None
            if isinstance(families, list) and families:
                first = families[0]
                malware = first.get("display_name") if isinstance(first, dict) else str(first)
            reference = (
                f"https://otx.alienvault.com/pulse/{pulse['id']}" if pulse.get("id") else None
            )

            for indicator in (pulse.get("indicators") or [])[:max_indicators]:
                if not isinstance(indicator, dict):
                    continue
                kind = _OTX_TYPES.get(str(indicator.get("type")))
                if kind is None:
                    continue
                ioc = make_ioc(
                    indicator.get("indicator") or "",
                    self.name,
                    ioc_type=kind,
                    first_seen=norm_ts(indicator.get("created")),
                    tags=tags,
                    malware=malware,
                    confidence=50,
                    reference=reference,
                )
                if ioc:
                    out.append(ioc)
        return out
