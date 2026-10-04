"""Tor Project node list (Onionoo) - relays and exit nodes.

Source: https://onionoo.torproject.org/ (official Tor metrics API, no key).

These are *context* indicators, not malware: they are stored with low
confidence and excluded from detection exports by default (see
``exports.exclude_sources`` in config.yaml). Use them to explain away
scanner/exit-node traffic rather than to alert on it.
"""
from __future__ import annotations

import json
import pathlib

from ..models import IOC
from ..normalize import make_ioc, norm_ts
from .base import Feed, FeedError

_FIELDS = "or_addresses,exit_addresses,flags,first_seen,last_seen,fingerprint,country,as_name"


def _strip_port(address: str) -> str:
    """'1.2.3.4:9001' -> '1.2.3.4'; '[2606:4700::1]:9001' -> '2606:4700::1'."""
    address = address.strip()
    if address.startswith("["):
        return address[1:].split("]", 1)[0]
    if ":" in address:
        return address.rsplit(":", 1)[0]
    return address


class TorFeed(Feed):
    name = "tor"
    url = "https://onionoo.torproject.org/details"
    _page_size = 2000

    def fetch(self, session) -> list[IOC]:
        local = self.options.get("local_file")
        if local:
            path = pathlib.Path(local)
            if not path.is_file():
                raise FeedError(f"{self.name}: local_file not found: {local}")
            return self.parse(path.read_bytes())

        max_records = int(self.options.get("max_records", 20000))
        relays: list[dict] = []
        offset = 0
        for _ in range(20):  # hard cap: 20 * 2000 = 40k relays
            params = {
                "type": "relay",
                "running": "true",
                "limit": self._page_size,
                "offset": offset,
                "fields": _FIELDS,
            }
            response = session.get(self.url, params=params, timeout=120)
            response.raise_for_status()
            page = self._parse_page(response.content)
            relays.extend(page)
            if len(page) < self._page_size or len(relays) >= max_records:
                break
            offset += self._page_size
        return self.parse({"relays": relays[:max_records]})

    # -- parsing -----------------------------------------------------------
    def _parse_page(self, raw: bytes | str) -> list[dict]:
        text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else raw
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise FeedError(f"{self.name}: invalid JSON: {exc}") from exc
        relays = data.get("relays")
        if not isinstance(relays, list):
            raise FeedError(f"{self.name}: unexpected payload (no relays list)")
        return relays

    def parse(self, raw, exits_only: bool | None = None) -> list[IOC]:
        if isinstance(raw, dict):
            relays = raw.get("relays") or []
        else:
            relays = self._parse_page(raw)
        if exits_only is None:
            exits_only = bool(self.options.get("exits_only", False))

        merged: dict[str, IOC] = {}
        for relay in relays:
            if not isinstance(relay, dict):
                continue
            flags = [str(flag) for flag in (relay.get("flags") or [])]
            is_exit = "Exit" in flags
            if exits_only and not is_exit:
                continue

            relay_tags = ["tor", "tor-relay"]
            if is_exit:
                relay_tags.append("tor-exit")
            if "Guard" in flags:
                relay_tags.append("tor-guard")
            if relay.get("country"):
                relay_tags.append(f"country:{relay['country']}")
            if relay.get("as_name"):
                relay_tags.append(f"as:{relay['as_name']}")

            fingerprint = relay.get("fingerprint") or ""
            reference = (
                f"https://metrics.torproject.org/rs.html#details/{fingerprint}"
                if fingerprint
                else "https://onionoo.torproject.org/"
            )

            addresses: list[tuple[str, list[str]]] = [
                (_strip_port(str(addr)), relay_tags) for addr in (relay.get("or_addresses") or [])
            ]
            addresses += [
                (str(addr), ["tor", "tor-exit"]) for addr in (relay.get("exit_addresses") or [])
            ]

            for value, tags in addresses:
                ioc = make_ioc(
                    value,
                    self.name,
                    first_seen=norm_ts(relay.get("first_seen")),
                    last_seen=norm_ts(relay.get("last_seen")),
                    tags=tags,
                    confidence=25,
                    reference=reference,
                )
                if ioc is None:
                    continue
                existing = merged.get(ioc.key)
                if existing is None:
                    merged[ioc.key] = ioc
                else:
                    for tag in ioc.tags:
                        if tag not in existing.tags:
                            existing.tags.append(tag)
                    stamps = [s for s in (existing.first_seen, ioc.first_seen) if s]
                    existing.first_seen = min(stamps) if stamps else None
                    stamps = [s for s in (existing.last_seen, ioc.last_seen) if s]
                    existing.last_seen = max(stamps) if stamps else None
        return list(merged.values())
