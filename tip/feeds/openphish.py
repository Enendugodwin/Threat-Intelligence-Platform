"""OpenPhish public phishing feed (GitHub mirror, keyless).

Source: https://github.com/openphish/public_feed (mirrors openphish.com/feed.txt)
"""
from __future__ import annotations

from ..models import IOC
from ..normalize import make_ioc
from .base import Feed


class OpenPhishFeed(Feed):
    name = "openphish"
    url = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"

    def parse(self, raw: bytes | str) -> list[IOC]:
        text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else raw
        max_records = int(self.options.get("max_records", 1000))
        out: list[IOC] = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            ioc = make_ioc(line, self.name, tags=["phishing"], confidence=70)
            if ioc:
                out.append(ioc)
            if len(out) >= max_records:
                break
        return out
