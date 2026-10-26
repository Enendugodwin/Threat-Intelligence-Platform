"""Keyless blocklist feeds.

These are plain-text lists (one indicator per line, ``#`` comments ignored) that
complement the abuse.ch feeds without requiring an API key. They are lower
confidence than curated CTI and are tagged with ``blocklist`` so consumers can
filter them.

Feeds are skipped automatically (``SkipFeed``) by :class:`Feed` only when an
Auth-Key is required; these need no credentials.
"""
from __future__ import annotations

from ..models import IOC
from .base import Feed
from ..normalize import make_ioc

_HEADER_HINTS = (
    "begin",
    "updated",
    "last",
    "comment",
    "blocklist",
    "malware",
    "ip",
    "domain",
)


class _TextBlocklistFeedMixin:
    """Shared parser for line-delimited IP / domain blocklists."""

    force_type: str | None = None
    default_tags: tuple[str, ...] = ()
    confidence = 50
    max_records_default = 3000

    def parse(self, raw: bytes | str) -> list[IOC]:  # type: ignore[override]
        text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else raw
        max_records = int(self.options.get("max_records", self.max_records_default))
        tags = list(self.default_tags)
        out: list[IOC] = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(";") or line.startswith("//"):
                continue
            # Drop inline comments and whitespace-separated metadata.
            value = line.split("#", 1)[0].strip()
            if not value or " " in value or "\t" in value:
                parts = value.split()
                if not parts:
                    continue
                value = parts[0]
            if value.lower() in _HEADER_HINTS:
                continue
            ioc = make_ioc(
                value,
                self.name,
                ioc_type=self.force_type,
                tags=tags,
                confidence=self.confidence,
            )
            if ioc:
                out.append(ioc)
            if len(out) >= max_records:
                break
        return out


class BlocklistDeFeed(_TextBlocklistFeedMixin, Feed):
    """blocklist.de - IPs reported for brute-force / abuse (keyless)."""

    name = "blocklist_de"
    url = "https://lists.blocklist.de/lists/all.txt"
    force_type = "ipv4"
    default_tags = ("blocklist", "bruteforce")
    confidence = 45
    max_records_default = 3000


class BinaryDefenseFeed(_TextBlocklistFeedMixin, Feed):
    """Binary Defense banlist - attacker / C2 IPs seen in the wild."""

    name = "binarydefense"
    url = "https://www.binarydefense.com/banlist.txt"
    force_type = "ipv4"
    default_tags = ("blocklist", "c2")
    confidence = 55
    max_records_default = 2000


class GreenSnowFeed(_TextBlocklistFeedMixin, Feed):
    """GreenSnow - community blocklist of abusive IPs."""

    name = "greensnow"
    url = "https://blocklist.greensnow.co/greensnow.txt"
    force_type = "ipv4"
    default_tags = ("blocklist",)
    confidence = 50
    max_records_default = 2000


class PhishingArmyFeed(_TextBlocklistFeedMixin, Feed):
    """Phishing Army - extended phishing domain blocklist."""

    name = "phishing_army"
    url = "https://phishing.army/download/phishing_army_blocklist_extended.txt"
    force_type = "domain"
    default_tags = ("blocklist", "phishing")
    confidence = 45
    max_records_default = 3000


class EmergingThreatsCompromisedFeed(_TextBlocklistFeedMixin, Feed):
    """ET Open - compromised hosts seen by Emerging Threats sensors."""

    name = "et_compromised"
    url = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
    force_type = "ipv4"
    default_tags = ("blocklist", "compromised-host")
    confidence = 60
    max_records_default = 1000


class URLhausFilterFeed(_TextBlocklistFeedMixin, Feed):
    """URLhaus domain blocklist mirror (keyless fallback for URLhaus).

    Source: https://gitlab.com/malware-filter/urlhaus-filter
    Used when no abuse.ch Auth-Key is available; contains domains/hosts seen
    distributing malware, not full URLs.
    """

    name = "urlhaus_filter"
    url = "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains.txt"
    force_type = None
    default_tags = ("blocklist", "urlhaus", "malware")
    confidence = 55
    max_records_default = 5000
