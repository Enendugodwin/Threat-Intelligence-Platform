"""Core data model for the threat intel pipeline."""
from __future__ import annotations

from dataclasses import dataclass, field

IOC_TYPES = ("domain", "url", "ipv4", "ipv6", "sha256", "sha1", "md5", "email")


@dataclass
class IOC:
    """A single normalized indicator of compromise."""

    value: str
    type: str
    source: str
    first_seen: str | None = None
    last_seen: str | None = None
    tags: list[str] = field(default_factory=list)
    malware: str | None = None
    confidence: int = 50
    reference: str | None = None

    @property
    def key(self) -> str:
        """Stable dedupe key: type + lowercased value."""
        return f"{self.type}:{self.value.lower()}"

    def to_dict(self) -> dict:
        return {
            "value": self.value,
            "type": self.type,
            "source": self.source,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "tags": list(self.tags),
            "malware": self.malware,
            "confidence": self.confidence,
            "reference": self.reference,
        }
