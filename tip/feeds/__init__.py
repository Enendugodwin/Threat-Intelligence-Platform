"""Feed connectors."""
from .base import Feed, FeedError
from .circl import CIRCLFeed
from .feodo import FeodoFeed
from .malwarebazaar import MalwareBazaarFeed
from .openphish import OpenPhishFeed
from .otx import OTXFeed
from .threatfox import ThreatFoxFeed
from .tor import TorFeed
from .urlhaus import URLhausFeed

FEED_CLASSES: dict[str, type[Feed]] = {
    "urlhaus": URLhausFeed,
    "feodo": FeodoFeed,
    "threatfox": ThreatFoxFeed,
    "malwarebazaar": MalwareBazaarFeed,
    "openphish": OpenPhishFeed,
    "circl": CIRCLFeed,
    "tor": TorFeed,
    "otx": OTXFeed,
}

__all__ = ["Feed", "FeedError", "FEED_CLASSES", "build_feeds"]


def build_feeds(config: dict) -> list[Feed]:
    """Instantiate enabled feeds from the ``feeds:`` config section."""
    feeds: list[Feed] = []
    section = config.get("feeds") or {}
    for name, cls in FEED_CLASSES.items():
        options = section.get(name) or {}
        if not options.get("enabled", False):
            continue
        feeds.append(cls(options))
    return feeds
