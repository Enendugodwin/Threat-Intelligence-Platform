"""Feed connectors."""
from .base import AUTH_KEY_ENV, Feed, FeedError, SkipFeed
from .blocklists import (
    BinaryDefenseFeed,
    BlocklistDeFeed,
    EmergingThreatsCompromisedFeed,
    GreenSnowFeed,
    PhishingArmyFeed,
    URLhausFilterFeed,
)
from .circl import CIRCLFeed
from .feodo import FeodoFeed
from .malwarebazaar import MalwareBazaarFeed
from .openphish import OpenPhishFeed
from .otx import OTXFeed
from .threatfox import ThreatFoxFeed
from .tor import TorFeed
from .tweetfeed import TweetFeed
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
    "blocklist_de": BlocklistDeFeed,
    "binarydefense": BinaryDefenseFeed,
    "greensnow": GreenSnowFeed,
    "phishing_army": PhishingArmyFeed,
    "et_compromised": EmergingThreatsCompromisedFeed,
    "urlhaus_filter": URLhausFilterFeed,
    "tweetfeed": TweetFeed,
}

__all__ = ["Feed", "FeedError", "SkipFeed", "AUTH_KEY_ENV", "FEED_CLASSES", "build_feeds"]


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
