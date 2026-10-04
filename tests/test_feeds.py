import pathlib

from tip.feeds.circl import CIRCLFeed
from tip.feeds.feodo import FeodoFeed
from tip.feeds.malwarebazaar import MalwareBazaarFeed
from tip.feeds.openphish import OpenPhishFeed
from tip.feeds.otx import OTXFeed
from tip.feeds.threatfox import ThreatFoxFeed
from tip.feeds.tor import TorFeed
from tip.feeds.urlhaus import URLhausFeed

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
_FILES = {
    "urlhaus": "urlhaus.csv",
    "feodo": "feodo.json",
    "threatfox": "threatfox.json",
    "malwarebazaar": "malwarebazaar.txt",
    "openphish": "openphish.txt",
    "circl": "circl_feed.json",
    "tor": "tor.json",
    "otx": "otx.json",
}


def _fetch(feed_cls):
    path = FIXTURES / _FILES[feed_cls.name]
    return feed_cls({"local_file": str(path)}).fetch(None)


def test_urlhaus_parse():
    iocs = _fetch(URLhausFeed)
    urls = [i for i in iocs if i.type == "url"]
    domains = [i for i in iocs if i.type == "domain"]
    assert len(urls) == 3
    assert any(i.value == "malware-cdn-one.com" for i in domains)
    online = next(i for i in urls if i.value.endswith("/bin.sh"))
    assert online.confidence == 80
    assert "Mozi" in online.tags


def test_feodo_parse():
    iocs = _fetch(FeodoFeed)
    assert len(iocs) == 2
    emotet = next(i for i in iocs if i.malware == "Emotet")
    assert emotet.value == "91.92.240.11"
    assert emotet.confidence == 85
    assert "port:443" in emotet.tags


def test_threatfox_parse():
    iocs = _fetch(ThreatFoxFeed)
    kinds = {i.type for i in iocs}
    assert {"url", "domain", "sha256", "ipv4"} <= kinds
    ip = next(i for i in iocs if i.type == "ipv4")
    assert ip.value == "45.61.136.77"
    assert "port:4444" in ip.tags
    assert ip.malware == "Cobalt Strike"


def test_otx_parse():
    iocs = _fetch(OTXFeed)
    assert len(iocs) == 2  # the URI-type indicator is skipped
    lockbit = next(i for i in iocs if i.malware == "LockBit")
    assert "ransomware" in lockbit.tags


def test_tor_parse():
    iocs = _fetch(TorFeed)
    assert len(iocs) == 3
    exit_v4 = next(i for i in iocs if i.value == "204.8.96.141")
    assert "tor-exit" in exit_v4.tags
    assert exit_v4.confidence == 25
    ipv6 = next(i for i in iocs if i.type == "ipv6")
    assert ipv6.value == "2606:4700:4700::141"
    plain_relay = next(i for i in iocs if i.value == "45.61.136.55")
    assert "tor-relay" in plain_relay.tags
    assert "tor-exit" not in plain_relay.tags


def test_malwarebazaar_parse():
    iocs = _fetch(MalwareBazaarFeed)
    assert len(iocs) == 2
    assert all(i.type == "sha256" for i in iocs)
    assert "malware-sample" in iocs[0].tags


def test_openphish_parse():
    iocs = _fetch(OpenPhishFeed)
    assert len(iocs) == 3
    assert all(i.type == "url" for i in iocs)
    assert "phishing" in iocs[0].tags


def test_circl_parse():
    iocs = _fetch(CIRCLFeed)
    assert len(iocs) == 6  # 5 from the newer event + 1 from the older event
    kinds = {i.type for i in iocs}
    assert {"domain", "ipv4", "url", "sha256"} <= kinds
    values = {i.value for i in iocs}
    assert "circl-bad.net" in values
    assert not any("should-not-import" in v for v in values)  # to_ids=false excluded
    assert all("circl-osint" in i.tags for i in iocs)
