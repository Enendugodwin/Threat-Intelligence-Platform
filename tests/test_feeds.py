import pathlib

from tip.feeds.feodo import FeodoFeed
from tip.feeds.otx import OTXFeed
from tip.feeds.threatfox import ThreatFoxFeed
from tip.feeds.urlhaus import URLhausFeed

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
_FILES = {
    "urlhaus": "urlhaus.csv",
    "feodo": "feodo.json",
    "threatfox": "threatfox.json",
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
