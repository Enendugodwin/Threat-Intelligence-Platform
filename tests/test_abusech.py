"""abuse.ch auth/skip behaviour and authenticated API parsing.

The keyless abuse.ch export URLs were retired in 2026 (HTTP 410 Gone); these
tests pin the replacement behaviour without hitting the network.
"""
import json

import pytest

from tip.feeds.base import AUTH_KEY_ENV, SkipFeed
from tip.feeds.malwarebazaar import MalwareBazaarFeed
from tip.feeds.threatfox import ThreatFoxFeed
from tip.feeds.urlhaus import URLhausFeed
from tip.pipeline import run_sync


def test_abusech_feeds_skip_without_key(monkeypatch):
    monkeypatch.delenv(AUTH_KEY_ENV, raising=False)
    for feed in (URLhausFeed(), ThreatFoxFeed(), MalwareBazaarFeed()):
        with pytest.raises(SkipFeed):
            feed._resolve_request()


def test_urlhaus_uses_auth_key_in_url_and_header(monkeypatch):
    monkeypatch.setenv(AUTH_KEY_ENV, "test-key")
    feed = URLhausFeed()
    url, headers, _kwargs = feed._resolve_request()
    assert url == "https://urlhaus-api.abuse.ch/v2/files/exports/test-key/recent.csv"
    assert headers["Auth-Key"] == "test-key"


def test_threatfox_uses_authenticated_api(monkeypatch):
    monkeypatch.setenv(AUTH_KEY_ENV, "test-key")
    feed = ThreatFoxFeed({"days": 3})
    url, headers, kwargs = feed._resolve_request()
    assert url == "https://threatfox-api.abuse.ch/api/v1/"
    assert headers["Auth-Key"] == "test-key"
    assert kwargs["json"] == {"query": "get_iocs", "days": 3}


def test_threatfox_parses_api_response():
    payload = {
        "query_status": "ok",
        "data": [
            {
                "id": "41",
                "ioc": "gaga.com",
                "ioc_type": "domain",
                "malware_printable": "Dridex",
                "confidence_level": 50,
                "first_seen": "2020-12-08 13:36:27 UTC",
                "tags": ["exe", "test"],
            },
            {
                "id": "42",
                "ioc": "45.61.136.77:4444",
                "ioc_type": "ip:port",
                "malware_printable": "Cobalt Strike",
                "confidence_level": 90,
                "first_seen": "2026-10-20 10:00:00 UTC",
                "tags": [],
            },
        ],
    }
    iocs = ThreatFoxFeed().parse(json.dumps(payload))
    domain = next(i for i in iocs if i.type == "domain")
    assert domain.first_seen == "2020-12-08T13:36:27Z"
    assert domain.tags == ["exe", "test"]
    ip = next(i for i in iocs if i.type == "ipv4")
    assert ip.value == "45.61.136.77"
    assert "port:4444" in ip.tags


def test_malwarebazaar_parses_api_response():
    payload = {
        "query_status": "ok",
        "data": [
            {
                "sha256_hash": "A" * 64,
                "first_seen": "2026-10-20 10:00:00",
                "signature": "Remcos",
            }
        ],
    }
    iocs = MalwareBazaarFeed().parse(json.dumps(payload))
    assert len(iocs) == 1
    assert iocs[0].type == "sha256"
    assert iocs[0].malware == "Remcos"
    assert "malware-sample" in iocs[0].tags


def test_sync_records_skipped_feeds(tmp_path, monkeypatch):
    monkeypatch.delenv(AUTH_KEY_ENV, raising=False)
    config = {
        "feeds": {"urlhaus": {"enabled": True}},
        "storage": {"prune_after_days": 20},
    }
    stats = run_sync(config, tmp_path)
    assert stats["skipped"] == ["urlhaus"]
    assert stats["skipped_reasons"]["urlhaus"]
    assert not stats.get("fatal")

def test_feed_health_marks_skipped_and_retention():
    from tip.report import _feed_health

    config = {
        "feeds": {"urlhaus": {"enabled": True}, "feodo": {"enabled": True}},
        "storage": {"prune_after_days": 20},
    }
    health = _feed_health(
        config,
        {
            "stats": {
                "feeds": {"feodo": 5},
                "skipped": ["urlhaus"],
                "skipped_reasons": {"urlhaus": "no key"},
                "pruned": 120,
            }
        },
    )
    assert health["ok"] == 1
    assert health["total"] == 1
    assert health["skipped"] == 0
    assert health["optional"] == ["URLhaus"]
    assert health["retention_days"] == 20
    assert health["last_pruned"] == 120
    assert all(f["name"] != "urlhaus" for f in health["feeds"])
