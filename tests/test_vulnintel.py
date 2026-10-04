import pathlib

from tip import geo, vulnintel
from tip.models import IOC
from tip.store import Store


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


class FakeSession:
    def __init__(self, get_map=None, post_map=None):
        self.get_map = get_map or {}
        self.post_map = list(post_map or [])

    def get(self, url, params=None, timeout=None):
        for needle, payload in self.get_map.items():
            if needle in url:
                return FakeResponse(payload)
        raise RuntimeError(f"no fake GET for {url}")

    def post(self, url, params=None, json=None, timeout=None):
        if not self.post_map:
            raise RuntimeError(f"no fake POST for {url}")
        return FakeResponse(self.post_map.pop(0))


KEV_PAYLOAD = {
    "catalogVersion": "2026.10.02",
    "count": 2,
    "vulnerabilities": [
        {
            "cveID": "CVE-2026-0002",
            "vendorProject": "Acme",
            "product": "Router",
            "vulnerabilityName": "Bug B",
            "dateAdded": "2026-09-30",
            "dueDate": "2026-10-21",
            "knownRansomwareCampaignUse": "Known",
            "shortDescription": "desc b",
            "requiredAction": "patch b",
        },
        {
            "cveID": "CVE-2026-0001",
            "vendorProject": "Acme",
            "product": "VPN",
            "vulnerabilityName": "Bug A",
            "dateAdded": "2026-08-01",
            "dueDate": "2026-08-22",
            "knownRansomwareCampaignUse": "Unknown",
            "shortDescription": "desc a",
            "requiredAction": "patch a",
        },
    ],
}
EPSS_PAYLOAD = {
    "data": [
        {"cve": "CVE-2026-0001", "epss": "0.5", "percentile": "0.9"},
        {"cve": "CVE-2026-0002", "epss": "0.9", "percentile": "0.99"},
    ]
}


def test_fetch_kev_sorts_enriches_and_caches(tmp_path, monkeypatch):
    monkeypatch.setattr(vulnintel.time, "sleep", lambda seconds: None)
    session = FakeSession(get_map={"known_exploited": KEV_PAYLOAD, "epss": EPSS_PAYLOAD})
    monkeypatch.setattr(vulnintel, "make_session", lambda: session)
    config = {"vulnintel": {"enabled": True, "max_entries": 10}}

    stats = vulnintel.fetch_kev(config, tmp_path)
    assert stats["total"] == 2
    doc = vulnintel.load_kev(tmp_path)
    assert [entry["cve"] for entry in doc["entries"]] == ["CVE-2026-0002", "CVE-2026-0001"]
    assert doc["entries"][0]["epss"] == 0.9
    assert doc["entries"][0]["ransomware"] is True

    # second run: EPSS comes from the cache, no new lookups
    session2 = FakeSession(get_map={"known_exploited": KEV_PAYLOAD})
    monkeypatch.setattr(vulnintel, "make_session", lambda: session2)
    stats2 = vulnintel.fetch_kev(config, tmp_path)
    assert stats2["epss_fetched"] == 0


GEO_BATCH = [
    {"status": "success", "country": "Netherlands", "countryCode": "NL", "city": "Amsterdam",
     "lat": 52.37, "lon": 4.89, "query": "45.61.136.10"},
    {"status": "success", "country": "United States", "countryCode": "US", "city": "Ashburn",
     "lat": 39.04, "lon": -77.48, "query": "91.92.240.11"},
]


def test_build_geo_lookup_and_cache(tmp_path, monkeypatch):
    store = Store(tmp_path / "iocs.sqlite")
    store.upsert_many(
        [
            IOC(value="45.61.136.10", type="ipv4", source="threatfox", confidence=80),
            IOC(value="91.92.240.11", type="ipv4", source="feodo", confidence=85),
        ]
    )
    store.close()

    monkeypatch.setattr(geo.time, "sleep", lambda seconds: None)
    session = FakeSession(post_map=[GEO_BATCH])
    monkeypatch.setattr(geo, "make_session", lambda: session)
    config = {"geo": {"enabled": True, "max_ips": 10, "include_sources": ["threatfox", "feodo"]}}

    stats = geo.build_geo(config, tmp_path)
    assert stats["selected"] == 2
    assert stats["looked_up"] == 2
    doc = geo.load_geo(tmp_path)
    assert doc["ips"]["45.61.136.10"]["country"] == "Netherlands"

    stats2 = geo.build_geo(config, tmp_path)
    assert stats2["looked_up"] == 0
    assert stats2["cached"] == 2
