import pathlib

from tip import reportfeed
from tip.reportfeed import (
    _classify,
    _extract_cves,
    _extract_iocs,
    _extract_tags,
    _extract_techniques,
    _summarize,
    fetch_reports,
    load_reports,
)


class FakeParsed:
    def __init__(self, entries):
        self.entries = entries
        self.bozo = False
        self.version = "rss20"
        self.status = 200


def _entry(**kw):
    base = {"title": "T", "link": "https://vendor.test/post/1", "summary": ""}
    base.update(kw)
    return base


# -- extraction -------------------------------------------------------------


def test_extract_iocs_defanged_and_filtered():
    text = (
        "See hxxp://c2-badguy[.]net/payload and 185.220.101.99 and "
        "44d88612fea8a8f36de82e1278abb02f and microsoft.com."
    )
    iocs = _extract_iocs("", text, blocked={"microsoft.com"}, limit=50)
    values = {(i["type"], i["value"]) for i in iocs}
    assert ("url", "hxxp://c2-badguy[.]net/payload") in values
    assert ("ipv4", "185[.]220[.]101[.]99") in values
    assert ("md5", "44d88612fea8a8f36de82e1278abb02f") in values
    assert any(t == "domain" and v == "c2-badguy[.]net" for t, v in values)
    assert not any("microsoft" in v for _, v in values)


def test_private_ips_and_asset_urls_filtered():
    html = '<a href="https://assets.good-cdn.com/logo.png">x</a>'
    text = "visit https://assets.good-cdn.com/logo.png http://10.0.0.5/x https://evil-drop.net/a.exe"
    iocs = _extract_iocs(html, text, blocked=set(), limit=50)
    values = [i["value"] for i in iocs]
    assert not any("logo" in v for v in values)
    assert not any("10[.]0[.]0[.]5" in v for v in values)
    assert any("evil-drop" in v for v in values)


def test_extract_cves():
    text = "see CVE-2026-1234 and cve-2025-11111 and CVE-2026-1234"
    assert _extract_cves(text) == ["CVE-2025-11111", "CVE-2026-1234"]


def test_summarize_skips_boilerplate():
    text = (
        "Welcome to this week's edition of the Threat Source newsletter. Sign up here. "
        "Threat actors abused RMM tools to persist in victim networks. "
        "The campaign targeted finance teams across multiple regions."
    )
    out = _summarize(text)
    assert "RMM tools" in out
    assert "newsletter" not in out.lower()


def test_summarize_prefers_security_content():
    text = (
        "Fall is officially here in Maryland and the temperature dropped. "
        "That is why we love autumn. "
        "The actors exploited CVE-2026-1234 to deploy a backdoor on Zimbra servers."
    )
    out = _summarize(text)
    assert "CVE-2026-1234" in out
    assert "Maryland" not in out


def test_extract_tags_and_techniques():
    tags = _extract_tags(
        "UAT-11587 targets governments across Asia",
        "The actor used T1566.001 phishing and deployed Cobalt Strike.",
        ["Cobalt Strike", "LockBit"],
    )
    assert "Cobalt Strike" in tags
    assert any(t.startswith("UAT") for t in tags)
    assert _extract_techniques("uses T1071.001 and T1055 here") == ["T1055", "T1071.001"]


def test_classify_rules():
    rules = {
        "windows": ["windows", "active directory"],
        "linux": ["linux", "ubuntu"],
        "cisco": ["cisco", "ios xe"],
        "paloalto": ["pan-os", "globalprotect"],
    }
    assert _classify("New Windows RAT campaign", "", "general", rules) == "windows"
    assert _classify("Misc post", "", "paloalto", rules) == "paloalto"
    assert _classify("Misc post", "exploits ubuntu servers heavily", "general", rules) == "linux"
    assert _classify("Misc post", "nothing here", "general", rules) == "general"
    assert _classify("Cisco IOS XE advisory", "also mentions windows", "cisco", rules) == "cisco"


# -- fetch / merge / prune ---------------------------------------------------


def _config(tmp_path: pathlib.Path) -> dict:
    return {
        "reports": {
            "enabled": True,
            "max_entries_per_source": 10,
            "max_reports": 2,
            "max_iocs_per_report": 50,
            "detail_chars": 500,
            "curated_file": str(tmp_path / "curated.yaml"),
            "recommendations_file": str(tmp_path / "recs.yaml"),
            "sources": {
                "src_a": {
                    "enabled": True,
                    "name": "Source A",
                    "url": "https://a.vendor.test/blog",
                    "category": "windows",
                },
                "src_b": {"enabled": False, "url": "https://b.vendor.test/blog"},
            },
            "category_rules": {"windows": ["windows"], "linux": ["linux"]},
        }
    }


def test_fetch_reports_merge_prune_and_curated(tmp_path, monkeypatch):
    entries = [
        _entry(
            title=f"Windows post {i}",
            link=f"https://vendor.test/post/{i}",
            summary="Uses http://c2-evil.net/x, 45.61.136.9 and CVE-2026-1001",
            published_parsed=(2026, 10, i, 0, 0, 0, 0, 0, 0),
        )
        for i in range(1, 4)
    ]
    monkeypatch.setattr(reportfeed.feedparser, "parse", lambda url, **kw: FakeParsed(entries))
    (tmp_path / "curated.yaml").write_text(
        "reports:\n"
        "  - title: Curated one\n"
        "    url: https://internal.example/report\n"
        "    category: cisco\n"
        "    recommendations: ['Internal: notify the infra team']\n",
        encoding="utf-8",
    )
    (tmp_path / "recs.yaml").write_text(
        "categories:\n  windows: ['Patch Windows systems']\nsources: {}\nreports: {}\n",
        encoding="utf-8",
    )

    stats = fetch_reports(_config(tmp_path), tmp_path)
    assert stats["sources"]["src_a"] == 3
    assert stats["curated"] == 1

    doc = load_reports(tmp_path)
    assert len(doc["reports"]) == 3  # max_reports=2 newest + the curated one

    curated = [r for r in doc["reports"] if r["curated"]]
    assert len(curated) == 1
    assert curated[0]["category"] == "cisco"

    feed = next(r for r in doc["reports"] if not r["curated"])
    assert feed["category"] == "windows"
    assert feed["iocs"]
    assert any("CVE-2026-1001" in rec for rec in feed["recommendations"])
    assert any("Patch Windows systems" in rec for rec in feed["recommendations"])

    # second run must be idempotent
    fetch_reports(_config(tmp_path), tmp_path)
    assert len(load_reports(tmp_path)["reports"]) == 3


def test_fetch_reports_isolates_source_failure(tmp_path, monkeypatch):
    def boom(url, **kwargs):
        raise RuntimeError("network down")

    monkeypatch.setattr(reportfeed.feedparser, "parse", boom)
    stats = fetch_reports(_config(tmp_path), tmp_path)
    assert "src_a" in stats["errors"]
    assert stats["total"] == 0
