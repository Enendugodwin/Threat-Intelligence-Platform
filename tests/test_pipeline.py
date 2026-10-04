import pathlib

from tip.attack import load_attack_map
from tip.exports import sigma as sigma_mod
from tip.exports import stix as stix_mod
from tip.exports import suricata as suricata_mod
from tip.exports import tor as tor_export
from tip.pipeline import run_sync
from tip.report import build_context, write_report
from tip.site import build_site
from tip.store import Store

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"


def _config():
    return {
        "feeds": {
            "urlhaus": {"enabled": True, "local_file": str(FIXTURES / "urlhaus.csv")},
            "feodo": {"enabled": True, "local_file": str(FIXTURES / "feodo.json")},
            "threatfox": {"enabled": True, "local_file": str(FIXTURES / "threatfox.json")},
            "tor": {"enabled": True, "local_file": str(FIXTURES / "tor.json")},
            "otx": {"enabled": False},
        },
        "storage": {"prune_after_days": 45},
        "exports": {},
        "report": {"window_days": 7, "top_n": 10, "repo_url": "https://example.invalid/repo"},
    }


def test_offline_pipeline_end_to_end(tmp_path):
    config = _config()
    data_dir = tmp_path / "data"

    stats = run_sync(config, data_dir)
    assert not stats.get("fatal")
    assert stats["new"] > 0
    assert stats["fetched"] >= stats["new"]
    assert (data_dir / "counters.json").is_file()

    # second run: everything already known -> nothing new, but rows updated
    again = run_sync(config, data_dir)
    assert again["new"] == 0
    assert again["updated"] > 0

    attack = load_attack_map(ROOT / "config" / "attack_map.yaml")
    with Store(data_dir / "iocs.sqlite") as store:
        context = build_context(store, config, attack)
        rows = store.rows_for_export(30, 1000, 0, exclude_sources=["tor"])
        tor_rows = store.source_rows("tor")

    reports_doc = {
        "generated_at": "2026-10-04T00:00:00Z",
        "categories": ["windows", "linux", "cisco", "paloalto", "general"],
        "reports": [
            {
                "id": "abc123def4567890",
                "title": "Test advisory",
                "url": "https://vendor.test/advisory",
                "source": "test",
                "source_name": "Test Source",
                "category": "windows",
                "published": "2026-10-01T00:00:00Z",
                "fetched": "2026-10-04T00:00:00Z",
                "summary": "Short summary of the advisory.",
                "content": "Full excerpt text.",
                "iocs": [{"type": "domain", "value": "bad[.]example-bad[.]net"}],
                "cves": ["CVE-2026-0001"],
                "recommendations": ["Do the thing"],
                "curated": False,
            }
        ],
    }

    assert context["totals"]["total"] == again["total"]
    assert context["notable"]
    assert context["tor"]["total"] == 3
    assert context["tor"]["exits"] == 2
    assert all("tor" not in str(row["sources"] or "").split(",") for row in rows)

    report_paths = write_report(context, tmp_path / "reports", ROOT / "templates")
    text = report_paths[0].read_text(encoding="utf-8")
    assert "Threat Intel Pulse" in text
    assert "[.]" in text  # indicators are defanged in reports

    site_paths = build_site(context, tmp_path / "site", ROOT / "templates", reports=reports_doc)
    index = site_paths[0].read_text(encoding="utf-8")
    assert "Threat Intel Pipeline" in index
    assert 'href="reports.html"' in index

    site_dir = tmp_path / "site"
    feed = (site_dir / "reports.html").read_text(encoding="utf-8")
    assert "filterbar" in feed and "cat-windows" in feed and "Test advisory" in feed
    detail = (site_dir / "report-abc123def4567890.html").read_text(encoding="utf-8")
    assert "Do the thing" in detail
    assert "bad[.]example-bad[.]net" in detail

    bundle = stix_mod.build_bundle(rows)
    assert bundle["_meta"]["indicator_count"] > 0
    assert sigma_mod.build_rules(rows, attack)
    assert suricata_mod.build_rules(rows)

    tor_path, tor_count = tor_export.write_nodes(tor_rows, tmp_path / "dist" / "tor" / "tor_nodes.txt")
    assert tor_count == 3
    assert tor_path.exists()
