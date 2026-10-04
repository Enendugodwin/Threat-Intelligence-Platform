from tip.scoring import ioc_risk, org_profile, technology_matches


def test_ioc_risk_scales_with_evidence():
    weak = ioc_risk(
        confidence=20,
        sources=1,
        last_seen="2024-01-01",
        has_malware=False,
        ioc_type="domain",
    )
    strong = ioc_risk(
        confidence=100,
        sources=3,
        last_seen="2026-10-04T00:00:00Z",
        has_malware=True,
        ioc_type="sha256",
    )
    assert strong["score"] > weak["score"]
    assert strong["level"] == "critical"
    assert weak["level"] in ("low", "info", "medium")
    assert 0 <= weak["score"] <= 100


def test_ioc_risk_missing_recency_neutral():
    score = ioc_risk(confidence=50, sources=1, last_seen=None, has_malware=False, ioc_type="ipv4")
    assert 0 <= score["score"] <= 100
    assert score["level"] in ("critical", "high", "medium", "low", "info")


def test_technology_matches_and_org_profile():
    matches = technology_matches(["vmware esxi", "PAN-OS"], "Broadcom", "VMware ESXi", "")
    assert matches == ["vmware esxi"]
    assert technology_matches([], "anything") == []
    org = org_profile({"organization": {"enabled": True, "name": "X", "technologies": ["pan-os"]}})
    assert org["enabled"] is True
    assert org["terms"] == ["pan-os"]
    assert org_profile({"organization": {"enabled": True, "technologies": []}})["enabled"] is False
