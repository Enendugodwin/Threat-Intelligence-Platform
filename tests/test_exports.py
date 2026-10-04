import csv

import yaml

from tip.attack import AttackMap
from tip.exports import csv_export
from tip.exports import sigma as sigma_mod
from tip.exports import stix as stix_mod
from tip.exports import suricata as suricata_mod

ROWS = [
    {
        "key": "domain:c2-steady-host.com",
        "value": "c2-steady-host.com",
        "type": "domain",
        "malware": "RedLine Stealer",
        "sources": "threatfox",
        "confidence": 75,
        "first_seen": "2026-10-02T09:00:00Z",
        "last_seen": None,
        "reference": "https://threatfox.abuse.ch/ioc/2/",
    },
    {
        "key": "domain:malware-cdn-one.com",
        "value": "malware-cdn-one.com",
        "type": "domain",
        "malware": "Mozi",
        "sources": "urlhaus",
        "confidence": 80,
        "first_seen": "2026-10-04T16:32:20Z",
        "last_seen": None,
        "reference": "https://urlhaus.abuse.ch/url/1/",
    },
    {
        "key": "ipv4:91.92.240.11",
        "value": "91.92.240.11",
        "type": "ipv4",
        "malware": "Emotet",
        "sources": "feodo",
        "confidence": 85,
        "first_seen": "2025-11-02T08:15:00Z",
        "last_seen": "2026-10-03T00:00:00Z",
        "reference": None,
    },
    {
        "key": "sha256:aa11",
        "value": "a" * 64,
        "type": "sha256",
        "malware": "Emotet",
        "sources": "threatfox",
        "confidence": 90,
        "first_seen": "2026-10-01T11:00:00Z",
        "last_seen": None,
        "reference": None,
    },
]

ATTACK = AttackMap(
    {
        "techniques": {
            "T1071.001": {"name": "Web Protocols", "tactics": ["command-and-control"]}
        },
        "families": {"emotet": ["T1071.001"]},
        "default_techniques": ["T1071.001"],
    }
)


def test_sigma_rules_valid_and_deterministic():
    rules = sigma_mod.build_rules(ROWS, ATTACK)
    assert rules
    for rule in rules:
        assert yaml.safe_load(yaml.safe_dump(rule))["id"] == rule["id"]

    ids = [r["id"] for r in rules]
    assert ids == [r["id"] for r in sigma_mod.build_rules(ROWS, ATTACK)]

    domains: set[str] = set()
    for rule in rules:
        domains.update((rule["detection"].get("selection_apex") or {}).get("QueryName", []))
    assert {"c2-steady-host.com", "malware-cdn-one.com"} <= domains

    tagged = [r for r in rules if r["tags"]]
    assert tagged and all(t.startswith("attack.") for t in tagged[0]["tags"])


def test_sigma_chunking():
    rows = [dict(ROWS[0], key=f"domain:d{i}.com", value=f"d{i}.com") for i in range(3)]
    rules = sigma_mod.build_rules(rows, ATTACK, max_values_per_rule=1)
    assert len(rules) == 3
    assert all("part" in r["title"] for r in rules)


def test_stix_bundle():
    bundle = stix_mod.build_bundle(ROWS, generated_at="2026-10-05T00:00:00Z")
    assert bundle["type"] == "bundle"
    assert bundle["_meta"]["indicator_count"] == 4

    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    patterns = {i["pattern"] for i in indicators}
    assert "[domain-name:value = 'c2-steady-host.com']" in patterns
    assert "[ipv4-addr:value = '91.92.240.11']" in patterns
    assert f"[file:hashes.'SHA-256' = '{'a' * 64}']" in patterns
    assert all(i["object_marking_refs"] for i in indicators)

    malware_names = {o["name"] for o in bundle["objects"] if o["type"] == "malware"}
    assert {"Emotet", "Mozi", "RedLine Stealer"} <= malware_names

    again = stix_mod.build_bundle(ROWS, generated_at="2026-10-05T00:00:00Z")
    ids_a = sorted(o["id"] for o in bundle["objects"] if o["type"] == "indicator")
    ids_b = sorted(o["id"] for o in again["objects"] if o["type"] == "indicator")
    assert ids_a == ids_b


def test_suricata_rules():
    lines = suricata_mod.build_rules(ROWS)
    assert any(line.startswith("alert ip") and "91.92.240.11" in line for line in lines)
    assert any("c2-steady-host.com" in line and "dns.query" in line for line in lines)
    sids = [line.split("sid:")[1].split(";")[0] for line in lines]
    assert len(sids) == len(set(sids))


def test_csv_export(tmp_path):
    path = csv_export.write_csv(ROWS, tmp_path / "iocs.csv")
    with path.open(newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == 4
    assert rows[0]["value"] == "c2-steady-host.com"
