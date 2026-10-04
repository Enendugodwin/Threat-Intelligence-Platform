import pathlib

from tip.attack import load_attack_map

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _map():
    return load_attack_map(ROOT / "config" / "attack_map.yaml")


def test_family_lookup_variants():
    attack = _map()
    assert "T1071.001" in attack.family_techniques("QakBot")
    assert "T1071.001" in attack.family_techniques("js.fakeupdates")  # dot-prefix stripped
    assert "T1555" in attack.family_techniques("win.redline")  # dot-prefix stripped
    assert "T1486" in attack.family_techniques("LockBit")
    assert attack.family_techniques("totally-unknown-thing") == []


def test_tag_and_default_rules():
    attack = _map()
    techs = attack.techniques_for(None, ["ransomware", "loader"], "domain")
    assert "T1486" in techs and "T1105" in techs
    assert attack.techniques_for(None, [], "domain") == ["T1071.001"]
    assert attack.techniques_for(None, [], "sha256") == []


def test_aliases_in_tags_match_families():
    attack = _map()
    # threatfox-style alias tag for a known family
    techs = attack.techniques_for(None, ["SocGholish"], "url")
    assert "T1189" in techs


def test_coverage_aggregation():
    attack = _map()
    rows = [
        {"malware": "Emotet", "tags": "[]", "type": "domain"},
        {"malware": None, "tags": '["ransomware"]', "type": "ipv4"},
    ]
    coverage = attack.coverage(rows)
    assert coverage["T1071.001"]["count"] >= 1
    assert coverage["T1486"]["name"] == "Data Encrypted for Impact"
    assert coverage["T1486"]["basis"]["tag"] == 1
    assert coverage["T1071.001"]["primary"] >= 1
    assert coverage["T1071.001"]["basis"]["family"] >= 1
