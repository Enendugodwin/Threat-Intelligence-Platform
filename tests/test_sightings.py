from tip.sightings import import_sightings, sights_summary
from tip.store import Store


def test_sightings_import_and_map(tmp_path):
    csv_path = tmp_path / "sightings.csv"
    csv_path.write_text(
        "value,type,sensor,asset,first_seen,last_seen,count\n"
        "evil[.]com,,firewall,edge-fw,2026-10-03T21:12:00Z,2026-10-04T18:44:00Z,7\n"
        "http://evil[.]com/x,url,dns,dc1,2026-10-04T00:00:00Z,2026-10-04T01:00:00Z,3\n"
        "not-an-ioc,,edr,,,,\n",
        encoding="utf-8",
    )
    stats = import_sightings(tmp_path, csv_path)
    assert stats["records"] == 2
    assert stats["skipped"] == 1

    summary = sights_summary(tmp_path)
    assert summary["total_sightings"] == 10
    assert "firewall" in summary["sensors"]

    with Store(tmp_path / "iocs.sqlite") as store:
        smap = store.sightings_map()
    assert smap["domain:evil.com"]["count"] == 7
    assert smap["domain:evil.com"]["sensors"] == ["firewall"]

    # same (sensor, asset) re-import: count keeps the max, not the sum
    csv_path.write_text(
        "value,type,sensor,asset,first_seen,last_seen,count\n"
        "evil[.]com,,firewall,edge-fw,2026-10-03T21:00:00Z,,4\n",
        encoding="utf-8",
    )
    import_sightings(tmp_path, csv_path)
    with Store(tmp_path / "iocs.sqlite") as store:
        smap = store.sightings_map()
    assert smap["domain:evil.com"]["count"] == 7  # max(7, 4)

    # a different sensor adds to the total and unions sensors
    csv_path.write_text(
        "value,type,sensor,asset,first_seen,last_seen,count\n"
        "evil[.]com,,dns,dc1,2026-10-04T00:00:00Z,,5\n",
        encoding="utf-8",
    )
    import_sightings(tmp_path, csv_path)
    with Store(tmp_path / "iocs.sqlite") as store:
        smap = store.sightings_map()
    assert smap["domain:evil.com"]["count"] == 12
    assert sorted(smap["domain:evil.com"]["sensors"]) == ["dns", "firewall"]
