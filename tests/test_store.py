from tip.models import IOC
from tip.store import Store


def _ioc(**kw):
    base = dict(value="evil.com", type="domain", source="feed-a")
    base.update(kw)
    return IOC(**base)


def test_upsert_merge_and_stats(tmp_path):
    store = Store(tmp_path / "iocs.sqlite")
    new, updated = store.upsert_many([_ioc()])
    assert (new, updated) == (1, 0)

    second = _ioc(source="feed-b", tags=["loader"], malware="Emotet", confidence=80)
    new, updated = store.upsert_many([second])
    assert (new, updated) == (0, 1)
    assert dict(store.counts_by_source()) == {"feed-a": 1, "feed-b": 1}

    row = store.all_rows()[0]
    assert row["malware"] == "Emotet"
    assert row["confidence"] == 80
    assert "loader" in row["tags"]
    store.close()


def test_batch_dedupe_merges_sources(tmp_path):
    store = Store(tmp_path / "iocs.sqlite")
    new, updated = store.upsert_many([_ioc(), _ioc(source="feed-b")])
    assert (new, updated) == (1, 0)
    assert dict(store.counts_by_source()) == {"feed-a": 1, "feed-b": 1}
    store.close()


def test_new_since_and_prune(tmp_path):
    store = Store(tmp_path / "iocs.sqlite")
    store.upsert_many([_ioc()], now="2020-01-01T00:00:00Z")
    assert store.new_since(7) == []  # ingested too long ago
    removed = store.prune(45)
    assert removed == 1
    assert store.total() == 0
    store.close()


def test_reseen_indicator_survives_prune(tmp_path):
    store = Store(tmp_path / "iocs.sqlite")
    store.upsert_many([_ioc()], now="2020-01-01T00:00:00Z")
    store.upsert_many([_ioc()])  # seen again today -> seen_at refreshed
    assert store.prune(45) == 0
    assert store.total() == 1
    store.close()


def test_rows_for_export_excludes_sources(tmp_path):
    store = Store(tmp_path / "iocs.sqlite")
    store.upsert_many([_ioc(), _ioc(value="45.61.136.9", type="ipv4", source="tor")])
    rows = store.rows_for_export(30, 100, 0, exclude_sources=["tor"])
    assert len(rows) == 1
    assert rows[0]["value"] == "evil.com"
    store.close()


def test_run_history(tmp_path):
    store = Store(tmp_path / "iocs.sqlite")
    store.record_run({"started_at": "2026-10-04T00:00:00Z", "finished_at": "2026-10-04T00:01:00Z", "new": 3})
    last = store.last_run()
    assert last is not None
    assert last["stats"]["new"] == 3
    store.close()
