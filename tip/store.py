"""SQLite persistence with source tracking, dedupe/merge, and run history."""
from __future__ import annotations

import json
import pathlib
import sqlite3
from datetime import datetime, timedelta, timezone

from .models import IOC

SCHEMA = """
CREATE TABLE IF NOT EXISTS iocs (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    type        TEXT NOT NULL,
    first_seen  TEXT,
    last_seen   TEXT,
    ingested_at TEXT NOT NULL,
    seen_at     TEXT,
    malware     TEXT,
    tags        TEXT NOT NULL DEFAULT '[]',
    confidence  INTEGER NOT NULL DEFAULT 50,
    reference   TEXT
);
CREATE TABLE IF NOT EXISTS ioc_sources (
    key    TEXT NOT NULL,
    source TEXT NOT NULL,
    PRIMARY KEY (key, source)
);
CREATE TABLE IF NOT EXISTS runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at  TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    stats       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type);
CREATE INDEX IF NOT EXISTS idx_iocs_malware ON iocs(malware);
CREATE INDEX IF NOT EXISTS idx_iocs_ingested ON iocs(ingested_at);
CREATE INDEX IF NOT EXISTS idx_ioc_sources_source ON ioc_sources(source);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _cutoff(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _pairs(rows) -> list[tuple]:
    return [(r[0], r[1]) for r in rows]


def _union(a, b) -> list[str]:
    out: list[str] = []
    for item in list(a) + list(b):
        s = str(item)
        if s and s not in out:
            out.append(s)
    return out


def _min_ts(*values):
    vals = [v for v in values if v]
    return min(vals) if vals else None


def _max_ts(*values):
    vals = [v for v in values if v]
    return max(vals) if vals else None


def _merge_group(members: list[IOC]) -> IOC:
    """Merge duplicate IOCs (same key) reported by one or more feeds."""
    base = members[0]
    first = _min_ts(*(m.first_seen for m in members))
    last = _max_ts(*(m.last_seen for m in members))
    tags = _union([], [t for m in members for t in m.tags])
    malware = next((m.malware for m in members if m.malware), None)
    reference = next((m.reference for m in members if m.reference), None)
    confidence = max(m.confidence for m in members)
    return IOC(
        value=base.value,
        type=base.type,
        source=base.source,
        first_seen=first,
        last_seen=last,
        tags=tags,
        malware=malware,
        confidence=confidence,
        reference=reference,
    )


class Store:
    """Thin SQLite wrapper. Accepts plain dicts or sqlite rows on read paths."""

    def __init__(self, path: str | pathlib.Path):
        self.path = pathlib.Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self._migrate()
        self.conn.commit()

    def _migrate(self) -> None:
        """Add columns introduced after the first release (idempotent)."""
        columns = {row[1] for row in self.conn.execute("PRAGMA table_info(iocs)")}
        if "seen_at" not in columns:
            self.conn.execute("ALTER TABLE iocs ADD COLUMN seen_at TEXT")
            self.conn.execute("UPDATE iocs SET seen_at = ingested_at WHERE seen_at IS NULL")

    # -- lifecycle ---------------------------------------------------------
    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- writes ------------------------------------------------------------
    def upsert_many(self, iocs: list[IOC], now: str | None = None) -> tuple[int, int]:
        """Insert/merge IOCs. Returns (new, updated) counts for distinct keys.

        Duplicate keys within the batch are merged first; every contributing
        source is recorded in ``ioc_sources``.
        """
        now = now or utcnow()
        groups: dict[str, list[IOC]] = {}
        for ioc in iocs:
            groups.setdefault(ioc.key, []).append(ioc)

        new = updated = 0
        for key, members in groups.items():
            merged = _merge_group(members)
            sources = sorted({m.source for m in members})
            row = self.conn.execute("SELECT * FROM iocs WHERE key = ?", (key,)).fetchone()

            if row is None:
                new += 1
                self.conn.execute(
                    "INSERT INTO iocs (key, value, type, first_seen, last_seen, ingested_at,"
                    " seen_at, malware, tags, confidence, reference) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        key,
                        merged.value,
                        merged.type,
                        merged.first_seen,
                        merged.last_seen,
                        now,
                        now,
                        merged.malware,
                        json.dumps(merged.tags, ensure_ascii=False),
                        merged.confidence,
                        merged.reference,
                    ),
                )
            else:
                updated += 1
                merged.tags = _union(json.loads(row["tags"] or "[]"), merged.tags)
                merged.first_seen = _min_ts(row["first_seen"], merged.first_seen)
                merged.last_seen = _max_ts(row["last_seen"], merged.last_seen)
                merged.malware = row["malware"] or merged.malware
                merged.confidence = max(int(row["confidence"] or 0), merged.confidence)
                merged.reference = row["reference"] or merged.reference
                self.conn.execute(
                    "UPDATE iocs SET value=?, first_seen=?, last_seen=?, malware=?, tags=?,"
                    " confidence=?, reference=?, seen_at=? WHERE key=?",
                    (
                        merged.value,
                        merged.first_seen,
                        merged.last_seen,
                        merged.malware,
                        json.dumps(merged.tags, ensure_ascii=False),
                        merged.confidence,
                        merged.reference,
                        now,
                        key,
                    ),
                )

            for source in sources:
                self.conn.execute(
                    "INSERT OR IGNORE INTO ioc_sources (key, source) VALUES (?, ?)", (key, source)
                )

        self.conn.commit()
        return new, updated

    def prune(self, days: int) -> int:
        """Drop IOCs that have been in the database longer than ``days``."""
        cutoff = _cutoff(days)
        cur = self.conn.execute(
            "DELETE FROM iocs WHERE COALESCE(seen_at, ingested_at) < ?", (cutoff,)
        )
        removed = cur.rowcount
        self.conn.execute("DELETE FROM ioc_sources WHERE key NOT IN (SELECT key FROM iocs)")
        self.conn.commit()
        return removed

    def record_run(self, stats: dict) -> None:
        self.conn.execute(
            "INSERT INTO runs (started_at, finished_at, stats) VALUES (?, ?, ?)",
            (
                stats.get("started_at") or utcnow(),
                stats.get("finished_at") or utcnow(),
                json.dumps(stats, ensure_ascii=False, sort_keys=True),
            ),
        )
        self.conn.commit()

    # -- reads -------------------------------------------------------------
    def total(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]

    def count_confidence(self, minimum: int = 80) -> int:
        return self.conn.execute(
            "SELECT COUNT(*) FROM iocs WHERE confidence >= ?", (int(minimum),)
        ).fetchone()[0]

    def activity(self, days: int = 7) -> dict:
        """Sum run deltas over the last N days (actual new/updated/pruned)."""
        cutoff = _cutoff(days)
        rows = self.conn.execute(
            "SELECT stats FROM runs WHERE finished_at >= ?", (cutoff,)
        ).fetchall()
        new = updated = pruned = 0
        for row in rows:
            try:
                stats = json.loads(row["stats"] or "{}")
            except (TypeError, json.JSONDecodeError):
                continue
            new += int(stats.get("new") or 0)
            updated += int(stats.get("updated") or 0)
            pruned += int(stats.get("pruned") or 0)
        return {"new": new, "updated": updated, "pruned": pruned, "runs": len(rows)}

    def counts_by_type(self) -> list[tuple[str, int]]:
        return _pairs(
            self.conn.execute("SELECT type, COUNT(*) FROM iocs GROUP BY type ORDER BY 2 DESC")
        )

    def counts_by_source(self) -> list[tuple[str, int]]:
        return _pairs(
            self.conn.execute(
                "SELECT source, COUNT(*) FROM ioc_sources GROUP BY source ORDER BY 2 DESC"
            )
        )

    def top_malware(self, limit: int = 20) -> list[tuple[str, int]]:
        return _pairs(
            self.conn.execute(
                "SELECT malware, COUNT(*) FROM iocs WHERE malware IS NOT NULL"
                " GROUP BY malware ORDER BY 2 DESC LIMIT ?",
                (limit,),
            )
        )

    def all_rows(self, limit: int | None = None) -> list[sqlite3.Row]:
        sql = "SELECT * FROM iocs ORDER BY key"
        if limit:
            sql += f" LIMIT {int(limit)}"
        return self.conn.execute(sql).fetchall()

    def new_since(self, days: int, limit: int | None = None) -> list[sqlite3.Row]:
        sql = (
            "SELECT i.*, COALESCE((SELECT GROUP_CONCAT(s.source) FROM ioc_sources s"
            " WHERE s.key = i.key), '') AS sources"
            " FROM iocs i WHERE i.ingested_at >= ?"
            " ORDER BY i.confidence DESC, i.first_seen DESC"
        )
        params: list = [_cutoff(days)]
        if limit:
            sql += " LIMIT ?"
            params.append(int(limit))
        return self.conn.execute(sql, params).fetchall()

    def rows_for_export(
        self,
        days: int,
        limit: int,
        min_confidence: int = 0,
        exclude_sources: list[str] | None = None,
    ) -> list[sqlite3.Row]:
        cutoff = _cutoff(days)
        clauses = [
            "(i.ingested_at >= ? OR COALESCE(i.last_seen, i.ingested_at) >= ?)",
            "i.confidence >= ?",
        ]
        params: list = [cutoff, cutoff, min_confidence]
        for source in exclude_sources or []:
            clauses.append("i.key NOT IN (SELECT key FROM ioc_sources WHERE source = ?)")
            params.append(source)
        sql = (
            "SELECT i.*, COALESCE((SELECT GROUP_CONCAT(s.source) FROM ioc_sources s"
            " WHERE s.key = i.key), '') AS sources"
            " FROM iocs i WHERE " + " AND ".join(clauses)
            + " ORDER BY i.confidence DESC, i.first_seen DESC LIMIT ?"
        )
        params.append(int(limit))
        return self.conn.execute(sql, params).fetchall()

    def source_rows(self, source: str, limit: int | None = None) -> list[sqlite3.Row]:
        """Rows reported by one source (e.g. the Tor context list)."""
        sql = (
            "SELECT i.*, COALESCE((SELECT GROUP_CONCAT(s.source) FROM ioc_sources s"
            " WHERE s.key = i.key), '') AS sources"
            " FROM iocs i JOIN ioc_sources src ON src.key = i.key AND src.source = ?"
            " ORDER BY i.value"
        )
        params: list = [source]
        if limit:
            sql += " LIMIT ?"
            params.append(int(limit))
        return self.conn.execute(sql, params).fetchall()

    def last_run(self) -> dict | None:
        row = self.conn.execute("SELECT * FROM runs ORDER BY id DESC LIMIT 1").fetchone()
        if row is None:
            return None
        out = dict(row)
        try:
            out["stats"] = json.loads(out["stats"])
        except (TypeError, json.JSONDecodeError):
            out["stats"] = {}
        return out

    def stats(self) -> dict:
        return {
            "total": self.total(),
            "by_type": dict(self.counts_by_type()),
            "by_source": dict(self.counts_by_source()),
            "by_malware": dict(self.top_malware()),
        }
