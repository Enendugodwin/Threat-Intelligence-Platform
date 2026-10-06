"""Heuristic MITRE ATT&CK mapping for IOCs from public feeds.

Mapping is intentionally simple and explainable:

1. exact / partial match of the malware family against ``families``
2. alias match: tags that name a known family
3. regex tag rules (e.g. any tag containing "ransomware")
4. optional default techniques for network-type IOCs with no other signal

It is a heuristic - good enough for reporting coverage trends, not a
substitute for analyst attribution.
"""
from __future__ import annotations

import json
import re

import yaml


def load_attack_map(path) -> "AttackMap":
    with open(path, "r", encoding="utf-8") as fh:
        return AttackMap(yaml.safe_load(fh) or {})


class AttackMap:
    def __init__(self, cfg: dict):
        self.techniques: dict[str, dict] = cfg.get("techniques") or {}
        self.families: dict[str, list[str]] = {
            str(k).strip().lower(): list(v or []) for k, v in (cfg.get("families") or {}).items()
        }
        self.tag_rules = [
            (re.compile(str(rule["match"]), re.IGNORECASE), list(rule.get("techniques") or []))
            for rule in (cfg.get("tag_rules") or [])
            if rule.get("match")
        ]
        self.default_techniques: list[str] = list(cfg.get("default_techniques") or [])

    # -- mapping -----------------------------------------------------------
    def family_techniques(self, malware: str | None) -> list[str]:
        if not malware:
            return []
        m = str(malware).strip().lower()
        candidates = [m]
        if "." in m:
            candidates.append(m.split(".")[-1])  # js.fakeupdates -> fakeupdates
        if m.endswith("loader") and len(m) > 6:
            candidates.append(m[: -len("loader")])  # bazarloader -> bazar
        for candidate in candidates:
            if candidate in self.families:
                return list(self.families[candidate])
        for family, techniques in self.families.items():
            if family in m:
                return list(techniques)
        return []

    def techniques_for(self, malware: str | None, tags, ioc_type: str | None) -> list[str]:
        return self.classification(malware, tags, ioc_type)[0]

    def classification(self, malware: str | None, tags, ioc_type: str | None) -> tuple[list[str], str]:
        """Return ``(techniques, basis)`` where basis is family|tag|heuristic|none.

        The basis makes evidence strength visible: family mappings are the
        strongest signal, regex tag rules are inferred, and the configured
        ``default_techniques`` are heuristics applied to bare network IOCs.
        """
        found: set[str] = set(self.family_techniques(malware))
        basis = "family" if found else ""
        tag_list = [str(t) for t in (tags or [])]

        if not found:
            for tag in tag_list:
                t = tag.strip().lower()
                if t in self.families:
                    found.update(self.families[t])
                    basis = basis or "tag"

        tag_hits = False
        blob = " ".join(tag_list)
        for rx, techniques in self.tag_rules:
            if rx.search(blob):
                found.update(techniques)
                tag_hits = True
        if tag_hits and not basis:
            basis = "tag"

        if not found and ioc_type in ("domain", "url", "ipv4", "ipv6"):
            found.update(self.default_techniques)
            basis = "heuristic"

        if not found:
            basis = "none"
        return sorted(found), basis

    def name(self, technique_id: str) -> str:
        return (self.techniques.get(technique_id) or {}).get("name", technique_id)

    def tactics(self, technique_id: str) -> list[str]:
        return list((self.techniques.get(technique_id) or {}).get("tactics") or [])

    # -- aggregation -------------------------------------------------------
    def coverage(
        self,
        rows,
        classifications: dict[str, tuple[list[str], str]] | None = None,
    ) -> dict[str, dict]:
        """Count IOCs per technique, split by evidence basis.

        Entries carry ``count`` (all), ``primary`` (family + tag evidence) and
        ``basis`` counts so heuristics can be excluded from the headline number.
        Sorted by primary evidence first. Callers that already classified rows
        can pass that mapping to avoid repeating regex/tag evaluation.
        """
        counts: dict[str, dict] = {}
        for row in rows:
            try:
                key = str(row["key"])
            except (IndexError, KeyError, TypeError):
                key = ""
            result = classifications.get(key) if classifications is not None else None
            if result is None:
                try:
                    tags = json.loads(row["tags"] or "[]")
                except (TypeError, ValueError):
                    tags = []
                result = self.classification(row["malware"], tags, row["type"])
            techniques, basis = result
            for technique in techniques:
                entry = counts.setdefault(
                    technique,
                    {
                        "count": 0,
                        "name": self.name(technique),
                        "tactics": self.tactics(technique),
                        "basis": {"family": 0, "tag": 0, "heuristic": 0},
                    },
                )
                entry["count"] += 1
                if basis in entry["basis"]:
                    entry["basis"][basis] += 1
        for entry in counts.values():
            entry["primary"] = entry["basis"].get("family", 0) + entry["basis"].get("tag", 0)
        return dict(
            sorted(counts.items(), key=lambda kv: (-kv[1]["primary"], -kv[1]["count"], kv[0]))
        )
