"""Generate Sigma rules ("IOC watchlist" style) from threat intel.

Sigma is normally used for behavioural detections; these rules intentionally
take the watchlist approach that most SOCs still need: match the raw
domains/IPs/hashes seen in public feeds. They are marked ``experimental`` and
should be converted with sigma-cli before deployment.
"""
from __future__ import annotations

import pathlib
import re
import uuid
from datetime import datetime, timezone

import yaml

from ..normalize import detect_type, host_from_url

UUID_NS = uuid.uuid5(uuid.NAMESPACE_URL, "threat-intel-pipeline")
_REPO_URL = "https://github.com/Enendugodwin/threat-intel-pipeline"

_SIGMA_KINDS = ("domain", "ipv4", "ipv6", "sha256", "sha1", "md5")
_HASH_KINDS = ("sha256", "sha1", "md5")


def _slug(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", str(text).lower()).strip("-")
    return (slug[:60] or "unknown")


def _chunks(items: list, size: int) -> list[list]:
    return [items[i : i + size] for i in range(0, len(items), size)]


def _rule(family: str, kind: str, values: list[str], part: int, total_parts: int,
          techniques: list[str]) -> dict:
    suffix = f" (part {part}/{total_parts})" if total_parts > 1 else ""
    rule_id = str(uuid.uuid5(UUID_NS, f"sigma:{family.lower()}:{kind}:{part}"))
    tags = [f"attack.{t.lower().replace('.', '_')}" for t in techniques]

    if kind == "domain":
        logsource = {"category": "dns_query"}
        detection = {
            "selection_apex": {"QueryName": values},
            "selection_subdomains": {"QueryName|endswith": [f".{v}" for v in values]},
            "condition": "selection_apex or selection_subdomains",
        }
    elif kind in ("ipv4", "ipv6"):
        logsource = {"category": "firewall"}
        suffix_len = "/32" if kind == "ipv4" else "/128"
        detection = {
            "selection": {"DestinationIp|cidr": [f"{v}{suffix_len}" for v in values]},
            "condition": "selection",
        }
    else:
        logsource = {"category": "process_creation", "product": "windows"}
        detection = {"selection": {"Hashes|contains": values}, "condition": "selection"}

    rule = {
        "title": f"Threat Intel Watchlist - {family} {kind} IOCs{suffix}",
        "id": rule_id,
        "status": "experimental",
        "description": (
            f"Auto-generated from public threat intel feeds. Matches {len(values)} "
            f"{kind} indicator(s) attributed to '{family}'. Regenerated on every "
            "pipeline run - do not edit by hand; tune or override instead."
        ),
        "references": [_REPO_URL],
        "author": "threat-intel-pipeline",
        "date": datetime.now(timezone.utc).strftime("%Y/%m/%d"),
        "tags": tags,
        "logsource": logsource,
        "detection": detection,
        "falsepositives": [
            "Stale, sinkholed, or repurposed indicators",
            "Shared hosting / cloud infrastructure",
        ],
        "level": "high" if family.lower() != "unattributed" else "medium",
    }
    return rule


def build_rules(rows, attack, max_values_per_rule: int = 200, min_confidence: int = 0) -> list[dict]:
    groups: dict[tuple[str, str], dict[str, str]] = {}

    for row in rows:
        try:
            confidence = int(row["confidence"] or 0)
        except (TypeError, ValueError):
            confidence = 0
        if confidence < min_confidence:
            continue

        kind = row["type"]
        value = row["value"]
        if kind == "url":
            host = host_from_url(value)
            if not host:
                continue
            kind = detect_type(host) or "domain"
            value = host
        if kind not in _SIGMA_KINDS:
            continue

        family = str(row["malware"] or "").strip() or "unattributed"
        bucket = groups.setdefault((family, kind), {})
        bucket.setdefault(value, row["reference"] or "")

    rules: list[dict] = []
    for (family, kind), values_map in sorted(groups.items()):
        values = sorted(values_map)
        chunks = _chunks(values, max(1, int(max_values_per_rule))) or [[]]
        techniques = attack.family_techniques(family)
        for part, chunk in enumerate(chunks, start=1):
            rules.append(_rule(family, kind, chunk, part, len(chunks), techniques))
    return rules


def write_rules(rules: list[dict], out_dir: str | pathlib.Path) -> list[pathlib.Path]:
    out_dir = pathlib.Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[pathlib.Path] = []
    for index, rule in enumerate(rules, start=1):
        filename = f"ti-{_slug(rule['title'])}-{index:04d}.yml"
        path = out_dir / filename
        path.write_text(
            yaml.safe_dump(rule, sort_keys=False, allow_unicode=True, width=200),
            encoding="utf-8",
        )
        written.append(path)

    readme = out_dir / "README.md"
    readme.write_text(
        "# Generated Sigma rules\n\n"
        "IOC watchlist rules generated by `threat-intel-pipeline`. They are\n"
        "`experimental` by design - review and tune before production use.\n\n"
        "Convert and validate with [sigma-cli](https://github.com/SigmaHQ/sigma-cli):\n\n"
        "```bash\n"
        "sigma check ti-*.yml\n"
        "sigma convert -t splunk ti-*.yml\n"
        "sigma convert -t elasticsearch ti-*.yml\n"
        "```\n",
        encoding="utf-8",
    )
    written.append(readme)
    return written
