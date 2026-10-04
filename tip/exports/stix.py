"""STIX 2.1 bundle export.

Indicators are exported as deterministic STIX objects (stable UUIDv5 ids) so
regenerating a bundle produces a clean diff and OpenCTI/MISP ingestion stays
idempotent. Every object is marked TLP:CLEAR and attributed to the identity
``threat-intel-pipeline``.
"""
from __future__ import annotations

import json
import pathlib
import uuid
from datetime import datetime, timezone

UUID_NS = uuid.uuid5(uuid.NAMESPACE_URL, "threat-intel-pipeline")
IDENTITY_ID = f"identity--{uuid.uuid5(UUID_NS, 'identity')}"
TLP_CLEAR_ID = "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
TLP_CLEAR_CREATED = "2017-01-20T00:00:00.000Z"

_TYPE_MAP = {
    "domain": "domain-name:value",
    "url": "url:value",
    "ipv4": "ipv4-addr:value",
    "ipv6": "ipv6-addr:value",
    "email": "email-addr:value",
}
_HASH_MAP = {"sha256": "SHA-256", "sha1": "SHA-1", "md5": "MD5"}


def _esc(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace("'", "\\'")


def pattern_for(ioc_type: str, value: str) -> str | None:
    if ioc_type in _TYPE_MAP:
        return f"[{_TYPE_MAP[ioc_type]} = '{_esc(value)}']"
    if ioc_type in _HASH_MAP:
        return f"[file:hashes.'{_HASH_MAP[ioc_type]}' = '{_esc(value)}']"
    return None


def _now(generated_at: str | None = None) -> str:
    if generated_at:
        return generated_at
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _base_object(spec_type: str, object_id: str, now: str) -> dict:
    return {
        "type": spec_type,
        "spec_version": "2.1",
        "id": object_id,
        "created": now,
        "modified": now,
        "created_by_ref": IDENTITY_ID,
        "object_marking_refs": [TLP_CLEAR_ID],
    }


def build_bundle(rows, generated_at: str | None = None) -> dict:
    now = _now(generated_at)
    objects: list[dict] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": IDENTITY_ID,
            "created": TLP_CLEAR_CREATED,
            "modified": TLP_CLEAR_CREATED,
            "name": "threat-intel-pipeline",
            "identity_class": "system",
        },
        {
            "type": "marking-definition",
            "spec_version": "2.1",
            "id": TLP_CLEAR_ID,
            "created": TLP_CLEAR_CREATED,
            "definition_type": "tlp",
            "definition": {"tlp": "clear"},
        },
    ]
    malware_cache: dict[str, str] = {}
    indicator_count = 0

    for row in rows:
        pattern = pattern_for(row["type"], row["value"])
        if not pattern:
            continue
        key = row["key"] if "key" in row.keys() else f"{row['type']}:{row['value']}"
        indicator_id = f"indicator--{uuid.uuid5(UUID_NS, f'indicator:{key}')}"

        sources = [s for s in str(row["sources"] or "").split(",") if s]
        source_name = sources[0] if sources else "unknown"
        description = f"Source: {', '.join(sources) if sources else source_name}"
        if row["malware"]:
            description += f" | Malware family: {row['malware']}"

        indicator = _base_object("indicator", indicator_id, now)
        indicator.update(
            {
                "name": f"Malicious {row['type']}: {row['value']}",
                "description": description,
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": row["first_seen"] or now,
                "confidence": int(row["confidence"] or 50),
                "labels": ["malicious-activity"],
            }
        )
        if row["reference"]:
            indicator["external_references"] = [
                {"source_name": source_name, "url": row["reference"]}
            ]
        objects.append(indicator)
        indicator_count += 1

        if row["malware"]:
            family = str(row["malware"]).strip()
            malware_id = malware_cache.get(family.lower())
            if malware_id is None:
                malware_id = f"malware--{uuid.uuid5(UUID_NS, f'malware:{family.lower()}')}"
                malware_cache[family.lower()] = malware_id
                malware_obj = _base_object("malware", malware_id, now)
                malware_obj.update({"name": family, "is_family": True})
                objects.append(malware_obj)
            rel_id = f"relationship--{uuid.uuid5(UUID_NS, f'indicates:{key}:{family.lower()}')}"
            relationship = _base_object("relationship", rel_id, now)
            relationship.update(
                {
                    "relationship_type": "indicates",
                    "source_ref": indicator_id,
                    "target_ref": malware_id,
                }
            )
            objects.append(relationship)

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
        "_meta": {"indicator_count": indicator_count, "generated_at": now},
    }


def write_bundle(bundle: dict, path: str | pathlib.Path) -> pathlib.Path:
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    return path
