"""STIX 2.1 bundle for the report feed: threat actors, malware and report objects.

Indicator references reuse the same deterministic UUIDv5 namespace as the main
bundle, so a report's ``object_refs`` line up with the indicator objects
exported alongside it. Import both bundles into OpenCTI/MISP for the full
picture (actors -> malware -> indicators, grouped per report).
"""
from __future__ import annotations

import re
import uuid

from ..normalize import refang
from . import stix as base

_ACTOR_RE = re.compile(
    r"^(?:APT\d{1,2}|UNC\d{3,6}|UAT-\d{4,5}|Storm-\d{4,5}|FIN\d{1,2}|TA\d{2,4}|G\d{4}"
    r"|Operation\s+.+)$",
    re.IGNORECASE,
)


def _published(value: str, fallback: str) -> str:
    value = str(value or "").strip()
    return value if len(value) >= 10 and value[:4].isdigit() else fallback


def build_reports_bundle(
    reports_doc: dict,
    family_names=None,
    generated_at: str | None = None,
    max_reports: int = 150,
) -> dict:
    now = base._now(generated_at)
    family_names = {str(name).lower() for name in (family_names or [])}

    objects: list[dict] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": base.IDENTITY_ID,
            "created": base.TLP_CLEAR_CREATED,
            "modified": base.TLP_CLEAR_CREATED,
            "name": "threat-intel-pipeline",
            "identity_class": "system",
        },
        {
            "type": "marking-definition",
            "spec_version": "2.1",
            "id": base.TLP_CLEAR_ID,
            "created": base.TLP_CLEAR_CREATED,
            "definition_type": "tlp",
            "definition": {"tlp": "clear"},
        },
    ]

    actor_ids: dict[str, str] = {}
    malware_ids: dict[str, str] = {}
    relationships: set[tuple[str, str]] = set()
    report_count = 0

    for report in (reports_doc.get("reports") or [])[:max_reports]:
        tags = [str(tag).strip() for tag in report.get("tags") or []]
        actor_refs: list[str] = []
        malware_refs: list[str] = []

        for tag in tags:
            if _ACTOR_RE.match(tag):
                key = tag.lower()
                actor_id = actor_ids.get(key)
                if actor_id is None:
                    actor_id = f"threat-actor--{uuid.uuid5(base.UUID_NS, f'actor:{key}')}"
                    actor_ids[key] = actor_id
                    obj = base._base_object("threat-actor", actor_id, now)
                    obj.update({"name": tag})
                    objects.append(obj)
                actor_refs.append(actor_id)
            if tag.lower() in family_names:
                key = tag.lower()
                malware_id = malware_ids.get(key)
                if malware_id is None:
                    malware_id = f"malware--{uuid.uuid5(base.UUID_NS, f'malware:{key}')}"
                    malware_ids[key] = malware_id
                    obj = base._base_object("malware", malware_id, now)
                    obj.update({"name": tag, "is_family": True})
                    objects.append(obj)
                malware_refs.append(malware_id)

        for actor_ref in actor_refs:
            for malware_ref in malware_refs:
                pair = (actor_ref, malware_ref)
                if pair in relationships:
                    continue
                relationships.add(pair)
                rel_id = f"relationship--{uuid.uuid5(base.UUID_NS, f'uses:{actor_ref}:{malware_ref}')}"
                rel = base._base_object("relationship", rel_id, now)
                rel.update(
                    {
                        "relationship_type": "uses",
                        "source_ref": actor_ref,
                        "target_ref": malware_ref,
                    }
                )
                objects.append(rel)

        indicator_refs: list[str] = []
        for ioc in report.get("iocs") or []:
            value = refang(str(ioc.get("value") or ""))
            kind = str(ioc.get("type") or "")
            if not value or not kind:
                continue
            indicator_refs.append(
                f"indicator--{uuid.uuid5(base.UUID_NS, f'indicator:{kind}:{value.lower()}')}"
            )

        if not indicator_refs and not actor_refs and not malware_refs:
            continue

        report_id = f"report--{uuid.uuid5(base.UUID_NS, f'report:{report.get('id')}')}"
        obj = base._base_object("report", report_id, now)
        obj.update(
            {
                "name": str(report.get("title") or "")[:120] or str(report.get("id")),
                "description": str(report.get("summary") or "")[:1000],
                "report_types": ["threat-report"],
                "published": _published(report.get("published"), now),
                "object_refs": (indicator_refs[:300] + actor_refs + malware_refs)
                or [base.IDENTITY_ID],
            }
        )
        objects.append(obj)
        report_count += 1

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
        "_meta": {
            "report_count": report_count,
            "actor_count": len(actor_ids),
            "malware_count": len(malware_ids),
            "generated_at": now,
        },
    }
