"""Optional OpenCTI push connector - EXPERIMENTAL.

Pushes indicators one by one through the GraphQL ``indicatorAdd`` mutation.
Verify field names against your OpenCTI version before relying on it; the
canonical way to bulk-load is importing the STIX bundle via an OpenCTI
ingestion connector, which is what `dist/stix/bundle.json` is for.

Environment:

    OPENCTI_URL=https://opencti.example.org
    OPENCTI_TOKEN=<api token>
"""
from __future__ import annotations

import os

from ..exports.stix import pattern_for

_OBSERVABLE_MAP = {
    "domain": "Domain-Name",
    "url": "Url",
    "ipv4": "IPv4-Addr",
    "ipv6": "IPv6-Addr",
    "sha256": "StixFile",
    "sha1": "StixFile",
    "md5": "StixFile",
    "email": "Email-Addr",
}

_MUTATION = """
mutation AddIndicator($input: IndicatorAddInput!) {
  indicatorAdd(input: $input) { id }
}
"""


def push_new(rows, url: str | None = None, token: str | None = None) -> dict:
    url = (url or os.environ.get("OPENCTI_URL", "")).rstrip("/")
    token = token or os.environ.get("OPENCTI_TOKEN", "")
    if not url or not token:
        raise RuntimeError("OPENCTI_URL and OPENCTI_TOKEN must be set (environment or .env)")

    import requests

    session = requests.Session()
    session.headers["Authorization"] = f"Bearer {token}"
    added = errors = 0

    for row in rows:
        pattern = pattern_for(row["type"], row["value"])
        observable_type = _OBSERVABLE_MAP.get(row["type"])
        if not pattern or not observable_type:
            continue
        variables = {
            "input": {
                "name": row["value"],
                "pattern": pattern,
                "pattern_type": "stix",
                "x_opencti_main_observable_type": observable_type,
                "confidence": int(row["confidence"] or 50),
                "valid_from": row["first_seen"] or None,
                "externalReferences": (
                    [{"source_name": "threat-intel-pipeline", "url": row["reference"]}]
                    if row["reference"]
                    else []
                ),
            }
        }
        try:
            response = session.post(
                f"{url}/graphql", json={"query": _MUTATION, "variables": variables}, timeout=30
            )
            payload = response.json()
        except Exception:  # noqa: BLE001 - count and continue
            errors += 1
            continue
        if response.status_code == 200 and not payload.get("errors"):
            added += 1
        else:
            errors += 1
    return {"added": added, "errors": errors}
