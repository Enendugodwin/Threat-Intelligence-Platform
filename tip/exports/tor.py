"""Export the current Tor node/exit list as plain text.

The format is deliberately boring: one address per line after a short
``#``-comment header, ready for firewall sets, proxy bypass lists or
threat-intel platform uploads.
"""
from __future__ import annotations

import pathlib
from datetime import datetime, timezone


def write_nodes(rows, path: str | pathlib.Path) -> tuple[pathlib.Path, int]:
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    addresses = sorted({str(row["value"]) for row in rows})
    header = (
        "# Tor relay/exit node addresses (source: Tor Project Onionoo)\n"
        f"# Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}\n"
        f"# Addresses: {len(addresses)}\n"
    )
    body = "\n".join(addresses) + ("\n" if addresses else "")
    path.write_text(header + body, encoding="utf-8")
    return path, len(addresses)
