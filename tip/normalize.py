"""IOC parsing, validation, normalization, and refang/defang helpers."""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from urllib.parse import quote, urlsplit, urlunsplit

from .models import IOC

__all__ = [
    "detect_type",
    "defang",
    "refang",
    "is_public",
    "host_from_url",
    "normalize_value",
    "make_ioc",
    "norm_ts",
    "virustotal_url",
]

_URL_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$",
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(
    r"^[a-z0-9._%+-]+@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)
_HASH_RES = {
    "md5": re.compile(r"^[0-9a-f]{32}$", re.IGNORECASE),
    "sha1": re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE),
    "sha256": re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE),
}

_BLOCKED_NAMES = {
    "localhost",
    "localhost.localdomain",
    "example.com",
    "example.org",
    "example.net",
}
_BLOCKED_SUFFIXES = (
    ".local",
    ".localdomain",
    ".internal",
    ".lan",
    ".home",
    ".arpa",
    ".invalid",
    ".test",
    ".example",
    ".onion",
)

# ---------------------------------------------------------------------------
# refang / defang
# ---------------------------------------------------------------------------

_HXXP_RE = re.compile(r"(?i)\bhxxp(s?)\s*(?:\[:\]|\(:\)|:)\s*//")
_HXXP_PLAIN_RE = re.compile(r"(?i)\bhxxp(s?)://")
_REFANG_REPLACEMENTS = (
    ("[.]", "."),
    ("(.)", "."),
    ("{.}", "."),
    ("[dot]", "."),
    ("[DOT]", "."),
    ("[:]", ":"),
    ("[/]", "/"),
    ("[at]", "@"),
    ("[@]", "@"),
)


def refang(text: str) -> str:
    """Turn defanged indicators (hxxp://evil[.]com) back into real form."""
    t = (text or "").strip()
    if not t:
        return t
    t = re.sub(r"(?i)\bhxxp(s?)://", r"http\1://", t)
    t = _HXXP_RE.sub(lambda m: "https://" if m.group(1) else "http://", t)
    for src, dst in _REFANG_REPLACEMENTS:
        t = t.replace(src, dst)
    return t


def defang(text: str) -> str:
    """Make an indicator safe to display (hxxp://evil[.]com)."""
    t = (text or "").strip()
    if not t:
        return t
    t = re.sub(r"(?i)^(https?)://", lambda m: "hxxps://" if m.group(1).lower() == "https" else "hxxp://", t)
    return t.replace(".", "[.]")


# Kept for clarity in callers that only need scheme handling.
def _unused_plain_hxxp(text: str) -> str:  # pragma: no cover - helper for future use
    return _HXXP_PLAIN_RE.sub(r"http\1://", text)


# ---------------------------------------------------------------------------
# type detection / validation
# ---------------------------------------------------------------------------


def detect_type(value: str) -> str | None:
    """Best-effort IOC type detection. Returns None for unrecognized values."""
    v = (value or "").strip()
    if not v:
        return None
    if _URL_RE.match(v):
        return "url"
    for hash_type, rx in _HASH_RES.items():
        if rx.match(v):
            return hash_type
    if _EMAIL_RE.match(v):
        return "email"
    try:
        ip = ipaddress.ip_address(v)
    except ValueError:
        pass
    else:
        return "ipv6" if ip.version == 6 else "ipv4"
    if _DOMAIN_RE.match(v):
        return "domain"
    if v.endswith(".") and _DOMAIN_RE.match(v[:-1]):
        return "domain"  # tolerate fully-qualified trailing dot
    return None


def is_public(value: str, ioc_type: str) -> bool:
    """Reject private / reserved infrastructure and placeholder domains."""
    if ioc_type in ("ipv4", "ipv6"):
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return False
        return not (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    host = (value or "").lower().rstrip(".")
    if not host or host in _BLOCKED_NAMES:
        return False
    if host.endswith(_BLOCKED_SUFFIXES):
        return False
    if "." not in host:
        return False
    return True


def host_from_url(url: str) -> str | None:
    """Extract the (lowercased) hostname from a URL."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    host = parts.hostname
    return host.lower().rstrip(".") if host else None


def normalize_value(value: str, ioc_type: str) -> str:
    """Canonicalize an indicator value for storage and matching."""
    v = (value or "").strip()
    if ioc_type == "url":
        parts = urlsplit(v)
        return urlunsplit(
            (parts.scheme.lower(), parts.netloc.lower(), parts.path, parts.query, parts.fragment)
        )
    if ioc_type == "domain":
        return v.lower().rstrip(".")
    if ioc_type == "email":
        return v.lower()
    if ioc_type in ("ipv4", "ipv6"):
        return str(ipaddress.ip_address(v))
    if ioc_type in _HASH_RES:
        return v.lower()
    return v


def make_ioc(
    value: str,
    source: str,
    *,
    ioc_type: str | None = None,
    first_seen: str | None = None,
    last_seen: str | None = None,
    tags: list[str] | None = None,
    malware: str | None = None,
    confidence: int = 50,
    reference: str | None = None,
) -> IOC | None:
    """Build a validated, normalized IOC. Returns None if the value is unusable."""
    v = refang(value)
    if not v:
        return None
    t = ioc_type or detect_type(v)
    if not t:
        return None
    try:
        v = normalize_value(v, t)
    except ValueError:
        return None

    if t == "url":
        host = host_from_url(v)
        if not host:
            return None
        host_type = detect_type(host) or "domain"
        if not is_public(host, host_type):
            return None
    elif t == "domain":
        if not _DOMAIN_RE.match(v) or not is_public(v, t):
            return None
    elif t in ("ipv4", "ipv6"):
        if not is_public(v, t):
            return None
    elif t == "email":
        if not _EMAIL_RE.match(v):
            return None

    return IOC(
        value=v,
        type=t,
        source=source,
        first_seen=norm_ts(first_seen),
        last_seen=norm_ts(last_seen),
        tags=[str(x) for x in (tags or []) if str(x).strip()],
        malware=malware or None,
        confidence=int(confidence),
        reference=reference,
    )


# ---------------------------------------------------------------------------
# timestamps
# ---------------------------------------------------------------------------


def norm_ts(ts: str | None) -> str | None:
    """Normalize feed timestamps to ``YYYY-MM-DDTHH:MM:SSZ`` (UTC)."""
    if ts is None:
        return None
    s = str(ts).strip()
    if not s:
        return None
    candidate = s.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(candidate)
    except ValueError:
        return s
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def virustotal_url(ioc_type: str, value: str) -> str:
    """Lookup link for a (possibly defanged) indicator on VirusTotal."""
    real = refang(value)
    if ioc_type in ("sha256", "sha1", "md5"):
        return f"https://www.virustotal.com/gui/file/{quote(real, safe='')}"
    if ioc_type in ("ipv4", "ipv6"):
        return f"https://www.virustotal.com/gui/ip-address/{quote(real, safe='')}"
    if ioc_type == "domain":
        return f"https://www.virustotal.com/gui/domain/{quote(real, safe='')}"
    return f"https://www.virustotal.com/gui/search/{quote(real, safe='')}"
