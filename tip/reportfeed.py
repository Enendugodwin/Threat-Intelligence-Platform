"""Report feed: vendor advisories -> normalized reports with IOCs and recommendations.

Reports are kept in ``data/reports.json`` (committed, so the feed survives CI
cache loss). Sources are RSS/Atom feeds configured under ``reports.sources``.
Operator-curated reports and recommendations live in the YAML files configured
by ``reports.curated_file`` / ``reports.recommendations_file``.

IOC extraction is deliberately best-effort: advisory text is refanged, scanned
for URLs/IPs/hashes/domains/CVEs, validated through the same rules as the main
feeds, then stored **defanged** (these pages are for humans; machine-readable
indicators live in ``dist/``).
"""
from __future__ import annotations

import hashlib
import html
import json
import logging
import pathlib
import re
from datetime import datetime, timezone

import feedparser
import yaml

from .normalize import defang, make_ioc, refang

log = logging.getLogger("tip.reportfeed")

CATEGORY_ORDER = ("windows", "linux", "cisco", "paloalto", "general")
CATEGORY_LABELS = {
    "windows": "Windows",
    "linux": "Linux",
    "cisco": "Cisco",
    "paloalto": "Palo Alto",
    "general": "General",
}

_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 "
    "threat-intel-pipeline/0.1"
)

_HTML_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")
_HREF_RE = re.compile(r"""href=["']([^"']+)["']""", re.IGNORECASE)
_URL_RE = re.compile(r"https?://[^\s\"'<>\)\]]+")
_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b")
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|edu|gov|mil|int|io|co|ai|app|dev|cloud|info|biz|online|site|shop"
    r"|live|club|xyz|top|icu|cc|tv|me|su|ru|cn|hk|tw|jp|kr|sg|my|id|ph|vn|th|in|pk"
    r"|ir|tr|il|sa|ae|za|ng|ke|eg|ma|br|ar|mx|cl|pe|ua|by|lt|lv|ee|pl|cz|sk|hu|ro|bg"
    r"|gr|hr|si|rs|uk|de|fr|nl|be|es|it|pt|ch|at|se|no|dk|fi|us|ca|au|nz)(?![a-z0-9-])\b",
    re.IGNORECASE,
)

_ASSET_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".css", ".js",
    ".woff", ".woff2", ".ttf", ".mp4", ".pdf",
)

# Vendor / tooling / social domains that would otherwise flood the extraction.
_BENIGN_DOMAINS = {
    "microsoft.com", "microsoftonline.com", "windows.com", "azure.com",
    "cisco.com", "paloaltonetworks.com", "ubuntu.com", "canonical.com",
    "debian.org", "redhat.com", "fedoraproject.org", "suse.com", "kernel.org",
    "cisa.gov", "nist.gov", "mitre.org", "sans.org", "isc.sans.edu",
    "first.org", "owasp.org", "iacr.org", "ietf.org", "rfc-editor.org",
    "github.com", "githubusercontent.com", "gitlab.com", "sourceforge.net",
    "google.com", "googleusercontent.com", "gstatic.com", "youtube.com",
    "twitter.com", "x.com", "linkedin.com", "facebook.com", "mastodon.social",
    "cloudflare.com", "akamaihd.net", "akamai.com", "amazonaws.com", "awsstatic.com",
    "feedburner.com", "w3.org", "schema.org", "wordpress.org", "wp.com",
    "ghost.io", "ghost.org", "substack.com", "medium.com", "substackcdn.com",
    "virustotal.com", "abuse.ch", "alienvault.com", "otx.alienvault.com",
    "opencti.io", "shodan.io", "censys.io", "urlscan.io", "zscaler.com",
    "creativecommons.org", "paypal.com", "patreon.com", "apple.com",
    "mozilla.org", "adobe.com", "java.com", "oracle.com", "vmware.com",
    "broadcom.com", "citrix.com", "fortinet.com", "f5.com", "juniper.net",
    "elastic.co", "splunk.com", "sentinelone.com", "crowdstrike.com",
    "trendmicro.com", "bitdefender.com", "kaspersky.com", "eset.com",
    "malwarebytes.com", "proofpoint.com", "mimecast.com", "barracuda.com",
}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _clean_text(raw: str) -> str:
    text = _HTML_TAG_RE.sub(" ", raw or "")
    text = html.unescape(text)
    return _WS_RE.sub(" ", text).strip()


def _entry_text(entry) -> str:
    content = entry.get("content")
    if content and isinstance(content, list):
        return str(content[0].get("value") or "")
    return str(entry.get("summary") or "")


def _entry_date(entry) -> str:
    for key in ("published_parsed", "updated_parsed"):
        parsed = entry.get(key)
        if parsed:
            try:
                return datetime(*parsed[:6], tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            except (TypeError, ValueError):
                continue
    return ""


def _report_id(url: str) -> str:
    return hashlib.sha1(url.strip().encode("utf-8")).hexdigest()[:16]


def _domain_of(url: str) -> str:
    match = re.match(r"https?://([^/]+)", url or "")
    if not match:
        return ""
    host = match.group(1).split("@")[-1].split(":")[0].lower().rstrip(".")
    return host


def _host_is_benign(host: str, blocked: set[str]) -> bool:
    host = host.lower().rstrip(".")
    if not host:
        return True
    parts = host.split(".")
    for i in range(len(parts) - 1):
        if ".".join(parts[i:]) in blocked:
            return True
    return host in blocked


def _blocked_hosts(report_url: str, source_cfg: dict) -> set[str]:
    blocked = set(_BENIGN_DOMAINS)
    own = _domain_of(report_url)
    if own:
        blocked.add(own)
        if own.startswith("www."):
            blocked.add(own[4:])
    for item in source_cfg.get("blocked_domains") or []:
        blocked.add(str(item).lower().rstrip("."))
    return blocked


def _classify(title: str, text: str, default: str, rules: dict) -> str:
    """Title keywords win, then the source default, then body keywords."""

    def first_match(blob: str) -> str | None:
        for category in CATEGORY_ORDER:
            for keyword in (rules.get(category) or []):
                keyword = str(keyword).strip().lower()
                if keyword and re.search(r"\b" + re.escape(keyword) + r"\b", blob):
                    return category
        return None

    match = first_match((title or "").lower())
    if match:
        return match
    if default in CATEGORY_ORDER and default != "general":
        return default
    return first_match((text or "").lower()) or "general"


# ---------------------------------------------------------------------------
# IOC extraction
# ---------------------------------------------------------------------------


def _extract_iocs(raw_html: str, plain_text: str, blocked: set[str], limit: int) -> list[dict]:
    real_html = refang(raw_html or "")
    real_text = refang(plain_text or "")

    found: dict[str, dict] = {}

    def add(value: str, forced_type: str | None = None) -> None:
        if len(found) >= limit:
            return
        ioc = make_ioc(value, "report", ioc_type=forced_type)
        if ioc is None:
            return
        if ioc.type in ("url", "domain"):
            host = _domain_of(ioc.value) if ioc.type == "url" else ioc.value
            if _host_is_benign(host, blocked):
                return
            if ioc.type == "url" and ioc.value.lower().split("?")[0].endswith(_ASSET_EXTENSIONS):
                return
        key = f"{ioc.type}:{ioc.value.lower()}"
        if key not in found:
            found[key] = {"type": ioc.type, "value": defang(ioc.value)}

    # hashes first (most specific), then urls / hrefs, ips, domains
    for match in _HASH_RE.finditer(real_text):
        add(match.group(0))
    for match in _URL_RE.finditer(real_text):
        add(match.group(0).rstrip(".,;:!?)\"'"))
    for match in _HREF_RE.finditer(real_html):
        add(match.group(1).rstrip(".,;:!?)\"'"))
    for match in _IPV4_RE.finditer(real_text):
        add(match.group(0))
    for match in _DOMAIN_RE.finditer(real_text):
        add(match.group(0))

    return list(found.values())[:limit]


def _extract_cves(text: str, limit: int = 10) -> list[str]:
    return sorted({m.upper() for m in _CVE_RE.findall(text or "")})[:limit]


# ---------------------------------------------------------------------------
# report building
# ---------------------------------------------------------------------------


def _build_report(entry, source_id: str, source_cfg: dict, rules: dict,
                  max_iocs: int, detail_chars: int, now: str) -> dict | None:
    url = str(entry.get("link") or entry.get("id") or "").strip()
    if not url:
        return None
    raw_html = _entry_text(entry)
    plain = _clean_text(raw_html)
    title = _clean_text(str(entry.get("title") or "")) or url
    blocked = _blocked_hosts(url, source_cfg)
    category = _classify(title, plain, str(source_cfg.get("category") or "general"), rules)
    return {
        "id": _report_id(url),
        "title": title[:220],
        "url": url,
        "source": source_id,
        "source_name": str(source_cfg.get("name") or source_id),
        "category": category,
        "published": _entry_date(entry),
        "fetched": now,
        "summary": plain[:300],
        "content": plain[:detail_chars],
        "iocs": _extract_iocs(raw_html, plain, blocked, max_iocs),
        "cves": _extract_cves(f"{title} {plain}"),
        "recommendations": [],
        "curated": False,
    }


def _normalize_curated_iocs(items) -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()
    for item in items:
        if isinstance(item, dict):
            value, forced = item.get("value"), item.get("type")
        else:
            value, forced = item, None
        ioc = make_ioc(str(value or ""), "report", ioc_type=forced)
        if ioc is None:
            continue
        key = f"{ioc.type}:{ioc.value.lower()}"
        if key in seen:
            continue
        seen.add(key)
        out.append({"type": ioc.type, "value": defang(ioc.value)})
    return out


def _merge_curated(by_id: dict[str, dict], curated_file: str | pathlib.Path, now: str) -> None:
    data = _load_yaml(curated_file)
    for item in (data or {}).get("reports") or []:
        if not isinstance(item, dict) or not item.get("url"):
            continue
        url = str(item["url"]).strip()
        rid = _report_id(url)
        existing = by_id.get(rid) or {}
        category = item.get("category")
        by_id[rid] = {
            "id": rid,
            "title": str(item.get("title") or existing.get("title") or url)[:220],
            "url": url,
            "source": "curated",
            "source_name": str(item.get("source_name") or "Curated"),
            "category": category if category in CATEGORY_ORDER else existing.get("category", "general"),
            "published": str(item.get("published") or existing.get("published") or ""),
            "fetched": now,
            "summary": str(item.get("summary") or existing.get("summary") or "")[:300],
            "content": str(item.get("content") or item.get("summary") or existing.get("content") or "")[:4000],
            "iocs": _normalize_curated_iocs(item.get("iocs") or []),
            "cves": [str(c).upper() for c in (item.get("cves") or [])],
            "recommendations": [str(x) for x in (item.get("recommendations") or []) if str(x).strip()],
            "curated": True,
        }


# ---------------------------------------------------------------------------
# recommendations
# ---------------------------------------------------------------------------


def _recommendations(report: dict, cfg: dict) -> list[str]:
    specific = [str(x) for x in (report.get("recommendations") or []) if str(x).strip()]
    by_id = [str(x) for x in ((cfg.get("reports") or {}).get(report["id"]) or []) if str(x).strip()]

    automatic: list[str] = []
    if report.get("cves"):
        cves = report["cves"]
        listing = ", ".join(cves[:5]) + (" ..." if len(cves) > 5 else "")
        automatic.append(f"Assess exposure and patch affected systems: {listing}")
    if report.get("iocs"):
        automatic.append(
            f"Block or hunt the {len(report['iocs'])} extracted indicator(s) above; "
            "machine-readable feeds are in dist/iocs.csv."
        )

    category = [str(x) for x in ((cfg.get("categories") or {}).get(report["category"]) or []) if str(x).strip()]
    source = [str(x) for x in ((cfg.get("sources") or {}).get(report["source"]) or []) if str(x).strip()]

    merged: list[str] = []
    for item in specific + by_id + automatic + category + source:
        if item and item not in merged:
            merged.append(item)
    return merged


# ---------------------------------------------------------------------------
# persistence
# ---------------------------------------------------------------------------


def _load_json(path: pathlib.Path) -> dict:
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _load_yaml(path: str | pathlib.Path) -> dict:
    path = pathlib.Path(path)
    if not path.is_file():
        return {}
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        log.warning("cannot read %s: %s", path, exc)
        return {}


def reports_path(data_dir: str | pathlib.Path) -> pathlib.Path:
    return pathlib.Path(data_dir) / "reports.json"


def load_reports(data_dir: str | pathlib.Path) -> dict:
    return _load_json(reports_path(data_dir))


def save_reports(data_dir: str | pathlib.Path, doc: dict) -> pathlib.Path:
    path = reports_path(data_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2, sort_keys=False), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# main entry point
# ---------------------------------------------------------------------------


def fetch_reports(config: dict, data_dir: str | pathlib.Path) -> dict:
    """Fetch configured report sources, merge with existing + curated, save."""
    cfg = config.get("reports") or {}
    stats: dict = {"sources": {}, "errors": {}, "total": 0, "skipped": False}
    if not cfg.get("enabled", True):
        stats["skipped"] = True
        return stats

    data_dir = pathlib.Path(data_dir)
    existing = load_reports(data_dir)
    by_id: dict[str, dict] = {r["id"]: r for r in existing.get("reports", []) if r.get("id")}

    now = _utcnow()
    rules = cfg.get("category_rules") or {}
    max_entries = int(cfg.get("max_entries_per_source", 20))
    max_iocs = int(cfg.get("max_iocs_per_report", 100))
    detail_chars = int(cfg.get("detail_chars", 2500))
    max_reports = int(cfg.get("max_reports", 150))

    for source_id, source_cfg in (cfg.get("sources") or {}).items():
        source_cfg = source_cfg or {}
        if not source_cfg.get("enabled"):
            continue
        url = source_cfg.get("url")
        if not url:
            continue
        try:
            parsed = feedparser.parse(url, request_headers={"User-Agent": _USER_AGENT})
            if not parsed.entries:
                reason = getattr(parsed, "bozo_exception", None) or f"status {getattr(parsed, 'status', '?')}"
                raise RuntimeError(f"no entries ({reason})")
            count = 0
            for entry in parsed.entries[:max_entries]:
                report = _build_report(entry, source_id, source_cfg, rules, max_iocs, detail_chars, now)
                if report is None:
                    continue
                old = by_id.get(report["id"]) or {}
                if old.get("curated"):
                    continue  # curated content wins
                report["recommendations"] = []
                by_id[report["id"]] = report
                count += 1
            stats["sources"][source_id] = count
            log.info("report source %s: %d reports", source_id, count)
        except Exception as exc:  # noqa: BLE001 - isolate per-source failures
            stats["errors"][source_id] = f"{type(exc).__name__}: {exc}"
            log.warning("report source %s failed: %s", source_id, exc)

    _merge_curated(by_id, cfg.get("curated_file", "intel/curated_reports.yaml"), now)

    recs_cfg = _load_yaml(cfg.get("recommendations_file", "intel/recommendations.yaml"))
    for report in by_id.values():
        report["recommendations"] = _recommendations(report, recs_cfg)

    curated = [r for r in by_id.values() if r.get("curated")]
    others = sorted(
        (r for r in by_id.values() if not r.get("curated")),
        key=lambda r: r.get("published") or r.get("fetched") or "",
        reverse=True,
    )[:max_reports]
    kept = sorted(curated + others, key=lambda r: r.get("published") or r.get("fetched") or "", reverse=True)

    doc = {
        "generated_at": now,
        "categories": list(CATEGORY_ORDER),
        "reports": kept,
    }
    save_reports(data_dir, doc)

    stats["total"] = len(kept)
    stats["curated"] = len(curated)
    log.info("report feed: %d reports tracked (%d curated)", stats["total"], stats["curated"])
    return stats
