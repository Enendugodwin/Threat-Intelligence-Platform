# threat-intel-pipeline

[![tests](https://github.com/Enendugodwin/Threat-Intelligence-Platform/actions/workflows/tests.yml/badge.svg)](https://github.com/Enendugodwin/Threat-Intelligence-Platform/actions/workflows/tests.yml)

A small, serverless threat-intel pipeline for blue-team work. It pulls public
CTI feeds on a schedule, normalizes and dedupes indicators, maps them to MITRE
ATT&CK (heuristically), and publishes finished products:

| Output | Path | Use |
| --- | --- | --- |
| STIX 2.1 bundle | `dist/stix/bundle.json` | OpenCTI / MISP / SIEM TI ingestion |
| Sigma rules (IOC watchlists) | `dist/sigma/*.yml` | convert with sigma-cli, load into your SIEM |
| Suricata rules | `dist/suricata/ti.rules` | network detection |
| CSV indicator set | `dist/iocs.csv` | quick lookups / watchlists |
| Tor node list | `dist/tor/tor_nodes.txt` | firewall / proxy context (relays + exits) |
| Report feed | `site/reports.html` (+ per-report pages) | filterable vendor advisory bank with IOCs + recommendations |
| Report data | `data/reports.json` | normalized report feed (committed) |
| Attack map | `site/map.html` | geolocated C2/infrastructure origins (Leaflet) |
| KEV + EPSS | `site/kev.html` | known exploited vulnerabilities with exploit-probability scoring |
| Markdown report | `reports/latest.md` | intel pulse for the week |
| HTML dashboard | `site/index.html` | published to GitHub Pages |

It runs entirely on GitHub: **Actions** execute the pipeline every 6 hours and
**Pages** hosts the dashboard. No server required. MISP/OpenCTI connectors ship
in the box for when you later point it at a VPS (see `deploy/README.md`).

## How it works

```
URLhaus ─────┐
Feodo ───────┤   normalize     SQLite     ATT&CK        exports
ThreatFox ───┼─► validate ───► store ───► mapping ──┬─► STIX 2.1 / CSV
Tor Onionoo ─┤   dedupe       (cached)   heuristics  ├─► Sigma watchlists
OTX ─────────┘   refang                              ├─► Suricata rules
                                                     ├─► Tor node list
                                                     ├─► Markdown report
                                                     └─► HTML dashboard (Pages)
```

A parallel **report feed** ingests vendor advisories (RSS/Atom) into
`data/reports.json` and renders `site/reports.html` - filterable by category
(Windows / Linux / Hypervisors / Network Devices / Cisco / Palo Alto / General)
and searchable - with a per-report IOC list and recommendations. Vulnerability
intelligence (CISA KEV + FIRST EPSS) renders `site/kev.html`, and high-signal
C2 IPs are geolocated (cached in `data/geo.json`) for the `site/map.html`
infrastructure-geolocation map.

- **Feeds** (keyless by default): URLhaus, Feodo Tracker C2 blocklist, ThreatFox,
  MalwareBazaar (sample hashes), OpenPhish (phishing URLs), the CIRCL MISP OSINT
  feed, and Tor Project Onionoo (relay/exit node context - kept out of detections
  by default). AlienVault OTX is supported with a free API key, and CISA KEV +
  FIRST EPSS power the vulnerability page.
- **Normalization**: refang/defang handling, type detection, private/reserved
  address rejection, dedupe across feeds with source tracking.
- **ATT&CK mapping**: family table + tag heuristics in `config/attack_map.yaml`.
  It is explicitly a *heuristic* for coverage trends, not attribution truth.
- **Exports**: deterministic ids (STIX UUIDv5, Sigma rule ids, Suricata SIDs)
  so re-runs produce clean diffs and idempotent ingestion.

## Quickstart (local)

```powershell
# Windows (host) - note: the Store "python" stub is not enough, use a real install
py -3 -m venv .venv        # or: & "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe" -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt

python -m tip sync         # fetch feeds -> data/iocs.sqlite
python -m tip report       # reports/latest.md
python -m tip export       # dist/ (STIX, Sigma, Suricata, CSV)
python -m tip site         # site/index.html - open it in a browser
python -m tip stats        # database summary
```

Linux/macOS is the same with `python3 -m venv .venv && source .venv/bin/activate`.

Copy `.env.example` to `.env` if you want to enable OTX or connectors.

## Run it online on GitHub (no server)

1. Create a **public** repo (Pages on the free plan needs public) and push this code.
2. Repo → *Settings → Actions → General → Workflow permissions*:
   select **Read and write permissions** (the sync job commits reports).
3. Repo → *Settings → Pages → Source*: **GitHub Actions**.
4. Optional: *Settings → Secrets and variables → Actions* → add `OTX_API_KEY`.
5. The pipeline runs automatically: on every push to `main`, on the 6-hourly
   schedule (`23 */6 * * *` UTC), and on demand via *Actions → sync → Run workflow*.

The job fetches feeds, commits `reports/` + `site/` + `data/counters.json`,
uploads `dist/` and `reports/` as the `threat-intel-output` artifact, and
deploys the dashboard to `https://<user>.github.io/threat-intel-pipeline/`.

> GitHub disables schedules after 60 days of repository inactivity - the bot's
> own commits count as activity, so this keeps itself alive as long as the
> repository exists.

## Configuration

`config/config.yaml`:

- `feeds.*.enabled` - toggle feeds; `urlhaus.max_records` caps how much of the
  CSV is ingested per run; `urlhaus.derive_domains` adds URL hostnames as
  domain indicators.
- `storage.prune_after_days` - indicators not re-seen in N days are dropped.
- `exports.window_days` / `exports.max_rows` / `exports.min_confidence` - what
  goes into STIX/Sigma/Suricata/CSV.
- `exports.exclude_sources` - sources kept out of those exports (default `tor`;
  Tor nodes are context, not malware, and would only add detection noise - the
  dedicated list still ships as `dist/tor/tor_nodes.txt`).
- `feeds.tor.exits_only` - restrict the Tor section to exit nodes.
- `report.window_days` / `report.top_n` / `report.tor_sample` - reporting window,
  notable-IOC cap, and Tor sample size.
- `vulnintel.*` - KEV page: `max_entries` (how many newest entries to track).
- `geo.*` - attack-origin map: `max_ips` lookups per run and `include_sources`
  (`threatfox`/`feodo`; report-extracted IPs are always included).

`config/attack_map.yaml` - ATT&CK techniques, malware family → technique
mapping, regex tag rules, and default techniques. Extend it for families you
care about.

## Report feed

`site/reports.html` is a bank of vendor advisories and research, filterable by
category (Windows / Linux / Hypervisors / Network Devices / Cisco / Palo Alto /
General) and searchable across titles, summaries, tags and sources; refreshed on
every sync. Each report gets its own page with:

- **Extracted indicators** - best-effort IOC extraction (URLs, domains, IPv4,
  hashes) from the advisory text, refanged first and shown defanged. Extraction
  is heuristic: validate before blocking.
- **Recommendations** - merged from four layers, most specific first:
  1. curated per-report notes (`intel/curated_reports.yaml`, or the `reports:`
     map in `intel/recommendations.yaml` keyed by report ID)
  2. automatic rules (CVEs -> patch advice; IOCs -> block/hunt)
  3. category baseline (`intel/recommendations.yaml` -> `categories`)
  4. source-specific notes (`intel/recommendations.yaml` -> `sources`)

Sources are configured under `reports.sources` in `config/config.yaml`
(Microsoft Security Blog, Cisco Talos, Unit 42, Ubuntu Security Notices, The
DFIR Report, SANS ISC). CISA is included but disabled by default - its Akamai
edge returns 403 to Python clients and CI runners. Normalized data lives in
`data/reports.json` (newest 150 feed reports plus all curated entries). Every
report page shows its **Report ID** so operator recommendations can be pinned
to it. Cards surface extracted tags (families, actors, themes) and linked
ATT&CK techniques; CVEs that appear in the KEV catalog are badged on report
pages. The category filter is CSS-only (radio inputs) and works without
JavaScript. Dashboard charts drill down: type bars, family rows and ATT&CK
techniques open per-group indicator pages, every indicator clicks through to a
VirusTotal lookup, and KEV rows link to NVD plus the reports that reference
them.

## Risk scoring & IOC Explorer

Every indicator gets a **risk score** (0-100, level CRITICAL/HIGH/MEDIUM/LOW/INFO)
combining source confidence, multi-source corroboration, recency, malware
association and indicator type - deliberately separate from raw feed confidence
(`tip/scoring.py`). The **IOC Explorer** (`site/explorer.html`) searches the
risk-ranked index client-side (top 10,000, type/risk filters) with each result
linking to VirusTotal.

Dashboard metrics show **actual run deltas** - new/updated/pruned *this run* plus
7-day activity from the run history - instead of window counts, so "new" stays
believable. The ATT&CK coverage table separates **family/tag evidence from the
default heuristic** (`config/attack_map.yaml` -> `default_techniques`); heuristic
mappings are shown as "+N heuristic" and excluded from the headline count.

## Environment matching, evidence & action queue

- `organization:` in `config.yaml` describes your technology stack (for example
  `["vmware esxi", "pan-os", "cisco asa", "f5 big-ip"]`). With it enabled, KEV
  rows gain an **Environment** column (MATCHED / not detected), report cards are
  badged "in your stack", report pages show an exposure banner, and the
  dashboard and KEV cards count affected entries.
- **Per-source evidence**: every source keeps its own confidence and first/last
  seen per indicator (the `ioc_sources` table), surfaced in the explorer, the
  notable table and all drill-down pages as `source:confidence` values.
- **Action queue** on the Overview ranks what to review first: overdue
  ransomware-linked / high-EPSS KEV entries (environment matches first),
  high-risk multi-source or malware-associated indicators, and reports that
  reference KEV CVEs - each with Investigate and Lookup links.

## Adding a feed

Implement `tip/feeds/base.py::Feed`:

```python
class MyFeed(Feed):
    name = "myfeed"
    url = "https://example.org/feed.json"

    def parse(self, raw) -> list[IOC]:
        ...  # return make_ioc(...) results
```

Register it in `tip/feeds/__init__.py::FEED_CLASSES`, enable it in
`config/config.yaml`, and add a fixture-based test. Feed failures are isolated:
one broken feed never fails the run unless all of them fail.

## Optional connectors (MISP / OpenCTI)

```powershell
pip install pymisp
$env:MISP_URL = "https://misp.example.org"; $env:MISP_API_KEY = "..."
python -m tip push --misp --days 7
```

OpenCTI (`python -m tip push --opencti`) is experimental - for production use,
import `dist/stix/bundle.json` with an OpenCTI ingestion connector instead
(idempotent thanks to deterministic ids). See `deploy/README.md` for hosting
MISP/OpenCTI on a VPS later.

## Data sources & terms

- [URLhaus](https://urlhaus.abuse.ch/) (abuse.ch) - malware URLs
- [Feodo Tracker](https://feodotracker.abuse.ch/) (abuse.ch) - botnet C2 blocklist
- [ThreatFox](https://threatfox.abuse.ch/) (abuse.ch) - IOCs
- [Tor Project Onionoo](https://onionoo.torproject.org/) - Tor relay/exit node addresses (context data)
- [MalwareBazaar](https://bazaar.abuse.ch/) (abuse.ch) - recent malware sample hashes
- [OpenPhish](https://openphish.com/) - phishing URLs (via the public-feed GitHub mirror)
- [CIRCL MISP OSINT feed](https://www.circl.lu/doc/misp/feed-osint/) - community indicators
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) - exploited vulnerabilities
- [FIRST EPSS](https://www.first.org/epss/) - exploit-probability scoring
- [MITRE ATT&CK](https://attack.mitre.org/) - technique references (linked, not fetched)
- [ip-api.com](https://ip-api.com/) - approximate IP geolocation for the map (free tier, cached)
- [AlienVault OTX](https://otx.alienvault.com/) - pulses (optional key)

Review each provider's terms of use before commercial deployment; feeds are
free for research/personal use and ask for attribution.

## Project layout

```
tip/
  cli.py            python -m tip <sync|report|export|site|stats|push>
  pipeline.py       orchestration + HTTP session (retries, UA)
  feeds/            one module per feed, keyless by default
  normalize.py      refang/defang, type detection, validation
  store.py          SQLite: dedupe/merge, source tracking, run history
  attack.py         heuristic ATT&CK mapping (config/attack_map.yaml)
  exports/          stix.py, sigma.py, suricata.py, csv_export.py, tor.py
  connectors/       misp.py, opencti.py (optional)
  report.py/site.py context building + Jinja rendering
  reportfeed.py     vendor report feed (RSS/Atom) -> data/reports.json
  vulnintel.py      CISA KEV catalog + EPSS scoring -> data/kev.json
  geo.py            ip-api.com geolocation (cached) -> data/geo.json
  scoring.py        IOC risk scoring (confidence, corroboration, recency, context)
templates/          Jinja UI (base + components + report.md.j2)
design-system/      ui-ux-pro-max design system (Cyberpunk UI, MASTER.md)
config/             config.yaml, attack_map.yaml
intel/              recommendations.yaml, curated_reports.yaml
tests/              fixture-based suite (offline, no network)
```

## Roadmap ideas

- [x] Core: feeds, normalize, store, ATT&CK mapping, reports
- [x] Serverless deployment: Actions schedule + Pages dashboard + artifacts
- [x] Optional MISP/OpenCTI connectors
- [x] Dashboard redesign with the `ui-ux-pro-max` design system (Cyberpunk UI)
- [x] Report feed: vendor advisories with IOC extraction, categories and recommendations
- [x] Attack-origins map, CISA KEV + EPSS page, extra sources (MalwareBazaar / OpenPhish / CIRCL)
- [x] Run-delta metrics, risk scoring, IOC Explorer, ATT&CK evidence split, dynamic source list
- [x] Phase 3: environment matching, per-source evidence, action queue; broader categories + report search
- [ ] VT / AbuseIPDB enrichment for top indicators
- [ ] Weekly digest issue (GitHub Issues bot)
- [ ] YARA rule export for payload hashes

## License

MIT - see `LICENSE`.
