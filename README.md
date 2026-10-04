# threat-intel-pipeline

[![tests](https://github.com/Enendugodwin/threat-intel-pipeline/actions/workflows/tests.yml/badge.svg)](https://github.com/Enendugodwin/threat-intel-pipeline/actions/workflows/tests.yml)

A small, serverless threat-intel pipeline for blue-team work. It pulls public
CTI feeds on a schedule, normalizes and dedupes indicators, maps them to MITRE
ATT&CK (heuristically), and publishes finished products:

| Output | Path | Use |
| --- | --- | --- |
| STIX 2.1 bundle | `dist/stix/bundle.json` | OpenCTI / MISP / SIEM TI ingestion |
| Sigma rules (IOC watchlists) | `dist/sigma/*.yml` | convert with sigma-cli, load into your SIEM |
| Suricata rules | `dist/suricata/ti.rules` | network detection |
| CSV indicator set | `dist/iocs.csv` | quick lookups / watchlists |
| Markdown report | `reports/latest.md` | intel pulse for the week |
| HTML dashboard | `site/index.html` | published to GitHub Pages |

It runs entirely on GitHub: **Actions** execute the pipeline every 6 hours and
**Pages** hosts the dashboard. No server required. MISP/OpenCTI connectors ship
in the box for when you later point it at a VPS (see `deploy/README.md`).

## How it works

```
URLhaus ─┐
Feodo ───┤   normalize     SQLite     ATT&CK        exports
ThreatFox┼─► validate ───► store ───► mapping ──┬─► STIX 2.1 bundle
OTX ─────┘   dedupe       (cached)   heuristics  ├─► Sigma watchlists
             refang                              ├─► Suricata rules
                                                 ├─► CSV
                                                 ├─► Markdown report
                                                 └─► HTML dashboard (Pages)
```

- **Feeds** (keyless by default): URLhaus, Feodo Tracker C2 blocklist, ThreatFox.
  AlienVault OTX is supported with a free API key.
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
5. Either wait for the schedule (`23 */6 * * *` UTC) or run *Actions → sync →
   Run workflow*.

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
- `report.window_days` / `report.top_n` - reporting window and notable-IOC cap.

`config/attack_map.yaml` - ATT&CK techniques, malware family → technique
mapping, regex tag rules, and default techniques. Extend it for families you
care about.

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
  exports/          stix.py, sigma.py, suricata.py, csv_export.py
  connectors/       misp.py, opencti.py (optional)
  report.py/site.py context building + Jinja rendering
templates/          report.md.j2, base/index/report HTML
config/             config.yaml, attack_map.yaml
tests/              fixture-based suite (offline, no network)
```

## Roadmap ideas

- [x] Core: feeds, normalize, store, ATT&CK mapping, reports
- [x] Serverless deployment: Actions schedule + Pages dashboard + artifacts
- [x] Optional MISP/OpenCTI connectors
- [ ] VT / AbuseIPDB enrichment for top indicators
- [ ] Weekly digest issue (GitHub Issues bot)
- [ ] YARA rule export for payload hashes

## License

MIT - see `LICENSE`.
