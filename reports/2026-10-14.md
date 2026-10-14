# Threat Intel Pulse — 2026-10-14

**Window:** last 7 days · **Generated:** 2026-10-14T12:08:52Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 62994 |
| New in window | 21820 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5000 | ok |
| feodo | 5 | ok |
| threatfox | 8262 | ok |
| malwarebazaar | 977 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8605 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 24311 | 11849 |
| sha256 | 11962 | 3693 |
| domain | 11273 | 3347 |
| ipv4 | 11185 | 2012 |
| ipv6 | 3020 | 156 |
| md5 | 634 | 382 |
| sha1 | 609 | 381 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 10373 |
| Exit nodes | 2244 |
| Other relays | 8129 |
| New in window | 955 |

Sample (20 of 10373, source: Tor Project Onionoo):
- `1[.]201[.]176[.]176`
- `1[.]248[.]96[.]163`
- `100[.]1[.]157[.]56`
- `100[.]2[.]63[.]41`
- `101[.]186[.]157[.]91`
- `101[.]55[.]125[.]10`
- `102[.]130[.]113[.]29`
- `102[.]130[.]113[.]30`
- `102[.]130[.]113[.]42`
- `102[.]130[.]113[.]9`
- `102[.]130[.]115[.]59`
- `102[.]130[.]117[.]167`
- `102[.]130[.]119[.]48`
- `102[.]130[.]127[.]117`
- `102[.]205[.]44[.]36`
- `102[.]205[.]44[.]5`
- `102[.]211[.]56[.]20`
- `102[.]211[.]56[.]25`
- `102[.]216[.]253[.]63`
- `102[.]68[.]99[.]63`

Full list: `dist/tor/tor_nodes.txt` (in the `threat-intel-output` workflow artifact).
## Top malware families

| Family | Indicators | New | ATT&CK (heuristic) |
| --- | --- | --- | --- |
| Unknown Loader | 4871 | 761 | — |
| Mirai | 4173 | 834 | T1498, T1071.001 |
| Vidar | 2486 | 2213 | T1555, T1071.001, T1567 |
| AsyncRAT | 2263 | 87 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| ClearFake | 1827 | 779 | — |
| IClickFix | 1328 | 596 | — |
| Cobalt Strike | 1324 | 81 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| Unknown malware | 1029 | 471 | — |
| Unknown Stealer | 627 | 437 | — |
| php.shin_webshell | 467 | 348 | — |
| PureRAT | 406 | 61 | — |
| VShell | 349 | 237 | — |
| AMOS | 325 | 172 | — |
| Sliver | 286 | 264 | T1071.001, T1573, T1090, T1055 |
| AdaptixC2 | 281 | 30 | — |
| Remcos | 236 | 97 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| Unknown RAT | 204 | 37 | — |
| DanaBot | 193 | 130 | T1566.001, T1071.001, T1555, T1041 |
| Remus | 176 | 71 | — |
| Formbook | 133 | 73 | T1566.001, T1056.001, T1555, T1071.001, T1567 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1105 | Ingress Tool Transfer | command-and-control | 20226 |
| T1071.001 | Web Protocols | command-and-control | 40500 |
| T1498 | Network Denial of Service | impact | 9542 |
| T1204.002 | Malicious File | execution | 7654 |
| T1027 | Obfuscated Files or Information | defense-evasion | 7643 |
| T1573 | Encrypted Channel | command-and-control | 6765 |
| T1555 | Credentials from Password Stores | credential-access | 5174 |
| T1567 | Exfiltration Over Web Service | exfiltration | 4981 |
| T1566 | Phishing | initial-access | 4525 |
| T1566.002 | Spearphishing Link | initial-access | 4525 |
| T1056.001 | Keylogging | collection, credential-access | 3582 |
| T1566.001 | Spearphishing Attachment | initial-access | 3268 |
| T1552.001 | Credentials In Files | credential-access | 3007 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 2770 |
| T1113 | Screen Capture | collection | 2735 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1836 |
| T1090 | Proxy | command-and-control | 1644 |
| T1059.001 | PowerShell | execution | 1337 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 337 |
| T1059.005 | Visual Basic | execution | 83 |
| T1189 | Drive-by Compromise | initial-access | 23 |
| T1218 | System Binary Proxy Execution | defense-evasion | 23 |
| T1021.001 | Remote Desktop Protocol | lateral-movement | 14 |
| T1486 | Data Encrypted for Impact | impact | 14 |
| T1490 | Inhibit System Recovery | impact | 14 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 14 |
| T1003 | OS Credential Dumping | credential-access | 4 |
| T1190 | Exploit Public-Facing Application | initial-access | 3 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`77[.]221[.]155[.]66`](https://www.virustotal.com/gui/ip-address/77.221.155.66) | ipv4 | Unknown malware | threatfox | 2026-10-14T12:05:03Z | 100 |
| [`hxxps://ot[.]777wins[.]org/ov`](https://www.virustotal.com/gui/search/https%3A%2F%2Fot.777wins.org%2Fov) | url | Vidar | threatfox | 2026-10-14T12:04:41Z | 100 |
| [`hxxps://ot[.]777wins[.]org/xs`](https://www.virustotal.com/gui/search/https%3A%2F%2Fot.777wins.org%2Fxs) | url | Vidar | threatfox | 2026-10-14T12:02:14Z | 100 |
| [`hxxps://ot[.]777wins[.]org`](https://www.virustotal.com/gui/search/https%3A%2F%2Fot.777wins.org) | url | Vidar | threatfox | 2026-10-14T12:01:10Z | 100 |
| [`hxxps://g[.]777wins[.]org/or/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fg.777wins.org%2For%2F) | url | Vidar | threatfox | 2026-10-14T12:00:48Z | 100 |
| [`hxxps://g[.]777wins[.]org/or`](https://www.virustotal.com/gui/search/https%3A%2F%2Fg.777wins.org%2For) | url | Vidar | threatfox | 2026-10-14T12:00:30Z | 100 |
| [`hxxps://g[.]777wins[.]org/fz`](https://www.virustotal.com/gui/search/https%3A%2F%2Fg.777wins.org%2Ffz) | url | Vidar | threatfox | 2026-10-14T11:58:15Z | 100 |
| [`hxxps://g[.]777wins[.]org/vb`](https://www.virustotal.com/gui/search/https%3A%2F%2Fg.777wins.org%2Fvb) | url | Vidar | threatfox | 2026-10-14T11:57:08Z | 100 |
| [`hxxps://g[.]777wins[.]org/l/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fg.777wins.org%2Fl%2F) | url | Vidar | threatfox | 2026-10-14T11:55:48Z | 100 |
| [`hxxps://g[.]777wins[.]org/l`](https://www.virustotal.com/gui/search/https%3A%2F%2Fg.777wins.org%2Fl) | url | Vidar | threatfox | 2026-10-14T11:54:20Z | 100 |
| [`hxxps://g[.]777wins[.]org/m8`](https://www.virustotal.com/gui/search/https%3A%2F%2Fg.777wins.org%2Fm8) | url | Vidar | threatfox | 2026-10-14T11:52:19Z | 100 |
| [`hxxps://g[.]777wins[.]org/nn`](https://www.virustotal.com/gui/search/https%3A%2F%2Fg.777wins.org%2Fnn) | url | Vidar | threatfox | 2026-10-14T11:52:02Z | 100 |
| [`hxxps://g[.]777wins[.]org/nn/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fg.777wins.org%2Fnn%2F) | url | Vidar | threatfox | 2026-10-14T11:50:48Z | 100 |
| [`hxxps://g[.]777wins[.]org/k`](https://www.virustotal.com/gui/search/https%3A%2F%2Fg.777wins.org%2Fk) | url | Vidar | threatfox | 2026-10-14T11:49:14Z | 100 |
| [`hxxps://g[.]777wins[.]org/ks`](https://www.virustotal.com/gui/search/https%3A%2F%2Fg.777wins.org%2Fks) | url | Vidar | threatfox | 2026-10-14T11:46:51Z | 100 |
| [`hxxps://g[.]777wins[.]org/py/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fg.777wins.org%2Fpy%2F) | url | Vidar | threatfox | 2026-10-14T11:45:48Z | 100 |
| [`hxxps://g[.]777wins[.]org/py`](https://www.virustotal.com/gui/search/https%3A%2F%2Fg.777wins.org%2Fpy) | url | Vidar | threatfox | 2026-10-14T11:44:18Z | 100 |
| [`hxxps://g[.]777wins[.]org/ql`](https://www.virustotal.com/gui/search/https%3A%2F%2Fg.777wins.org%2Fql) | url | Vidar | threatfox | 2026-10-14T11:44:05Z | 100 |
| [`hxxps://g[.]777wins[.]org/yr/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fg.777wins.org%2Fyr%2F) | url | Vidar | threatfox | 2026-10-14T11:40:48Z | 100 |
| [`hxxps://g[.]777wins[.]org/yr`](https://www.virustotal.com/gui/search/https%3A%2F%2Fg.777wins.org%2Fyr) | url | Vidar | threatfox | 2026-10-14T11:40:47Z | 100 |
| [`hxxps://g[.]777wins[.]org/f`](https://www.virustotal.com/gui/search/https%3A%2F%2Fg.777wins.org%2Ff) | url | Vidar | threatfox | 2026-10-14T11:38:20Z | 100 |
| [`wuntred[.]com`](https://www.virustotal.com/gui/domain/wuntred.com) | domain | Unknown Loader | threatfox | 2026-10-14T11:37:56Z | 100 |
| [`51[.]79[.]124[.]111`](https://www.virustotal.com/gui/ip-address/51.79.124.111) | ipv4 | Unknown Webinject | threatfox | 2026-10-14T11:37:20Z | 100 |
| [`63c973360d81debdfae4dbbe551f23bd1263e63da056aa0f6b0f373984112e5a`](https://www.virustotal.com/gui/file/63c973360d81debdfae4dbbe551f23bd1263e63da056aa0f6b0f373984112e5a) | sha256 | AMOS | threatfox | 2026-10-14T11:36:37Z | 100 |
| [`hxxps://forge-ridge[.]com/curl/qvien3y4pg/96ia76zt2cqcr1u6htij1l[.]dat`](https://www.virustotal.com/gui/search/https%3A%2F%2Fforge-ridge.com%2Fcurl%2Fqvien3y4pg%2F96ia76zt2cqcr1u6htij1l.dat) | url | AMOS | threatfox, urlhaus | 2026-10-14T11:36:36Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
