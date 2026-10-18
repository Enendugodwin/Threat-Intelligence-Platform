# Threat Intel Pulse — 2026-10-18

**Window:** last 7 days · **Generated:** 2026-10-18T20:55:04Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 77847 |
| New in window | 24551 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5000 | ok |
| feodo | 5 | ok |
| threatfox | 7530 | ok |
| malwarebazaar | 905 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8756 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 31597 | 12877 |
| sha256 | 15338 | 4989 |
| domain | 13474 | 3255 |
| ipv4 | 12461 | 2343 |
| ipv6 | 3266 | 309 |
| md5 | 868 | 389 |
| sha1 | 843 | 389 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 11204 |
| Exit nodes | 2405 |
| Other relays | 8799 |
| New in window | 1207 |

Sample (20 of 11204, source: Tor Project Onionoo):
- `1[.]201[.]176[.]176`
- `1[.]235[.]159[.]83`
- `1[.]248[.]96[.]163`
- `1[.]34[.]44[.]234`
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

Full list: `dist/tor/tor_nodes.txt` (in the `threat-intel-output` workflow artifact).
## Top malware families

| Family | Indicators | New | ATT&CK (heuristic) |
| --- | --- | --- | --- |
| Unknown Loader | 5376 | 809 | — |
| Vidar | 5219 | 4752 | T1555, T1071.001, T1567 |
| Mirai | 5038 | 1163 | T1498, T1071.001 |
| AsyncRAT | 2319 | 102 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| IClickFix | 2097 | 808 | — |
| ClearFake | 1994 | 327 | — |
| Unknown malware | 1567 | 718 | — |
| Cobalt Strike | 1360 | 88 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| VShell | 887 | 635 | — |
| AMOS | 705 | 467 | — |
| php.shin_webshell | 648 | 312 | — |
| Unknown Stealer | 635 | 75 | — |
| PureRAT | 450 | 69 | — |
| Sliver | 368 | 331 | T1071.001, T1573, T1090, T1055 |
| Remcos | 339 | 166 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| AdaptixC2 | 302 | 30 | — |
| Remus | 248 | 88 | — |
| Unknown RAT | 228 | 49 | — |
| DanaBot | 195 | 99 | T1566.001, T1071.001, T1555, T1041 |
| Formbook | 187 | 88 | T1566.001, T1056.001, T1555, T1071.001, T1567 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1071.001 | Web Protocols | command-and-control | 49622 |
| T1105 | Ingress Tool Transfer | command-and-control | 23960 |
| T1498 | Network Denial of Service | impact | 12050 |
| T1204.002 | Malicious File | execution | 9481 |
| T1027 | Obfuscated Files or Information | defense-evasion | 9319 |
| T1573 | Encrypted Channel | command-and-control | 8892 |
| T1555 | Credentials from Password Stores | credential-access | 8620 |
| T1567 | Exfiltration Over Web Service | exfiltration | 8425 |
| T1566 | Phishing | initial-access | 6885 |
| T1566.002 | Spearphishing Link | initial-access | 6885 |
| T1552.001 | Credentials In Files | credential-access | 5155 |
| T1056.001 | Keylogging | collection, credential-access | 3953 |
| T1566.001 | Spearphishing Attachment | initial-access | 3634 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 3027 |
| T1113 | Screen Capture | collection | 2966 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1992 |
| T1090 | Proxy | command-and-control | 1766 |
| T1059.001 | PowerShell | execution | 1374 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 383 |
| T1189 | Drive-by Compromise | initial-access | 178 |
| T1218 | System Binary Proxy Execution | defense-evasion | 178 |
| T1059.005 | Visual Basic | execution | 94 |
| T1021.001 | Remote Desktop Protocol | lateral-movement | 14 |
| T1486 | Data Encrypted for Impact | impact | 14 |
| T1490 | Inhibit System Recovery | impact | 14 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 14 |
| T1190 | Exploit Public-Facing Application | initial-access | 5 |
| T1003 | OS Credential Dumping | credential-access | 4 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://pw[.]9windaftar[.]com/jk/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fpw.9windaftar.com%2Fjk%2F) | url | Vidar | threatfox | 2026-10-18T20:45:48Z | 100 |
| [`hxxps://pw[.]9windaftar[.]com/mw/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fpw.9windaftar.com%2Fmw%2F) | url | Vidar | threatfox | 2026-10-18T20:40:48Z | 100 |
| [`hxxps://pw[.]9windaftar[.]com/eu/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fpw.9windaftar.com%2Feu%2F) | url | Vidar | threatfox | 2026-10-18T20:35:48Z | 100 |
| [`hxxps://o7[.]9kio[.]org/f/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fo7.9kio.org%2Ff%2F) | url | Vidar | threatfox | 2026-10-18T20:30:48Z | 100 |
| [`hxxps://pw[.]9windaftar[.]com/gv2/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fpw.9windaftar.com%2Fgv2%2F) | url | Vidar | threatfox | 2026-10-18T20:30:48Z | 100 |
| [`0f15e62f49dbbc90c604ee07ef8eb716d2f68435767a486631d470def6ebeb36`](https://www.virustotal.com/gui/file/0f15e62f49dbbc90c604ee07ef8eb716d2f68435767a486631d470def6ebeb36) | sha256 | AMOS | threatfox | 2026-10-18T20:27:03Z | 100 |
| [`hxxps://pw[.]9windaftar[.]com/lb/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fpw.9windaftar.com%2Flb%2F) | url | Vidar | threatfox | 2026-10-18T20:25:48Z | 100 |
| [`hxxps://pw[.]9windaftar[.]com/nf5/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fpw.9windaftar.com%2Fnf5%2F) | url | Vidar | threatfox | 2026-10-18T20:20:48Z | 100 |
| [`hxxps://pw[.]9windaftar[.]com/lr/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fpw.9windaftar.com%2Flr%2F) | url | Vidar | threatfox | 2026-10-18T20:15:48Z | 100 |
| [`hxxps://pw[.]9windaftar[.]com/ht/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fpw.9windaftar.com%2Fht%2F) | url | Vidar | threatfox | 2026-10-18T20:10:48Z | 100 |
| [`159[.]89[.]170[.]166`](https://www.virustotal.com/gui/ip-address/159.89.170.166) | ipv4 | Remus | threatfox | 2026-10-18T20:10:21Z | 100 |
| [`hxxps://pw[.]9windaftar[.]com/qjt/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fpw.9windaftar.com%2Fqjt%2F) | url | Vidar | threatfox | 2026-10-18T20:05:48Z | 100 |
| [`hxxps://o7[.]9kio[.]org/r/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fo7.9kio.org%2Fr%2F) | url | Vidar | threatfox | 2026-10-18T20:00:48Z | 100 |
| [`hxxps://qp[.]9windaftar[.]com/nm/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fqp.9windaftar.com%2Fnm%2F) | url | Vidar | threatfox | 2026-10-18T20:00:48Z | 100 |
| [`hxxps://qp[.]9windaftar[.]com/ln/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fqp.9windaftar.com%2Fln%2F) | url | Vidar | threatfox | 2026-10-18T19:55:48Z | 100 |
| [`hxxps://qp[.]9windaftar[.]com/kf/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fqp.9windaftar.com%2Fkf%2F) | url | Vidar | threatfox | 2026-10-18T19:50:48Z | 100 |
| [`hxxps://qp[.]9windaftar[.]com/ny/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fqp.9windaftar.com%2Fny%2F) | url | Vidar | threatfox | 2026-10-18T19:45:48Z | 100 |
| [`hxxps://qp[.]9windaftar[.]com/fc/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fqp.9windaftar.com%2Ffc%2F) | url | Vidar | threatfox | 2026-10-18T19:40:48Z | 100 |
| [`ed8bc2b4ab3d52999ecd782cddc6b43fd87a07c086e1a1285ac44a70ee55603f`](https://www.virustotal.com/gui/file/ed8bc2b4ab3d52999ecd782cddc6b43fd87a07c086e1a1285ac44a70ee55603f) | sha256 | AMOS | threatfox | 2026-10-18T19:40:11Z | 100 |
| [`f4d558133f6ffc69d42dd5c3504938e82fe1a4ef241344f729ae22f6d200cd1e`](https://www.virustotal.com/gui/file/f4d558133f6ffc69d42dd5c3504938e82fe1a4ef241344f729ae22f6d200cd1e) | sha256 | AMOS | threatfox | 2026-10-18T19:40:10Z | 100 |
| [`a65580c55059b46ef3300dd5223602f7bcc603f96c1642cc71d9bab2a5e62e7a`](https://www.virustotal.com/gui/file/a65580c55059b46ef3300dd5223602f7bcc603f96c1642cc71d9bab2a5e62e7a) | sha256 | AMOS | threatfox | 2026-10-18T19:40:10Z | 100 |
| [`002c0ba824e249fbb67b3c91a0c5d97f22bef4f90c78451e9d6ebe9f7c5a3501`](https://www.virustotal.com/gui/file/002c0ba824e249fbb67b3c91a0c5d97f22bef4f90c78451e9d6ebe9f7c5a3501) | sha256 | AMOS | threatfox | 2026-10-18T19:40:10Z | 100 |
| [`hxxps://qp[.]9windaftar[.]com/x0/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fqp.9windaftar.com%2Fx0%2F) | url | Vidar | threatfox | 2026-10-18T19:35:48Z | 100 |
| [`9acdd4de139103b21098bac2dba33e1547e39821296c1b89c9d4d2eded750509`](https://www.virustotal.com/gui/file/9acdd4de139103b21098bac2dba33e1547e39821296c1b89c9d4d2eded750509) | sha256 | AMOS | threatfox | 2026-10-18T19:35:47Z | 100 |
| [`hxxps://qp[.]9windaftar[.]com/tvu/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fqp.9windaftar.com%2Ftvu%2F) | url | Vidar | threatfox | 2026-10-18T19:30:50Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
