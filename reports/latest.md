# Threat Intel Pulse — 2026-10-11

**Window:** last 7 days · **Generated:** 2026-10-11T22:12:00Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 54076 |
| New in window | 27745 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5001 | ok |
| feodo | 5 | ok |
| threatfox | 5756 | ok |
| malwarebazaar | 865 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8585 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 18983 | 13851 |
| sha256 | 10590 | 6096 |
| domain | 10319 | 4960 |
| ipv4 | 10246 | 1732 |
| ipv6 | 2963 | 245 |
| md5 | 500 | 443 |
| sha1 | 475 | 418 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 10025 |
| Exit nodes | 2220 |
| Other relays | 7805 |
| New in window | 1219 |

Sample (20 of 10025, source: Tor Project Onionoo):
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
| Unknown Loader | 4562 | 1868 | — |
| Mirai | 3810 | 1510 | T1498, T1071.001 |
| AsyncRAT | 2224 | 1029 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| ClearFake | 1676 | 1385 | — |
| IClickFix | 1290 | 957 | — |
| Cobalt Strike | 1273 | 45 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| Unknown malware | 887 | 452 | — |
| Vidar | 600 | 439 | T1555, T1071.001, T1567 |
| Unknown Stealer | 564 | 396 | — |
| PureRAT | 381 | 51 | — |
| php.shin_webshell | 355 | 304 | — |
| AdaptixC2 | 273 | 33 | — |
| VShell | 257 | 169 | — |
| AMOS | 249 | 166 | — |
| Unknown RAT | 179 | 47 | — |
| Remcos | 174 | 83 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| Remus | 161 | 83 | — |
| DanaBot | 136 | 73 | T1566.001, T1071.001, T1555, T1041 |
| DCRat | 110 | 13 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| Formbook | 100 | 84 | T1566.001, T1056.001, T1555, T1071.001, T1567 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1105 | Ingress Tool Transfer | command-and-control | 16941 |
| T1071.001 | Web Protocols | command-and-control | 35348 |
| T1498 | Network Denial of Service | impact | 8835 |
| T1204.002 | Malicious File | execution | 5726 |
| T1027 | Obfuscated Files or Information | defense-evasion | 5715 |
| T1573 | Encrypted Channel | command-and-control | 5071 |
| T1056.001 | Keylogging | collection, credential-access | 3351 |
| T1566 | Phishing | initial-access | 3043 |
| T1566.002 | Spearphishing Link | initial-access | 3043 |
| T1566.001 | Spearphishing Attachment | initial-access | 3028 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 2644 |
| T1113 | Screen Capture | collection | 2612 |
| T1555 | Credentials from Password Stores | credential-access | 2349 |
| T1567 | Exfiltration Over Web Service | exfiltration | 2213 |
| T1552.001 | Credentials In Files | credential-access | 1579 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1519 |
| T1090 | Proxy | command-and-control | 1354 |
| T1059.001 | PowerShell | execution | 1286 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 265 |
| T1059.005 | Visual Basic | execution | 70 |
| T1189 | Drive-by Compromise | initial-access | 22 |
| T1218 | System Binary Proxy Execution | defense-evasion | 22 |
| T1021.001 | Remote Desktop Protocol | lateral-movement | 8 |
| T1486 | Data Encrypted for Impact | impact | 8 |
| T1490 | Inhibit System Recovery | impact | 8 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 8 |
| T1003 | OS Credential Dumping | credential-access | 1 |
| T1190 | Exploit Public-Facing Application | initial-access | 1 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://irc[.]5tr[.]org`](https://www.virustotal.com/gui/search/https%3A%2F%2Firc.5tr.org) | url | Vidar | threatfox | 2026-10-11T21:53:19Z | 100 |
| [`irc[.]5tr[.]org`](https://www.virustotal.com/gui/domain/irc.5tr.org) | domain | Vidar | threatfox | 2026-10-11T21:50:48Z | 100 |
| [`hxxps://irc[.]5tr[.]org/`](https://www.virustotal.com/gui/search/https%3A%2F%2Firc.5tr.org%2F) | url | Vidar | threatfox | 2026-10-11T21:50:48Z | 100 |
| [`irc[.]iakmialor[.]web[.]id`](https://www.virustotal.com/gui/domain/irc.iakmialor.web.id) | domain | Vidar | threatfox | 2026-10-11T21:50:48Z | 100 |
| [`hxxps://irc[.]iakmialor[.]web[.]id/`](https://www.virustotal.com/gui/search/https%3A%2F%2Firc.iakmialor.web.id%2F) | url | Vidar | threatfox | 2026-10-11T21:50:48Z | 100 |
| [`hxxps://leb[.]5tr[.]org`](https://www.virustotal.com/gui/search/https%3A%2F%2Fleb.5tr.org) | url | Vidar | threatfox | 2026-10-11T21:38:02Z | 100 |
| [`leb[.]5tr[.]org`](https://www.virustotal.com/gui/domain/leb.5tr.org) | domain | Vidar | threatfox | 2026-10-11T21:35:48Z | 100 |
| [`hxxps://leb[.]5tr[.]org/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fleb.5tr.org%2F) | url | Vidar | threatfox | 2026-10-11T21:35:48Z | 100 |
| [`leb[.]iakmialor[.]web[.]id`](https://www.virustotal.com/gui/domain/leb.iakmialor.web.id) | domain | Vidar | threatfox | 2026-10-11T21:35:48Z | 100 |
| [`hxxps://leb[.]iakmialor[.]web[.]id/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fleb.iakmialor.web.id%2F) | url | Vidar | threatfox | 2026-10-11T21:35:48Z | 100 |
| [`hxxps://qli[.]5tr[.]org`](https://www.virustotal.com/gui/search/https%3A%2F%2Fqli.5tr.org) | url | Vidar | threatfox | 2026-10-11T21:21:58Z | 100 |
| [`qli[.]5tr[.]org`](https://www.virustotal.com/gui/domain/qli.5tr.org) | domain | Vidar | threatfox | 2026-10-11T21:20:48Z | 100 |
| [`hxxps://qli[.]5tr[.]org/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fqli.5tr.org%2F) | url | Vidar | threatfox | 2026-10-11T21:20:48Z | 100 |
| [`qli[.]iakmialor[.]web[.]id`](https://www.virustotal.com/gui/domain/qli.iakmialor.web.id) | domain | Vidar | threatfox | 2026-10-11T21:20:48Z | 100 |
| [`hxxps://qli[.]iakmialor[.]web[.]id/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fqli.iakmialor.web.id%2F) | url | Vidar | threatfox | 2026-10-11T21:20:48Z | 100 |
| [`hxxps://qli[.]iakmialor[.]web[.]id`](https://www.virustotal.com/gui/search/https%3A%2F%2Fqli.iakmialor.web.id) | url | Vidar | threatfox | 2026-10-11T21:16:51Z | 100 |
| [`hxxps://vhu[.]5tr[.]org`](https://www.virustotal.com/gui/search/https%3A%2F%2Fvhu.5tr.org) | url | Vidar | threatfox | 2026-10-11T21:02:37Z | 100 |
| [`drvto[.]site`](https://www.virustotal.com/gui/domain/drvto.site) | domain | ClearFake | threatfox | 2026-10-11T21:01:56Z | 100 |
| [`vhu[.]iakmialor[.]web[.]id`](https://www.virustotal.com/gui/domain/vhu.iakmialor.web.id) | domain | Vidar | threatfox | 2026-10-11T21:00:49Z | 100 |
| [`hxxps://vhu[.]iakmialor[.]web[.]id/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fvhu.iakmialor.web.id%2F) | url | Vidar | threatfox | 2026-10-11T21:00:49Z | 100 |
| [`vhu[.]5tr[.]org`](https://www.virustotal.com/gui/domain/vhu.5tr.org) | domain | Vidar | threatfox | 2026-10-11T21:00:48Z | 100 |
| [`hxxps://vhu[.]5tr[.]org/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fvhu.5tr.org%2F) | url | Vidar | threatfox | 2026-10-11T21:00:48Z | 100 |
| [`hxxps://jig[.]iakmialor[.]web[.]id`](https://www.virustotal.com/gui/search/https%3A%2F%2Fjig.iakmialor.web.id) | url | Vidar | threatfox | 2026-10-11T20:58:18Z | 100 |
| [`jig[.]5tr[.]org`](https://www.virustotal.com/gui/domain/jig.5tr.org) | domain | Vidar | threatfox | 2026-10-11T20:45:48Z | 100 |
| [`hxxps://jig[.]5tr[.]org/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fjig.5tr.org%2F) | url | Vidar | threatfox | 2026-10-11T20:45:48Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
