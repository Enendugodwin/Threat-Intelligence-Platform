# Threat Intel Pulse — 2026-10-16

**Window:** last 7 days · **Generated:** 2026-10-16T11:39:42Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 70229 |
| New in window | 22388 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5001 | ok |
| feodo | 5 | ok |
| threatfox | 8300 | ok |
| malwarebazaar | 1057 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8707 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 28181 | 11924 |
| sha256 | 13372 | 4027 |
| domain | 12171 | 3160 |
| ipv4 | 11760 | 2133 |
| ipv6 | 3176 | 261 |
| md5 | 797 | 442 |
| sha1 | 772 | 441 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 10809 |
| Exit nodes | 2370 |
| Other relays | 8439 |
| New in window | 1095 |

Sample (20 of 10809, source: Tor Project Onionoo):
- `1[.]201[.]176[.]176`
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
- `102[.]216[.]253[.]63`

Full list: `dist/tor/tor_nodes.txt` (in the `threat-intel-output` workflow artifact).
## Top malware families

| Family | Indicators | New | ATT&CK (heuristic) |
| --- | --- | --- | --- |
| Unknown Loader | 4997 | 520 | — |
| Vidar | 4495 | 4126 | T1555, T1071.001, T1567 |
| Mirai | 4286 | 744 | T1498, T1071.001 |
| AsyncRAT | 2306 | 114 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| ClearFake | 1903 | 684 | — |
| IClickFix | 1562 | 668 | — |
| Cobalt Strike | 1338 | 81 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| Unknown malware | 1271 | 639 | — |
| VShell | 653 | 522 | — |
| Unknown Stealer | 630 | 136 | — |
| php.shin_webshell | 560 | 336 | — |
| AMOS | 444 | 256 | — |
| PureRAT | 421 | 54 | — |
| Sliver | 312 | 289 | T1071.001, T1573, T1090, T1055 |
| Remcos | 293 | 131 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| AdaptixC2 | 287 | 29 | — |
| Remus | 233 | 94 | — |
| Unknown RAT | 205 | 34 | — |
| DanaBot | 195 | 132 | T1566.001, T1071.001, T1555, T1041 |
| Formbook | 184 | 96 | T1566.001, T1056.001, T1555, T1071.001, T1567 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1105 | Ingress Tool Transfer | command-and-control | 22637 |
| T1071.001 | Web Protocols | command-and-control | 44661 |
| T1498 | Network Denial of Service | impact | 9974 |
| T1204.002 | Malicious File | execution | 9279 |
| T1027 | Obfuscated Files or Information | defense-evasion | 9117 |
| T1573 | Encrypted Channel | command-and-control | 8549 |
| T1555 | Credentials from Password Stores | credential-access | 7505 |
| T1567 | Exfiltration Over Web Service | exfiltration | 7310 |
| T1566 | Phishing | initial-access | 5426 |
| T1566.002 | Spearphishing Link | initial-access | 5426 |
| T1552.001 | Credentials In Files | credential-access | 4644 |
| T1056.001 | Keylogging | collection, credential-access | 3828 |
| T1566.001 | Spearphishing Attachment | initial-access | 3515 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 2932 |
| T1113 | Screen Capture | collection | 2892 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1892 |
| T1090 | Proxy | command-and-control | 1686 |
| T1059.001 | PowerShell | execution | 1351 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 363 |
| T1189 | Drive-by Compromise | initial-access | 176 |
| T1218 | System Binary Proxy Execution | defense-evasion | 176 |
| T1059.005 | Visual Basic | execution | 91 |
| T1021.001 | Remote Desktop Protocol | lateral-movement | 14 |
| T1486 | Data Encrypted for Impact | impact | 14 |
| T1490 | Inhibit System Recovery | impact | 14 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 14 |
| T1190 | Exploit Public-Facing Application | initial-access | 5 |
| T1003 | OS Credential Dumping | credential-access | 4 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`citaasesoriareyes[.]com`](https://www.virustotal.com/gui/domain/citaasesoriareyes.com) | domain | ClearFake | threatfox | 2026-10-16T11:33:44Z | 100 |
| [`hxxps://l[.]888idrcatchy[.]org/to`](https://www.virustotal.com/gui/search/https%3A%2F%2Fl.888idrcatchy.org%2Fto) | url | Vidar | threatfox | 2026-10-16T11:32:44Z | 100 |
| [`hxxps://l[.]888idrcatchy[.]org/om/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fl.888idrcatchy.org%2Fom%2F) | url | Vidar | threatfox | 2026-10-16T11:30:48Z | 100 |
| [`hxxps://l[.]888idrcatchy[.]org/om`](https://www.virustotal.com/gui/search/https%3A%2F%2Fl.888idrcatchy.org%2Fom) | url | Vidar | threatfox | 2026-10-16T11:30:16Z | 100 |
| [`hxxps://l[.]888idrcatchy[.]org/ua`](https://www.virustotal.com/gui/search/https%3A%2F%2Fl.888idrcatchy.org%2Fua) | url | Vidar | threatfox | 2026-10-16T11:30:05Z | 100 |
| [`hxxps://l[.]888idrcatchy[.]org/ie`](https://www.virustotal.com/gui/search/https%3A%2F%2Fl.888idrcatchy.org%2Fie) | url | Vidar | threatfox | 2026-10-16T11:26:33Z | 100 |
| [`hxxps://l[.]888idrcatchy[.]org/gw/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fl.888idrcatchy.org%2Fgw%2F) | url | Vidar | threatfox | 2026-10-16T11:25:48Z | 100 |
| [`hxxps://l[.]888idrcatchy[.]org/gw`](https://www.virustotal.com/gui/search/https%3A%2F%2Fl.888idrcatchy.org%2Fgw) | url | Vidar | threatfox | 2026-10-16T11:24:22Z | 100 |
| [`hxxps://l[.]888idrcatchy[.]org/bn`](https://www.virustotal.com/gui/search/https%3A%2F%2Fl.888idrcatchy.org%2Fbn) | url | Vidar | threatfox | 2026-10-16T11:22:29Z | 100 |
| [`hxxps://l[.]888idrcatchy[.]org/t8`](https://www.virustotal.com/gui/search/https%3A%2F%2Fl.888idrcatchy.org%2Ft8) | url | Vidar | threatfox | 2026-10-16T11:21:27Z | 100 |
| [`hxxps://l[.]888idrcatchy[.]org/t8/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fl.888idrcatchy.org%2Ft8%2F) | url | Vidar | threatfox | 2026-10-16T11:20:48Z | 100 |
| [`hxxps://l[.]888idrcatchy[.]org/gp`](https://www.virustotal.com/gui/search/https%3A%2F%2Fl.888idrcatchy.org%2Fgp) | url | Vidar | threatfox | 2026-10-16T11:19:15Z | 100 |
| [`hxxps://l[.]888idrcatchy[.]org/kgh`](https://www.virustotal.com/gui/search/https%3A%2F%2Fl.888idrcatchy.org%2Fkgh) | url | Vidar | threatfox | 2026-10-16T11:17:21Z | 100 |
| [`hxxps://l[.]888idrcatchy[.]org/bj`](https://www.virustotal.com/gui/search/https%3A%2F%2Fl.888idrcatchy.org%2Fbj) | url | Vidar | threatfox | 2026-10-16T11:15:53Z | 100 |
| [`hxxps://l[.]888idrcatchy[.]org/bj/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fl.888idrcatchy.org%2Fbj%2F) | url | Vidar | threatfox | 2026-10-16T11:15:48Z | 100 |
| [`hxxps://l[.]888idrcatchy[.]org/vol`](https://www.virustotal.com/gui/search/https%3A%2F%2Fl.888idrcatchy.org%2Fvol) | url | Vidar | threatfox | 2026-10-16T11:13:56Z | 100 |
| [`94[.]154[.]40[.]109`](https://www.virustotal.com/gui/ip-address/94.154.40.109) | ipv4 | Remcos | threatfox | 2026-10-16T11:12:40Z | 100 |
| [`hxxps://l[.]888idrcatchy[.]org/sq/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fl.888idrcatchy.org%2Fsq%2F) | url | Vidar | threatfox | 2026-10-16T11:10:48Z | 100 |
| [`hxxps://l[.]888idrcatchy[.]org/sq`](https://www.virustotal.com/gui/search/https%3A%2F%2Fl.888idrcatchy.org%2Fsq) | url | Vidar | threatfox | 2026-10-16T11:10:41Z | 100 |
| [`hxxps://l[.]888idrcatchy[.]org/y2u`](https://www.virustotal.com/gui/search/https%3A%2F%2Fl.888idrcatchy.org%2Fy2u) | url | Vidar | threatfox | 2026-10-16T11:08:27Z | 100 |
| [`hxxps://l[.]888idrcatchy[.]org/u`](https://www.virustotal.com/gui/search/https%3A%2F%2Fl.888idrcatchy.org%2Fu) | url | Vidar | threatfox | 2026-10-16T11:06:53Z | 100 |
| [`hxxps://l[.]888idrcatchy[.]org/yg/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fl.888idrcatchy.org%2Fyg%2F) | url | Vidar | threatfox | 2026-10-16T11:05:48Z | 100 |
| [`hxxps://l[.]888idrcatchy[.]org/yg`](https://www.virustotal.com/gui/search/https%3A%2F%2Fl.888idrcatchy.org%2Fyg) | url | Vidar | threatfox | 2026-10-16T11:04:25Z | 100 |
| [`hxxps://l[.]888idrcatchy[.]org/zc`](https://www.virustotal.com/gui/search/https%3A%2F%2Fl.888idrcatchy.org%2Fzc) | url | Vidar | threatfox | 2026-10-16T11:02:22Z | 100 |
| [`hxxps://l[.]888idrcatchy[.]org`](https://www.virustotal.com/gui/search/https%3A%2F%2Fl.888idrcatchy.org) | url | Vidar | threatfox | 2026-10-16T11:01:45Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
