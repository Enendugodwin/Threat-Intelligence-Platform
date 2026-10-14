# Threat Intel Pulse — 2026-10-14

**Window:** last 7 days · **Generated:** 2026-10-14T21:49:44Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 64379 |
| New in window | 22681 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5000 | ok |
| feodo | 5 | ok |
| threatfox | 8262 | ok |
| malwarebazaar | 1237 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8605 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 24922 | 12231 |
| sha256 | 12534 | 4096 |
| domain | 11373 | 3387 |
| ipv4 | 11280 | 2045 |
| ipv6 | 3027 | 159 |
| md5 | 634 | 382 |
| sha1 | 609 | 381 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 10396 |
| Exit nodes | 2247 |
| Other relays | 8149 |
| New in window | 955 |

Sample (20 of 10396, source: Tor Project Onionoo):
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
| Unknown Loader | 4901 | 790 | — |
| Mirai | 4194 | 849 | T1498, T1071.001 |
| Vidar | 2886 | 2606 | T1555, T1071.001, T1567 |
| AsyncRAT | 2268 | 90 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| ClearFake | 1847 | 788 | — |
| IClickFix | 1332 | 599 | — |
| Cobalt Strike | 1325 | 82 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| Unknown malware | 1038 | 477 | — |
| Unknown Stealer | 627 | 437 | — |
| php.shin_webshell | 489 | 359 | — |
| PureRAT | 409 | 56 | — |
| VShell | 353 | 239 | — |
| AMOS | 336 | 176 | — |
| Sliver | 297 | 275 | T1071.001, T1573, T1090, T1055 |
| AdaptixC2 | 283 | 32 | — |
| Remcos | 257 | 114 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| Unknown RAT | 204 | 36 | — |
| DanaBot | 194 | 131 | T1566.001, T1071.001, T1555, T1041 |
| Remus | 180 | 71 | — |
| Formbook | 133 | 71 | T1566.001, T1056.001, T1555, T1071.001, T1567 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1105 | Ingress Tool Transfer | command-and-control | 20728 |
| T1071.001 | Web Protocols | command-and-control | 41174 |
| T1498 | Network Denial of Service | impact | 9638 |
| T1204.002 | Malicious File | execution | 7943 |
| T1027 | Obfuscated Files or Information | defense-evasion | 7932 |
| T1573 | Encrypted Channel | command-and-control | 7101 |
| T1555 | Credentials from Password Stores | credential-access | 5605 |
| T1567 | Exfiltration Over Web Service | exfiltration | 5411 |
| T1566 | Phishing | initial-access | 4525 |
| T1566.002 | Spearphishing Link | initial-access | 4525 |
| T1056.001 | Keylogging | collection, credential-access | 3614 |
| T1552.001 | Credentials In Files | credential-access | 3323 |
| T1566.001 | Spearphishing Attachment | initial-access | 3298 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 2798 |
| T1113 | Screen Capture | collection | 2763 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1852 |
| T1090 | Proxy | command-and-control | 1657 |
| T1059.001 | PowerShell | execution | 1338 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 339 |
| T1059.005 | Visual Basic | execution | 85 |
| T1189 | Drive-by Compromise | initial-access | 23 |
| T1218 | System Binary Proxy Execution | defense-evasion | 23 |
| T1021.001 | Remote Desktop Protocol | lateral-movement | 14 |
| T1486 | Data Encrypted for Impact | impact | 14 |
| T1490 | Inhibit System Recovery | impact | 14 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 14 |
| T1190 | Exploit Public-Facing Application | initial-access | 5 |
| T1003 | OS Credential Dumping | credential-access | 4 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://t9[.]77tuna[.]org/d1`](https://www.virustotal.com/gui/search/https%3A%2F%2Ft9.77tuna.org%2Fd1) | url | Vidar | threatfox | 2026-10-14T21:44:33Z | 100 |
| [`hxxps://t9[.]77tuna[.]org/hf`](https://www.virustotal.com/gui/search/https%3A%2F%2Ft9.77tuna.org%2Fhf) | url | Vidar | threatfox | 2026-10-14T21:42:53Z | 100 |
| [`hxxps://t9[.]77tuna[.]org/a/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ft9.77tuna.org%2Fa%2F) | url | Vidar | threatfox | 2026-10-14T21:40:48Z | 100 |
| [`hxxps://t9[.]77tuna[.]org/a`](https://www.virustotal.com/gui/search/https%3A%2F%2Ft9.77tuna.org%2Fa) | url | Vidar | threatfox | 2026-10-14T21:40:36Z | 100 |
| [`hxxps://t9[.]77tuna[.]org/y4`](https://www.virustotal.com/gui/search/https%3A%2F%2Ft9.77tuna.org%2Fy4) | url | Vidar | threatfox | 2026-10-14T21:38:50Z | 100 |
| [`hxxps://t9[.]77tuna[.]org/h1`](https://www.virustotal.com/gui/search/https%3A%2F%2Ft9.77tuna.org%2Fh1) | url | Vidar | threatfox | 2026-10-14T21:37:10Z | 100 |
| [`hxxps://t9[.]77tuna[.]org/xfp/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ft9.77tuna.org%2Fxfp%2F) | url | Vidar | threatfox | 2026-10-14T21:35:48Z | 100 |
| [`hxxps://t9[.]77tuna[.]org/xfp`](https://www.virustotal.com/gui/search/https%3A%2F%2Ft9.77tuna.org%2Fxfp) | url | Vidar | threatfox | 2026-10-14T21:34:53Z | 100 |
| [`hxxps://t9[.]77tuna[.]org/tv`](https://www.virustotal.com/gui/search/https%3A%2F%2Ft9.77tuna.org%2Ftv) | url | Vidar | threatfox | 2026-10-14T21:32:03Z | 100 |
| [`hxxps://t9[.]77tuna[.]org/j1/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ft9.77tuna.org%2Fj1%2F) | url | Vidar | threatfox | 2026-10-14T21:30:48Z | 100 |
| [`hxxps://t9[.]77tuna[.]org/c3`](https://www.virustotal.com/gui/search/https%3A%2F%2Ft9.77tuna.org%2Fc3) | url | Vidar | threatfox | 2026-10-14T21:28:46Z | 100 |
| [`hxxps://t9[.]77tuna[.]org/es`](https://www.virustotal.com/gui/search/https%3A%2F%2Ft9.77tuna.org%2Fes) | url | Vidar | threatfox | 2026-10-14T21:26:39Z | 100 |
| [`hxxps://t9[.]77tuna[.]org/nv/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ft9.77tuna.org%2Fnv%2F) | url | Vidar | threatfox | 2026-10-14T21:25:48Z | 100 |
| [`hxxps://t9[.]77tuna[.]org/nv`](https://www.virustotal.com/gui/search/https%3A%2F%2Ft9.77tuna.org%2Fnv) | url | Vidar | threatfox | 2026-10-14T21:24:23Z | 100 |
| [`hxxps://t9[.]77tuna[.]org/lo`](https://www.virustotal.com/gui/search/https%3A%2F%2Ft9.77tuna.org%2Flo) | url | Vidar | threatfox | 2026-10-14T21:22:52Z | 100 |
| [`hxxps://t9[.]77tuna[.]org/fr`](https://www.virustotal.com/gui/search/https%3A%2F%2Ft9.77tuna.org%2Ffr) | url | Vidar | threatfox | 2026-10-14T21:21:49Z | 100 |
| [`hxxps://t9[.]77tuna[.]org/i3`](https://www.virustotal.com/gui/search/https%3A%2F%2Ft9.77tuna.org%2Fi3) | url | Vidar | threatfox | 2026-10-14T21:21:00Z | 100 |
| [`hxxps://t9[.]77tuna[.]org/re`](https://www.virustotal.com/gui/search/https%3A%2F%2Ft9.77tuna.org%2Fre) | url | Vidar | threatfox | 2026-10-14T21:18:34Z | 100 |
| [`hxxps://t9[.]77tuna[.]org/wi`](https://www.virustotal.com/gui/search/https%3A%2F%2Ft9.77tuna.org%2Fwi) | url | Vidar | threatfox | 2026-10-14T21:16:38Z | 100 |
| [`hxxps://t9[.]77tuna[.]org/o3`](https://www.virustotal.com/gui/search/https%3A%2F%2Ft9.77tuna.org%2Fo3) | url | Vidar | threatfox | 2026-10-14T21:15:50Z | 100 |
| [`hxxps://t9[.]77tuna[.]org/o3/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ft9.77tuna.org%2Fo3%2F) | url | Vidar | threatfox | 2026-10-14T21:15:48Z | 100 |
| [`hxxps://t9[.]77tuna[.]org/l5`](https://www.virustotal.com/gui/search/https%3A%2F%2Ft9.77tuna.org%2Fl5) | url | Vidar | threatfox | 2026-10-14T21:14:37Z | 100 |
| [`hxxps://t9[.]77tuna[.]org/yt`](https://www.virustotal.com/gui/search/https%3A%2F%2Ft9.77tuna.org%2Fyt) | url | Vidar | threatfox | 2026-10-14T21:11:27Z | 100 |
| [`hxxps://t9[.]77tuna[.]org/yt/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ft9.77tuna.org%2Fyt%2F) | url | Vidar | threatfox | 2026-10-14T21:10:48Z | 100 |
| [`213[.]152[.]162[.]19`](https://www.virustotal.com/gui/ip-address/213.152.162.19) | ipv4 | Remcos | threatfox | 2026-10-14T21:10:20Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
