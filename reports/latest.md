# Threat Intel Pulse — 2026-10-14

**Window:** last 7 days · **Generated:** 2026-10-14T05:04:56Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 61831 |
| New in window | 21362 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5000 | ok |
| feodo | 5 | ok |
| threatfox | 7958 | ok |
| malwarebazaar | 1131 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8576 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 23548 | 11511 |
| sha256 | 11847 | 3662 |
| ipv4 | 11091 | 2020 |
| domain | 11087 | 3241 |
| ipv6 | 3015 | 165 |
| md5 | 634 | 382 |
| sha1 | 609 | 381 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 10335 |
| Exit nodes | 2244 |
| Other relays | 8091 |
| New in window | 1006 |

Sample (20 of 10335, source: Tor Project Onionoo):
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
| Unknown Loader | 4867 | 758 | — |
| Mirai | 4169 | 832 | T1498, T1071.001 |
| AsyncRAT | 2261 | 85 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| Vidar | 2191 | 1936 | T1555, T1071.001, T1567 |
| ClearFake | 1817 | 813 | — |
| IClickFix | 1324 | 594 | — |
| Cobalt Strike | 1319 | 78 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| Unknown malware | 993 | 446 | — |
| Unknown Stealer | 624 | 436 | — |
| php.shin_webshell | 452 | 349 | — |
| PureRAT | 404 | 59 | — |
| VShell | 349 | 238 | — |
| AMOS | 299 | 153 | — |
| Sliver | 284 | 262 | T1071.001, T1573, T1090, T1055 |
| AdaptixC2 | 280 | 29 | — |
| Remcos | 228 | 95 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| Unknown RAT | 197 | 30 | — |
| DanaBot | 193 | 130 | T1566.001, T1071.001, T1555, T1041 |
| Remus | 176 | 73 | — |
| Formbook | 133 | 73 | T1566.001, T1056.001, T1555, T1071.001, T1567 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1105 | Ingress Tool Transfer | command-and-control | 19835 |
| T1071.001 | Web Protocols | command-and-control | 39892 |
| T1498 | Network Denial of Service | impact | 9488 |
| T1204.002 | Malicious File | execution | 7422 |
| T1027 | Obfuscated Files or Information | defense-evasion | 7411 |
| T1573 | Encrypted Channel | command-and-control | 6514 |
| T1555 | Credentials from Password Stores | credential-access | 4796 |
| T1567 | Exfiltration Over Web Service | exfiltration | 4603 |
| T1566 | Phishing | initial-access | 4225 |
| T1566.002 | Spearphishing Link | initial-access | 4225 |
| T1056.001 | Keylogging | collection, credential-access | 3558 |
| T1566.001 | Spearphishing Attachment | initial-access | 3254 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 2756 |
| T1113 | Screen Capture | collection | 2721 |
| T1552.001 | Credentials In Files | credential-access | 2716 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1820 |
| T1090 | Proxy | command-and-control | 1637 |
| T1059.001 | PowerShell | execution | 1332 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 337 |
| T1059.005 | Visual Basic | execution | 74 |
| T1189 | Drive-by Compromise | initial-access | 23 |
| T1218 | System Binary Proxy Execution | defense-evasion | 23 |
| T1021.001 | Remote Desktop Protocol | lateral-movement | 14 |
| T1486 | Data Encrypted for Impact | impact | 14 |
| T1490 | Inhibit System Recovery | impact | 14 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 14 |
| T1003 | OS Credential Dumping | credential-access | 4 |
| T1190 | Exploit Public-Facing Application | initial-access | 2 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://bk[.]77777w[.]net/j14`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbk.77777w.net%2Fj14) | url | Vidar | threatfox | 2026-10-14T04:54:35Z | 100 |
| [`hxxps://bk[.]77777w[.]net/i1`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbk.77777w.net%2Fi1) | url | Vidar | threatfox | 2026-10-14T04:52:18Z | 100 |
| [`hxxps://bk[.]77777w[.]net/jd1/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbk.77777w.net%2Fjd1%2F) | url | Vidar | threatfox | 2026-10-14T04:50:48Z | 100 |
| [`hxxps://bk[.]77777w[.]net/jd1`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbk.77777w.net%2Fjd1) | url | Vidar | threatfox | 2026-10-14T04:50:29Z | 100 |
| [`hxxps://bk[.]77777w[.]net/j5o`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbk.77777w.net%2Fj5o) | url | Vidar | threatfox | 2026-10-14T04:48:35Z | 100 |
| [`hxxps://bk[.]77777w[.]net/vp`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbk.77777w.net%2Fvp) | url | Vidar | threatfox | 2026-10-14T04:46:19Z | 100 |
| [`hxxps://bk[.]77777w[.]net/xq/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbk.77777w.net%2Fxq%2F) | url | Vidar | threatfox | 2026-10-14T04:45:48Z | 100 |
| [`hxxps://bk[.]77777w[.]net/xq`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbk.77777w.net%2Fxq) | url | Vidar | threatfox | 2026-10-14T04:44:23Z | 100 |
| [`hxxps://bk[.]77777w[.]net/ex`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbk.77777w.net%2Fex) | url | Vidar | threatfox | 2026-10-14T04:42:52Z | 100 |
| [`hxxps://bk[.]77777w[.]net/d07/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbk.77777w.net%2Fd07%2F) | url | Vidar | threatfox | 2026-10-14T04:40:48Z | 100 |
| [`hxxps://bk[.]77777w[.]net/d07`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbk.77777w.net%2Fd07) | url | Vidar | threatfox | 2026-10-14T04:40:23Z | 100 |
| [`hxxps://bk[.]77777w[.]net/t`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbk.77777w.net%2Ft) | url | Vidar | threatfox | 2026-10-14T04:38:21Z | 100 |
| [`hxxps://bk[.]77777w[.]net/n`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbk.77777w.net%2Fn) | url | Vidar | threatfox | 2026-10-14T04:36:34Z | 100 |
| [`hxxps://bk[.]77777w[.]net/nz/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbk.77777w.net%2Fnz%2F) | url | Vidar | threatfox | 2026-10-14T04:35:48Z | 100 |
| [`hxxps://bk[.]77777w[.]net/nz`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbk.77777w.net%2Fnz) | url | Vidar | threatfox | 2026-10-14T04:35:10Z | 100 |
| [`hxxps://bk[.]77777w[.]net/v5g`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbk.77777w.net%2Fv5g) | url | Vidar | threatfox | 2026-10-14T04:32:54Z | 100 |
| [`hxxps://bk[.]77777w[.]net/uc/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbk.77777w.net%2Fuc%2F) | url | Vidar | threatfox | 2026-10-14T04:30:48Z | 100 |
| [`hxxps://bk[.]77777w[.]net/uc`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbk.77777w.net%2Fuc) | url | Vidar | threatfox | 2026-10-14T04:30:34Z | 100 |
| [`hxxps://bk[.]77777w[.]net/n4`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbk.77777w.net%2Fn4) | url | Vidar | threatfox | 2026-10-14T04:28:39Z | 100 |
| [`hxxps://bk[.]77777w[.]net/xf`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbk.77777w.net%2Fxf) | url | Vidar | threatfox | 2026-10-14T04:26:57Z | 100 |
| [`hxxps://bk[.]77777w[.]net/z7/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbk.77777w.net%2Fz7%2F) | url | Vidar | threatfox | 2026-10-14T04:25:48Z | 100 |
| [`amanahceria[.]us[.]com`](https://www.virustotal.com/gui/domain/amanahceria.us.com) | domain | ClearFake | threatfox | 2026-10-14T04:25:28Z | 100 |
| [`hxxps://bk[.]77777w[.]net/z7`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbk.77777w.net%2Fz7) | url | Vidar | threatfox | 2026-10-14T04:25:16Z | 100 |
| [`hxxps://bk[.]77777w[.]net/p3`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbk.77777w.net%2Fp3) | url | Vidar | threatfox | 2026-10-14T04:22:22Z | 100 |
| [`hxxps://bk[.]77777w[.]net/d/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbk.77777w.net%2Fd%2F) | url | Vidar | threatfox | 2026-10-14T04:20:48Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
