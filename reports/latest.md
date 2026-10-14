# Threat Intel Pulse — 2026-10-14

**Window:** last 7 days · **Generated:** 2026-10-14T17:22:28Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 63804 |
| New in window | 22106 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5000 | ok |
| feodo | 5 | ok |
| threatfox | 8171 | ok |
| malwarebazaar | 1140 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8578 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 24686 | 11995 |
| sha256 | 12259 | 3821 |
| domain | 11355 | 3369 |
| ipv4 | 11235 | 2000 |
| ipv6 | 3026 | 158 |
| md5 | 634 | 382 |
| sha1 | 609 | 381 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 10387 |
| Exit nodes | 2246 |
| Other relays | 8141 |
| New in window | 946 |

Sample (20 of 10387, source: Tor Project Onionoo):
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
| Mirai | 4179 | 834 | T1498, T1071.001 |
| Vidar | 2710 | 2430 | T1555, T1071.001, T1567 |
| AsyncRAT | 2266 | 88 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| ClearFake | 1843 | 784 | — |
| IClickFix | 1332 | 599 | — |
| Cobalt Strike | 1325 | 82 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| Unknown malware | 1029 | 468 | — |
| Unknown Stealer | 627 | 437 | — |
| php.shin_webshell | 482 | 352 | — |
| PureRAT | 406 | 53 | — |
| VShell | 352 | 238 | — |
| AMOS | 332 | 172 | — |
| Sliver | 290 | 268 | T1071.001, T1573, T1090, T1055 |
| AdaptixC2 | 282 | 31 | — |
| Remcos | 254 | 111 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| Unknown RAT | 204 | 36 | — |
| DanaBot | 193 | 130 | T1566.001, T1071.001, T1555, T1041 |
| Remus | 180 | 71 | — |
| Formbook | 133 | 71 | T1566.001, T1056.001, T1555, T1071.001, T1567 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1105 | Ingress Tool Transfer | command-and-control | 20539 |
| T1071.001 | Web Protocols | command-and-control | 40912 |
| T1498 | Network Denial of Service | impact | 9603 |
| T1204.002 | Malicious File | execution | 7815 |
| T1027 | Obfuscated Files or Information | defense-evasion | 7804 |
| T1573 | Encrypted Channel | command-and-control | 6958 |
| T1555 | Credentials from Password Stores | credential-access | 5413 |
| T1567 | Exfiltration Over Web Service | exfiltration | 5220 |
| T1566 | Phishing | initial-access | 4525 |
| T1566.002 | Spearphishing Link | initial-access | 4525 |
| T1056.001 | Keylogging | collection, credential-access | 3605 |
| T1566.001 | Spearphishing Attachment | initial-access | 3291 |
| T1552.001 | Credentials In Files | credential-access | 3183 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 2793 |
| T1113 | Screen Capture | collection | 2758 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1841 |
| T1090 | Proxy | command-and-control | 1649 |
| T1059.001 | PowerShell | execution | 1338 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 337 |
| T1059.005 | Visual Basic | execution | 83 |
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
| [`185[.]157[.]163[.]135`](https://www.virustotal.com/gui/ip-address/185.157.163.135) | ipv4 | Remcos | threatfox | 2026-10-14T17:19:45Z | 100 |
| [`hxxps://zv[.]77tuna[.]org/h9`](https://www.virustotal.com/gui/search/https%3A%2F%2Fzv.77tuna.org%2Fh9) | url | Vidar | threatfox | 2026-10-14T17:18:25Z | 100 |
| [`hxxps://zv[.]77tuna[.]org/gu`](https://www.virustotal.com/gui/search/https%3A%2F%2Fzv.77tuna.org%2Fgu) | url | Vidar | threatfox | 2026-10-14T17:16:18Z | 100 |
| [`hxxps://zv[.]77tuna[.]org/fx/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fzv.77tuna.org%2Ffx%2F) | url | Vidar | threatfox | 2026-10-14T17:15:48Z | 100 |
| [`hxxps://zv[.]77tuna[.]org/fx`](https://www.virustotal.com/gui/search/https%3A%2F%2Fzv.77tuna.org%2Ffx) | url | Vidar | threatfox | 2026-10-14T17:14:29Z | 100 |
| [`172[.]81[.]131[.]177`](https://www.virustotal.com/gui/ip-address/172.81.131.177) | ipv4 | Remcos | threatfox | 2026-10-14T17:13:06Z | 100 |
| [`hxxps://zv[.]77tuna[.]org/c4`](https://www.virustotal.com/gui/search/https%3A%2F%2Fzv.77tuna.org%2Fc4) | url | Vidar | threatfox | 2026-10-14T17:12:53Z | 100 |
| [`107[.]174[.]19[.]22`](https://www.virustotal.com/gui/ip-address/107.174.19.22) | ipv4 | Remcos | threatfox | 2026-10-14T17:11:52Z | 100 |
| [`hxxps://zv[.]77tuna[.]org/os/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fzv.77tuna.org%2Fos%2F) | url | Vidar | threatfox | 2026-10-14T17:10:48Z | 100 |
| [`hxxps://zv[.]77tuna[.]org/os`](https://www.virustotal.com/gui/search/https%3A%2F%2Fzv.77tuna.org%2Fos) | url | Vidar | threatfox | 2026-10-14T17:10:30Z | 100 |
| [`38[.]49[.]209[.]244`](https://www.virustotal.com/gui/ip-address/38.49.209.244) | ipv4 | Remcos | threatfox | 2026-10-14T17:10:07Z | 100 |
| [`hxxps://zv[.]77tuna[.]org/f3`](https://www.virustotal.com/gui/search/https%3A%2F%2Fzv.77tuna.org%2Ff3) | url | Vidar | threatfox | 2026-10-14T17:08:38Z | 100 |
| [`hxxps://zv[.]77tuna[.]org/e`](https://www.virustotal.com/gui/search/https%3A%2F%2Fzv.77tuna.org%2Fe) | url | Vidar | threatfox | 2026-10-14T17:07:44Z | 100 |
| [`hxxps://zv[.]77tuna[.]org/tq/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fzv.77tuna.org%2Ftq%2F) | url | Vidar | threatfox | 2026-10-14T17:05:48Z | 100 |
| [`hxxps://zv[.]77tuna[.]org/tq`](https://www.virustotal.com/gui/search/https%3A%2F%2Fzv.77tuna.org%2Ftq) | url | Vidar | threatfox | 2026-10-14T17:04:25Z | 100 |
| [`hxxps://zv[.]77tuna[.]org/st`](https://www.virustotal.com/gui/search/https%3A%2F%2Fzv.77tuna.org%2Fst) | url | Vidar | threatfox | 2026-10-14T17:02:27Z | 100 |
| [`hxxps://dkz[.]77tuna[.]org/q/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fdkz.77tuna.org%2Fq%2F) | url | Vidar | threatfox | 2026-10-14T17:00:49Z | 100 |
| [`hxxps://dkz[.]77tuna[.]org/q`](https://www.virustotal.com/gui/search/https%3A%2F%2Fdkz.77tuna.org%2Fq) | url | Vidar | threatfox | 2026-10-14T17:00:28Z | 100 |
| [`hxxps://dkz[.]77tuna[.]org/j1`](https://www.virustotal.com/gui/search/https%3A%2F%2Fdkz.77tuna.org%2Fj1) | url | Vidar | threatfox | 2026-10-14T16:58:18Z | 100 |
| [`hxxps://dkz[.]77tuna[.]org/gi`](https://www.virustotal.com/gui/search/https%3A%2F%2Fdkz.77tuna.org%2Fgi) | url | Vidar | threatfox | 2026-10-14T16:56:29Z | 100 |
| [`hxxps://dkz[.]77tuna[.]org/u4/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fdkz.77tuna.org%2Fu4%2F) | url | Vidar | threatfox | 2026-10-14T16:55:48Z | 100 |
| [`hxxps://dkz[.]77tuna[.]org/u4`](https://www.virustotal.com/gui/search/https%3A%2F%2Fdkz.77tuna.org%2Fu4) | url | Vidar | threatfox | 2026-10-14T16:55:06Z | 100 |
| [`hxxps://dkz[.]77tuna[.]org/ij`](https://www.virustotal.com/gui/search/https%3A%2F%2Fdkz.77tuna.org%2Fij) | url | Vidar | threatfox | 2026-10-14T16:52:57Z | 100 |
| [`hxxps://dkz[.]77tuna[.]org/ajz/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fdkz.77tuna.org%2Fajz%2F) | url | Vidar | threatfox | 2026-10-14T16:50:48Z | 100 |
| [`hxxps://dkz[.]77tuna[.]org/ajz`](https://www.virustotal.com/gui/search/https%3A%2F%2Fdkz.77tuna.org%2Fajz) | url | Vidar | threatfox | 2026-10-14T16:50:22Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
