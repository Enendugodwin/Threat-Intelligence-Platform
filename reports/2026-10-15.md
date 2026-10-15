# Threat Intel Pulse — 2026-10-15

**Window:** last 7 days · **Generated:** 2026-10-15T11:45:57Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 66583 |
| New in window | 21706 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5000 | ok |
| feodo | 5 | ok |
| threatfox | 8612 | ok |
| malwarebazaar | 1177 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8698 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 26047 | 11153 |
| sha256 | 12986 | 4251 |
| domain | 11603 | 3260 |
| ipv4 | 11441 | 2040 |
| ipv6 | 3137 | 243 |
| md5 | 697 | 380 |
| sha1 | 672 | 379 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 10576 |
| Exit nodes | 2348 |
| Other relays | 8228 |
| New in window | 1011 |

Sample (20 of 10576, source: Tor Project Onionoo):
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
| Unknown Loader | 4902 | 760 | — |
| Mirai | 4227 | 827 | T1498, T1071.001 |
| Vidar | 3471 | 3151 | T1555, T1071.001, T1567 |
| AsyncRAT | 2279 | 95 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| ClearFake | 1870 | 744 | — |
| IClickFix | 1492 | 686 | — |
| Cobalt Strike | 1333 | 87 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| Unknown malware | 1047 | 471 | — |
| VShell | 646 | 528 | — |
| Unknown Stealer | 628 | 276 | — |
| php.shin_webshell | 514 | 372 | — |
| PureRAT | 411 | 51 | — |
| AMOS | 374 | 202 | — |
| Sliver | 298 | 275 | T1071.001, T1573, T1090, T1055 |
| AdaptixC2 | 285 | 31 | — |
| Remcos | 271 | 120 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| Unknown RAT | 204 | 34 | — |
| DanaBot | 194 | 131 | T1566.001, T1071.001, T1555, T1041 |
| Remus | 182 | 58 | — |
| Formbook | 172 | 102 | T1566.001, T1056.001, T1555, T1071.001, T1567 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1105 | Ingress Tool Transfer | command-and-control | 21434 |
| T1071.001 | Web Protocols | command-and-control | 42431 |
| T1498 | Network Denial of Service | impact | 9736 |
| T1204.002 | Malicious File | execution | 8549 |
| T1027 | Obfuscated Files or Information | defense-evasion | 8388 |
| T1573 | Encrypted Channel | command-and-control | 7779 |
| T1555 | Credentials from Password Stores | credential-access | 6306 |
| T1567 | Exfiltration Over Web Service | exfiltration | 6112 |
| T1566 | Phishing | initial-access | 4825 |
| T1566.002 | Spearphishing Link | initial-access | 4825 |
| T1552.001 | Credentials In Files | credential-access | 3810 |
| T1056.001 | Keylogging | collection, credential-access | 3725 |
| T1566.001 | Spearphishing Attachment | initial-access | 3424 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 2862 |
| T1113 | Screen Capture | collection | 2827 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1866 |
| T1090 | Proxy | command-and-control | 1666 |
| T1059.001 | PowerShell | execution | 1346 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 362 |
| T1189 | Drive-by Compromise | initial-access | 175 |
| T1218 | System Binary Proxy Execution | defense-evasion | 175 |
| T1059.005 | Visual Basic | execution | 89 |
| T1021.001 | Remote Desktop Protocol | lateral-movement | 14 |
| T1486 | Data Encrypted for Impact | impact | 14 |
| T1490 | Inhibit System Recovery | impact | 14 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 14 |
| T1190 | Exploit Public-Facing Application | initial-access | 5 |
| T1003 | OS Credential Dumping | credential-access | 4 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://aj[.]7dewaslot[.]org/vd`](https://www.virustotal.com/gui/search/https%3A%2F%2Faj.7dewaslot.org%2Fvd) | url | Vidar | threatfox | 2026-10-15T11:38:25Z | 100 |
| [`hxxps://aj[.]7dewaslot[.]org/rd`](https://www.virustotal.com/gui/search/https%3A%2F%2Faj.7dewaslot.org%2Frd) | url | Vidar | threatfox | 2026-10-15T11:36:35Z | 100 |
| [`hxxps://aj[.]7dewaslot[.]org/zx/`](https://www.virustotal.com/gui/search/https%3A%2F%2Faj.7dewaslot.org%2Fzx%2F) | url | Vidar | threatfox | 2026-10-15T11:35:48Z | 100 |
| [`hxxps://aj[.]7dewaslot[.]org/zx`](https://www.virustotal.com/gui/search/https%3A%2F%2Faj.7dewaslot.org%2Fzx) | url | Vidar | threatfox | 2026-10-15T11:34:22Z | 100 |
| [`hxxps://aj[.]7dewaslot[.]org/cf`](https://www.virustotal.com/gui/search/https%3A%2F%2Faj.7dewaslot.org%2Fcf) | url | Vidar | threatfox | 2026-10-15T11:33:18Z | 100 |
| [`hxxps://aj[.]7dewaslot[.]org/t/`](https://www.virustotal.com/gui/search/https%3A%2F%2Faj.7dewaslot.org%2Ft%2F) | url | Vidar | threatfox | 2026-10-15T11:30:48Z | 100 |
| [`hxxps://aj[.]7dewaslot[.]org/t`](https://www.virustotal.com/gui/search/https%3A%2F%2Faj.7dewaslot.org%2Ft) | url | Vidar | threatfox | 2026-10-15T11:30:30Z | 100 |
| [`hxxps://aj[.]7dewaslot[.]org/rz`](https://www.virustotal.com/gui/search/https%3A%2F%2Faj.7dewaslot.org%2Frz) | url | Vidar | threatfox | 2026-10-15T11:28:23Z | 100 |
| [`hxxps://aj[.]7dewaslot[.]org/ak`](https://www.virustotal.com/gui/search/https%3A%2F%2Faj.7dewaslot.org%2Fak) | url | Vidar | threatfox | 2026-10-15T11:26:13Z | 100 |
| [`hxxps://aj[.]7dewaslot[.]org/yz/`](https://www.virustotal.com/gui/search/https%3A%2F%2Faj.7dewaslot.org%2Fyz%2F) | url | Vidar | threatfox | 2026-10-15T11:25:48Z | 100 |
| [`w1lefe83[.]cyclingjordan[.]co`](https://www.virustotal.com/gui/domain/w1lefe83.cyclingjordan.co) | domain | ClearFake | threatfox | 2026-10-15T11:24:50Z | 100 |
| [`hxxps://aj[.]7dewaslot[.]org/yz`](https://www.virustotal.com/gui/search/https%3A%2F%2Faj.7dewaslot.org%2Fyz) | url | Vidar | threatfox | 2026-10-15T11:24:21Z | 100 |
| [`hxxps://aj[.]7dewaslot[.]org/t6`](https://www.virustotal.com/gui/search/https%3A%2F%2Faj.7dewaslot.org%2Ft6) | url | Vidar | threatfox | 2026-10-15T11:22:28Z | 100 |
| [`hxxps://aj[.]7dewaslot[.]org/gc`](https://www.virustotal.com/gui/search/https%3A%2F%2Faj.7dewaslot.org%2Fgc) | url | Vidar | threatfox | 2026-10-15T11:21:00Z | 100 |
| [`hxxps://aj[.]7dewaslot[.]org/gc/`](https://www.virustotal.com/gui/search/https%3A%2F%2Faj.7dewaslot.org%2Fgc%2F) | url | Vidar | threatfox | 2026-10-15T11:20:48Z | 100 |
| [`hxxps://aj[.]7dewaslot[.]org/x`](https://www.virustotal.com/gui/search/https%3A%2F%2Faj.7dewaslot.org%2Fx) | url | Vidar | threatfox | 2026-10-15T11:18:14Z | 100 |
| [`hxxps://aj[.]7dewaslot[.]org/fu`](https://www.virustotal.com/gui/search/https%3A%2F%2Faj.7dewaslot.org%2Ffu) | url | Vidar | threatfox | 2026-10-15T11:17:16Z | 100 |
| [`hxxps://aj[.]7dewaslot[.]org/yl/`](https://www.virustotal.com/gui/search/https%3A%2F%2Faj.7dewaslot.org%2Fyl%2F) | url | Vidar | threatfox | 2026-10-15T11:15:48Z | 100 |
| [`hxxps://aj[.]7dewaslot[.]org/yl`](https://www.virustotal.com/gui/search/https%3A%2F%2Faj.7dewaslot.org%2Fyl) | url | Vidar | threatfox | 2026-10-15T11:14:27Z | 100 |
| [`hxxps://aj[.]7dewaslot[.]org/ok`](https://www.virustotal.com/gui/search/https%3A%2F%2Faj.7dewaslot.org%2Fok) | url | Vidar | threatfox | 2026-10-15T11:12:58Z | 100 |
| [`hxxps://aj[.]7dewaslot[.]org/ea/`](https://www.virustotal.com/gui/search/https%3A%2F%2Faj.7dewaslot.org%2Fea%2F) | url | Vidar | threatfox | 2026-10-15T11:10:48Z | 100 |
| [`hxxps://aj[.]7dewaslot[.]org/ea`](https://www.virustotal.com/gui/search/https%3A%2F%2Faj.7dewaslot.org%2Fea) | url | Vidar | threatfox | 2026-10-15T11:10:35Z | 100 |
| [`hxxps://aj[.]7dewaslot[.]org/wm`](https://www.virustotal.com/gui/search/https%3A%2F%2Faj.7dewaslot.org%2Fwm) | url | Vidar | threatfox | 2026-10-15T11:08:46Z | 100 |
| [`hxxps://aj[.]7dewaslot[.]org/kl`](https://www.virustotal.com/gui/search/https%3A%2F%2Faj.7dewaslot.org%2Fkl) | url | Vidar | threatfox | 2026-10-15T11:06:32Z | 100 |
| [`hxxps://aj[.]7dewaslot[.]org/eds/`](https://www.virustotal.com/gui/search/https%3A%2F%2Faj.7dewaslot.org%2Feds%2F) | url | Vidar | threatfox | 2026-10-15T11:05:48Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
