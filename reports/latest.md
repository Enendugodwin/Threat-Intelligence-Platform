# Threat Intel Pulse — 2026-10-19

**Window:** last 7 days · **Generated:** 2026-10-19T04:56:47Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 78485 |
| New in window | 24409 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5000 | ok |
| feodo | 5 | ok |
| threatfox | 7318 | ok |
| malwarebazaar | 876 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8720 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 32031 | 13048 |
| sha256 | 15447 | 4857 |
| domain | 13502 | 3183 |
| ipv4 | 12523 | 2277 |
| ipv6 | 3271 | 308 |
| md5 | 868 | 368 |
| sha1 | 843 | 368 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 11256 |
| Exit nodes | 2410 |
| Other relays | 8846 |
| New in window | 1230 |

Sample (20 of 11256, source: Tor Project Onionoo):
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
| Unknown Loader | 5386 | 817 | — |
| Vidar | 5337 | 4737 | T1555, T1071.001, T1567 |
| Mirai | 5055 | 1147 | T1498, T1071.001 |
| AsyncRAT | 2320 | 96 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| IClickFix | 2097 | 807 | — |
| ClearFake | 2004 | 328 | — |
| Unknown malware | 1571 | 684 | — |
| Cobalt Strike | 1360 | 87 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| VShell | 892 | 635 | — |
| AMOS | 740 | 491 | — |
| php.shin_webshell | 660 | 305 | — |
| Unknown Stealer | 635 | 71 | — |
| PureRAT | 450 | 69 | — |
| Sliver | 368 | 308 | T1071.001, T1573, T1090, T1055 |
| Remcos | 341 | 167 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| AdaptixC2 | 302 | 29 | — |
| Remus | 250 | 89 | — |
| Unknown RAT | 228 | 49 | — |
| DanaBot | 195 | 59 | T1566.001, T1071.001, T1555, T1041 |
| Formbook | 187 | 86 | T1566.001, T1056.001, T1555, T1071.001, T1567 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1071.001 | Web Protocols | command-and-control | 49979 |
| T1105 | Ingress Tool Transfer | command-and-control | 24119 |
| T1498 | Network Denial of Service | impact | 12195 |
| T1204.002 | Malicious File | execution | 9496 |
| T1027 | Obfuscated Files or Information | defense-evasion | 9334 |
| T1573 | Encrypted Channel | command-and-control | 8904 |
| T1555 | Credentials from Password Stores | credential-access | 8773 |
| T1567 | Exfiltration Over Web Service | exfiltration | 8578 |
| T1566 | Phishing | initial-access | 7051 |
| T1566.002 | Spearphishing Link | initial-access | 7051 |
| T1552.001 | Credentials In Files | credential-access | 5194 |
| T1056.001 | Keylogging | collection, credential-access | 3959 |
| T1566.001 | Spearphishing Attachment | initial-access | 3639 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 3031 |
| T1113 | Screen Capture | collection | 2970 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1993 |
| T1090 | Proxy | command-and-control | 1766 |
| T1059.001 | PowerShell | execution | 1374 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 384 |
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
| [`hxxps://j[.]9kio[.]org/m/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fj.9kio.org%2Fm%2F) | url | Vidar | threatfox | 2026-10-19T04:50:48Z | 100 |
| [`hxxps://v6[.]9wing[.]org/s/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fv6.9wing.org%2Fs%2F) | url | Vidar | threatfox | 2026-10-19T04:50:48Z | 100 |
| [`hxxps://v6[.]9wing[.]org/k8/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fv6.9wing.org%2Fk8%2F) | url | Vidar | threatfox | 2026-10-19T04:45:48Z | 100 |
| [`hxxps://v6[.]9wing[.]org/r/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fv6.9wing.org%2Fr%2F) | url | Vidar | threatfox | 2026-10-19T04:40:48Z | 100 |
| [`172[.]111[.]150[.]135`](https://www.virustotal.com/gui/ip-address/172.111.150.135) | ipv4 | Remcos | threatfox | 2026-10-19T04:40:04Z | 100 |
| [`aeba6d2af47c87977b0525c6e640cb769b4bd3d866956f7dc8d0c6bab48e7495`](https://www.virustotal.com/gui/file/aeba6d2af47c87977b0525c6e640cb769b4bd3d866956f7dc8d0c6bab48e7495) | sha256 | AMOS | threatfox | 2026-10-19T04:37:07Z | 100 |
| [`hxxps://v6[.]9wing[.]org/jx/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fv6.9wing.org%2Fjx%2F) | url | Vidar | threatfox | 2026-10-19T04:35:48Z | 100 |
| [`6fde54ea9de9309cc801d48f06af383b5820b42f89bbd8df5b60e5f827fafb5e`](https://www.virustotal.com/gui/file/6fde54ea9de9309cc801d48f06af383b5820b42f89bbd8df5b60e5f827fafb5e) | sha256 | AMOS | threatfox | 2026-10-19T04:31:02Z | 100 |
| [`hxxps://v6[.]9wing[.]org/vj/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fv6.9wing.org%2Fvj%2F) | url | Vidar | threatfox | 2026-10-19T04:30:48Z | 100 |
| [`hxxps://v6[.]9wing[.]org/mp/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fv6.9wing.org%2Fmp%2F) | url | Vidar | threatfox | 2026-10-19T04:25:48Z | 100 |
| [`hxxps://v6[.]9wing[.]org/l9/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fv6.9wing.org%2Fl9%2F) | url | Vidar | threatfox | 2026-10-19T04:20:48Z | 100 |
| [`hxxps://v6[.]9wing[.]org/b96/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fv6.9wing.org%2Fb96%2F) | url | Vidar | threatfox | 2026-10-19T04:15:48Z | 100 |
| [`j[.]9kio[.]org`](https://www.virustotal.com/gui/domain/j.9kio.org) | domain | Vidar | threatfox | 2026-10-19T04:10:48Z | 100 |
| [`hxxps://j[.]9kio[.]org/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fj.9kio.org%2F) | url | Vidar | threatfox | 2026-10-19T04:10:48Z | 100 |
| [`hxxps://v6[.]9wing[.]org/p4/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fv6.9wing.org%2Fp4%2F) | url | Vidar | threatfox | 2026-10-19T04:10:48Z | 100 |
| [`hxxps://v6[.]9wing[.]org/m1/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fv6.9wing.org%2Fm1%2F) | url | Vidar | threatfox | 2026-10-19T04:05:48Z | 100 |
| [`218ee68ec44c3deef77ff315a1f8bbb948aa108b4b5e2baa7a9b05770927f23e`](https://www.virustotal.com/gui/file/218ee68ec44c3deef77ff315a1f8bbb948aa108b4b5e2baa7a9b05770927f23e) | sha256 | AMOS | threatfox | 2026-10-19T04:04:51Z | 100 |
| [`hxxps://k9n[.]9wing[.]org/a7/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fk9n.9wing.org%2Fa7%2F) | url | Vidar | threatfox | 2026-10-19T04:00:48Z | 100 |
| [`e03049253c5b68f67d575be20548a6d80d1ed344010ce3e48a85d190cc1f608d`](https://www.virustotal.com/gui/file/e03049253c5b68f67d575be20548a6d80d1ed344010ce3e48a85d190cc1f608d) | sha256 | AMOS | threatfox | 2026-10-19T03:58:44Z | 100 |
| [`hxxps://k9n[.]9wing[.]org/g2/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fk9n.9wing.org%2Fg2%2F) | url | Vidar | threatfox | 2026-10-19T03:55:48Z | 100 |
| [`feb45477f2f3cfebd93f47aa68288d41b84ad309d852158ff3d78dfc72021835`](https://www.virustotal.com/gui/file/feb45477f2f3cfebd93f47aa68288d41b84ad309d852158ff3d78dfc72021835) | sha256 | AMOS | threatfox | 2026-10-19T03:52:38Z | 100 |
| [`hxxps://k9n[.]9wing[.]org/ms/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fk9n.9wing.org%2Fms%2F) | url | Vidar | threatfox | 2026-10-19T03:50:48Z | 100 |
| [`hxxps://k9n[.]9wing[.]org/o/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fk9n.9wing.org%2Fo%2F) | url | Vidar | threatfox | 2026-10-19T03:45:48Z | 100 |
| [`hxxps://k9n[.]9wing[.]org/z7/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fk9n.9wing.org%2Fz7%2F) | url | Vidar | threatfox | 2026-10-19T03:40:48Z | 100 |
| [`fb617d2319c498e327069f1ebbcc1c05756c894bf34ff0f879f0f8a82ffbaf1c`](https://www.virustotal.com/gui/file/fb617d2319c498e327069f1ebbcc1c05756c894bf34ff0f879f0f8a82ffbaf1c) | sha256 | AMOS | threatfox | 2026-10-19T03:36:30Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
