# Threat Intel Pulse — 2026-10-17

**Window:** last 7 days · **Generated:** 2026-10-17T20:45:44Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 74748 |
| New in window | 23311 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5001 | ok |
| feodo | 5 | ok |
| threatfox | 7847 | ok |
| malwarebazaar | 805 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8727 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 30109 | 12327 |
| sha256 | 14811 | 4853 |
| domain | 12803 | 2797 |
| ipv4 | 12121 | 2185 |
| ipv6 | 3229 | 291 |
| md5 | 850 | 429 |
| sha1 | 825 | 429 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 11043 |
| Exit nodes | 2390 |
| Other relays | 8653 |
| New in window | 1159 |

Sample (20 of 11043, source: Tor Project Onionoo):
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
| Unknown Loader | 5155 | 593 | — |
| Mirai | 4899 | 1134 | T1498, T1071.001 |
| Vidar | 4899 | 4478 | T1555, T1071.001, T1567 |
| AsyncRAT | 2317 | 109 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| ClearFake | 1952 | 319 | — |
| IClickFix | 1799 | 561 | — |
| Unknown malware | 1373 | 602 | — |
| Cobalt Strike | 1348 | 80 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| VShell | 882 | 695 | — |
| Unknown Stealer | 631 | 76 | — |
| php.shin_webshell | 616 | 330 | — |
| AMOS | 602 | 387 | — |
| PureRAT | 437 | 62 | — |
| Remcos | 331 | 161 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| Sliver | 321 | 287 | T1071.001, T1573, T1090, T1055 |
| AdaptixC2 | 296 | 28 | — |
| Remus | 242 | 94 | — |
| Unknown RAT | 212 | 40 | — |
| DanaBot | 195 | 102 | T1566.001, T1071.001, T1555, T1041 |
| Formbook | 187 | 89 | T1566.001, T1056.001, T1555, T1071.001, T1567 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1105 | Ingress Tool Transfer | command-and-control | 23426 |
| T1071.001 | Web Protocols | command-and-control | 46853 |
| T1498 | Network Denial of Service | impact | 10714 |
| T1204.002 | Malicious File | execution | 9451 |
| T1027 | Obfuscated Files or Information | defense-evasion | 9289 |
| T1573 | Encrypted Channel | command-and-control | 8782 |
| T1555 | Credentials from Password Stores | credential-access | 8148 |
| T1567 | Exfiltration Over Web Service | exfiltration | 7953 |
| T1566 | Phishing | initial-access | 6327 |
| T1566.002 | Spearphishing Link | initial-access | 6327 |
| T1552.001 | Credentials In Files | credential-access | 5002 |
| T1056.001 | Keylogging | collection, credential-access | 3908 |
| T1566.001 | Spearphishing Attachment | initial-access | 3593 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 2996 |
| T1113 | Screen Capture | collection | 2947 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1926 |
| T1090 | Proxy | command-and-control | 1706 |
| T1059.001 | PowerShell | execution | 1362 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 378 |
| T1189 | Drive-by Compromise | initial-access | 178 |
| T1218 | System Binary Proxy Execution | defense-evasion | 178 |
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
| [`21fd4621502f4fb9240b76333ed40f6097f1a4a7a9359dcc20fe198f49eee5f8`](https://www.virustotal.com/gui/file/21fd4621502f4fb9240b76333ed40f6097f1a4a7a9359dcc20fe198f49eee5f8) | sha256 | AMOS | threatfox | 2026-10-17T20:36:54Z | 100 |
| [`hxxps://qj[.]988boss[.]org/x8/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fqj.988boss.org%2Fx8%2F) | url | Vidar | threatfox | 2026-10-17T20:35:48Z | 100 |
| [`1c40ac1b4c9a79ea6077b440c3b7c176bc7e34535b29ccdff8171d0209df359f`](https://www.virustotal.com/gui/file/1c40ac1b4c9a79ea6077b440c3b7c176bc7e34535b29ccdff8171d0209df359f) | sha256 | AMOS | threatfox | 2026-10-17T20:32:23Z | 100 |
| [`hxxps://qj[.]988boss[.]org/g5/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fqj.988boss.org%2Fg5%2F) | url | Vidar | threatfox | 2026-10-17T20:30:48Z | 100 |
| [`hxxps://qj[.]988boss[.]org/lx/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fqj.988boss.org%2Flx%2F) | url | Vidar | threatfox | 2026-10-17T20:25:48Z | 100 |
| [`57472f87eb20bf1a2e3b4dcba5d37d38f87f1769073e311b4095552a6f0c6470`](https://www.virustotal.com/gui/file/57472f87eb20bf1a2e3b4dcba5d37d38f87f1769073e311b4095552a6f0c6470) | sha256 | AMOS | threatfox | 2026-10-17T20:22:25Z | 100 |
| [`hxxps://qj[.]988boss[.]org/xl/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fqj.988boss.org%2Fxl%2F) | url | Vidar | threatfox | 2026-10-17T20:20:48Z | 100 |
| [`hxxps://qj[.]988boss[.]org/w/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fqj.988boss.org%2Fw%2F) | url | Vidar | threatfox | 2026-10-17T20:15:48Z | 100 |
| [`hxxps://qj[.]988boss[.]org/ar/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fqj.988boss.org%2Far%2F) | url | Vidar | threatfox | 2026-10-17T20:10:48Z | 100 |
| [`hxxps://qj[.]988boss[.]org/ql/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fqj.988boss.org%2Fql%2F) | url | Vidar | threatfox | 2026-10-17T20:05:48Z | 100 |
| [`hxxps://ay[.]988boss[.]org/d/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fay.988boss.org%2Fd%2F) | url | Vidar | threatfox | 2026-10-17T20:00:48Z | 100 |
| [`hxxps://ay[.]988boss[.]org/mi/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fay.988boss.org%2Fmi%2F) | url | Vidar | threatfox | 2026-10-17T19:55:48Z | 100 |
| [`hxxps://ay[.]988boss[.]org/b6d/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fay.988boss.org%2Fb6d%2F) | url | Vidar | threatfox | 2026-10-17T19:50:48Z | 100 |
| [`ukq8hm2z[.]socop[.]space`](https://www.virustotal.com/gui/domain/ukq8hm2z.socop.space) | domain | ClearFake | threatfox | 2026-10-17T19:49:50Z | 100 |
| [`hxxps://ay[.]988boss[.]org/u2/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fay.988boss.org%2Fu2%2F) | url | Vidar | threatfox | 2026-10-17T19:45:48Z | 100 |
| [`hxxps://ay[.]988boss[.]org/x9/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fay.988boss.org%2Fx9%2F) | url | Vidar | threatfox | 2026-10-17T19:40:48Z | 100 |
| [`hxxps://ay[.]988boss[.]org/ncj/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fay.988boss.org%2Fncj%2F) | url | Vidar | threatfox | 2026-10-17T19:35:48Z | 100 |
| [`e8453cdb2e9b6e5f4777bbebec65282d5cd5399496dfce268d2adfb2d1e615ba`](https://www.virustotal.com/gui/file/e8453cdb2e9b6e5f4777bbebec65282d5cd5399496dfce268d2adfb2d1e615ba) | sha256 | AMOS | threatfox | 2026-10-17T19:35:35Z | 100 |
| [`6461311bcc3d675ebfdae2edc2044612fe993d245503a523ac96dd0390139685`](https://www.virustotal.com/gui/file/6461311bcc3d675ebfdae2edc2044612fe993d245503a523ac96dd0390139685) | sha256 | AMOS | threatfox | 2026-10-17T19:31:35Z | 100 |
| [`hxxps://ay[.]988boss[.]org/lkj/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fay.988boss.org%2Flkj%2F) | url | Vidar | threatfox | 2026-10-17T19:30:48Z | 100 |
| [`da57728231344d24de415d0edd2e34b45548822813e9407c53bad697263603ae`](https://www.virustotal.com/gui/file/da57728231344d24de415d0edd2e34b45548822813e9407c53bad697263603ae) | sha256 | AMOS | threatfox | 2026-10-17T19:27:35Z | 100 |
| [`hxxps://ay[.]988boss[.]org/zt/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fay.988boss.org%2Fzt%2F) | url | Vidar | threatfox | 2026-10-17T19:25:48Z | 100 |
| [`5e4af631dbaf78d4ec26d83923b281a8877b9b5ced30fe79f34bb62ded7511f4`](https://www.virustotal.com/gui/file/5e4af631dbaf78d4ec26d83923b281a8877b9b5ced30fe79f34bb62ded7511f4) | sha256 | AMOS | threatfox | 2026-10-17T19:23:40Z | 100 |
| [`03ad802733201bfd34994486492ce660be05149498d6f4fb4cb86f87d889ca91`](https://www.virustotal.com/gui/file/03ad802733201bfd34994486492ce660be05149498d6f4fb4cb86f87d889ca91) | sha256 | AMOS | threatfox | 2026-10-17T19:21:15Z | 100 |
| [`hxxps://ay[.]988boss[.]org/e0/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fay.988boss.org%2Fe0%2F) | url | Vidar | threatfox | 2026-10-17T19:20:48Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
