# Threat Intel Pulse — 2026-10-11

**Window:** last 7 days · **Generated:** 2026-10-11T06:08:37Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 52604 |
| New in window | 52604 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5001 | ok |
| feodo | 5 | ok |
| threatfox | 6831 | ok |
| malwarebazaar | 809 | ok |
| openphish | 300 | ok |
| circl | 614 | ok |
| tor | 8628 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 18319 | 18319 |
| sha256 | 10237 | 10237 |
| domain | 10128 | 10128 |
| ipv4 | 10034 | 10034 |
| ipv6 | 2953 | 2953 |
| md5 | 479 | 479 |
| sha1 | 454 | 454 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 9970 |
| Exit nodes | 2217 |
| Other relays | 7753 |
| New in window | 9970 |

Sample (20 of 9970, source: Tor Project Onionoo):
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
| Unknown Loader | 4558 | 4558 | — |
| Mirai | 3768 | 3768 | T1498, T1071.001 |
| AsyncRAT | 2213 | 2213 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| ClearFake | 1651 | 1651 | — |
| IClickFix | 1272 | 1272 | — |
| Cobalt Strike | 1269 | 1269 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| Unknown malware | 812 | 812 | — |
| Unknown Stealer | 559 | 559 | — |
| Vidar | 453 | 453 | T1555, T1071.001, T1567 |
| PureRAT | 379 | 379 | — |
| php.shin_webshell | 319 | 319 | — |
| AdaptixC2 | 270 | 270 | — |
| VShell | 239 | 239 | — |
| AMOS | 220 | 220 | — |
| Unknown RAT | 176 | 176 | — |
| Remcos | 170 | 170 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| Remus | 153 | 153 | — |
| DCRat | 108 | 108 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| Formbook | 97 | 97 | T1566.001, T1056.001, T1555, T1071.001, T1567 |
| Havoc | 96 | 96 | — |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1105 | Ingress Tool Transfer | command-and-control | 16476 |
| T1071.001 | Web Protocols | command-and-control | 34719 |
| T1498 | Network Denial of Service | impact | 8729 |
| T1204.002 | Malicious File | execution | 5650 |
| T1027 | Obfuscated Files or Information | defense-evasion | 5639 |
| T1573 | Encrypted Channel | command-and-control | 4964 |
| T1056.001 | Keylogging | collection, credential-access | 3300 |
| T1566.001 | Spearphishing Attachment | initial-access | 2937 |
| T1566 | Phishing | initial-access | 2872 |
| T1566.002 | Spearphishing Link | initial-access | 2872 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 2607 |
| T1113 | Screen Capture | collection | 2575 |
| T1555 | Credentials from Password Stores | credential-access | 2086 |
| T1567 | Exfiltration Over Web Service | exfiltration | 1991 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1486 |
| T1552.001 | Credentials In Files | credential-access | 1470 |
| T1090 | Proxy | command-and-control | 1322 |
| T1059.001 | PowerShell | execution | 1282 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 215 |
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
| [`27[.]50[.]63[.]50`](https://www.virustotal.com/gui/ip-address/27.50.63.50) | ipv4 | VShell | threatfox | 2026-10-11T05:05:05Z | 100 |
| [`199[.]102[.]217[.]211`](https://www.virustotal.com/gui/ip-address/199.102.217.211) | ipv4 | VShell | threatfox | 2026-10-11T05:05:04Z | 100 |
| [`77[.]232[.]43[.]21`](https://www.virustotal.com/gui/ip-address/77.232.43.21) | ipv4 | Jackskid | threatfox | 2026-10-11T04:47:00Z | 100 |
| [`g5wm6nzi[.]kulonprogo[.]org`](https://www.virustotal.com/gui/domain/g5wm6nzi.kulonprogo.org) | domain | ClearFake | threatfox | 2026-10-11T03:03:43Z | 100 |
| [`101[.]34[.]239[.]216`](https://www.virustotal.com/gui/ip-address/101.34.239.216) | ipv4 | Jackskid | threatfox | 2026-10-11T02:44:22Z | 100 |
| [`119[.]45[.]12[.]154`](https://www.virustotal.com/gui/ip-address/119.45.12.154) | ipv4 | Jackskid | threatfox | 2026-10-11T02:44:22Z | 100 |
| [`43[.]136[.]129[.]131`](https://www.virustotal.com/gui/ip-address/43.136.129.131) | ipv4 | Jackskid | threatfox | 2026-10-11T02:44:22Z | 100 |
| [`82[.]157[.]209[.]41`](https://www.virustotal.com/gui/ip-address/82.157.209.41) | ipv4 | Jackskid | threatfox | 2026-10-11T02:44:22Z | 100 |
| [`3bse5c5d[.]b00kself[.]com`](https://www.virustotal.com/gui/domain/3bse5c5d.b00kself.com) | domain | ClearFake | threatfox | 2026-10-11T02:40:00Z | 100 |
| [`gp[.]4-win[.]org`](https://www.virustotal.com/gui/domain/gp.4-win.org) | domain | Vidar | threatfox | 2026-10-11T00:55:48Z | 100 |
| [`hxxps://gp[.]4-win[.]org/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fgp.4-win.org%2F) | url | Vidar | threatfox | 2026-10-11T00:55:48Z | 100 |
| [`gp[.]54toto[.]org`](https://www.virustotal.com/gui/domain/gp.54toto.org) | domain | Vidar | threatfox | 2026-10-11T00:40:48Z | 100 |
| [`hxxps://gp[.]54toto[.]org/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fgp.54toto.org%2F) | url | Vidar | threatfox | 2026-10-11T00:40:48Z | 100 |
| [`tcea[.]top`](https://www.virustotal.com/gui/domain/tcea.top) | domain | IClickFix | threatfox | 2026-10-10T23:20:57Z | 100 |
| [`tennis-forecast[.]com`](https://www.virustotal.com/gui/domain/tennis-forecast.com) | domain | IClickFix | threatfox | 2026-10-10T23:20:57Z | 100 |
| [`unigadgetz[.]com`](https://www.virustotal.com/gui/domain/unigadgetz.com) | domain | IClickFix | threatfox | 2026-10-10T23:20:57Z | 100 |
| [`activesummary[.]us`](https://www.virustotal.com/gui/domain/activesummary.us) | domain | IClickFix | threatfox | 2026-10-10T23:20:56Z | 100 |
| [`amberbriefs[.]au`](https://www.virustotal.com/gui/domain/amberbriefs.au) | domain | IClickFix | threatfox | 2026-10-10T23:20:56Z | 100 |
| [`asongforyou[.]cool`](https://www.virustotal.com/gui/domain/asongforyou.cool) | domain | IClickFix | threatfox | 2026-10-10T23:20:56Z | 100 |
| [`bakarmandi[.]online`](https://www.virustotal.com/gui/domain/bakarmandi.online) | domain | IClickFix | threatfox | 2026-10-10T23:20:56Z | 100 |
| [`boxingready[.]com`](https://www.virustotal.com/gui/domain/boxingready.com) | domain | IClickFix | threatfox | 2026-10-10T23:20:56Z | 100 |
| [`comomudarsuamente[.]com`](https://www.virustotal.com/gui/domain/comomudarsuamente.com) | domain | IClickFix | threatfox | 2026-10-10T23:20:56Z | 100 |
| [`deception52[.]com`](https://www.virustotal.com/gui/domain/deception52.com) | domain | IClickFix | threatfox | 2026-10-10T23:20:56Z | 100 |
| [`dogbraintrainingpro[.]com`](https://www.virustotal.com/gui/domain/dogbraintrainingpro.com) | domain | IClickFix | threatfox | 2026-10-10T23:20:56Z | 100 |
| [`interiorhomedesignsbylianna[.]com`](https://www.virustotal.com/gui/domain/interiorhomedesignsbylianna.com) | domain | IClickFix | threatfox | 2026-10-10T23:20:56Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
