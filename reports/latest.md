# Threat Intel Pulse — 2026-10-17

**Window:** last 7 days · **Generated:** 2026-10-17T15:45:23Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 74484 |
| New in window | 23047 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5000 | ok |
| feodo | 5 | ok |
| threatfox | 8470 | ok |
| malwarebazaar | 824 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8744 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 29954 | 12172 |
| sha256 | 14747 | 4789 |
| domain | 12781 | 2775 |
| ipv4 | 12100 | 2164 |
| ipv6 | 3227 | 289 |
| md5 | 850 | 429 |
| sha1 | 825 | 429 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 11032 |
| Exit nodes | 2388 |
| Other relays | 8644 |
| New in window | 1148 |

Sample (20 of 11032, source: Tor Project Onionoo):
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
| Mirai | 4893 | 1128 | T1498, T1071.001 |
| Vidar | 4834 | 4413 | T1555, T1071.001, T1567 |
| AsyncRAT | 2316 | 108 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| ClearFake | 1949 | 316 | — |
| IClickFix | 1792 | 554 | — |
| Unknown malware | 1365 | 594 | — |
| Cobalt Strike | 1348 | 80 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| VShell | 882 | 695 | — |
| Unknown Stealer | 631 | 76 | — |
| php.shin_webshell | 610 | 324 | — |
| AMOS | 578 | 363 | — |
| PureRAT | 431 | 56 | — |
| Remcos | 330 | 160 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| Sliver | 321 | 287 | T1071.001, T1573, T1090, T1055 |
| AdaptixC2 | 296 | 28 | — |
| Remus | 242 | 94 | — |
| Unknown RAT | 212 | 40 | — |
| DanaBot | 195 | 102 | T1566.001, T1071.001, T1555, T1041 |
| Formbook | 187 | 89 | T1566.001, T1056.001, T1555, T1071.001, T1567 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1105 | Ingress Tool Transfer | command-and-control | 23339 |
| T1071.001 | Web Protocols | command-and-control | 46709 |
| T1498 | Network Denial of Service | impact | 10680 |
| T1204.002 | Malicious File | execution | 9450 |
| T1027 | Obfuscated Files or Information | defense-evasion | 9288 |
| T1573 | Encrypted Channel | command-and-control | 8772 |
| T1555 | Credentials from Password Stores | credential-access | 8051 |
| T1567 | Exfiltration Over Web Service | exfiltration | 7856 |
| T1566 | Phishing | initial-access | 6327 |
| T1566.002 | Spearphishing Link | initial-access | 6327 |
| T1552.001 | Credentials In Files | credential-access | 4969 |
| T1056.001 | Keylogging | collection, credential-access | 3899 |
| T1566.001 | Spearphishing Attachment | initial-access | 3591 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 2994 |
| T1113 | Screen Capture | collection | 2945 |
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
| [`ru5vv9op[.]adobeshin[.]com`](https://www.virustotal.com/gui/domain/ru5vv9op.adobeshin.com) | domain | ClearFake | threatfox | 2026-10-17T15:37:11Z | 100 |
| [`07b0271ae96fa7ba9fdae9db3d6a515fcdcb0379ce0f8316b0f837e82c2ed0af`](https://www.virustotal.com/gui/file/07b0271ae96fa7ba9fdae9db3d6a515fcdcb0379ce0f8316b0f837e82c2ed0af) | sha256 | AMOS | threatfox | 2026-10-17T15:36:52Z | 100 |
| [`hxxps://v61[.]8mytogel[.]org/ic/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fv61.8mytogel.org%2Fic%2F) | url | Vidar | threatfox | 2026-10-17T15:35:48Z | 100 |
| [`151b86dd6de5829d11a58e3b8d343f72825e4a49a6ae601ab48e138844d414a6`](https://www.virustotal.com/gui/file/151b86dd6de5829d11a58e3b8d343f72825e4a49a6ae601ab48e138844d414a6) | sha256 | AMOS | threatfox | 2026-10-17T15:32:57Z | 100 |
| [`hxxps://v61[.]8mytogel[.]org/yuk/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fv61.8mytogel.org%2Fyuk%2F) | url | Vidar | threatfox | 2026-10-17T15:30:48Z | 100 |
| [`4a09d3fdb1e3cd30f07f4942f5733dbc11ade71b36b41fecf3a5792b4098d9f9`](https://www.virustotal.com/gui/file/4a09d3fdb1e3cd30f07f4942f5733dbc11ade71b36b41fecf3a5792b4098d9f9) | sha256 | AMOS | threatfox | 2026-10-17T15:28:25Z | 100 |
| [`de8ff8c9634a91032d66fc10056f11aadf0350d4f6653447476a5535f09c8997`](https://www.virustotal.com/gui/file/de8ff8c9634a91032d66fc10056f11aadf0350d4f6653447476a5535f09c8997) | sha256 | AMOS | threatfox | 2026-10-17T15:26:59Z | 100 |
| [`ba902ec4c0c4aa948c6e64cf3a750472f7db8d21ffe89a841a80622a4fb9744c`](https://www.virustotal.com/gui/file/ba902ec4c0c4aa948c6e64cf3a750472f7db8d21ffe89a841a80622a4fb9744c) | sha256 | AMOS | threatfox | 2026-10-17T15:25:49Z | 100 |
| [`hxxps://v61[.]8mytogel[.]org/c9/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fv61.8mytogel.org%2Fc9%2F) | url | Vidar | threatfox | 2026-10-17T15:25:48Z | 100 |
| [`3b65af2a918dee97fcda1c67ad5fd3ff4358ca0a86d06edb09b1971fd6d62ba6`](https://www.virustotal.com/gui/file/3b65af2a918dee97fcda1c67ad5fd3ff4358ca0a86d06edb09b1971fd6d62ba6) | sha256 | AMOS | threatfox | 2026-10-17T15:24:44Z | 100 |
| [`130[.]12[.]180[.]32`](https://www.virustotal.com/gui/ip-address/130.12.180.32) | ipv4 | Unknown malware | threatfox | 2026-10-17T15:21:10Z | 100 |
| [`39rwd49tgi9[.]xyz`](https://www.virustotal.com/gui/domain/39rwd49tgi9.xyz) | domain | Unknown malware | threatfox | 2026-10-17T15:21:09Z | 100 |
| [`9egu923jfsdf[.]pro`](https://www.virustotal.com/gui/domain/9egu923jfsdf.pro) | domain | Unknown malware | threatfox | 2026-10-17T15:21:09Z | 100 |
| [`dfisjqef0s[.]app`](https://www.virustotal.com/gui/domain/dfisjqef0s.app) | domain | Unknown malware | threatfox | 2026-10-17T15:21:08Z | 100 |
| [`fallbackmaximidfjdsia[.]com`](https://www.virustotal.com/gui/domain/fallbackmaximidfjdsia.com) | domain | Unknown malware | threatfox | 2026-10-17T15:21:07Z | 100 |
| [`sfoig93rafa[.]io`](https://www.virustotal.com/gui/domain/sfoig93rafa.io) | domain | Unknown malware | threatfox | 2026-10-17T15:21:07Z | 100 |
| [`sg9sj8ifda[.]com`](https://www.virustotal.com/gui/domain/sg9sj8ifda.com) | domain | Unknown malware | threatfox | 2026-10-17T15:21:07Z | 100 |
| [`w9triu9w8vs[.]ro`](https://www.virustotal.com/gui/domain/w9triu9w8vs.ro) | domain | Unknown malware | threatfox | 2026-10-17T15:21:02Z | 100 |
| [`0475f2831e60ac0b229f346036e339d20ad1d1165b005a89b634dc7c67318c74`](https://www.virustotal.com/gui/file/0475f2831e60ac0b229f346036e339d20ad1d1165b005a89b634dc7c67318c74) | sha256 | Unknown malware | threatfox, malwarebazaar | 2026-10-17T15:21:01Z | 100 |
| [`0cc42472a07cf14668e899b73adafe666d02495bf9349715613c8e7ba57244ea`](https://www.virustotal.com/gui/file/0cc42472a07cf14668e899b73adafe666d02495bf9349715613c8e7ba57244ea) | sha256 | Unknown malware | threatfox, malwarebazaar | 2026-10-17T15:21:01Z | 100 |
| [`e59547abdff8019da736bcb8c252cbf5ce96b9695775031b10da334867b59b62`](https://www.virustotal.com/gui/file/e59547abdff8019da736bcb8c252cbf5ce96b9695775031b10da334867b59b62) | sha256 | Unknown malware | threatfox, malwarebazaar | 2026-10-17T15:21:01Z | 100 |
| [`8c21db937a85cf7ed804501cdfee7d1c543aa9a56d4d1187951b8f8048af1c10`](https://www.virustotal.com/gui/file/8c21db937a85cf7ed804501cdfee7d1c543aa9a56d4d1187951b8f8048af1c10) | sha256 | Unknown malware | threatfox, malwarebazaar | 2026-10-17T15:21:00Z | 100 |
| [`9d0891f849ccc8c0eff4ea961702087eeeceeb00cff94a7cb0542839be3421f5`](https://www.virustotal.com/gui/file/9d0891f849ccc8c0eff4ea961702087eeeceeb00cff94a7cb0542839be3421f5) | sha256 | Unknown malware | threatfox, malwarebazaar | 2026-10-17T15:21:00Z | 100 |
| [`f5cf1b8ee8ddced3fb5e081dc1543669c3b62767c45da63002032da87632839d`](https://www.virustotal.com/gui/file/f5cf1b8ee8ddced3fb5e081dc1543669c3b62767c45da63002032da87632839d) | sha256 | Unknown malware | threatfox, malwarebazaar | 2026-10-17T15:20:59Z | 100 |
| [`536a376337fed899e58a86baca1fc584d570be8e708b6c302cc6f24626dfcfd7`](https://www.virustotal.com/gui/file/536a376337fed899e58a86baca1fc584d570be8e708b6c302cc6f24626dfcfd7) | sha256 | Unknown malware | threatfox, malwarebazaar | 2026-10-17T15:20:59Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
