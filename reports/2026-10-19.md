# Threat Intel Pulse — 2026-10-19

**Window:** last 7 days · **Generated:** 2026-10-19T22:30:18Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 80564 |
| New in window | 24074 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5001 | ok |
| feodo | 5 | ok |
| threatfox | 6579 | ok |
| malwarebazaar | 1182 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8727 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 32893 | 12435 |
| sha256 | 16239 | 5170 |
| domain | 13628 | 3110 |
| ipv4 | 12696 | 2205 |
| ipv6 | 3288 | 309 |
| md5 | 923 | 423 |
| sha1 | 897 | 422 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 11344 |
| Exit nodes | 2418 |
| Other relays | 8926 |
| New in window | 1211 |

Sample (20 of 11344, source: Tor Project Onionoo):
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
| Vidar | 5571 | 4781 | T1555, T1071.001, T1567 |
| Unknown Loader | 5419 | 837 | — |
| Mirai | 5093 | 1037 | T1498, T1071.001 |
| AsyncRAT | 2323 | 90 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| IClickFix | 2104 | 801 | — |
| ClearFake | 2029 | 331 | — |
| Unknown malware | 1618 | 687 | — |
| Cobalt Strike | 1363 | 79 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| VShell | 904 | 625 | — |
| AMOS | 819 | 552 | — |
| php.shin_webshell | 684 | 297 | — |
| Unknown Stealer | 641 | 75 | — |
| PureRAT | 455 | 68 | — |
| Sliver | 377 | 316 | T1071.001, T1573, T1090, T1055 |
| Remcos | 359 | 163 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| AdaptixC2 | 303 | 28 | — |
| Remus | 259 | 95 | — |
| Unknown RAT | 228 | 43 | — |
| Formbook | 206 | 98 | T1566.001, T1056.001, T1555, T1071.001, T1567 |
| DanaBot | 195 | 3 | T1566.001, T1071.001, T1555, T1041 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1071.001 | Web Protocols | command-and-control | 50776 |
| T1105 | Ingress Tool Transfer | command-and-control | 24514 |
| T1498 | Network Denial of Service | impact | 12419 |
| T1204.002 | Malicious File | execution | 9557 |
| T1027 | Obfuscated Files or Information | defense-evasion | 9395 |
| T1555 | Credentials from Password Stores | credential-access | 9131 |
| T1573 | Encrypted Channel | command-and-control | 8980 |
| T1567 | Exfiltration Over Web Service | exfiltration | 8936 |
| T1566 | Phishing | initial-access | 7354 |
| T1566.002 | Spearphishing Link | initial-access | 7354 |
| T1552.001 | Credentials In Files | credential-access | 5311 |
| T1056.001 | Keylogging | collection, credential-access | 4021 |
| T1566.001 | Spearphishing Attachment | initial-access | 3701 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 3067 |
| T1113 | Screen Capture | collection | 3005 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 2007 |
| T1090 | Proxy | command-and-control | 1778 |
| T1059.001 | PowerShell | execution | 1377 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 391 |
| T1189 | Drive-by Compromise | initial-access | 178 |
| T1218 | System Binary Proxy Execution | defense-evasion | 178 |
| T1059.005 | Visual Basic | execution | 95 |
| T1021.001 | Remote Desktop Protocol | lateral-movement | 14 |
| T1486 | Data Encrypted for Impact | impact | 14 |
| T1490 | Inhibit System Recovery | impact | 14 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 14 |
| T1190 | Exploit Public-Facing Application | initial-access | 10 |
| T1003 | OS Credential Dumping | credential-access | 4 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`1e7cc2bd060683795a7bfa0ee3610e6b896c71ad20677b65ccde4278594911f9`](https://www.virustotal.com/gui/file/1e7cc2bd060683795a7bfa0ee3610e6b896c71ad20677b65ccde4278594911f9) | sha256 | AMOS | threatfox | 2026-10-19T22:24:44Z | 100 |
| [`hxxps://t8[.]abanda88[.]org/h/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ft8.abanda88.org%2Fh%2F) | url | Vidar | threatfox | 2026-10-19T22:20:48Z | 100 |
| [`hxxps://t8[.]abanda88[.]org/vd/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ft8.abanda88.org%2Fvd%2F) | url | Vidar | threatfox | 2026-10-19T22:15:48Z | 100 |
| [`hxxps://t8[.]abanda88[.]org/n5z/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ft8.abanda88.org%2Fn5z%2F) | url | Vidar | threatfox | 2026-10-19T22:10:48Z | 100 |
| [`o[.]9qoi[.]org`](https://www.virustotal.com/gui/domain/o.9qoi.org) | domain | Vidar | threatfox | 2026-10-19T22:05:49Z | 100 |
| [`hxxps://o[.]9qoi[.]org/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fo.9qoi.org%2F) | url | Vidar | threatfox | 2026-10-19T22:05:49Z | 100 |
| [`hxxps://t8[.]abanda88[.]org/va/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ft8.abanda88.org%2Fva%2F) | url | Vidar | threatfox | 2026-10-19T22:05:49Z | 100 |
| [`jm[.]88kfc[.]org`](https://www.virustotal.com/gui/domain/jm.88kfc.org) | domain | Vidar | threatfox | 2026-10-19T22:05:48Z | 100 |
| [`hxxps://jm[.]88kfc[.]org/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fjm.88kfc.org%2F) | url | Vidar | threatfox | 2026-10-19T22:05:48Z | 100 |
| [`y4[.]8g8g[.]org`](https://www.virustotal.com/gui/domain/y4.8g8g.org) | domain | Vidar | threatfox | 2026-10-19T22:05:48Z | 100 |
| [`hxxps://y4[.]8g8g[.]org/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fy4.8g8g.org%2F) | url | Vidar | threatfox | 2026-10-19T22:05:48Z | 100 |
| [`43[.]248[.]102[.]182`](https://www.virustotal.com/gui/ip-address/43.248.102.182) | ipv4 | NjRAT | threatfox | 2026-10-19T22:05:02Z | 100 |
| [`hxxps://y4[.]8g8g[.]org`](https://www.virustotal.com/gui/search/https%3A%2F%2Fy4.8g8g.org) | url | Vidar | threatfox | 2026-10-19T22:02:18Z | 100 |
| [`hxxps://jm[.]88kfc[.]org`](https://www.virustotal.com/gui/search/https%3A%2F%2Fjm.88kfc.org) | url | Vidar | threatfox | 2026-10-19T22:02:17Z | 100 |
| [`hxxps://ua[.]abanda88[.]org/oe/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fua.abanda88.org%2Foe%2F) | url | Vidar | threatfox | 2026-10-19T22:00:49Z | 100 |
| [`hxxps://ua[.]abanda88[.]org/j9/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fua.abanda88.org%2Fj9%2F) | url | Vidar | threatfox | 2026-10-19T21:55:48Z | 100 |
| [`hxxps://ua[.]abanda88[.]org/za/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fua.abanda88.org%2Fza%2F) | url | Vidar | threatfox | 2026-10-19T21:50:48Z | 100 |
| [`hxxps://ua[.]abanda88[.]org/wd/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fua.abanda88.org%2Fwd%2F) | url | Vidar | threatfox | 2026-10-19T21:45:48Z | 100 |
| [`hxxps://ua[.]abanda88[.]org/w/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fua.abanda88.org%2Fw%2F) | url | Vidar | threatfox | 2026-10-19T21:40:48Z | 100 |
| [`hxxps://ua[.]abanda88[.]org/l6/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fua.abanda88.org%2Fl6%2F) | url | Vidar | threatfox | 2026-10-19T21:35:48Z | 100 |
| [`edcd480853dfa06c03a0f2b555f0187fad9a71782fb1d993701951f4d91173d7`](https://www.virustotal.com/gui/file/edcd480853dfa06c03a0f2b555f0187fad9a71782fb1d993701951f4d91173d7) | sha256 | AMOS | threatfox | 2026-10-19T21:33:14Z | 100 |
| [`28b34e7fe74ecf775a5b15fe1e75a22138d9c68829156c134b19d48e568f2046`](https://www.virustotal.com/gui/file/28b34e7fe74ecf775a5b15fe1e75a22138d9c68829156c134b19d48e568f2046) | sha256 | AMOS | threatfox | 2026-10-19T21:32:12Z | 100 |
| [`70e339bcf38b2d79774daa135ec598f2ecd99c6ec1cd9e810bbf005da9aab64d`](https://www.virustotal.com/gui/file/70e339bcf38b2d79774daa135ec598f2ecd99c6ec1cd9e810bbf005da9aab64d) | sha256 | AMOS | threatfox | 2026-10-19T21:31:10Z | 100 |
| [`hxxps://ua[.]abanda88[.]org/tg/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fua.abanda88.org%2Ftg%2F) | url | Vidar | threatfox | 2026-10-19T21:30:48Z | 100 |
| [`989b86835519fc0354d7ff54d2b5162c639d98b642835bcf4c822188e039e9fa`](https://www.virustotal.com/gui/file/989b86835519fc0354d7ff54d2b5162c639d98b642835bcf4c822188e039e9fa) | sha256 | AMOS | threatfox | 2026-10-19T21:30:08Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
