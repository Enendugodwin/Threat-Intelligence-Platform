# Threat Intel Pulse — 2026-10-12

**Window:** last 7 days · **Generated:** 2026-10-12T06:13:35Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 54656 |
| New in window | 27414 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5001 | ok |
| feodo | 5 | ok |
| threatfox | 5700 | ok |
| malwarebazaar | 765 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8602 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 19331 | 13782 |
| sha256 | 10692 | 5955 |
| domain | 10383 | 4980 |
| ipv4 | 10308 | 1699 |
| ipv6 | 2967 | 225 |
| md5 | 500 | 399 |
| sha1 | 475 | 374 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 10082 |
| Exit nodes | 2222 |
| Other relays | 7860 |
| New in window | 1162 |

Sample (20 of 10082, source: Tor Project Onionoo):
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
| Unknown Loader | 4563 | 1862 | — |
| Mirai | 3855 | 1396 | T1498, T1071.001 |
| AsyncRAT | 2228 | 1029 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| ClearFake | 1686 | 1368 | — |
| IClickFix | 1290 | 957 | — |
| Cobalt Strike | 1275 | 43 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| Unknown malware | 891 | 451 | — |
| Vidar | 701 | 531 | T1555, T1071.001, T1567 |
| Unknown Stealer | 565 | 397 | — |
| PureRAT | 381 | 49 | — |
| php.shin_webshell | 368 | 306 | — |
| VShell | 276 | 178 | — |
| AdaptixC2 | 273 | 33 | — |
| AMOS | 250 | 165 | — |
| Unknown RAT | 179 | 44 | — |
| Remcos | 177 | 83 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| Remus | 161 | 76 | — |
| DanaBot | 136 | 73 | T1566.001, T1071.001, T1555, T1041 |
| DCRat | 110 | 13 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| Formbook | 100 | 83 | T1566.001, T1056.001, T1555, T1071.001, T1567 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1105 | Ingress Tool Transfer | command-and-control | 17044 |
| T1071.001 | Web Protocols | command-and-control | 35625 |
| T1498 | Network Denial of Service | impact | 8901 |
| T1204.002 | Malicious File | execution | 5761 |
| T1027 | Obfuscated Files or Information | defense-evasion | 5750 |
| T1573 | Encrypted Channel | command-and-control | 5104 |
| T1056.001 | Keylogging | collection, credential-access | 3359 |
| T1566 | Phishing | initial-access | 3228 |
| T1566.002 | Spearphishing Link | initial-access | 3228 |
| T1566.001 | Spearphishing Attachment | initial-access | 3035 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 2651 |
| T1113 | Screen Capture | collection | 2619 |
| T1555 | Credentials from Password Stores | credential-access | 2456 |
| T1567 | Exfiltration Over Web Service | exfiltration | 2320 |
| T1552.001 | Credentials In Files | credential-access | 1608 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1521 |
| T1090 | Proxy | command-and-control | 1356 |
| T1059.001 | PowerShell | execution | 1288 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 265 |
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
| [`dri[.]6666k[.]org`](https://www.virustotal.com/gui/domain/dri.6666k.org) | domain | Vidar | threatfox | 2026-10-12T05:55:48Z | 100 |
| [`hxxps://dri[.]6666k[.]org/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fdri.6666k.org%2F) | url | Vidar | threatfox | 2026-10-12T05:55:48Z | 100 |
| [`i67d9ppi[.]b00kself[.]com`](https://www.virustotal.com/gui/domain/i67d9ppi.b00kself.com) | domain | ClearFake | threatfox | 2026-10-12T05:54:38Z | 100 |
| [`vok[.]6666k[.]org`](https://www.virustotal.com/gui/domain/vok.6666k.org) | domain | Vidar | threatfox | 2026-10-12T05:40:48Z | 100 |
| [`hxxps://vok[.]6666k[.]org/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fvok.6666k.org%2F) | url | Vidar | threatfox | 2026-10-12T05:40:48Z | 100 |
| [`hxxps://vok[.]6666k[.]org`](https://www.virustotal.com/gui/search/https%3A%2F%2Fvok.6666k.org) | url | Vidar | threatfox | 2026-10-12T05:39:07Z | 100 |
| [`hxxps://koi[.]6666k[.]org`](https://www.virustotal.com/gui/search/https%3A%2F%2Fkoi.6666k.org) | url | Vidar | threatfox | 2026-10-12T05:28:54Z | 100 |
| [`koi[.]6666k[.]org`](https://www.virustotal.com/gui/domain/koi.6666k.org) | domain | Vidar | threatfox | 2026-10-12T05:20:48Z | 100 |
| [`hxxps://koi[.]6666k[.]org/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fkoi.6666k.org%2F) | url | Vidar | threatfox | 2026-10-12T05:20:48Z | 100 |
| [`hxxps://myt[.]6666k[.]org`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmyt.6666k.org) | url | Vidar | threatfox | 2026-10-12T05:13:31Z | 100 |
| [`217[.]60[.]195[.]219`](https://www.virustotal.com/gui/ip-address/217.60.195.219) | ipv4 | Remcos | threatfox | 2026-10-12T05:10:03Z | 100 |
| [`myt[.]6666k[.]org`](https://www.virustotal.com/gui/domain/myt.6666k.org) | domain | Vidar | threatfox | 2026-10-12T05:05:48Z | 100 |
| [`hxxps://myt[.]6666k[.]org/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmyt.6666k.org%2F) | url | Vidar | threatfox | 2026-10-12T05:05:48Z | 100 |
| [`43[.]136[.]92[.]170`](https://www.virustotal.com/gui/ip-address/43.136.92.170) | ipv4 | Cobalt Strike | threatfox | 2026-10-12T05:05:03Z | 100 |
| [`172[.]111[.]161[.]134`](https://www.virustotal.com/gui/ip-address/172.111.161.134) | ipv4 | Remcos | threatfox | 2026-10-12T04:59:25Z | 100 |
| [`lrg[.]6666k[.]org`](https://www.virustotal.com/gui/domain/lrg.6666k.org) | domain | Vidar | threatfox | 2026-10-12T04:50:48Z | 100 |
| [`hxxps://lrg[.]6666k[.]org/`](https://www.virustotal.com/gui/search/https%3A%2F%2Flrg.6666k.org%2F) | url | Vidar | threatfox | 2026-10-12T04:50:48Z | 100 |
| [`7xum1r5l[.]lunza[.]store`](https://www.virustotal.com/gui/domain/7xum1r5l.lunza.store) | domain | ClearFake | threatfox | 2026-10-12T04:50:30Z | 100 |
| [`hxxps://bfb[.]6666k[.]org`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbfb.6666k.org) | url | Vidar | threatfox | 2026-10-12T04:36:47Z | 100 |
| [`bfb[.]6666k[.]org`](https://www.virustotal.com/gui/domain/bfb.6666k.org) | domain | Vidar | threatfox | 2026-10-12T04:35:48Z | 100 |
| [`hxxps://bfb[.]6666k[.]org/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbfb.6666k.org%2F) | url | Vidar | threatfox | 2026-10-12T04:35:48Z | 100 |
| [`lry[.]6666k[.]org`](https://www.virustotal.com/gui/domain/lry.6666k.org) | domain | Vidar | threatfox | 2026-10-12T04:20:48Z | 100 |
| [`hxxps://lry[.]6666k[.]org/`](https://www.virustotal.com/gui/search/https%3A%2F%2Flry.6666k.org%2F) | url | Vidar | threatfox | 2026-10-12T04:20:48Z | 100 |
| [`118[.]126[.]95[.]117`](https://www.virustotal.com/gui/ip-address/118.126.95.117) | ipv4 | Cobalt Strike | threatfox | 2026-10-12T04:05:04Z | 100 |
| [`hxxps://jte[.]6666k[.]org`](https://www.virustotal.com/gui/search/https%3A%2F%2Fjte.6666k.org) | url | Vidar | threatfox | 2026-10-12T04:03:01Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
