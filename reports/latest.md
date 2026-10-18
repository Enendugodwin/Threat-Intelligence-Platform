# Threat Intel Pulse — 2026-10-18

**Window:** last 7 days · **Generated:** 2026-10-18T16:00:04Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 77420 |
| New in window | 24124 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5000 | ok |
| feodo | 5 | ok |
| threatfox | 7429 | ok |
| malwarebazaar | 926 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8758 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 31436 | 12716 |
| sha256 | 15260 | 4911 |
| domain | 13440 | 3221 |
| ipv4 | 12312 | 2194 |
| ipv6 | 3261 | 304 |
| md5 | 868 | 389 |
| sha1 | 843 | 389 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 11182 |
| Exit nodes | 2403 |
| Other relays | 8779 |
| New in window | 1185 |

Sample (20 of 11182, source: Tor Project Onionoo):
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
| Unknown Loader | 5355 | 788 | — |
| Vidar | 5148 | 4681 | T1555, T1071.001, T1567 |
| Mirai | 4987 | 1112 | T1498, T1071.001 |
| AsyncRAT | 2318 | 101 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| IClickFix | 2097 | 808 | — |
| ClearFake | 1991 | 324 | — |
| Unknown malware | 1504 | 655 | — |
| Cobalt Strike | 1359 | 87 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| VShell | 887 | 635 | — |
| AMOS | 677 | 439 | — |
| php.shin_webshell | 640 | 304 | — |
| Unknown Stealer | 635 | 75 | — |
| PureRAT | 443 | 62 | — |
| Remcos | 336 | 163 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| Sliver | 324 | 287 | T1071.001, T1573, T1090, T1055 |
| AdaptixC2 | 300 | 28 | — |
| Remus | 246 | 86 | — |
| Unknown RAT | 228 | 49 | — |
| DanaBot | 195 | 99 | T1566.001, T1071.001, T1555, T1041 |
| Formbook | 187 | 88 | T1566.001, T1056.001, T1555, T1071.001, T1567 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1071.001 | Web Protocols | command-and-control | 49274 |
| T1105 | Ingress Tool Transfer | command-and-control | 23907 |
| T1498 | Network Denial of Service | impact | 11954 |
| T1204.002 | Malicious File | execution | 9480 |
| T1027 | Obfuscated Files or Information | defense-evasion | 9318 |
| T1573 | Encrypted Channel | command-and-control | 8829 |
| T1555 | Credentials from Password Stores | credential-access | 8521 |
| T1567 | Exfiltration Over Web Service | exfiltration | 8326 |
| T1566 | Phishing | initial-access | 6885 |
| T1566.002 | Spearphishing Link | initial-access | 6885 |
| T1552.001 | Credentials In Files | credential-access | 5126 |
| T1056.001 | Keylogging | collection, credential-access | 3941 |
| T1566.001 | Spearphishing Attachment | initial-access | 3629 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 3022 |
| T1113 | Screen Capture | collection | 2961 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1946 |
| T1090 | Proxy | command-and-control | 1720 |
| T1059.001 | PowerShell | execution | 1373 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 383 |
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
| [`hxxps://b2[.]9windaftar[.]com/c6/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fb2.9windaftar.com%2Fc6%2F) | url | Vidar | threatfox | 2026-10-18T15:50:48Z | 100 |
| [`hxxps://b2[.]9windaftar[.]com/b/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fb2.9windaftar.com%2Fb%2F) | url | Vidar | threatfox | 2026-10-18T15:45:48Z | 100 |
| [`hxxps://b2[.]9windaftar[.]com/yn/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fb2.9windaftar.com%2Fyn%2F) | url | Vidar | threatfox | 2026-10-18T15:40:48Z | 100 |
| [`hxxps://b2[.]9windaftar[.]com/n8/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fb2.9windaftar.com%2Fn8%2F) | url | Vidar | threatfox | 2026-10-18T15:35:48Z | 100 |
| [`hxxps://b2[.]9windaftar[.]com/ye/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fb2.9windaftar.com%2Fye%2F) | url | Vidar | threatfox | 2026-10-18T15:30:48Z | 100 |
| [`hxxps://vine-linen[.]com/curl/rb4p5pddi/v6m711xe0vdsrzr6y2f69y[.]json`](https://www.virustotal.com/gui/search/https%3A%2F%2Fvine-linen.com%2Fcurl%2Frb4p5pddi%2Fv6m711xe0vdsrzr6y2f69y.json) | url | AMOS | threatfox | 2026-10-18T15:26:34Z | 100 |
| [`hxxps://vine-linen[.]com/f/rjcf4ggdrb1wp5syzplnda/5r7r2qc0`](https://www.virustotal.com/gui/search/https%3A%2F%2Fvine-linen.com%2Ff%2Frjcf4ggdrb1wp5syzplnda%2F5r7r2qc0) | url | AMOS | threatfox | 2026-10-18T15:26:34Z | 100 |
| [`vine-linen[.]com`](https://www.virustotal.com/gui/domain/vine-linen.com) | domain | AMOS | threatfox | 2026-10-18T15:26:34Z | 100 |
| [`nova-49[.]com`](https://www.virustotal.com/gui/domain/nova-49.com) | domain | AMOS | threatfox | 2026-10-18T15:26:34Z | 100 |
| [`6e9fda95863ee943003d1b2ce25f4877f03c08d0cbfdaad1946450b6f4006fc2`](https://www.virustotal.com/gui/file/6e9fda95863ee943003d1b2ce25f4877f03c08d0cbfdaad1946450b6f4006fc2) | sha256 | AMOS | threatfox | 2026-10-18T15:26:33Z | 100 |
| [`85fce9826974549c2dd4c92a3207cf2543e10676ad2dfad7c8ea429f616cdf21`](https://www.virustotal.com/gui/file/85fce9826974549c2dd4c92a3207cf2543e10676ad2dfad7c8ea429f616cdf21) | sha256 | AMOS | threatfox | 2026-10-18T15:26:33Z | 100 |
| [`visadubai[.]com[.]vn`](https://www.virustotal.com/gui/domain/visadubai.com.vn) | domain | IClickFix | threatfox | 2026-10-18T15:25:50Z | 100 |
| [`warpfins[.]com`](https://www.virustotal.com/gui/domain/warpfins.com) | domain | IClickFix | threatfox | 2026-10-18T15:25:50Z | 100 |
| [`webfischerei[.]de`](https://www.virustotal.com/gui/domain/webfischerei.de) | domain | IClickFix | threatfox | 2026-10-18T15:25:50Z | 100 |
| [`weddart[.]it`](https://www.virustotal.com/gui/domain/weddart.it) | domain | IClickFix | threatfox | 2026-10-18T15:25:50Z | 100 |
| [`winwincookware[.]com`](https://www.virustotal.com/gui/domain/winwincookware.com) | domain | IClickFix | threatfox | 2026-10-18T15:25:50Z | 100 |
| [`woraset-partners[.]co[.]th`](https://www.virustotal.com/gui/domain/woraset-partners.co.th) | domain | IClickFix | threatfox | 2026-10-18T15:25:50Z | 100 |
| [`xinlin[.]tw`](https://www.virustotal.com/gui/domain/xinlin.tw) | domain | IClickFix | threatfox | 2026-10-18T15:25:50Z | 100 |
| [`xocdiapro[.]co`](https://www.virustotal.com/gui/domain/xocdiapro.co) | domain | IClickFix | threatfox | 2026-10-18T15:25:50Z | 100 |
| [`yumweb[.]com`](https://www.virustotal.com/gui/domain/yumweb.com) | domain | IClickFix | threatfox | 2026-10-18T15:25:50Z | 100 |
| [`zenithcomputers[.]com`](https://www.virustotal.com/gui/domain/zenithcomputers.com) | domain | IClickFix | threatfox | 2026-10-18T15:25:50Z | 100 |
| [`zmops[.]io`](https://www.virustotal.com/gui/domain/zmops.io) | domain | IClickFix | threatfox | 2026-10-18T15:25:50Z | 100 |
| [`sandandgarden[.]com[.]mx`](https://www.virustotal.com/gui/domain/sandandgarden.com.mx) | domain | IClickFix | threatfox | 2026-10-18T15:25:49Z | 100 |
| [`sapir-eng[.]com`](https://www.virustotal.com/gui/domain/sapir-eng.com) | domain | IClickFix | threatfox | 2026-10-18T15:25:49Z | 100 |
| [`sexstories[.]beauty`](https://www.virustotal.com/gui/domain/sexstories.beauty) | domain | IClickFix | threatfox | 2026-10-18T15:25:49Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
