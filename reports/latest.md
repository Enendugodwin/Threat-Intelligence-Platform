# Threat Intel Pulse — 2026-10-18

**Window:** last 7 days · **Generated:** 2026-10-18T11:25:23Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 76407 |
| New in window | 23803 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5000 | ok |
| feodo | 5 | ok |
| threatfox | 7350 | ok |
| malwarebazaar | 906 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8755 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 30981 | 12662 |
| sha256 | 15192 | 4955 |
| domain | 13047 | 2919 |
| ipv4 | 12232 | 2198 |
| ipv6 | 3244 | 291 |
| md5 | 868 | 389 |
| sha1 | 843 | 389 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 11128 |
| Exit nodes | 2394 |
| Other relays | 8734 |
| New in window | 1157 |

Sample (20 of 11128, source: Tor Project Onionoo):
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
| Unknown Loader | 5175 | 610 | — |
| Vidar | 5088 | 4633 | T1555, T1071.001, T1567 |
| Mirai | 4956 | 1110 | T1498, T1071.001 |
| AsyncRAT | 2318 | 104 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| ClearFake | 1966 | 315 | — |
| IClickFix | 1918 | 646 | — |
| Unknown malware | 1500 | 686 | — |
| Cobalt Strike | 1351 | 82 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| VShell | 887 | 642 | — |
| AMOS | 654 | 432 | — |
| php.shin_webshell | 636 | 317 | — |
| Unknown Stealer | 635 | 76 | — |
| PureRAT | 442 | 63 | — |
| Remcos | 332 | 162 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| Sliver | 323 | 289 | T1071.001, T1573, T1090, T1055 |
| AdaptixC2 | 300 | 30 | — |
| Remus | 246 | 93 | — |
| Unknown RAT | 228 | 52 | — |
| DanaBot | 195 | 100 | T1566.001, T1071.001, T1555, T1041 |
| Formbook | 187 | 88 | T1566.001, T1056.001, T1555, T1071.001, T1567 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1105 | Ingress Tool Transfer | command-and-control | 23797 |
| T1071.001 | Web Protocols | command-and-control | 47633 |
| T1498 | Network Denial of Service | impact | 10880 |
| T1204.002 | Malicious File | execution | 9473 |
| T1027 | Obfuscated Files or Information | defense-evasion | 9311 |
| T1573 | Encrypted Channel | command-and-control | 8805 |
| T1555 | Credentials from Password Stores | credential-access | 8418 |
| T1567 | Exfiltration Over Web Service | exfiltration | 8223 |
| T1566 | Phishing | initial-access | 6597 |
| T1566.002 | Spearphishing Link | initial-access | 6597 |
| T1552.001 | Credentials In Files | credential-access | 5087 |
| T1056.001 | Keylogging | collection, credential-access | 3918 |
| T1566.001 | Spearphishing Attachment | initial-access | 3601 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 2999 |
| T1113 | Screen Capture | collection | 2950 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1934 |
| T1090 | Proxy | command-and-control | 1711 |
| T1059.001 | PowerShell | execution | 1365 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 383 |
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
| [`hxxps://g94[.]9win[.]cyou/lg/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fg94.9win.cyou%2Flg%2F) | url | Vidar | threatfox | 2026-10-18T11:15:48Z | 100 |
| [`hxxps://g94[.]9win[.]cyou/i/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fg94.9win.cyou%2Fi%2F) | url | Vidar | threatfox | 2026-10-18T11:10:48Z | 100 |
| [`hxxps://g94[.]9win[.]cyou/gj/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fg94.9win.cyou%2Fgj%2F) | url | Vidar | threatfox | 2026-10-18T11:05:48Z | 100 |
| [`hxxps://vl[.]9win[.]cyou/s/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fvl.9win.cyou%2Fs%2F) | url | Vidar | threatfox | 2026-10-18T11:00:49Z | 100 |
| [`hxxps://vl[.]9win[.]cyou/ve/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fvl.9win.cyou%2Fve%2F) | url | Vidar | threatfox | 2026-10-18T10:55:48Z | 100 |
| [`hxxps://vl[.]9win[.]cyou/vn/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fvl.9win.cyou%2Fvn%2F) | url | Vidar | threatfox | 2026-10-18T10:50:49Z | 100 |
| [`hxxps://vl[.]9win[.]cyou/uf/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fvl.9win.cyou%2Fuf%2F) | url | Vidar | threatfox | 2026-10-18T10:45:48Z | 100 |
| [`hxxps://vl[.]9win[.]cyou/d/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fvl.9win.cyou%2Fd%2F) | url | Vidar | threatfox | 2026-10-18T10:40:48Z | 100 |
| [`hxxps://vl[.]9win[.]cyou/vw/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fvl.9win.cyou%2Fvw%2F) | url | Vidar | threatfox | 2026-10-18T10:35:48Z | 100 |
| [`130[.]94[.]1[.]88`](https://www.virustotal.com/gui/ip-address/130.94.1.88) | ipv4 | Sliver | threatfox | 2026-10-18T10:34:49Z | 100 |
| [`167[.]99[.]227[.]197`](https://www.virustotal.com/gui/ip-address/167.99.227.197) | ipv4 | Sliver | threatfox | 2026-10-18T10:34:49Z | 100 |
| [`hxxps://vl[.]9win[.]cyou/jr/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fvl.9win.cyou%2Fjr%2F) | url | Vidar | threatfox | 2026-10-18T10:30:48Z | 100 |
| [`hxxps://frame97[.]com/f/k7e0e3iquhg0jhqinjctaq/r03r7eyj`](https://www.virustotal.com/gui/search/https%3A%2F%2Fframe97.com%2Ff%2Fk7e0e3iquhg0jhqinjctaq%2Fr03r7eyj) | url | AMOS | threatfox, urlhaus | 2026-10-18T10:28:48Z | 100 |
| [`frame97[.]com`](https://www.virustotal.com/gui/domain/frame97.com) | domain | AMOS | threatfox, urlhaus | 2026-10-18T10:28:48Z | 100 |
| [`hxxps://frame97[.]com/curl/va07rvox9/yu7tj8ts6cv9hy9cpcje7[.]json`](https://www.virustotal.com/gui/search/https%3A%2F%2Fframe97.com%2Fcurl%2Fva07rvox9%2Fyu7tj8ts6cv9hy9cpcje7.json) | url | AMOS | threatfox, urlhaus | 2026-10-18T10:28:48Z | 100 |
| [`2b66b4b8780569cd63159360fbc53761d6ba15c7635c977976d55c77d1d93079`](https://www.virustotal.com/gui/file/2b66b4b8780569cd63159360fbc53761d6ba15c7635c977976d55c77d1d93079) | sha256 | AMOS | threatfox, malwarebazaar | 2026-10-18T10:28:48Z | 100 |
| [`47e9e1bf4296b651d4d5d3bd066a0e3ceb44c4f897aa1edac79197d1ec680e6c`](https://www.virustotal.com/gui/file/47e9e1bf4296b651d4d5d3bd066a0e3ceb44c4f897aa1edac79197d1ec680e6c) | sha256 | AMOS | threatfox, malwarebazaar | 2026-10-18T10:28:47Z | 100 |
| [`hxxps://v[.]9win[.]cyou/cu/api/v2/collect`](https://www.virustotal.com/gui/search/https%3A%2F%2Fv.9win.cyou%2Fcu%2Fapi%2Fv2%2Fcollect) | url | Vidar | threatfox | 2026-10-18T10:28:13Z | 100 |
| [`9win[.]cyou`](https://www.virustotal.com/gui/domain/9win.cyou) | domain | Vidar | threatfox | 2026-10-18T10:28:13Z | 100 |
| [`hxxps://vl[.]9win[.]cyou/ok/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fvl.9win.cyou%2Fok%2F) | url | Vidar | threatfox | 2026-10-18T10:25:48Z | 100 |
| [`hxxps://vl[.]9win[.]cyou/xo/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fvl.9win.cyou%2Fxo%2F) | url | Vidar | threatfox | 2026-10-18T10:20:48Z | 100 |
| [`206[.]123[.]137[.]176`](https://www.virustotal.com/gui/ip-address/206.123.137.176) | ipv4 | Remcos | threatfox | 2026-10-18T10:18:35Z | 100 |
| [`hxxps://vl[.]9win[.]cyou/j1/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fvl.9win.cyou%2Fj1%2F) | url | Vidar | threatfox | 2026-10-18T10:15:48Z | 100 |
| [`hxxps://vl[.]9win[.]cyou/x/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fvl.9win.cyou%2Fx%2F) | url | Vidar | threatfox | 2026-10-18T10:10:48Z | 100 |
| [`tjt7bjni[.]bociljepe[.]info`](https://www.virustotal.com/gui/domain/tjt7bjni.bociljepe.info) | domain | ClearFake | threatfox | 2026-10-18T10:10:17Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
