# Threat Intel Pulse — 2026-10-09

**Window:** last 7 days · **Generated:** 2026-10-09T13:34:52Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 48369 |
| New in window | 48369 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5001 | ok |
| feodo | 5 | ok |
| threatfox | 6394 | ok |
| malwarebazaar | 908 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8636 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 16570 | 16570 |
| ipv4 | 9692 | 9692 |
| sha256 | 9438 | 9438 |
| domain | 9061 | 9061 |
| ipv6 | 2922 | 2922 |
| md5 | 355 | 355 |
| sha1 | 331 | 331 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 9746 |
| Exit nodes | 2198 |
| Other relays | 7548 |
| New in window | 9746 |

Sample (20 of 9746, source: Tor Project Onionoo):
- `1[.]201[.]176[.]176`
- `1[.]248[.]96[.]163`
- `100[.]1[.]157[.]56`
- `100[.]2[.]63[.]41`
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
- `103[.]105[.]21[.]2`

Full list: `dist/tor/tor_nodes.txt` (in the `threat-intel-output` workflow artifact).
## Top malware families

| Family | Indicators | New | ATT&CK (heuristic) |
| --- | --- | --- | --- |
| Unknown Loader | 4474 | 4474 | — |
| Mirai | 3490 | 3490 | T1498, T1071.001 |
| AsyncRAT | 2194 | 2194 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| Cobalt Strike | 1263 | 1263 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| ClearFake | 1228 | 1228 | — |
| IClickFix | 899 | 899 | — |
| Unknown malware | 642 | 642 | — |
| Unknown Stealer | 503 | 503 | — |
| PureRAT | 368 | 368 | — |
| Vidar | 364 | 364 | T1555, T1071.001, T1567 |
| AdaptixC2 | 261 | 261 | — |
| php.shin_webshell | 236 | 236 | — |
| AMOS | 195 | 195 | — |
| Unknown RAT | 171 | 171 | — |
| Remcos | 166 | 166 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| Remus | 141 | 141 | — |
| VShell | 135 | 135 | — |
| DCRat | 106 | 106 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| Evilginx | 95 | 95 | — |
| Havoc | 93 | 93 | — |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1105 | Ingress Tool Transfer | command-and-control | 15556 |
| T1071.001 | Web Protocols | command-and-control | 32546 |
| T1498 | Network Denial of Service | impact | 8255 |
| T1204.002 | Malicious File | execution | 5592 |
| T1027 | Obfuscated Files or Information | defense-evasion | 5581 |
| T1573 | Encrypted Channel | command-and-control | 4861 |
| T1056.001 | Keylogging | collection, credential-access | 3196 |
| T1566.001 | Spearphishing Attachment | initial-access | 2833 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 2562 |
| T1113 | Screen Capture | collection | 2530 |
| T1566 | Phishing | initial-access | 2208 |
| T1566.002 | Spearphishing Link | initial-access | 2208 |
| T1555 | Credentials from Password Stores | credential-access | 1877 |
| T1567 | Exfiltration Over Web Service | exfiltration | 1814 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1453 |
| T1552.001 | Credentials In Files | credential-access | 1397 |
| T1090 | Proxy | command-and-control | 1304 |
| T1059.001 | PowerShell | execution | 1276 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 172 |
| T1059.005 | Visual Basic | execution | 63 |
| T1189 | Drive-by Compromise | initial-access | 21 |
| T1218 | System Binary Proxy Execution | defense-evasion | 21 |
| T1021.001 | Remote Desktop Protocol | lateral-movement | 8 |
| T1486 | Data Encrypted for Impact | impact | 8 |
| T1490 | Inhibit System Recovery | impact | 8 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 8 |
| T1003 | OS Credential Dumping | credential-access | 1 |
| T1190 | Exploit Public-Facing Application | initial-access | 1 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`104[.]248[.]144[.]172`](https://www.virustotal.com/gui/ip-address/104.248.144.172) | ipv4 | Remus | threatfox | 2026-10-09T13:05:07Z | 100 |
| [`b55e16170cbba64cb8fe432d2004c0b011db6318ed41dd359637a2afe9d6545b`](https://www.virustotal.com/gui/file/b55e16170cbba64cb8fe432d2004c0b011db6318ed41dd359637a2afe9d6545b) | sha256 | AMOS | threatfox | 2026-10-09T13:05:06Z | 100 |
| [`3e0b7f50928f8b8f08f1527129a5c8aad50df66e88f2c34a3fd3056081e26d77`](https://www.virustotal.com/gui/file/3e0b7f50928f8b8f08f1527129a5c8aad50df66e88f2c34a3fd3056081e26d77) | sha256 | AMOS | threatfox | 2026-10-09T13:05:06Z | 100 |
| [`hxxps://pro[.]jasperwater[.]info/auth/dashboard-cache`](https://www.virustotal.com/gui/search/https%3A%2F%2Fpro.jasperwater.info%2Fauth%2Fdashboard-cache) | url | SmartApeSG | threatfox | 2026-10-09T13:05:06Z | 100 |
| [`39[.]104[.]200[.]49`](https://www.virustotal.com/gui/ip-address/39.104.200.49) | ipv4 | VShell | threatfox | 2026-10-09T13:05:06Z | 100 |
| [`pro[.]jasperwater[.]info`](https://www.virustotal.com/gui/domain/pro.jasperwater.info) | domain | SmartApeSG | threatfox | 2026-10-09T13:05:05Z | 100 |
| [`hxxps://pro[.]jasperwater[.]info/auth/permission-render[.]js`](https://www.virustotal.com/gui/search/https%3A%2F%2Fpro.jasperwater.info%2Fauth%2Fpermission-render.js) | url | SmartApeSG | threatfox | 2026-10-09T13:05:05Z | 100 |
| [`194[.]182[.]79[.]61`](https://www.virustotal.com/gui/ip-address/194.182.79.61) | ipv4 | Remcos | threatfox | 2026-10-09T13:05:04Z | 100 |
| [`deba43734e342776a2724c6cf12557aa7bbbd93200a4f2bfa8f2e7f7ef1b56a8`](https://www.virustotal.com/gui/file/deba43734e342776a2724c6cf12557aa7bbbd93200a4f2bfa8f2e7f7ef1b56a8) | sha256 | AMOS | threatfox | 2026-10-09T13:05:04Z | 100 |
| [`48ypnsgk[.]porel[.]store`](https://www.virustotal.com/gui/domain/48ypnsgk.porel.store) | domain | ClearFake | threatfox | 2026-10-09T12:28:01Z | 100 |
| [`45[.]144[.]172[.]49`](https://www.virustotal.com/gui/ip-address/45.144.172.49) | ipv4 | Jackskid | threatfox | 2026-10-09T11:54:40Z | 100 |
| [`708329a7a39e5391fe3e938933e5758b685d080146c0b703f1805e179d2bae8d`](https://www.virustotal.com/gui/file/708329a7a39e5391fe3e938933e5758b685d080146c0b703f1805e179d2bae8d) | sha256 | AMOS | threatfox | 2026-10-09T11:13:16Z | 100 |
| [`45[.]135[.]194[.]116`](https://www.virustotal.com/gui/ip-address/45.135.194.116) | ipv4 | Aisuru | threatfox | 2026-10-09T11:13:16Z | 100 |
| [`199[.]101[.]198[.]165`](https://www.virustotal.com/gui/ip-address/199.101.198.165) | ipv4 | Remcos | threatfox | 2026-10-09T11:13:16Z | 100 |
| [`67[.]220[.]71[.]211`](https://www.virustotal.com/gui/ip-address/67.220.71.211) | ipv4 | Aisuru | threatfox | 2026-10-09T10:52:11Z | 100 |
| [`45[.]127[.]32[.]69`](https://www.virustotal.com/gui/ip-address/45.127.32.69) | ipv4 | Aisuru | threatfox | 2026-10-09T10:52:10Z | 100 |
| [`172[.]94[.]99[.]29`](https://www.virustotal.com/gui/ip-address/172.94.99.29) | ipv4 | XWorm | threatfox | 2026-10-09T10:48:33Z | 100 |
| [`192[.]3[.]73[.]139`](https://www.virustotal.com/gui/ip-address/192.3.73.139) | ipv4 | Remcos | threatfox | 2026-10-09T10:48:31Z | 100 |
| [`hxxps://1rvrental[.]com/g[.]php`](https://www.virustotal.com/gui/search/https%3A%2F%2F1rvrental.com%2Fg.php) | url | Unknown malware | threatfox, urlhaus | 2026-10-09T10:48:30Z | 100 |
| [`1rvrental[.]com`](https://www.virustotal.com/gui/domain/1rvrental.com) | domain | Unknown malware | threatfox, urlhaus | 2026-10-09T10:48:30Z | 100 |
| [`hxxp://1rvrental[.]com/r`](https://www.virustotal.com/gui/search/http%3A%2F%2F1rvrental.com%2Fr) | url | Unknown malware | threatfox | 2026-10-09T10:48:30Z | 100 |
| [`edgnltatqptann[.]com`](https://www.virustotal.com/gui/domain/edgnltatqptann.com) | domain | DeerStealer | threatfox | 2026-10-09T10:48:29Z | 100 |
| [`aeyibtnr[.]com`](https://www.virustotal.com/gui/domain/aeyibtnr.com) | domain | DeerStealer | threatfox | 2026-10-09T10:48:29Z | 100 |
| [`anwhinweudee[.]com`](https://www.virustotal.com/gui/domain/anwhinweudee.com) | domain | DeerStealer | threatfox | 2026-10-09T10:48:28Z | 100 |
| [`141[.]98[.]10[.]150`](https://www.virustotal.com/gui/ip-address/141.98.10.150) | ipv4 | Remcos | threatfox | 2026-10-09T10:48:27Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
