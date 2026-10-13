# Threat Intel Pulse — 2026-10-13

**Window:** last 7 days · **Generated:** 2026-10-13T14:25:08Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 59608 |
| New in window | 25029 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5001 | ok |
| feodo | 5 | ok |
| threatfox | 6821 | ok |
| malwarebazaar | 1118 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8545 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 22264 | 13085 |
| sha256 | 11576 | 4237 |
| ipv4 | 10978 | 2087 |
| domain | 10671 | 4607 |
| ipv6 | 3000 | 200 |
| md5 | 572 | 407 |
| sha1 | 547 | 406 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 10257 |
| Exit nodes | 2235 |
| Other relays | 8022 |
| New in window | 1089 |

Sample (20 of 10257, source: Tor Project Onionoo):
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
| Unknown Loader | 4586 | 1770 | — |
| Mirai | 4052 | 725 | T1498, T1071.001 |
| AsyncRAT | 2252 | 87 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| ClearFake | 1726 | 871 | — |
| Vidar | 1551 | 1327 | T1555, T1071.001, T1567 |
| IClickFix | 1318 | 934 | — |
| Cobalt Strike | 1313 | 78 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| Unknown malware | 974 | 463 | — |
| Unknown Stealer | 573 | 397 | — |
| php.shin_webshell | 431 | 342 | — |
| PureRAT | 399 | 59 | — |
| VShell | 346 | 237 | — |
| AMOS | 290 | 158 | — |
| Sliver | 281 | 261 | T1071.001, T1573, T1090, T1055 |
| AdaptixC2 | 277 | 31 | — |
| Remcos | 218 | 109 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| DanaBot | 193 | 130 | T1566.001, T1071.001, T1555, T1041 |
| Unknown RAT | 192 | 35 | — |
| Remus | 173 | 80 | — |
| Formbook | 122 | 82 | T1566.001, T1056.001, T1555, T1071.001, T1567 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1105 | Ingress Tool Transfer | command-and-control | 19068 |
| T1071.001 | Web Protocols | command-and-control | 38496 |
| T1498 | Network Denial of Service | impact | 9302 |
| T1204.002 | Malicious File | execution | 6970 |
| T1027 | Obfuscated Files or Information | defense-evasion | 6959 |
| T1573 | Encrypted Channel | command-and-control | 6037 |
| T1555 | Credentials from Password Stores | credential-access | 4079 |
| T1566 | Phishing | initial-access | 3922 |
| T1566.002 | Spearphishing Link | initial-access | 3922 |
| T1567 | Exfiltration Over Web Service | exfiltration | 3886 |
| T1056.001 | Keylogging | collection, credential-access | 3510 |
| T1566.001 | Spearphishing Attachment | initial-access | 3216 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 2729 |
| T1113 | Screen Capture | collection | 2694 |
| T1552.001 | Credentials In Files | credential-access | 2214 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1811 |
| T1090 | Proxy | command-and-control | 1628 |
| T1059.001 | PowerShell | execution | 1326 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 337 |
| T1059.005 | Visual Basic | execution | 74 |
| T1189 | Drive-by Compromise | initial-access | 23 |
| T1218 | System Binary Proxy Execution | defense-evasion | 23 |
| T1021.001 | Remote Desktop Protocol | lateral-movement | 11 |
| T1486 | Data Encrypted for Impact | impact | 11 |
| T1490 | Inhibit System Recovery | impact | 11 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 11 |
| T1003 | OS Credential Dumping | credential-access | 4 |
| T1190 | Exploit Public-Facing Application | initial-access | 2 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://t6[.]6r6r6[.]org/rj`](https://www.virustotal.com/gui/search/https%3A%2F%2Ft6.6r6r6.org%2Frj) | url | Vidar | threatfox | 2026-10-13T14:19:24Z | 100 |
| [`hxxps://t6[.]6r6r6[.]org/zu/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ft6.6r6r6.org%2Fzu%2F) | url | Vidar | threatfox | 2026-10-13T14:15:48Z | 100 |
| [`hxxps://t6[.]6r6r6[.]org/zu`](https://www.virustotal.com/gui/search/https%3A%2F%2Ft6.6r6r6.org%2Fzu) | url | Vidar | threatfox | 2026-10-13T14:15:43Z | 100 |
| [`baff2658000b5e7f8c533a802691e87d6441e916df6486187e86fd9734a8c331`](https://www.virustotal.com/gui/file/baff2658000b5e7f8c533a802691e87d6441e916df6486187e86fd9734a8c331) | sha256 | AMOS | threatfox | 2026-10-13T14:13:44Z | 100 |
| [`hxxps://new[.]sunstonewell[.]info/verify/principal-sessionstore`](https://www.virustotal.com/gui/search/https%3A%2F%2Fnew.sunstonewell.info%2Fverify%2Fprincipal-sessionstore) | url | SmartApeSG | threatfox | 2026-10-13T14:13:43Z | 100 |
| [`new[.]sunstonewell[.]info`](https://www.virustotal.com/gui/domain/new.sunstonewell.info) | domain | SmartApeSG | threatfox | 2026-10-13T14:13:42Z | 100 |
| [`hxxps://new[.]sunstonewell[.]info/verify/logout-template[.]js`](https://www.virustotal.com/gui/search/https%3A%2F%2Fnew.sunstonewell.info%2Fverify%2Flogout-template.js) | url | SmartApeSG | threatfox | 2026-10-13T14:13:41Z | 100 |
| [`138ea0b71b71dd0ef5d66ddeed1e8f5eca4a562558fc68660d64a007d5690e1f`](https://www.virustotal.com/gui/file/138ea0b71b71dd0ef5d66ddeed1e8f5eca4a562558fc68660d64a007d5690e1f) | sha256 | AMOS | threatfox | 2026-10-13T14:13:41Z | 100 |
| [`motherotters[.]com`](https://www.virustotal.com/gui/domain/motherotters.com) | domain | Unknown Stealer | threatfox | 2026-10-13T14:13:40Z | 100 |
| [`healskills[.]com`](https://www.virustotal.com/gui/domain/healskills.com) | domain | Unknown Stealer | threatfox | 2026-10-13T14:13:39Z | 100 |
| [`hxxps://t6[.]6r6r6[.]org/xy`](https://www.virustotal.com/gui/search/https%3A%2F%2Ft6.6r6r6.org%2Fxy) | url | Vidar | threatfox | 2026-10-13T14:12:54Z | 100 |
| [`176[.]65[.]139[.]41`](https://www.virustotal.com/gui/ip-address/176.65.139.41) | ipv4 | Aisuru | threatfox | 2026-10-13T14:12:26Z | 100 |
| [`hxxps://t6[.]6r6r6[.]org/f6/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ft6.6r6r6.org%2Ff6%2F) | url | Vidar | threatfox | 2026-10-13T14:10:48Z | 100 |
| [`hxxps://t6[.]6r6r6[.]org/f6`](https://www.virustotal.com/gui/search/https%3A%2F%2Ft6.6r6r6.org%2Ff6) | url | Vidar | threatfox | 2026-10-13T14:10:28Z | 100 |
| [`hxxps://t6[.]6r6r6[.]org/gl`](https://www.virustotal.com/gui/search/https%3A%2F%2Ft6.6r6r6.org%2Fgl) | url | Vidar | threatfox | 2026-10-13T14:08:33Z | 100 |
| [`hxxps://t6[.]6r6r6[.]org/rl`](https://www.virustotal.com/gui/search/https%3A%2F%2Ft6.6r6r6.org%2Frl) | url | Vidar | threatfox | 2026-10-13T14:06:31Z | 100 |
| [`hxxps://t6[.]6r6r6[.]org/tnl/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ft6.6r6r6.org%2Ftnl%2F) | url | Vidar | threatfox | 2026-10-13T14:05:48Z | 100 |
| [`hxxps://t6[.]6r6r6[.]org/tnl`](https://www.virustotal.com/gui/search/https%3A%2F%2Ft6.6r6r6.org%2Ftnl) | url | Vidar | threatfox | 2026-10-13T14:04:41Z | 100 |
| [`hxxps://t6[.]6r6r6[.]org/es`](https://www.virustotal.com/gui/search/https%3A%2F%2Ft6.6r6r6.org%2Fes) | url | Vidar | threatfox | 2026-10-13T14:03:23Z | 100 |
| [`hxxps://mj[.]6r6r6[.]org/xw/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmj.6r6r6.org%2Fxw%2F) | url | Vidar | threatfox | 2026-10-13T14:00:49Z | 100 |
| [`hxxps://mj[.]6r6r6[.]org/xw`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmj.6r6r6.org%2Fxw) | url | Vidar | threatfox | 2026-10-13T14:00:32Z | 100 |
| [`hxxps://mj[.]6r6r6[.]org/nu`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmj.6r6r6.org%2Fnu) | url | Vidar | threatfox | 2026-10-13T13:58:14Z | 100 |
| [`hxxps://mj[.]6r6r6[.]org/tl`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmj.6r6r6.org%2Ftl) | url | Vidar | threatfox | 2026-10-13T13:56:14Z | 100 |
| [`hxxps://mj[.]6r6r6[.]org/l/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmj.6r6r6.org%2Fl%2F) | url | Vidar | threatfox | 2026-10-13T13:55:48Z | 100 |
| [`hxxps://mj[.]6r6r6[.]org/l`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmj.6r6r6.org%2Fl) | url | Vidar | threatfox | 2026-10-13T13:54:19Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
