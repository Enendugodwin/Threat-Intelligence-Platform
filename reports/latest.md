# Threat Intel Pulse — 2026-10-08

**Window:** last 7 days · **Generated:** 2026-10-08T13:48:17Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 45809 |
| New in window | 45809 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5001 | ok |
| feodo | 5 | ok |
| threatfox | 8126 | ok |
| malwarebazaar | 875 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8657 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 15341 | 15341 |
| ipv4 | 9455 | 9455 |
| sha256 | 8955 | 8955 |
| domain | 8550 | 8550 |
| ipv6 | 2898 | 2898 |
| md5 | 317 | 317 |
| sha1 | 293 | 293 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 9593 |
| Exit nodes | 2192 |
| Other relays | 7401 |
| New in window | 9593 |

Sample (20 of 9593, source: Tor Project Onionoo):
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
| Unknown Loader | 4251 | 4251 | — |
| Mirai | 3315 | 3315 | T1498, T1071.001 |
| AsyncRAT | 2190 | 2190 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| Cobalt Strike | 1248 | 1248 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| ClearFake | 1192 | 1192 | — |
| IClickFix | 812 | 812 | — |
| Unknown malware | 591 | 591 | — |
| PureRAT | 360 | 360 | — |
| Unknown Stealer | 352 | 352 | — |
| Vidar | 319 | 319 | T1555, T1071.001, T1567 |
| AdaptixC2 | 255 | 255 | — |
| AMOS | 176 | 176 | — |
| Unknown RAT | 171 | 171 | — |
| Remcos | 156 | 156 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| php.shin_webshell | 142 | 142 | — |
| Remus | 126 | 126 | — |
| VShell | 118 | 118 | — |
| DCRat | 104 | 104 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| Evilginx | 95 | 95 | — |
| Havoc | 93 | 93 | — |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1105 | Ingress Tool Transfer | command-and-control | 14769 |
| T1071.001 | Web Protocols | command-and-control | 31319 |
| T1498 | Network Denial of Service | impact | 7879 |
| T1204.002 | Malicious File | execution | 5529 |
| T1027 | Obfuscated Files or Information | defense-evasion | 5518 |
| T1573 | Encrypted Channel | command-and-control | 4770 |
| T1056.001 | Keylogging | collection, credential-access | 3139 |
| T1566.001 | Spearphishing Attachment | initial-access | 2789 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 2529 |
| T1113 | Screen Capture | collection | 2507 |
| T1566 | Phishing | initial-access | 1843 |
| T1566.002 | Spearphishing Link | initial-access | 1843 |
| T1555 | Credentials from Password Stores | credential-access | 1665 |
| T1567 | Exfiltration Over Web Service | exfiltration | 1602 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1434 |
| T1090 | Proxy | command-and-control | 1288 |
| T1059.001 | PowerShell | execution | 1261 |
| T1552.001 | Credentials In Files | credential-access | 1240 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 171 |
| T1059.005 | Visual Basic | execution | 61 |
| T1189 | Drive-by Compromise | initial-access | 19 |
| T1218 | System Binary Proxy Execution | defense-evasion | 19 |
| T1021.001 | Remote Desktop Protocol | lateral-movement | 8 |
| T1486 | Data Encrypted for Impact | impact | 8 |
| T1490 | Inhibit System Recovery | impact | 8 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 8 |
| T1003 | OS Credential Dumping | credential-access | 1 |
| T1190 | Exploit Public-Facing Application | initial-access | 1 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`b54bc89673ab79915e3170e804009bb5a725e34510ce62f836614a339ee04f12`](https://www.virustotal.com/gui/file/b54bc89673ab79915e3170e804009bb5a725e34510ce62f836614a339ee04f12) | sha256 | Mirai | threatfox, malwarebazaar | 2026-10-08T13:40:09Z | 100 |
| [`80c21e15e56b4a956a48ab5826a9e389a8aeadc8e42fc7713739a4603e14bdf4`](https://www.virustotal.com/gui/file/80c21e15e56b4a956a48ab5826a9e389a8aeadc8e42fc7713739a4603e14bdf4) | sha256 | Mirai | threatfox, malwarebazaar | 2026-10-08T13:40:08Z | 100 |
| [`e97d800f769284cea76fef951df360a5be60f820a8a5af4a77447b441ee8620e`](https://www.virustotal.com/gui/file/e97d800f769284cea76fef951df360a5be60f820a8a5af4a77447b441ee8620e) | sha256 | Mirai | threatfox, malwarebazaar | 2026-10-08T13:40:06Z | 100 |
| [`8b350483d5b80efb837549355015c9279fda8278525b248dab7af1229e202454`](https://www.virustotal.com/gui/file/8b350483d5b80efb837549355015c9279fda8278525b248dab7af1229e202454) | sha256 | Mirai | threatfox, malwarebazaar | 2026-10-08T13:40:05Z | 100 |
| [`7e47c19f82d8a932da2ec9bd42d7b815a05bf4be9ae0e512544fdbfce5f930b8`](https://www.virustotal.com/gui/file/7e47c19f82d8a932da2ec9bd42d7b815a05bf4be9ae0e512544fdbfce5f930b8) | sha256 | Mirai | threatfox, malwarebazaar | 2026-10-08T13:40:04Z | 100 |
| [`cf4c6ac09be225112faaef95316a137eff30e91c0f5f8e7aaf0a4bcc6c76f477`](https://www.virustotal.com/gui/file/cf4c6ac09be225112faaef95316a137eff30e91c0f5f8e7aaf0a4bcc6c76f477) | sha256 | Kinsing | threatfox, malwarebazaar | 2026-10-08T13:40:02Z | 100 |
| [`4760e85cd7d66a6261cad0abb32d1cf5b8c574f02459e873d75018ccc9fdf24a`](https://www.virustotal.com/gui/file/4760e85cd7d66a6261cad0abb32d1cf5b8c574f02459e873d75018ccc9fdf24a) | sha256 | Mirai | threatfox, malwarebazaar | 2026-10-08T13:40:01Z | 100 |
| [`content[.]dlcore[.]cc`](https://www.virustotal.com/gui/domain/content.dlcore.cc) | domain | ACR Stealer | threatfox | 2026-10-08T13:15:29Z | 100 |
| [`120[.]76[.]143[.]184`](https://www.virustotal.com/gui/ip-address/120.76.143.184) | ipv4 | Cobalt Strike | threatfox | 2026-10-08T13:05:05Z | 100 |
| [`1c6pukow[.]sadis[.]store`](https://www.virustotal.com/gui/domain/1c6pukow.sadis.store) | domain | ClearFake | threatfox | 2026-10-08T12:43:36Z | 100 |
| [`hxxps://cdn[.]jsdelivr[.]net/gh/fjghds8576/defc5c6-f955-4bfe-beeb-0bb43404d004/ae33-a96d32`](https://www.virustotal.com/gui/search/https%3A%2F%2Fcdn.jsdelivr.net%2Fgh%2Ffjghds8576%2Fdefc5c6-f955-4bfe-beeb-0bb43404d004%2Fae33-a96d32) | url | ClearFake | threatfox | 2026-10-08T12:35:41Z | 100 |
| [`0to3v0ri[.]morib[.]store`](https://www.virustotal.com/gui/domain/0to3v0ri.morib.store) | domain | ClearFake | threatfox | 2026-10-08T12:26:24Z | 100 |
| [`hxxps://cdn[.]jsdelivr[.]net/gh/039cdcd43ebc/747f0c42-25b7-41a5-94b0-08b287e8231f/3fe-c4e74967a7a9`](https://www.virustotal.com/gui/search/https%3A%2F%2Fcdn.jsdelivr.net%2Fgh%2F039cdcd43ebc%2F747f0c42-25b7-41a5-94b0-08b287e8231f%2F3fe-c4e74967a7a9) | url | ClearFake | threatfox | 2026-10-08T12:21:50Z | 100 |
| [`hxxps://tb[.]333vip[.]org/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ftb.333vip.org%2F) | url | Vidar | threatfox | 2026-10-08T11:55:49Z | 100 |
| [`tb[.]3toto[.]com`](https://www.virustotal.com/gui/domain/tb.3toto.com) | domain | Vidar | threatfox | 2026-10-08T11:55:48Z | 100 |
| [`hxxps://tb[.]3toto[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ftb.3toto.com%2F) | url | Vidar | threatfox | 2026-10-08T11:55:48Z | 100 |
| [`tb[.]333vip[.]org`](https://www.virustotal.com/gui/domain/tb.333vip.org) | domain | Vidar | threatfox | 2026-10-08T11:55:48Z | 100 |
| [`45[.]156[.]87[.]230`](https://www.virustotal.com/gui/ip-address/45.156.87.230) | ipv4 | Aisuru | threatfox | 2026-10-08T11:47:15Z | 100 |
| [`f73b74f41b4c98d6a7acfdaecfdf82253c8437270fb74c8588e8c49983b667b7`](https://www.virustotal.com/gui/file/f73b74f41b4c98d6a7acfdaecfdf82253c8437270fb74c8588e8c49983b667b7) | sha256 | AMOS | threatfox | 2026-10-08T11:41:04Z | 100 |
| [`b5d0ed395d85559af488341a32f7337996abd0e9f6cf557ba2531f5f717172e1`](https://www.virustotal.com/gui/file/b5d0ed395d85559af488341a32f7337996abd0e9f6cf557ba2531f5f717172e1) | sha256 | Unknown malware | threatfox, malwarebazaar | 2026-10-08T11:28:19Z | 100 |
| [`a7de1484a6be2e1c918268eb2f794f383b357ef3d663aa46b0bf47ccf8cf3371`](https://www.virustotal.com/gui/file/a7de1484a6be2e1c918268eb2f794f383b357ef3d663aa46b0bf47ccf8cf3371) | sha256 | Unknown malware | threatfox, malwarebazaar | 2026-10-08T11:28:19Z | 100 |
| [`8e707060ba2def8a9b6865ed9429789dbd84ba4b6058f0dd5aefe462989fe4b8`](https://www.virustotal.com/gui/file/8e707060ba2def8a9b6865ed9429789dbd84ba4b6058f0dd5aefe462989fe4b8) | sha256 | Unknown malware | threatfox, malwarebazaar | 2026-10-08T11:28:19Z | 100 |
| [`f19b0fd9c9f768b0859754a8ff5edfbb6f73793f0006309d4be6feb55bd6a2fd`](https://www.virustotal.com/gui/file/f19b0fd9c9f768b0859754a8ff5edfbb6f73793f0006309d4be6feb55bd6a2fd) | sha256 | Unknown malware | threatfox, malwarebazaar | 2026-10-08T11:28:19Z | 100 |
| [`45[.]125[.]66[.]100`](https://www.virustotal.com/gui/ip-address/45.125.66.100) | ipv4 | Unknown malware | threatfox | 2026-10-08T11:28:19Z | 100 |
| [`95[.]211[.]44[.]207`](https://www.virustotal.com/gui/ip-address/95.211.44.207) | ipv4 | Remcos | threatfox | 2026-10-08T10:45:56Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
