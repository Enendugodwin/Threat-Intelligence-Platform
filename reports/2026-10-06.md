# Threat Intel Pulse — 2026-10-06

**Window:** last 7 days · **Generated:** 2026-10-06T19:37:53Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 40405 |
| New in window | 40405 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5001 | ok |
| feodo | 5 | ok |
| threatfox | 9396 | ok |
| malwarebazaar | 1538 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8619 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 12029 | 12029 |
| ipv4 | 9030 | 9030 |
| sha256 | 8180 | 8180 |
| domain | 7845 | 7845 |
| ipv6 | 2841 | 2841 |
| md5 | 252 | 252 |
| sha1 | 228 | 228 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 9295 |
| Exit nodes | 2161 |
| Other relays | 7134 |
| New in window | 9295 |

Sample (20 of 9295, source: Tor Project Onionoo):
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
| Unknown Loader | 4093 | 4093 | — |
| Mirai | 3304 | 3304 | T1498, T1071.001 |
| AsyncRAT | 2174 | 2174 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| Cobalt Strike | 1236 | 1236 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| ClearFake | 1003 | 1003 | — |
| IClickFix | 730 | 730 | — |
| Unknown malware | 546 | 546 | — |
| PureRAT | 340 | 340 | — |
| Vidar | 255 | 255 | T1555, T1071.001, T1567 |
| AdaptixC2 | 251 | 251 | — |
| Unknown Stealer | 186 | 186 | — |
| Unknown RAT | 167 | 167 | — |
| AMOS | 145 | 145 | — |
| Remcos | 133 | 133 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| VShell | 111 | 111 | — |
| Remus | 103 | 103 | — |
| php.shin_webshell | 103 | 103 | — |
| DCRat | 98 | 98 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| Evilginx | 93 | 93 | — |
| Havoc | 88 | 88 | — |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1105 | Ingress Tool Transfer | command-and-control | 12357 |
| T1071.001 | Web Protocols | command-and-control | 29337 |
| T1498 | Network Denial of Service | impact | 7173 |
| T1204.002 | Malicious File | execution | 5456 |
| T1027 | Obfuscated Files or Information | defense-evasion | 5445 |
| T1573 | Encrypted Channel | command-and-control | 4625 |
| T1056.001 | Keylogging | collection, credential-access | 3034 |
| T1566.001 | Spearphishing Attachment | initial-access | 2721 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 2481 |
| T1113 | Screen Capture | collection | 2459 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1416 |
| T1090 | Proxy | command-and-control | 1274 |
| T1059.001 | PowerShell | execution | 1248 |
| T1566 | Phishing | initial-access | 1027 |
| T1566.002 | Spearphishing Link | initial-access | 1027 |
| T1555 | Credentials from Password Stores | credential-access | 839 |
| T1567 | Exfiltration Over Web Service | exfiltration | 776 |
| T1552.001 | Credentials In Files | credential-access | 508 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 162 |
| T1059.005 | Visual Basic | execution | 59 |
| T1189 | Drive-by Compromise | initial-access | 17 |
| T1218 | System Binary Proxy Execution | defense-evasion | 17 |
| T1021.001 | Remote Desktop Protocol | lateral-movement | 5 |
| T1486 | Data Encrypted for Impact | impact | 5 |
| T1490 | Inhibit System Recovery | impact | 5 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 5 |
| T1003 | OS Credential Dumping | credential-access | 1 |
| T1190 | Exploit Public-Facing Application | initial-access | 1 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`114[.]66[.]20[.]236`](https://www.virustotal.com/gui/ip-address/114.66.20.236) | ipv4 | Quasar RAT | threatfox | 2026-10-06T19:05:05Z | 100 |
| [`up[.]3toto[.]com`](https://www.virustotal.com/gui/domain/up.3toto.com) | domain | Vidar | threatfox | 2026-10-06T18:20:48Z | 100 |
| [`hxxps://up[.]3toto[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fup.3toto.com%2F) | url | Vidar | threatfox | 2026-10-06T18:20:48Z | 100 |
| [`up[.]333vip[.]org`](https://www.virustotal.com/gui/domain/up.333vip.org) | domain | Vidar | threatfox | 2026-10-06T17:05:48Z | 100 |
| [`hxxps://up[.]333vip[.]org/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fup.333vip.org%2F) | url | Vidar | threatfox | 2026-10-06T17:05:48Z | 100 |
| [`89[.]32[.]41[.]19`](https://www.virustotal.com/gui/ip-address/89.32.41.19) | ipv4 | Potassium | threatfox | 2026-10-06T16:57:12Z | 100 |
| [`04ue33gt[.]truenarrator[.]com`](https://www.virustotal.com/gui/domain/04ue33gt.truenarrator.com) | domain | ClearFake | threatfox | 2026-10-06T16:52:25Z | 100 |
| [`hxxps://hi[.]3toto[.]com`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhi.3toto.com) | url | Vidar | threatfox | 2026-10-06T16:18:33Z | 100 |
| [`getsupportonlinenow[.]com`](https://www.virustotal.com/gui/domain/getsupportonlinenow.com) | domain | Unknown RAT | threatfox | 2026-10-06T16:18:31Z | 100 |
| [`43[.]228[.]157[.]72`](https://www.virustotal.com/gui/ip-address/43.228.157.72) | ipv4 | Remcos | threatfox | 2026-10-06T16:18:30Z | 100 |
| [`89[.]32[.]41[.]49`](https://www.virustotal.com/gui/ip-address/89.32.41.49) | ipv4 | Potassium | threatfox | 2026-10-06T16:03:36Z | 100 |
| [`0nna1vpc[.]sallysprattstudio[.]com`](https://www.virustotal.com/gui/domain/0nna1vpc.sallysprattstudio.com) | domain | ClearFake | threatfox | 2026-10-06T15:39:28Z | 100 |
| [`s5goru1r[.]kobet[.]store`](https://www.virustotal.com/gui/domain/s5goru1r.kobet.store) | domain | ClearFake | threatfox | 2026-10-06T15:22:12Z | 100 |
| [`hxxps://hi[.]333vip[.]org`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhi.333vip.org) | url | Vidar | threatfox | 2026-10-06T15:21:44Z | 100 |
| [`102[.]220[.]163[.]130`](https://www.virustotal.com/gui/ip-address/102.220.163.130) | ipv4 | Remcos | threatfox | 2026-10-06T15:21:43Z | 100 |
| [`91[.]92[.]242[.]19`](https://www.virustotal.com/gui/ip-address/91.92.242.19) | ipv4 | Potassium | threatfox | 2026-10-06T15:17:46Z | 100 |
| [`155[.]2[.]192[.]88`](https://www.virustotal.com/gui/ip-address/155.2.192.88) | ipv4 | Potassium | threatfox | 2026-10-06T15:00:19Z | 100 |
| [`51[.]89[.]199[.]102`](https://www.virustotal.com/gui/ip-address/51.89.199.102) | ipv4 | Potassium | threatfox | 2026-10-06T15:00:18Z | 100 |
| [`70185ccd2aca8d2232164abe51699c4698bed86c551c9edf284063b5791c054e`](https://www.virustotal.com/gui/file/70185ccd2aca8d2232164abe51699c4698bed86c551c9edf284063b5791c054e) | sha256 | AMOS | threatfox | 2026-10-06T15:00:18Z | 100 |
| [`a4f5bec5e206631a718b88e16f1a5fa3ebd0ad55955fd30001c29e42b601beeb`](https://www.virustotal.com/gui/file/a4f5bec5e206631a718b88e16f1a5fa3ebd0ad55955fd30001c29e42b601beeb) | sha256 | Unknown RAT | malwarebazaar, threatfox | 2026-10-06T14:30:50Z | 100 |
| [`2d8fb6368c33ba76766834ab0737e9e830d8413ece0e7568a93fa3f894cd7ef9`](https://www.virustotal.com/gui/file/2d8fb6368c33ba76766834ab0737e9e830d8413ece0e7568a93fa3f894cd7ef9) | sha256 | Unknown RAT | threatfox | 2026-10-06T14:30:50Z | 100 |
| [`ff1d48aeeda856e3b2f6aac842dc393e1156e1d5f783b1e7f812b3b0d5eb2986`](https://www.virustotal.com/gui/file/ff1d48aeeda856e3b2f6aac842dc393e1156e1d5f783b1e7f812b3b0d5eb2986) | sha256 | Unknown RAT | threatfox | 2026-10-06T14:30:49Z | 100 |
| [`c7ef30d2fbc1fad85c9e14c200b9328b7be55b83ab2080e8dd7e25be76abb2dc`](https://www.virustotal.com/gui/file/c7ef30d2fbc1fad85c9e14c200b9328b7be55b83ab2080e8dd7e25be76abb2dc) | sha256 | Unknown RAT | threatfox | 2026-10-06T14:30:49Z | 100 |
| [`5c1bf506401bda993ceedaf28b90ebff6d6beb92f33b9b975c21fc85b1be2614`](https://www.virustotal.com/gui/file/5c1bf506401bda993ceedaf28b90ebff6d6beb92f33b9b975c21fc85b1be2614) | sha256 | Unknown RAT | threatfox | 2026-10-06T14:30:49Z | 100 |
| [`debdc34170bd40bf2e18611eeb4605f99bd146b88c694cb1d7cf751976ead49e`](https://www.virustotal.com/gui/file/debdc34170bd40bf2e18611eeb4605f99bd146b88c694cb1d7cf751976ead49e) | sha256 | Unknown RAT | threatfox | 2026-10-06T14:30:48Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
