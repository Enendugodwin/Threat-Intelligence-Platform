# Threat Intel Pulse — 2026-10-20

**Window:** last 7 days · **Generated:** 2026-10-20T17:22:17Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 83601 |
| New in window | 23993 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5000 | ok |
| feodo | 5 | ok |
| threatfox | 6755 | ok |
| malwarebazaar | 1413 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8732 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 34430 | 12166 |
| sha256 | 17077 | 5501 |
| domain | 14015 | 3344 |
| ipv4 | 12845 | 1867 |
| ipv6 | 3302 | 302 |
| md5 | 979 | 407 |
| sha1 | 953 | 406 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 11443 |
| Exit nodes | 2426 |
| Other relays | 9017 |
| New in window | 1185 |

Sample (20 of 11443, source: Tor Project Onionoo):
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
| Vidar | 5854 | 4294 | T1555, T1071.001, T1567 |
| Unknown Loader | 5455 | 855 | — |
| Mirai | 5349 | 1191 | T1498, T1071.001 |
| AsyncRAT | 2334 | 79 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| IClickFix | 2107 | 789 | — |
| ClearFake | 2066 | 340 | — |
| Unknown malware | 1839 | 864 | — |
| Cobalt Strike | 1369 | 56 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| AMOS | 944 | 654 | — |
| VShell | 924 | 578 | — |
| php.shin_webshell | 710 | 279 | — |
| Unknown Stealer | 661 | 87 | — |
| PureRAT | 456 | 57 | — |
| Remus | 397 | 224 | — |
| Sliver | 382 | 100 | T1071.001, T1573, T1090, T1055 |
| Remcos | 370 | 152 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| AdaptixC2 | 304 | 27 | — |
| MacSync | 255 | 250 | — |
| Unknown RAT | 229 | 37 | — |
| Formbook | 224 | 96 | T1566.001, T1056.001, T1555, T1071.001, T1567 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1071.001 | Web Protocols | command-and-control | 52280 |
| T1105 | Ingress Tool Transfer | command-and-control | 25208 |
| T1498 | Network Denial of Service | impact | 12885 |
| T1555 | Credentials from Password Stores | credential-access | 9797 |
| T1204.002 | Malicious File | execution | 9648 |
| T1567 | Exfiltration Over Web Service | exfiltration | 9601 |
| T1027 | Obfuscated Files or Information | defense-evasion | 9486 |
| T1573 | Encrypted Channel | command-and-control | 9240 |
| T1566 | Phishing | initial-access | 7829 |
| T1566.002 | Spearphishing Link | initial-access | 7829 |
| T1552.001 | Credentials In Files | credential-access | 5701 |
| T1056.001 | Keylogging | collection, credential-access | 4129 |
| T1566.001 | Spearphishing Attachment | initial-access | 3756 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 3100 |
| T1113 | Screen Capture | collection | 3036 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 2022 |
| T1090 | Proxy | command-and-control | 1792 |
| T1059.001 | PowerShell | execution | 1383 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 397 |
| T1189 | Drive-by Compromise | initial-access | 179 |
| T1218 | System Binary Proxy Execution | defense-evasion | 179 |
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
| [`9ff5f3cbe9d011b755c7753b0b3a1b2f9c479089f443b8ff63d3270797da0928`](https://www.virustotal.com/gui/file/9ff5f3cbe9d011b755c7753b0b3a1b2f9c479089f443b8ff63d3270797da0928) | sha256 | AMOS | threatfox | 2026-10-20T17:15:57Z | 100 |
| [`hxxps://i1[.]abbastoto[.]org/et/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fi1.abbastoto.org%2Fet%2F) | url | Vidar | threatfox | 2026-10-20T17:15:48Z | 100 |
| [`hxxp://popeak[.]biz:8312/projects`](https://www.virustotal.com/gui/search/http%3A%2F%2Fpopeak.biz%3A8312%2Fprojects) | url | Remus | threatfox | 2026-10-20T17:15:16Z | 100 |
| [`128[.]90[.]102[.]120`](https://www.virustotal.com/gui/ip-address/128.90.102.120) | ipv4 | Remcos | threatfox | 2026-10-20T17:14:34Z | 100 |
| [`hxxp://finter28[.]help:5621/tokens`](https://www.virustotal.com/gui/search/http%3A%2F%2Ffinter28.help%3A5621%2Ftokens) | url | Remus | threatfox | 2026-10-20T17:13:44Z | 100 |
| [`c292ea73638bb2bcaea8d3f403993170517babe022ae638fe22d8c64c9564515`](https://www.virustotal.com/gui/file/c292ea73638bb2bcaea8d3f403993170517babe022ae638fe22d8c64c9564515) | sha256 | AMOS | threatfox | 2026-10-20T17:13:18Z | 100 |
| [`bf2e58e24d2708e25d437e91744ad358bed1e34dd5a57dd33d15b04ab68e6669`](https://www.virustotal.com/gui/file/bf2e58e24d2708e25d437e91744ad358bed1e34dd5a57dd33d15b04ab68e6669) | sha256 | AMOS | threatfox | 2026-10-20T17:10:50Z | 100 |
| [`hxxps://i1[.]abbastoto[.]org/l6/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fi1.abbastoto.org%2Fl6%2F) | url | Vidar | threatfox | 2026-10-20T17:10:48Z | 100 |
| [`hxxps://i1[.]abbastoto[.]org/zo/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fi1.abbastoto.org%2Fzo%2F) | url | Vidar | threatfox | 2026-10-20T17:05:48Z | 100 |
| [`hxxps://h[.]9winn[.]org/f`](https://www.virustotal.com/gui/search/https%3A%2F%2Fh.9winn.org%2Ff) | url | Vidar | threatfox | 2026-10-20T17:02:10Z | 100 |
| [`hxxp://catxlst[.]click:5890/collections`](https://www.virustotal.com/gui/search/http%3A%2F%2Fcatxlst.click%3A5890%2Fcollections) | url | Remus | threatfox | 2026-10-20T17:01:35Z | 100 |
| [`hxxps://h[.]9winn[.]org/f/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fh.9winn.org%2Ff%2F) | url | Vidar | threatfox | 2026-10-20T17:00:48Z | 100 |
| [`hxxps://e[.]abbastoto[.]org/rl/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fe.abbastoto.org%2Frl%2F) | url | Vidar | threatfox | 2026-10-20T17:00:48Z | 100 |
| [`hxxps://e[.]abbastoto[.]org/d1`](https://www.virustotal.com/gui/search/https%3A%2F%2Fe.abbastoto.org%2Fd1) | url | Vidar | threatfox | 2026-10-20T17:00:40Z | 100 |
| [`hxxp://tool01[.]art:7713/documents`](https://www.virustotal.com/gui/search/http%3A%2F%2Ftool01.art%3A7713%2Fdocuments) | url | Remus | threatfox | 2026-10-20T16:59:49Z | 100 |
| [`hxxp://darcy19[.]my:8312/projects`](https://www.virustotal.com/gui/search/http%3A%2F%2Fdarcy19.my%3A8312%2Fprojects) | url | Remus | threatfox | 2026-10-20T16:57:25Z | 100 |
| [`hxxps://e[.]abbastoto[.]org/vd/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fe.abbastoto.org%2Fvd%2F) | url | Vidar | threatfox | 2026-10-20T16:55:48Z | 100 |
| [`hxxps://w[.]abanda88[.]org/sk`](https://www.virustotal.com/gui/search/https%3A%2F%2Fw.abanda88.org%2Fsk) | url | Vidar | threatfox | 2026-10-20T16:55:41Z | 100 |
| [`e735ad29371082dcd485ebf095236a771e457b2f661fb8d7f7377a8e2b782d1c`](https://www.virustotal.com/gui/file/e735ad29371082dcd485ebf095236a771e457b2f661fb8d7f7377a8e2b782d1c) | sha256 | Mirai | threatfox | 2026-10-20T16:54:37Z | 100 |
| [`ff3d427dad17816af96bf163e840942b596cb534f0051d24161c9eb77d8382bc`](https://www.virustotal.com/gui/file/ff3d427dad17816af96bf163e840942b596cb534f0051d24161c9eb77d8382bc) | sha256 | Mirai | threatfox | 2026-10-20T16:54:36Z | 100 |
| [`00910dbf54bd447710f63b4e5309a676630d546c3b9f27b9ce7cd4271d163f69`](https://www.virustotal.com/gui/file/00910dbf54bd447710f63b4e5309a676630d546c3b9f27b9ce7cd4271d163f69) | sha256 | Mirai | threatfox | 2026-10-20T16:54:35Z | 100 |
| [`dcbcba0a0d2a7daa4caf7aa202362278dafacb6b38cab93f1d195ca6ff8f5205`](https://www.virustotal.com/gui/file/dcbcba0a0d2a7daa4caf7aa202362278dafacb6b38cab93f1d195ca6ff8f5205) | sha256 | Mirai | threatfox | 2026-10-20T16:54:34Z | 100 |
| [`c27fd566c8e1b0efa48b3f36ca5546f4bac3182f4c6706c39133aef39670868d`](https://www.virustotal.com/gui/file/c27fd566c8e1b0efa48b3f36ca5546f4bac3182f4c6706c39133aef39670868d) | sha256 | Mirai | threatfox | 2026-10-20T16:54:33Z | 100 |
| [`6aee7a332fde56bd9442f3d307dac29947f514ef8361ae6b5e52b843e905ee09`](https://www.virustotal.com/gui/file/6aee7a332fde56bd9442f3d307dac29947f514ef8361ae6b5e52b843e905ee09) | sha256 | Mirai | threatfox | 2026-10-20T16:54:31Z | 100 |
| [`c433957cc91e17664147cbbb9dabcee58a81747a4e4b3fdb233b6daedd8974ab`](https://www.virustotal.com/gui/file/c433957cc91e17664147cbbb9dabcee58a81747a4e4b3fdb233b6daedd8974ab) | sha256 | Mirai | threatfox | 2026-10-20T16:54:30Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
