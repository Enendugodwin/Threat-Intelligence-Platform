# Threat Intel Pulse — 2026-10-20

**Window:** last 7 days · **Generated:** 2026-10-20T21:44:30Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 83936 |
| New in window | 24328 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5000 | ok |
| feodo | 5 | ok |
| threatfox | 6866 | ok |
| malwarebazaar | 1437 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8690 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 34580 | 12316 |
| sha256 | 17201 | 5625 |
| domain | 14034 | 3363 |
| ipv4 | 12883 | 1905 |
| ipv6 | 3306 | 306 |
| md5 | 979 | 407 |
| sha1 | 953 | 406 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 11461 |
| Exit nodes | 2427 |
| Other relays | 9034 |
| New in window | 1203 |

Sample (20 of 11461, source: Tor Project Onionoo):
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
| Vidar | 5931 | 4371 | T1555, T1071.001, T1567 |
| Unknown Loader | 5457 | 857 | — |
| Mirai | 5414 | 1230 | T1498, T1071.001 |
| AsyncRAT | 2334 | 79 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| IClickFix | 2107 | 789 | — |
| ClearFake | 2075 | 349 | — |
| Unknown malware | 1841 | 866 | — |
| Cobalt Strike | 1369 | 56 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| AMOS | 999 | 709 | — |
| VShell | 937 | 591 | — |
| php.shin_webshell | 715 | 284 | — |
| Unknown Stealer | 662 | 88 | — |
| PureRAT | 458 | 59 | — |
| Remus | 426 | 253 | — |
| Sliver | 382 | 100 | T1071.001, T1573, T1090, T1055 |
| Remcos | 373 | 155 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| AdaptixC2 | 306 | 29 | — |
| MacSync | 257 | 252 | — |
| Unknown RAT | 229 | 37 | — |
| Formbook | 224 | 96 | T1566.001, T1056.001, T1555, T1071.001, T1567 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1071.001 | Web Protocols | command-and-control | 52526 |
| T1105 | Ingress Tool Transfer | command-and-control | 25280 |
| T1498 | Network Denial of Service | impact | 12981 |
| T1555 | Credentials from Password Stores | credential-access | 9930 |
| T1567 | Exfiltration Over Web Service | exfiltration | 9734 |
| T1204.002 | Malicious File | execution | 9680 |
| T1027 | Obfuscated Files or Information | defense-evasion | 9518 |
| T1573 | Encrypted Channel | command-and-control | 9292 |
| T1566 | Phishing | initial-access | 7829 |
| T1566.002 | Spearphishing Link | initial-access | 7829 |
| T1552.001 | Credentials In Files | credential-access | 5772 |
| T1056.001 | Keylogging | collection, credential-access | 4135 |
| T1566.001 | Spearphishing Attachment | initial-access | 3760 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 3104 |
| T1113 | Screen Capture | collection | 3040 |
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
| [`hxxps://q[.]9winn[.]org/d`](https://www.virustotal.com/gui/search/https%3A%2F%2Fq.9winn.org%2Fd) | url | Vidar | threatfox | 2026-10-20T21:39:48Z | 100 |
| [`d2bbbd9a8aa85ca603c52867e04c4f910466c0764d4a27d6bb338316860de0d1`](https://www.virustotal.com/gui/file/d2bbbd9a8aa85ca603c52867e04c4f910466c0764d4a27d6bb338316860de0d1) | sha256 | AMOS | threatfox | 2026-10-20T21:39:01Z | 100 |
| [`hxxps://s7[.]abbc123[.]org/bas/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fs7.abbc123.org%2Fbas%2F) | url | Vidar | threatfox | 2026-10-20T21:35:48Z | 100 |
| [`19459527965033538912c33d6d83f90502b807b8374c2ce08d929f07821bd214`](https://www.virustotal.com/gui/file/19459527965033538912c33d6d83f90502b807b8374c2ce08d929f07821bd214) | sha256 | AMOS | threatfox | 2026-10-20T21:35:21Z | 100 |
| [`558b6752b1d1afffac1f20c970ffb1148eb860e9d92be2221354238b0755f9da`](https://www.virustotal.com/gui/file/558b6752b1d1afffac1f20c970ffb1148eb860e9d92be2221354238b0755f9da) | sha256 | AMOS | threatfox | 2026-10-20T21:32:22Z | 100 |
| [`hxxp://slink4u[.]click:9692/files`](https://www.virustotal.com/gui/search/http%3A%2F%2Fslink4u.click%3A9692%2Ffiles) | url | Remus | threatfox | 2026-10-20T21:31:55Z | 100 |
| [`hxxps://s7[.]abbc123[.]org/t3q/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fs7.abbc123.org%2Ft3q%2F) | url | Vidar | threatfox | 2026-10-20T21:30:48Z | 100 |
| [`64d36fbccffa093c8975265608b7fc21036edd05d0185e27f37b373499169ee4`](https://www.virustotal.com/gui/file/64d36fbccffa093c8975265608b7fc21036edd05d0185e27f37b373499169ee4) | sha256 | AMOS | threatfox | 2026-10-20T21:28:56Z | 100 |
| [`hxxps://i1[.]abbastoto[.]org/mk`](https://www.virustotal.com/gui/search/https%3A%2F%2Fi1.abbastoto.org%2Fmk) | url | Vidar | threatfox | 2026-10-20T21:26:21Z | 100 |
| [`hxxps://s7[.]abbc123[.]org/fj/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fs7.abbc123.org%2Ffj%2F) | url | Vidar | threatfox | 2026-10-20T21:25:48Z | 100 |
| [`hxxp://darcy19[.]my:8312/imports`](https://www.virustotal.com/gui/search/http%3A%2F%2Fdarcy19.my%3A8312%2Fimports) | url | Remus | threatfox | 2026-10-20T21:25:39Z | 100 |
| [`302e2722d8f679e32e7760e922ae46b887a769ed4975283946308a701f5e6748`](https://www.virustotal.com/gui/file/302e2722d8f679e32e7760e922ae46b887a769ed4975283946308a701f5e6748) | sha256 | AMOS | threatfox | 2026-10-20T21:24:50Z | 100 |
| [`1c45e83f214fc193d3c643fdd08bac440e1c25cec08f5e9abb0b113390a8afb2`](https://www.virustotal.com/gui/file/1c45e83f214fc193d3c643fdd08bac440e1c25cec08f5e9abb0b113390a8afb2) | sha256 | AMOS | threatfox | 2026-10-20T21:22:21Z | 100 |
| [`hxxp://tool01[.]art:7713/transactions`](https://www.virustotal.com/gui/search/http%3A%2F%2Ftool01.art%3A7713%2Ftransactions) | url | Remus | threatfox | 2026-10-20T21:21:37Z | 100 |
| [`hxxp://netulse[.]sbs:5621/articles`](https://www.virustotal.com/gui/search/http%3A%2F%2Fnetulse.sbs%3A5621%2Farticles) | url | Remus | threatfox | 2026-10-20T21:21:07Z | 100 |
| [`hxxps://s7[.]abbc123[.]org/ri/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fs7.abbc123.org%2Fri%2F) | url | Vidar | threatfox | 2026-10-20T21:20:48Z | 100 |
| [`9c3551bc157cb2a038915ba6708b8a41e7188c6ff96cb120d5fcd8218b160ea5`](https://www.virustotal.com/gui/file/9c3551bc157cb2a038915ba6708b8a41e7188c6ff96cb120d5fcd8218b160ea5) | sha256 | AMOS | threatfox | 2026-10-20T21:19:25Z | 100 |
| [`hxxp://tool01[.]art:7713/comments`](https://www.virustotal.com/gui/search/http%3A%2F%2Ftool01.art%3A7713%2Fcomments) | url | Remus | threatfox | 2026-10-20T21:17:24Z | 100 |
| [`hxxp://retas3[.]help:7713/reviews`](https://www.virustotal.com/gui/search/http%3A%2F%2Fretas3.help%3A7713%2Freviews) | url | Remus | threatfox | 2026-10-20T21:16:52Z | 100 |
| [`hxxp://retas3[.]help:7713/exports`](https://www.virustotal.com/gui/search/http%3A%2F%2Fretas3.help%3A7713%2Fexports) | url | Remus | threatfox | 2026-10-20T21:16:43Z | 100 |
| [`hxxps://s7[.]abbc123[.]org/x3/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fs7.abbc123.org%2Fx3%2F) | url | Vidar | threatfox | 2026-10-20T21:15:48Z | 100 |
| [`hxxp://vydga2[.]xyz:5621/exports`](https://www.virustotal.com/gui/search/http%3A%2F%2Fvydga2.xyz%3A5621%2Fexports) | url | Remus | threatfox | 2026-10-20T21:14:19Z | 100 |
| [`hxxp://vydga2[.]xyz:5621/workspaces`](https://www.virustotal.com/gui/search/http%3A%2F%2Fvydga2.xyz%3A5621%2Fworkspaces) | url | Remus | threatfox | 2026-10-20T21:14:18Z | 100 |
| [`hxxp://finter28[.]help:5621/projects`](https://www.virustotal.com/gui/search/http%3A%2F%2Ffinter28.help%3A5621%2Fprojects) | url | Remus | threatfox | 2026-10-20T21:14:05Z | 100 |
| [`hxxp://tool01[.]art:7713/contacts`](https://www.virustotal.com/gui/search/http%3A%2F%2Ftool01.art%3A7713%2Fcontacts) | url | Remus | threatfox | 2026-10-20T21:12:40Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
