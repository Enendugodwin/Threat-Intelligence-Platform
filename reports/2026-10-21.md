# Threat Intel Pulse — 2026-10-21

**Window:** last 7 days · **Generated:** 2026-10-21T05:02:15Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 84985 |
| New in window | 23951 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5000 | ok |
| feodo | 5 | ok |
| threatfox | 7127 | ok |
| malwarebazaar | 1639 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8707 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 35070 | 12180 |
| sha256 | 17562 | 5767 |
| domain | 14160 | 3095 |
| ipv4 | 12954 | 1924 |
| ipv6 | 3307 | 296 |
| md5 | 979 | 345 |
| sha1 | 953 | 344 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 11500 |
| Exit nodes | 2428 |
| Other relays | 9072 |
| New in window | 1209 |

Sample (20 of 11500, source: Tor Project Onionoo):
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
| Vidar | 6057 | 4122 | T1555, T1071.001, T1567 |
| Unknown Loader | 5490 | 607 | — |
| Mirai | 5457 | 1197 | T1498, T1071.001 |
| AsyncRAT | 2334 | 73 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| IClickFix | 2186 | 864 | — |
| ClearFake | 2082 | 274 | — |
| Unknown malware | 1846 | 853 | — |
| Cobalt Strike | 1369 | 55 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| AMOS | 1067 | 766 | — |
| VShell | 962 | 616 | — |
| php.shin_webshell | 732 | 290 | — |
| Unknown Stealer | 662 | 37 | — |
| PureRAT | 458 | 54 | — |
| Remus | 437 | 262 | — |
| Sliver | 382 | 98 | T1071.001, T1573, T1090, T1055 |
| Remcos | 379 | 156 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| AdaptixC2 | 306 | 26 | — |
| MacSync | 257 | 252 | — |
| Unknown RAT | 229 | 32 | — |
| Formbook | 224 | 89 | T1566.001, T1056.001, T1555, T1071.001, T1567 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1071.001 | Web Protocols | command-and-control | 52947 |
| T1105 | Ingress Tool Transfer | command-and-control | 25366 |
| T1498 | Network Denial of Service | impact | 13070 |
| T1555 | Credentials from Password Stores | credential-access | 10125 |
| T1567 | Exfiltration Over Web Service | exfiltration | 9929 |
| T1204.002 | Malicious File | execution | 9714 |
| T1027 | Obfuscated Files or Information | defense-evasion | 9552 |
| T1573 | Encrypted Channel | command-and-control | 9329 |
| T1566 | Phishing | initial-access | 8129 |
| T1566.002 | Spearphishing Link | initial-access | 8129 |
| T1552.001 | Credentials In Files | credential-access | 5859 |
| T1056.001 | Keylogging | collection, credential-access | 4144 |
| T1566.001 | Spearphishing Attachment | initial-access | 3768 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 3112 |
| T1113 | Screen Capture | collection | 3048 |
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
| [`a68c66b3945a66e75877accfc954b18f4323ac4e4cf027418449470c0af78b76`](https://www.virustotal.com/gui/file/a68c66b3945a66e75877accfc954b18f4323ac4e4cf027418449470c0af78b76) | sha256 | Mirai | threatfox, malwarebazaar | 2026-10-21T04:54:31Z | 100 |
| [`hxxps://yb[.]abblbet[.]org/ij/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fyb.abblbet.org%2Fij%2F) | url | Vidar | threatfox | 2026-10-21T04:50:48Z | 100 |
| [`b5052707fbecd8647b4f13026df1b0cb8b54b7e652d517d14aa418e9c241b7d7`](https://www.virustotal.com/gui/file/b5052707fbecd8647b4f13026df1b0cb8b54b7e652d517d14aa418e9c241b7d7) | sha256 | AMOS | threatfox | 2026-10-21T04:46:33Z | 100 |
| [`hxxps://yb[.]abblbet[.]org/jm/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fyb.abblbet.org%2Fjm%2F) | url | Vidar | threatfox | 2026-10-21T04:45:48Z | 100 |
| [`c66da66fee552460de019b65b0824e4015bca4344d3df307592754a359a430e0`](https://www.virustotal.com/gui/file/c66da66fee552460de019b65b0824e4015bca4344d3df307592754a359a430e0) | sha256 | AMOS | threatfox | 2026-10-21T04:45:15Z | 100 |
| [`efd5fbce12a6b9c66b1154ee667303d379541b0eb19c44c2864067fe8648d28f`](https://www.virustotal.com/gui/file/efd5fbce12a6b9c66b1154ee667303d379541b0eb19c44c2864067fe8648d28f) | sha256 | AMOS | threatfox | 2026-10-21T04:42:29Z | 100 |
| [`hxxps://yb[.]abblbet[.]org/qx/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fyb.abblbet.org%2Fqx%2F) | url | Vidar | threatfox | 2026-10-21T04:40:48Z | 100 |
| [`05e7782e6f1b3f0c951138a44b7cf15e041e4d9b794e08daa8b4be86399a55b4`](https://www.virustotal.com/gui/file/05e7782e6f1b3f0c951138a44b7cf15e041e4d9b794e08daa8b4be86399a55b4) | sha256 | AMOS | threatfox | 2026-10-21T04:38:52Z | 100 |
| [`hxxps://yb[.]abblbet[.]org/vb/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fyb.abblbet.org%2Fvb%2F) | url | Vidar | threatfox | 2026-10-21T04:35:48Z | 100 |
| [`akhfbttn[.]blinderai[.]com`](https://www.virustotal.com/gui/domain/akhfbttn.blinderai.com) | domain | ClearFake | threatfox | 2026-10-21T04:35:18Z | 100 |
| [`d48b8fa62a2b19eebca276c84ecaa8858379ce810702372535483bb6fe9f1116`](https://www.virustotal.com/gui/file/d48b8fa62a2b19eebca276c84ecaa8858379ce810702372535483bb6fe9f1116) | sha256 | AMOS | threatfox | 2026-10-21T04:34:46Z | 100 |
| [`e990ec0eb21c1cfc1d53e7e43ae2e912cedc3d6ce3d0ac8bc442cc1783d4fa4b`](https://www.virustotal.com/gui/file/e990ec0eb21c1cfc1d53e7e43ae2e912cedc3d6ce3d0ac8bc442cc1783d4fa4b) | sha256 | AMOS | threatfox | 2026-10-21T04:31:44Z | 100 |
| [`hxxps://c[.]9winn[.]org/g/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fc.9winn.org%2Fg%2F) | url | Vidar | threatfox | 2026-10-21T04:30:48Z | 100 |
| [`hxxps://yb[.]abblbet[.]org/lo/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fyb.abblbet.org%2Flo%2F) | url | Vidar | threatfox | 2026-10-21T04:30:48Z | 100 |
| [`c5bd449668102c0e01da1394d924d61e71b8e166a03c98b22d26c10cdf9b98ed`](https://www.virustotal.com/gui/file/c5bd449668102c0e01da1394d924d61e71b8e166a03c98b22d26c10cdf9b98ed) | sha256 | AMOS | threatfox | 2026-10-21T04:28:22Z | 100 |
| [`hxxps://yb[.]abblbet[.]org/o5/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fyb.abblbet.org%2Fo5%2F) | url | Vidar | threatfox | 2026-10-21T04:25:48Z | 100 |
| [`8c503247e0851e81980e1205ad7578b2b39a0d87c6acefb8d2b876206f71d68b`](https://www.virustotal.com/gui/file/8c503247e0851e81980e1205ad7578b2b39a0d87c6acefb8d2b876206f71d68b) | sha256 | AMOS | threatfox | 2026-10-21T04:24:27Z | 100 |
| [`d9a13c77484e0f62d7db9f224bc87acaa0bb8a8bbccbaaaf96738a9b8f022ecb`](https://www.virustotal.com/gui/file/d9a13c77484e0f62d7db9f224bc87acaa0bb8a8bbccbaaaf96738a9b8f022ecb) | sha256 | AMOS | threatfox | 2026-10-21T04:20:52Z | 100 |
| [`c[.]9winn[.]org`](https://www.virustotal.com/gui/domain/c.9winn.org) | domain | Vidar | threatfox | 2026-10-21T04:20:48Z | 100 |
| [`hxxps://c[.]9winn[.]org/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fc.9winn.org%2F) | url | Vidar | threatfox | 2026-10-21T04:20:48Z | 100 |
| [`hxxps://yb[.]abblbet[.]org/kyr/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fyb.abblbet.org%2Fkyr%2F) | url | Vidar | threatfox | 2026-10-21T04:20:48Z | 100 |
| [`612b706f54d148111f20e393792fda57f73590b6bc6865a4e49656e670f9eefd`](https://www.virustotal.com/gui/file/612b706f54d148111f20e393792fda57f73590b6bc6865a4e49656e670f9eefd) | sha256 | AMOS | threatfox | 2026-10-21T04:16:20Z | 100 |
| [`hxxps://yb[.]abblbet[.]org/nc/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fyb.abblbet.org%2Fnc%2F) | url | Vidar | threatfox | 2026-10-21T04:15:48Z | 100 |
| [`hxxps://yb[.]abblbet[.]org/wb/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fyb.abblbet.org%2Fwb%2F) | url | Vidar | threatfox | 2026-10-21T04:10:48Z | 100 |
| [`hxxps://yb[.]abblbet[.]org/hq0/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fyb.abblbet.org%2Fhq0%2F) | url | Vidar | threatfox | 2026-10-21T04:05:47Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
