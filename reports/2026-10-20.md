# Threat Intel Pulse — 2026-10-20

**Window:** last 7 days · **Generated:** 2026-10-20T05:02:12Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 81293 |
| New in window | 23389 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5001 | ok |
| feodo | 5 | ok |
| threatfox | 6663 | ok |
| malwarebazaar | 1303 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8724 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 33290 | 12159 |
| sha256 | 16491 | 5196 |
| domain | 13649 | 3080 |
| ipv4 | 12750 | 1945 |
| ipv6 | 3293 | 308 |
| md5 | 923 | 351 |
| sha1 | 897 | 350 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 11391 |
| Exit nodes | 2423 |
| Other relays | 8968 |
| New in window | 1219 |

Sample (20 of 11391, source: Tor Project Onionoo):
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
| Vidar | 5663 | 4655 | T1555, T1071.001, T1567 |
| Unknown Loader | 5434 | 845 | — |
| Mirai | 5143 | 1045 | T1498, T1071.001 |
| AsyncRAT | 2323 | 77 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| IClickFix | 2104 | 792 | — |
| ClearFake | 2046 | 336 | — |
| Unknown malware | 1619 | 655 | — |
| Cobalt Strike | 1365 | 58 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| VShell | 909 | 629 | — |
| AMOS | 867 | 591 | — |
| php.shin_webshell | 692 | 289 | — |
| Unknown Stealer | 641 | 74 | — |
| PureRAT | 455 | 58 | — |
| Sliver | 377 | 96 | T1071.001, T1573, T1090, T1055 |
| Remcos | 363 | 161 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| AdaptixC2 | 303 | 27 | — |
| Remus | 262 | 97 | — |
| Unknown RAT | 228 | 40 | — |
| Formbook | 206 | 82 | T1566.001, T1056.001, T1555, T1071.001, T1567 |
| DanaBot | 195 | 2 | T1566.001, T1071.001, T1555, T1041 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1071.001 | Web Protocols | command-and-control | 51063 |
| T1105 | Ingress Tool Transfer | command-and-control | 24607 |
| T1498 | Network Denial of Service | impact | 12526 |
| T1204.002 | Malicious File | execution | 9579 |
| T1027 | Obfuscated Files or Information | defense-evasion | 9417 |
| T1555 | Credentials from Password Stores | credential-access | 9275 |
| T1567 | Exfiltration Over Web Service | exfiltration | 9079 |
| T1573 | Encrypted Channel | command-and-control | 8994 |
| T1566 | Phishing | initial-access | 7580 |
| T1566.002 | Spearphishing Link | initial-access | 7580 |
| T1552.001 | Credentials In Files | credential-access | 5370 |
| T1056.001 | Keylogging | collection, credential-access | 4026 |
| T1566.001 | Spearphishing Attachment | initial-access | 3708 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 3072 |
| T1113 | Screen Capture | collection | 3010 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 2009 |
| T1090 | Proxy | command-and-control | 1780 |
| T1059.001 | PowerShell | execution | 1379 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 393 |
| T1189 | Drive-by Compromise | initial-access | 178 |
| T1218 | System Binary Proxy Execution | defense-evasion | 178 |
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
| [`a6a8f49be35200b6d8121dac963fd319bbf334c765b20a177f66ae118a77e975`](https://www.virustotal.com/gui/file/a6a8f49be35200b6d8121dac963fd319bbf334c765b20a177f66ae118a77e975) | sha256 | Mirai | threatfox, malwarebazaar | 2026-10-20T04:54:18Z | 100 |
| [`9d0c0819b915625b6c7bc2898cb5f1248df6ab941ce86447c059c4d6de5e0002`](https://www.virustotal.com/gui/file/9d0c0819b915625b6c7bc2898cb5f1248df6ab941ce86447c059c4d6de5e0002) | sha256 | AMOS | threatfox | 2026-10-20T04:51:48Z | 100 |
| [`1b317f7c91282bc41153d12a28a41a883eeb655c245e76f8c3142a8cc8458bb4`](https://www.virustotal.com/gui/file/1b317f7c91282bc41153d12a28a41a883eeb655c245e76f8c3142a8cc8458bb4) | sha256 | AMOS | threatfox | 2026-10-20T04:51:22Z | 100 |
| [`hxxps://htj[.]abanda88[.]org/i1/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhtj.abanda88.org%2Fi1%2F) | url | Vidar | threatfox | 2026-10-20T04:50:48Z | 100 |
| [`b7a942961139b0f25e83e2bc6ce0eea66e363d7cbe7a2d10b28c040b56eebe04`](https://www.virustotal.com/gui/file/b7a942961139b0f25e83e2bc6ce0eea66e363d7cbe7a2d10b28c040b56eebe04) | sha256 | AMOS | threatfox | 2026-10-20T04:50:39Z | 100 |
| [`1a68e1064373a2e4a1a62dd3522e485e8a97bb408496d4aa4f01d78f0224196e`](https://www.virustotal.com/gui/file/1a68e1064373a2e4a1a62dd3522e485e8a97bb408496d4aa4f01d78f0224196e) | sha256 | AMOS | threatfox | 2026-10-20T04:50:12Z | 100 |
| [`130f6c64c3d4f209700c7c35a032102c1deb6f425ac697f983ad169e425b7c48`](https://www.virustotal.com/gui/file/130f6c64c3d4f209700c7c35a032102c1deb6f425ac697f983ad169e425b7c48) | sha256 | AMOS | threatfox | 2026-10-20T04:47:56Z | 100 |
| [`hxxps://htj[.]abanda88[.]org/qo/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhtj.abanda88.org%2Fqo%2F) | url | Vidar | threatfox | 2026-10-20T04:45:48Z | 100 |
| [`a826a65769a7f599aad01f0d2022ab969733e04be9d1134face4cba818e730fa`](https://www.virustotal.com/gui/file/a826a65769a7f599aad01f0d2022ab969733e04be9d1134face4cba818e730fa) | sha256 | AMOS | threatfox | 2026-10-20T04:44:57Z | 100 |
| [`7220623e993c91a35f79f9f039426863c0cc0fb41bdca2168c7402dc549d3c8b`](https://www.virustotal.com/gui/file/7220623e993c91a35f79f9f039426863c0cc0fb41bdca2168c7402dc549d3c8b) | sha256 | AMOS | threatfox | 2026-10-20T04:42:37Z | 100 |
| [`hxxps://htj[.]abanda88[.]org/p9/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhtj.abanda88.org%2Fp9%2F) | url | Vidar | threatfox | 2026-10-20T04:40:48Z | 100 |
| [`10bccd03d04a7661292b56ae457e5f2e6e2e4f8b4c9f72ae2a60ce69e64f559c`](https://www.virustotal.com/gui/file/10bccd03d04a7661292b56ae457e5f2e6e2e4f8b4c9f72ae2a60ce69e64f559c) | sha256 | AMOS | threatfox | 2026-10-20T04:40:13Z | 100 |
| [`875b5653ffe2f1f3913a36de04ec3004f24561bcc94d0e450332bafef61a0a30`](https://www.virustotal.com/gui/file/875b5653ffe2f1f3913a36de04ec3004f24561bcc94d0e450332bafef61a0a30) | sha256 | AMOS | threatfox | 2026-10-20T04:36:51Z | 100 |
| [`hxxps://htj[.]abanda88[.]org/vw/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhtj.abanda88.org%2Fvw%2F) | url | Vidar | threatfox | 2026-10-20T04:35:48Z | 100 |
| [`206[.]123[.]152[.]197`](https://www.virustotal.com/gui/ip-address/206.123.152.197) | ipv4 | Remcos | threatfox | 2026-10-20T04:35:04Z | 100 |
| [`75e4994373a51dbfe5f22f0f071c05dbedd077d80aa6a0051374121780868707`](https://www.virustotal.com/gui/file/75e4994373a51dbfe5f22f0f071c05dbedd077d80aa6a0051374121780868707) | sha256 | AMOS | threatfox | 2026-10-20T04:34:10Z | 100 |
| [`hxxps://htj[.]abanda88[.]org/pe/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhtj.abanda88.org%2Fpe%2F) | url | Vidar | threatfox | 2026-10-20T04:30:48Z | 100 |
| [`9e40c2c027e3bbbe89e9e4ddc1846ef271fc8d4c6c09282be4f7164cd96ca196`](https://www.virustotal.com/gui/file/9e40c2c027e3bbbe89e9e4ddc1846ef271fc8d4c6c09282be4f7164cd96ca196) | sha256 | AMOS | threatfox | 2026-10-20T04:29:52Z | 100 |
| [`23[.]132[.]164[.]193`](https://www.virustotal.com/gui/ip-address/23.132.164.193) | ipv4 | Remcos | threatfox | 2026-10-20T04:26:37Z | 100 |
| [`hxxps://htj[.]abanda88[.]org/ny/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhtj.abanda88.org%2Fny%2F) | url | Vidar | threatfox | 2026-10-20T04:25:48Z | 100 |
| [`hxxps://htj[.]abanda88[.]org/r/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhtj.abanda88.org%2Fr%2F) | url | Vidar | threatfox | 2026-10-20T04:20:48Z | 100 |
| [`hxxps://htj[.]abanda88[.]org/pn/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhtj.abanda88.org%2Fpn%2F) | url | Vidar | threatfox | 2026-10-20T04:15:48Z | 100 |
| [`hxxps://htj[.]abanda88[.]org/rig/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhtj.abanda88.org%2Frig%2F) | url | Vidar | threatfox | 2026-10-20T04:10:49Z | 100 |
| [`hxxp://scanchart-rny[.]com/ac/cc[.]php`](https://www.virustotal.com/gui/search/http%3A%2F%2Fscanchart-rny.com%2Fac%2Fcc.php) | url | Loki Password Stealer (PWS) | threatfox | 2026-10-20T04:10:03Z | 100 |
| [`se7ahj6q[.]laparnih[.]com`](https://www.virustotal.com/gui/domain/se7ahj6q.laparnih.com) | domain | ClearFake | threatfox | 2026-10-20T04:06:03Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
