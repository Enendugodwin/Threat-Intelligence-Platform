# Threat Intel Pulse — 2026-10-17

**Window:** last 7 days · **Generated:** 2026-10-17T04:42:32Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 72528 |
| New in window | 22584 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5000 | ok |
| feodo | 5 | ok |
| threatfox | 8369 | ok |
| malwarebazaar | 610 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8731 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 29205 | 12335 |
| sha256 | 14310 | 4676 |
| domain | 12307 | 2392 |
| ipv4 | 11939 | 2159 |
| ipv6 | 3198 | 270 |
| md5 | 797 | 376 |
| sha1 | 772 | 376 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 10916 |
| Exit nodes | 2378 |
| Other relays | 8538 |
| New in window | 1127 |

Sample (20 of 10916, source: Tor Project Onionoo):
- `1[.]201[.]176[.]176`
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
- `102[.]216[.]253[.]63`

Full list: `dist/tor/tor_nodes.txt` (in the `threat-intel-output` workflow artifact).
## Top malware families

| Family | Indicators | New | ATT&CK (heuristic) |
| --- | --- | --- | --- |
| Unknown Loader | 5029 | 474 | — |
| Mirai | 4827 | 1202 | T1498, T1071.001 |
| Vidar | 4673 | 4280 | T1555, T1071.001, T1567 |
| AsyncRAT | 2309 | 105 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| ClearFake | 1920 | 313 | — |
| IClickFix | 1570 | 353 | — |
| Cobalt Strike | 1347 | 83 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| Unknown malware | 1290 | 612 | — |
| VShell | 878 | 727 | — |
| Unknown Stealer | 630 | 83 | — |
| php.shin_webshell | 588 | 329 | — |
| AMOS | 488 | 283 | — |
| PureRAT | 427 | 52 | — |
| Remcos | 328 | 159 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| Sliver | 316 | 293 | T1071.001, T1573, T1090, T1055 |
| AdaptixC2 | 291 | 23 | — |
| Remus | 240 | 94 | — |
| Unknown RAT | 205 | 33 | — |
| DanaBot | 195 | 110 | T1566.001, T1071.001, T1555, T1041 |
| Formbook | 186 | 89 | T1566.001, T1056.001, T1555, T1071.001, T1567 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1105 | Ingress Tool Transfer | command-and-control | 23019 |
| T1071.001 | Web Protocols | command-and-control | 45786 |
| T1498 | Network Denial of Service | impact | 10573 |
| T1204.002 | Malicious File | execution | 9414 |
| T1027 | Obfuscated Files or Information | defense-evasion | 9252 |
| T1573 | Encrypted Channel | command-and-control | 8743 |
| T1555 | Credentials from Password Stores | credential-access | 7750 |
| T1567 | Exfiltration Over Web Service | exfiltration | 7555 |
| T1566 | Phishing | initial-access | 6027 |
| T1566.002 | Spearphishing Link | initial-access | 6027 |
| T1552.001 | Credentials In Files | credential-access | 4827 |
| T1056.001 | Keylogging | collection, credential-access | 3882 |
| T1566.001 | Spearphishing Attachment | initial-access | 3571 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 2978 |
| T1113 | Screen Capture | collection | 2933 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1917 |
| T1090 | Proxy | command-and-control | 1700 |
| T1059.001 | PowerShell | execution | 1361 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 375 |
| T1189 | Drive-by Compromise | initial-access | 177 |
| T1218 | System Binary Proxy Execution | defense-evasion | 177 |
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
| [`154[.]8[.]209[.]118`](https://www.virustotal.com/gui/ip-address/154.8.209.118) | ipv4 | VShell | threatfox | 2026-10-17T04:05:07Z | 100 |
| [`3[.]110[.]189[.]136`](https://www.virustotal.com/gui/ip-address/3.110.189.136) | ipv4 | VShell | threatfox | 2026-10-17T04:05:04Z | 100 |
| [`339285484b60a51ae06e6e8d59cf177d5fda512f49eb38aaf8ef9b10e3b55703`](https://www.virustotal.com/gui/file/339285484b60a51ae06e6e8d59cf177d5fda512f49eb38aaf8ef9b10e3b55703) | sha256 | Mirai | threatfox | 2026-10-17T03:54:13Z | 100 |
| [`df39ed227704f9d6661ab1c4c598d1cfed90472c6a8e3c75de58b01750382b48`](https://www.virustotal.com/gui/file/df39ed227704f9d6661ab1c4c598d1cfed90472c6a8e3c75de58b01750382b48) | sha256 | Mirai | threatfox | 2026-10-17T03:54:12Z | 100 |
| [`f922035da1db200f978c9df156697d398703d4caff2f618dd0f1486378f2feec`](https://www.virustotal.com/gui/file/f922035da1db200f978c9df156697d398703d4caff2f618dd0f1486378f2feec) | sha256 | Mirai | threatfox | 2026-10-17T03:54:08Z | 100 |
| [`242833b219f0f9dda69f68523c1fc7ea825d47055816534c1700026d104c4468`](https://www.virustotal.com/gui/file/242833b219f0f9dda69f68523c1fc7ea825d47055816534c1700026d104c4468) | sha256 | Mirai | threatfox | 2026-10-17T03:54:05Z | 100 |
| [`af90dd521ab85a4c8d3ee79e6e7413a1297a8b31caeb5a2ad0c0a0064282550f`](https://www.virustotal.com/gui/file/af90dd521ab85a4c8d3ee79e6e7413a1297a8b31caeb5a2ad0c0a0064282550f) | sha256 | Mirai | threatfox | 2026-10-17T03:54:04Z | 100 |
| [`1d37a1a5605c36b1f06174151af5791b0e818810a962053c7d043cde5f67621f`](https://www.virustotal.com/gui/file/1d37a1a5605c36b1f06174151af5791b0e818810a962053c7d043cde5f67621f) | sha256 | Mirai | threatfox | 2026-10-17T03:54:03Z | 100 |
| [`30db2a6a5946a66c05d900cc7091f466cb9783b56b031fcbaf5f634a7ae435b2`](https://www.virustotal.com/gui/file/30db2a6a5946a66c05d900cc7091f466cb9783b56b031fcbaf5f634a7ae435b2) | sha256 | Mirai | threatfox | 2026-10-17T03:54:02Z | 100 |
| [`69a50b7cacbe50d564fa01c8327c2fa6b16912dfd891b6eace43c8c0f00d68db`](https://www.virustotal.com/gui/file/69a50b7cacbe50d564fa01c8327c2fa6b16912dfd891b6eace43c8c0f00d68db) | sha256 | Mirai | threatfox | 2026-10-17T03:54:01Z | 100 |
| [`17669a9a117ab8bfc130cbfd61a12918a1d67c5183ecd2fdb534bb2a934e2d8f`](https://www.virustotal.com/gui/file/17669a9a117ab8bfc130cbfd61a12918a1d67c5183ecd2fdb534bb2a934e2d8f) | sha256 | Mirai | threatfox | 2026-10-17T03:53:56Z | 100 |
| [`63994ce1a8a1520520724353d00cf32e192123a021760b077aef45342f78acea`](https://www.virustotal.com/gui/file/63994ce1a8a1520520724353d00cf32e192123a021760b077aef45342f78acea) | sha256 | Mirai | threatfox | 2026-10-17T03:53:55Z | 100 |
| [`81722c7605e51e025796636e50b478daca07a7dbb6ccf3c07aad74ecc4522843`](https://www.virustotal.com/gui/file/81722c7605e51e025796636e50b478daca07a7dbb6ccf3c07aad74ecc4522843) | sha256 | Bashlite | threatfox | 2026-10-17T03:53:54Z | 100 |
| [`3b382773c6d6af85d284d0bf38064d761461879bde13269026d8dc88e4977063`](https://www.virustotal.com/gui/file/3b382773c6d6af85d284d0bf38064d761461879bde13269026d8dc88e4977063) | sha256 | Mirai | threatfox | 2026-10-17T03:53:53Z | 100 |
| [`4054396ee1fb4c0e1714eafdf6919cf223cbaa4324a61b51597bc0dca717ffc6`](https://www.virustotal.com/gui/file/4054396ee1fb4c0e1714eafdf6919cf223cbaa4324a61b51597bc0dca717ffc6) | sha256 | Mirai | threatfox, malwarebazaar | 2026-10-17T03:53:47Z | 100 |
| [`152[.]42[.]212[.]170`](https://www.virustotal.com/gui/ip-address/152.42.212.170) | ipv4 | Jackskid | threatfox | 2026-10-17T03:01:18Z | 100 |
| [`157[.]230[.]241[.]185`](https://www.virustotal.com/gui/ip-address/157.230.241.185) | ipv4 | Jackskid | threatfox | 2026-10-17T03:01:18Z | 100 |
| [`157[.]245[.]241[.]230`](https://www.virustotal.com/gui/ip-address/157.245.241.230) | ipv4 | Jackskid | threatfox | 2026-10-17T03:01:18Z | 100 |
| [`174[.]138[.]41[.]23`](https://www.virustotal.com/gui/ip-address/174.138.41.23) | ipv4 | Jackskid | threatfox | 2026-10-17T03:01:18Z | 100 |
| [`178[.]128[.]8[.]22`](https://www.virustotal.com/gui/ip-address/178.128.8.22) | ipv4 | Jackskid | threatfox | 2026-10-17T03:01:18Z | 100 |
| [`62b488d97bc45e03b81109bc4bb3d0269bd3758d1a7181ba901810836acb0c99`](https://www.virustotal.com/gui/file/62b488d97bc45e03b81109bc4bb3d0269bd3758d1a7181ba901810836acb0c99) | sha256 | Mirai | threatfox | 2026-10-17T02:54:24Z | 100 |
| [`3548e0d93a2feea987bcfd234168af9d3c917c57333aa6315e5f06764414cea8`](https://www.virustotal.com/gui/file/3548e0d93a2feea987bcfd234168af9d3c917c57333aa6315e5f06764414cea8) | sha256 | Mirai | threatfox | 2026-10-17T02:54:16Z | 100 |
| [`6237a6c34db19abb3c338493322926b27589e536f78ca65c967ed553b7300301`](https://www.virustotal.com/gui/file/6237a6c34db19abb3c338493322926b27589e536f78ca65c967ed553b7300301) | sha256 | Mirai | threatfox, malwarebazaar | 2026-10-17T02:54:14Z | 100 |
| [`0d1c407e12fa6826d6dc2f87fd4628d075e568bb129c53b48f56adc6f9bc6374`](https://www.virustotal.com/gui/file/0d1c407e12fa6826d6dc2f87fd4628d075e568bb129c53b48f56adc6f9bc6374) | sha256 | Mirai | threatfox | 2026-10-17T02:54:13Z | 100 |
| [`ad28d17642e5f777126510b4cf378c8dd8a9654e1029ab6249ece2f2bdeded7b`](https://www.virustotal.com/gui/file/ad28d17642e5f777126510b4cf378c8dd8a9654e1029ab6249ece2f2bdeded7b) | sha256 | Mirai | threatfox, malwarebazaar | 2026-10-17T02:54:08Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
