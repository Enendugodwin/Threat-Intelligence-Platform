# Threat Intel Pulse — 2026-10-16

**Window:** last 7 days · **Generated:** 2026-10-16T16:48:20Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 71204 |
| New in window | 22835 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5000 | ok |
| feodo | 5 | ok |
| threatfox | 8533 | ok |
| malwarebazaar | 661 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8680 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 28707 | 12137 |
| sha256 | 13684 | 4246 |
| domain | 12229 | 3168 |
| ipv4 | 11838 | 2146 |
| ipv6 | 3177 | 255 |
| md5 | 797 | 442 |
| sha1 | 772 | 441 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 10821 |
| Exit nodes | 2370 |
| Other relays | 8451 |
| New in window | 1075 |

Sample (20 of 10821, source: Tor Project Onionoo):
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
| Unknown Loader | 5000 | 522 | — |
| Vidar | 4662 | 4293 | T1555, T1071.001, T1567 |
| Mirai | 4342 | 764 | T1498, T1071.001 |
| AsyncRAT | 2309 | 114 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| ClearFake | 1912 | 684 | — |
| IClickFix | 1562 | 663 | — |
| Cobalt Strike | 1344 | 81 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| Unknown malware | 1282 | 638 | — |
| VShell | 875 | 737 | — |
| Unknown Stealer | 630 | 126 | — |
| php.shin_webshell | 568 | 332 | — |
| AMOS | 458 | 263 | — |
| PureRAT | 422 | 54 | — |
| Remcos | 325 | 159 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| Sliver | 316 | 293 | T1071.001, T1573, T1090, T1055 |
| AdaptixC2 | 288 | 26 | — |
| Remus | 235 | 94 | — |
| Unknown RAT | 205 | 34 | — |
| DanaBot | 195 | 132 | T1566.001, T1071.001, T1555, T1041 |
| Formbook | 186 | 97 | T1566.001, T1056.001, T1555, T1071.001, T1567 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1105 | Ingress Tool Transfer | command-and-control | 22817 |
| T1071.001 | Web Protocols | command-and-control | 45042 |
| T1498 | Network Denial of Service | impact | 10040 |
| T1204.002 | Malicious File | execution | 9399 |
| T1027 | Obfuscated Files or Information | defense-evasion | 9237 |
| T1573 | Encrypted Channel | command-and-control | 8719 |
| T1555 | Credentials from Password Stores | credential-access | 7706 |
| T1567 | Exfiltration Over Web Service | exfiltration | 7511 |
| T1566 | Phishing | initial-access | 5727 |
| T1566.002 | Spearphishing Link | initial-access | 5727 |
| T1552.001 | Credentials In Files | credential-access | 4791 |
| T1056.001 | Keylogging | collection, credential-access | 3867 |
| T1566.001 | Spearphishing Attachment | initial-access | 3554 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 2972 |
| T1113 | Screen Capture | collection | 2928 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1903 |
| T1090 | Proxy | command-and-control | 1697 |
| T1059.001 | PowerShell | execution | 1358 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 364 |
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
| [`xghc222o[.]amanahmaka[.]com`](https://www.virustotal.com/gui/domain/xghc222o.amanahmaka.com) | domain | ClearFake | threatfox | 2026-10-16T16:41:50Z | 100 |
| [`ggzc8z1w[.]travelley[.]health`](https://www.virustotal.com/gui/domain/ggzc8z1w.travelley.health) | domain | ClearFake | threatfox | 2026-10-16T16:41:35Z | 100 |
| [`hxxps://pro[.]jasperwater[.]info/auth/role-asset[.]js`](https://www.virustotal.com/gui/search/https%3A%2F%2Fpro.jasperwater.info%2Fauth%2Frole-asset.js) | url | SmartApeSG | threatfox | 2026-10-16T16:29:29Z | 100 |
| [`hxxps://seleniteatrium[.]org/middleware/oauth-effect[.]js`](https://www.virustotal.com/gui/search/https%3A%2F%2Fseleniteatrium.org%2Fmiddleware%2Foauth-effect.js) | url | SmartApeSG | threatfox | 2026-10-16T16:29:29Z | 100 |
| [`amanahtoto[.]cc`](https://www.virustotal.com/gui/domain/amanahtoto.cc) | domain | ClearFake | threatfox | 2026-10-16T16:29:09Z | 100 |
| [`9wqldolh[.]amanahjili[.]com`](https://www.virustotal.com/gui/domain/9wqldolh.amanahjili.com) | domain | ClearFake | threatfox | 2026-10-16T16:27:38Z | 100 |
| [`amanahtotoasli[.]us[.]com`](https://www.virustotal.com/gui/domain/amanahtotoasli.us.com) | domain | ClearFake | threatfox | 2026-10-16T16:14:34Z | 100 |
| [`hxxps://d6[.]76k[.]org`](https://www.virustotal.com/gui/search/https%3A%2F%2Fd6.76k.org) | url | Vidar | threatfox | 2026-10-16T16:12:49Z | 100 |
| [`hxxps://v01[.]88bravo[.]com`](https://www.virustotal.com/gui/search/https%3A%2F%2Fv01.88bravo.com) | url | Vidar | threatfox | 2026-10-16T16:11:11Z | 100 |
| [`v01[.]88bravo[.]com`](https://www.virustotal.com/gui/domain/v01.88bravo.com) | domain | Vidar | threatfox | 2026-10-16T16:10:48Z | 100 |
| [`hxxps://v01[.]88bravo[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fv01.88bravo.com%2F) | url | Vidar | threatfox | 2026-10-16T16:10:48Z | 100 |
| [`d2ae3982f07f89253b21d45321e97f57b4b81c78164c2504b2578958ca186362`](https://www.virustotal.com/gui/file/d2ae3982f07f89253b21d45321e97f57b4b81c78164c2504b2578958ca186362) | sha256 | Mirai | threatfox | 2026-10-16T15:54:20Z | 100 |
| [`c34e21f04453953d337a285b52b7a7879354f0bdfc8136e9a69789f0c819b3de`](https://www.virustotal.com/gui/file/c34e21f04453953d337a285b52b7a7879354f0bdfc8136e9a69789f0c819b3de) | sha256 | Mirai | threatfox | 2026-10-16T15:54:20Z | 100 |
| [`3d11f1b4703e85910c6f8e0087d97c106eb4e2db7496056125cbf675838180e7`](https://www.virustotal.com/gui/file/3d11f1b4703e85910c6f8e0087d97c106eb4e2db7496056125cbf675838180e7) | sha256 | Mirai | threatfox | 2026-10-16T15:54:19Z | 100 |
| [`4bec4b7cf78bfca1cfb3857492e944640e8aba60e593dfc7725eb936618f5c72`](https://www.virustotal.com/gui/file/4bec4b7cf78bfca1cfb3857492e944640e8aba60e593dfc7725eb936618f5c72) | sha256 | Mirai | threatfox | 2026-10-16T15:54:18Z | 100 |
| [`bef057527f8fbbb1ef79860ae831cfcc11b6e28dddeac6424cf7e7b70c14a491`](https://www.virustotal.com/gui/file/bef057527f8fbbb1ef79860ae831cfcc11b6e28dddeac6424cf7e7b70c14a491) | sha256 | Mirai | threatfox | 2026-10-16T15:54:17Z | 100 |
| [`e4d12208789f36efc5a1ff765088fed95d6bb5972d1a804a4536fd42366797d4`](https://www.virustotal.com/gui/file/e4d12208789f36efc5a1ff765088fed95d6bb5972d1a804a4536fd42366797d4) | sha256 | Mirai | threatfox | 2026-10-16T15:54:16Z | 100 |
| [`b2070ddbecc03dbb26cdc2a72df88e9fc5f6bb7215ea3e12d0d1035704553bde`](https://www.virustotal.com/gui/file/b2070ddbecc03dbb26cdc2a72df88e9fc5f6bb7215ea3e12d0d1035704553bde) | sha256 | Mirai | threatfox | 2026-10-16T15:54:07Z | 100 |
| [`09768b33697871b52d87d6422395568155e6bd39950785adf4d7dcd603c88470`](https://www.virustotal.com/gui/file/09768b33697871b52d87d6422395568155e6bd39950785adf4d7dcd603c88470) | sha256 | Mirai | threatfox | 2026-10-16T15:54:05Z | 100 |
| [`d1d78a81d451f8ae2ac73fcf26696f8c364e3521106e56bbf41020f51fb54e70`](https://www.virustotal.com/gui/file/d1d78a81d451f8ae2ac73fcf26696f8c364e3521106e56bbf41020f51fb54e70) | sha256 | Mirai | threatfox | 2026-10-16T15:54:04Z | 100 |
| [`336656fc6a31de7dda597b739354db26beea2315edc0628232d3972a8d65f98e`](https://www.virustotal.com/gui/file/336656fc6a31de7dda597b739354db26beea2315edc0628232d3972a8d65f98e) | sha256 | Mirai | threatfox | 2026-10-16T15:54:03Z | 100 |
| [`60ec6d3aaa6f36ddfcec5c33f0d6c9d22cef9b15765868f5913ef6cfeeac29cd`](https://www.virustotal.com/gui/file/60ec6d3aaa6f36ddfcec5c33f0d6c9d22cef9b15765868f5913ef6cfeeac29cd) | sha256 | Mirai | threatfox | 2026-10-16T15:53:57Z | 100 |
| [`62550c7ec27b049999506513f37f06eb5e2e1bf3c8fd1d2487e15ef70cdb2949`](https://www.virustotal.com/gui/file/62550c7ec27b049999506513f37f06eb5e2e1bf3c8fd1d2487e15ef70cdb2949) | sha256 | Mirai | threatfox | 2026-10-16T15:53:56Z | 100 |
| [`fe7cb6fa9d73b474e2256659d70a3bc71d20b9f38f2160bf0956166bb4131606`](https://www.virustotal.com/gui/file/fe7cb6fa9d73b474e2256659d70a3bc71d20b9f38f2160bf0956166bb4131606) | sha256 | Mirai | threatfox | 2026-10-16T15:53:55Z | 100 |
| [`85d13abbc39ecf5651d7912e955a85b6586624d6646864d74f260c878ad91b2d`](https://www.virustotal.com/gui/file/85d13abbc39ecf5651d7912e955a85b6586624d6646864d74f260c878ad91b2d) | sha256 | Mirai | threatfox | 2026-10-16T15:53:54Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
