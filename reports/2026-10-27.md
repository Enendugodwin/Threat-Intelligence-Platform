# Threat Intel Pulse — 2026-10-27

**Window:** last 7 days · **Generated:** 2026-10-27T12:28:43Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 91106 |
| New in window | 28578 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8676 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 390 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 504 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 2978 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 30729 | 6429 |
| ipv4 | 27035 | 14865 |
| domain | 16244 | 5674 |
| sha256 | 11914 | 1327 |
| ipv6 | 3397 | 238 |
| md5 | 917 | 45 |
| sha1 | 870 | 0 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 11831 |
| Exit nodes | 2260 |
| Other relays | 9571 |
| New in window | 973 |

Sample (20 of 11831, source: Tor Project Onionoo):
- `1[.]201[.]176[.]176`
- `1[.]235[.]159[.]83`
- `1[.]248[.]96[.]163`
- `1[.]34[.]44[.]234`
- `100[.]1[.]157[.]56`
- `100[.]2[.]63[.]41`
- `100[.]8[.]53[.]153`
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

Full list: `dist/tor/tor_nodes.txt` (in the `threat-intel-output` workflow artifact).
## Top malware families

| Family | Indicators | New | ATT&CK (heuristic) |
| --- | --- | --- | --- |
| Vidar | 6126 | 423 | T1555, T1071.001, T1567 |
| Unknown Loader | 3630 | 249 | — |
| Mirai | 2788 | 193 | T1498, T1071.001 |
| IClickFix | 2470 | 623 | — |
| ClearFake | 1768 | 40 | — |
| Unknown malware | 1732 | 182 | — |
| Cobalt Strike | 1352 | 9 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| AMOS | 1043 | 236 | — |
| VShell | 901 | 74 | — |
| php.shin_webshell | 669 | 35 | — |
| Unknown Stealer | 508 | 24 | — |
| PureRAT | 436 | 4 | — |
| Sliver | 384 | 8 | T1071.001, T1573, T1090, T1055 |
| Remus | 374 | 177 | — |
| Remcos | 372 | 24 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| AsyncRAT | 344 | 7 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| AdaptixC2 | 297 | 3 | — |
| MacSync | 257 | 237 | — |
| Formbook | 218 | 11 | T1566.001, T1056.001, T1555, T1071.001, T1567 |
| DanaBot | 193 | 1 | T1566.001, T1071.001, T1555, T1041 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1071.001 | Web Protocols | command-and-control | 57351 |
| T1105 | Ingress Tool Transfer | command-and-control | 17205 |
| T1566 | Phishing | initial-access | 15444 |
| T1566.002 | Spearphishing Link | initial-access | 15444 |
| T1555 | Credentials from Password Stores | credential-access | 9994 |
| T1567 | Exfiltration Over Web Service | exfiltration | 9797 |
| T1573 | Encrypted Channel | command-and-control | 8049 |
| T1498 | Network Denial of Service | impact | 6948 |
| T1204.002 | Malicious File | execution | 6692 |
| T1027 | Obfuscated Files or Information | defense-evasion | 6530 |
| T1552.001 | Credentials In Files | credential-access | 5694 |
| T1056.001 | Keylogging | collection, credential-access | 1974 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1886 |
| T1090 | Proxy | command-and-control | 1773 |
| T1566.001 | Spearphishing Attachment | initial-access | 1626 |
| T1059.001 | PowerShell | execution | 1364 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 1066 |
| T1113 | Screen Capture | collection | 1016 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 320 |
| T1189 | Drive-by Compromise | initial-access | 177 |
| T1218 | System Binary Proxy Execution | defense-evasion | 177 |
| T1059.005 | Visual Basic | execution | 38 |
| T1486 | Data Encrypted for Impact | impact | 31 |
| T1490 | Inhibit System Recovery | impact | 31 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 31 |
| T1190 | Exploit Public-Facing Application | initial-access | 21 |
| T1021.001 | Remote Desktop Protocol | lateral-movement | 12 |
| T1003 | OS Credential Dumping | credential-access | 4 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://rv[.]abc212[.]org/tj/`](https://www.virustotal.com/gui/search/https%3A%2F%2Frv.abc212.org%2Ftj%2F) | url | Vidar | threatfox | 2026-10-21T11:55:48Z | 100 |
| [`5d9e7b2c6e21e0d75a7f2aa8c7738ec8b7b2db3fa6567d8434403585a5053047`](https://www.virustotal.com/gui/file/5d9e7b2c6e21e0d75a7f2aa8c7738ec8b7b2db3fa6567d8434403585a5053047) | sha256 | Mirai | threatfox, malwarebazaar | 2026-10-21T11:54:32Z | 100 |
| [`hxxps://rv[.]abc212[.]org/eu/`](https://www.virustotal.com/gui/search/https%3A%2F%2Frv.abc212.org%2Feu%2F) | url | Vidar | threatfox | 2026-10-21T11:50:48Z | 100 |
| [`da307a62fad47ac3889c3c3233da87083dfc6e0aa7f16d3b34172dde015711f6`](https://www.virustotal.com/gui/file/da307a62fad47ac3889c3c3233da87083dfc6e0aa7f16d3b34172dde015711f6) | sha256 | AMOS | threatfox | 2026-10-21T11:49:33Z | 100 |
| [`hxxps://fastly[.]jsdelivr[.]net/gh/grog1274/5e7b-4919-ac27-3ca995d1d572/40b1-a0b2-86b13101d695`](https://www.virustotal.com/gui/search/https%3A%2F%2Ffastly.jsdelivr.net%2Fgh%2Fgrog1274%2F5e7b-4919-ac27-3ca995d1d572%2F40b1-a0b2-86b13101d695) | url | ClearFake | threatfox | 2026-10-21T11:47:41Z | 100 |
| [`a00047d22c9a977584daf29232df06c34d86003a5717c0efb9b68c5a72f02ce1`](https://www.virustotal.com/gui/file/a00047d22c9a977584daf29232df06c34d86003a5717c0efb9b68c5a72f02ce1) | sha256 | AMOS | threatfox | 2026-10-21T11:46:43Z | 100 |
| [`hxxps://rv[.]abc212[.]org/g1/`](https://www.virustotal.com/gui/search/https%3A%2F%2Frv.abc212.org%2Fg1%2F) | url | Vidar | threatfox | 2026-10-21T11:45:48Z | 100 |
| [`bcd9e5f793776dd7d16763be1c8e52ae80d0aea965181dfef3328d8c5b61f3d2`](https://www.virustotal.com/gui/file/bcd9e5f793776dd7d16763be1c8e52ae80d0aea965181dfef3328d8c5b61f3d2) | sha256 | AMOS | threatfox | 2026-10-21T11:44:03Z | 100 |
| [`hxxps://rv[.]abc212[.]org/ikm/`](https://www.virustotal.com/gui/search/https%3A%2F%2Frv.abc212.org%2Fikm%2F) | url | Vidar | threatfox | 2026-10-21T11:40:48Z | 100 |
| [`f177a32b795577319de1c213d24b6f5f879cf5d081c7791264bccbd4878589e6`](https://www.virustotal.com/gui/file/f177a32b795577319de1c213d24b6f5f879cf5d081c7791264bccbd4878589e6) | sha256 | AMOS | threatfox | 2026-10-21T11:39:45Z | 100 |
| [`hxxps://r[.]abc212[.]org/a6/api/metrics`](https://www.virustotal.com/gui/search/https%3A%2F%2Fr.abc212.org%2Fa6%2Fapi%2Fmetrics) | url | Vidar | threatfox | 2026-10-21T11:37:54Z | 100 |
| [`hxxps://rv[.]abc212[.]org/`](https://www.virustotal.com/gui/search/https%3A%2F%2Frv.abc212.org%2F) | url | Vidar | threatfox | 2026-10-21T11:37:54Z | 100 |
| [`abc212[.]org`](https://www.virustotal.com/gui/domain/abc212.org) | domain | Vidar | threatfox | 2026-10-21T11:37:53Z | 100 |
| [`a9bet[.]org`](https://www.virustotal.com/gui/domain/a9bet.org) | domain | Vidar | threatfox | 2026-10-21T11:37:53Z | 100 |
| [`r[.]abc212[.]org`](https://www.virustotal.com/gui/domain/r.abc212.org) | domain | Vidar | threatfox | 2026-10-21T11:37:52Z | 100 |
| [`rv[.]abc212[.]org`](https://www.virustotal.com/gui/domain/rv.abc212.org) | domain | Vidar | threatfox | 2026-10-21T11:37:52Z | 100 |
| [`065070b4b724e81feb94601b611e85fba0178f21e1d445ba7506c057f89fc618`](https://www.virustotal.com/gui/file/065070b4b724e81feb94601b611e85fba0178f21e1d445ba7506c057f89fc618) | sha256 | AMOS | threatfox | 2026-10-21T11:37:26Z | 100 |
| [`hxxps://rv[.]abc212[.]org/i/`](https://www.virustotal.com/gui/search/https%3A%2F%2Frv.abc212.org%2Fi%2F) | url | Vidar | threatfox | 2026-10-21T11:35:48Z | 100 |
| [`f2506201e049e9fe2242137a3e0ae1c6de67bb525af3e9f6959cd2500c6c76ab`](https://www.virustotal.com/gui/file/f2506201e049e9fe2242137a3e0ae1c6de67bb525af3e9f6959cd2500c6c76ab) | sha256 | AMOS | threatfox | 2026-10-21T11:34:44Z | 100 |
| [`cda3669e0e9de7a73f518770b8f2e9a33b44b5e554298f5511057535cae502db`](https://www.virustotal.com/gui/file/cda3669e0e9de7a73f518770b8f2e9a33b44b5e554298f5511057535cae502db) | sha256 | AMOS | threatfox | 2026-10-21T11:32:22Z | 100 |
| [`hxxps://z[.]a9bet[.]org/u/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fz.a9bet.org%2Fu%2F) | url | Vidar | threatfox | 2026-10-21T11:30:48Z | 100 |
| [`hxxps://rv[.]abc212[.]org/fk/`](https://www.virustotal.com/gui/search/https%3A%2F%2Frv.abc212.org%2Ffk%2F) | url | Vidar | threatfox | 2026-10-21T11:30:48Z | 100 |
| [`hxxps://boost-90[.]com/f/765jefvnrbjgvwnpdrkwdg/g4p2ym3t`](https://www.virustotal.com/gui/search/https%3A%2F%2Fboost-90.com%2Ff%2F765jefvnrbjgvwnpdrkwdg%2Fg4p2ym3t) | url | AMOS | threatfox, urlhaus | 2026-10-21T11:29:27Z | 100 |
| [`1d6102cbdf119cd3655d9beb30698a97ab69d996f2a1b913c0bd95b32076d2ac`](https://www.virustotal.com/gui/file/1d6102cbdf119cd3655d9beb30698a97ab69d996f2a1b913c0bd95b32076d2ac) | sha256 | AMOS | threatfox | 2026-10-21T11:29:27Z | 100 |
| [`5e74c21baf3f640e4a6334ac58dd9e0f3d3a29041098eda1204f70a6eae8223b`](https://www.virustotal.com/gui/file/5e74c21baf3f640e4a6334ac58dd9e0f3d3a29041098eda1204f70a6eae8223b) | sha256 | AMOS | threatfox | 2026-10-21T11:28:37Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
