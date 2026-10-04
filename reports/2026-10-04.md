# Threat Intel Pulse — 2026-10-04

**Window:** last 7 days · **Generated:** 2026-10-04T17:10:47Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 14858 |
| New in window | 14858 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 27 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5000 | ok |
| feodo | 5 | ok |
| threatfox | 11192 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 4760 | 4760 |
| domain | 4349 | 4349 |
| sha256 | 3255 | 3255 |
| ipv4 | 2380 | 2380 |
| md5 | 57 | 57 |
| sha1 | 57 | 57 |

## Top malware families

| Family | Indicators | New | ATT&CK (heuristic) |
| --- | --- | --- | --- |
| Unknown Loader | 2644 | 2644 | — |
| Mirai | 1939 | 1939 | T1498, T1071.001 |
| Cobalt Strike | 1225 | 1225 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| AsyncRAT | 1189 | 1189 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| Unknown malware | 432 | 432 | — |
| IClickFix | 329 | 329 | — |
| PureRAT | 326 | 326 | — |
| AdaptixC2 | 237 | 237 | — |
| ClearFake | 196 | 196 | — |
| Unknown Stealer | 166 | 166 | — |
| Vidar | 153 | 153 | T1555, T1071.001, T1567 |
| Unknown RAT | 132 | 132 | — |
| DCRat | 96 | 96 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| Evilginx | 91 | 91 | — |
| Remcos | 90 | 90 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| AMOS | 83 | 83 | — |
| Havoc | 83 | 83 | — |
| VShell | 83 | 83 | — |
| Remus | 78 | 78 | — |
| DanaBot | 62 | 62 | T1566.001, T1071.001, T1555, T1041 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1071.001 | Web Protocols | command-and-control | 12949 |
| T1105 | Ingress Tool Transfer | command-and-control | 5961 |
| T1498 | Network Denial of Service | impact | 4997 |
| T1573 | Encrypted Channel | command-and-control | 3467 |
| T1056.001 | Keylogging | collection, credential-access | 1861 |
| T1566.001 | Spearphishing Attachment | initial-access | 1559 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 1422 |
| T1113 | Screen Capture | collection | 1403 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1340 |
| T1090 | Proxy | command-and-control | 1252 |
| T1059.001 | PowerShell | execution | 1237 |
| T1555 | Credentials from Password Stores | credential-access | 490 |
| T1567 | Exfiltration Over Web Service | exfiltration | 428 |
| T1552.001 | Credentials In Files | credential-access | 307 |
| T1027 | Obfuscated Files or Information | defense-evasion | 270 |
| T1204.002 | Malicious File | execution | 270 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 115 |
| T1059.005 | Visual Basic | execution | 41 |
| T1566 | Phishing | initial-access | 7 |
| T1566.002 | Spearphishing Link | initial-access | 7 |
| T1189 | Drive-by Compromise | initial-access | 5 |
| T1218 | System Binary Proxy Execution | defense-evasion | 5 |
| T1021.001 | Remote Desktop Protocol | lateral-movement | 2 |
| T1486 | Data Encrypted for Impact | impact | 2 |
| T1490 | Inhibit System Recovery | impact | 2 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 2 |
| T1003 | OS Credential Dumping | credential-access | 1 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| `772da74caf28a60eac05e19bba793d81d9d9a91e3ff14166fc13958264ee2eb3` | sha256 | Mirai | threatfox | 2026-10-04T16:47:05Z | 100 |
| `b5651950e650267884e0797d2871ff52c44fa5a965ab134f6815cfaeb2981a6d` | sha256 | Mirai | threatfox | 2026-10-04T16:46:59Z | 100 |
| `3ff45f0989e79e14152380f9d7dc77dbbbb0045a7e929aece34dfa7e82fa86da` | sha256 | Mirai | threatfox | 2026-10-04T16:46:57Z | 100 |
| `4d04a95bbc8dd80f6cf431519c0f408adbdfa6b548405148c97c1b1ded46a295` | sha256 | Mirai | threatfox | 2026-10-04T16:46:56Z | 100 |
| `5f6abef21d17243af8a2c2e8172e225b2f161790b937ac20e998a47a68b606db` | sha256 | Mirai | threatfox | 2026-10-04T16:46:55Z | 100 |
| `1753a6655047fa98523d11ee29b22035be78dde8c12c2bf7f0c832936ca4ec73` | sha256 | Mirai | threatfox | 2026-10-04T16:46:54Z | 100 |
| `0424c93f0368bb41cdcf6aa577262a9155ddf0f13dc0dfaddc2bdc810719d804` | sha256 | Mirai | threatfox | 2026-10-04T16:46:53Z | 100 |
| `8a9a141f0f9651ff636f1082bd09177a77cca705dc49ea8e52bce2ea0915a91a` | sha256 | Mirai | threatfox | 2026-10-04T16:46:52Z | 100 |
| `d98073aff0574ff563679d1dfa2c3b81c7c7e92eed337a83f78eeceadfc7d8cd` | sha256 | Mirai | threatfox | 2026-10-04T16:46:51Z | 100 |
| `d08c7e654cc02a64d08ef113e7141c55a27e143c1ad0c5493e35f204de2b2561` | sha256 | Mirai | threatfox | 2026-10-04T16:46:50Z | 100 |
| `32c87d6a1bd9fd87e9ea33bcd6d41ecc8145741b718bd11ce97bd38a0d54d0c4` | sha256 | Mirai | threatfox | 2026-10-04T16:46:49Z | 100 |
| `55a5a6c52925d59621dadd70a5a80f54e24e54f99e4d587a19a16dcf992fdf85` | sha256 | Mirai | threatfox | 2026-10-04T16:46:48Z | 100 |
| `91065c82c2db1ee6fcb0aca51b6fbf189913d4082f9be6cf97422010633b7cd6` | sha256 | Mirai | threatfox | 2026-10-04T16:46:47Z | 100 |
| `564f1ed135185a33839ce1bce39fe409fc0219b313ab4e007ac6b4ff0608e7e6` | sha256 | Mirai | threatfox | 2026-10-04T16:46:39Z | 100 |
| `8ea5fe9dba1fc6f845f8ee1b5697733b04d96d638b79ed5f275d8d47bfbd591d` | sha256 | Mirai | threatfox | 2026-10-04T16:46:38Z | 100 |
| `31edb8dedf393ccf149f508a7031da33d21ce8b7bc9cd8865e6948738bb92151` | sha256 | Mirai | threatfox | 2026-10-04T16:46:37Z | 100 |
| `806385c4d1ce5fb675357095cb07a81e0a0aebe4962b66e5422e0000945c149d` | sha256 | Mirai | threatfox | 2026-10-04T16:46:36Z | 100 |
| `672fc7c9c852ff6678604d09ff94c763f1256eeb16d9c0e2e676ecbd28a67e32` | sha256 | Mirai | threatfox | 2026-10-04T16:46:34Z | 100 |
| `decd05faa551bbe6233cc69704a8d9b71dac11f373fe38b6b39bd31612dc13df` | sha256 | Mirai | threatfox | 2026-10-04T16:46:33Z | 100 |
| `ab72c44f7871d30726e85477e4a692a6ad5f0a428582a89e22fc107fef9f2b25` | sha256 | Mirai | threatfox | 2026-10-04T16:46:32Z | 100 |
| `0d639f3022035a5da5081074b2f19f1d6bac7b16a73bffa691c59fb0440c15c8` | sha256 | Mirai | threatfox | 2026-10-04T16:46:30Z | 100 |
| `dfba50b6cba1167e2720b9efff27b352730d85981154d685c27456bb51e71a78` | sha256 | Mirai | threatfox | 2026-10-04T16:46:29Z | 100 |
| `1ef61d490483af2715af8889cca733804be3cfae351a6170a36a827e4046207e` | sha256 | Mirai | threatfox | 2026-10-04T16:46:28Z | 100 |
| `6c325dd1fd740fbbbc566ad1a21d1bbb2be46e1ec5f2b4e7539fd5a5760e22b4` | sha256 | Mirai | threatfox | 2026-10-04T16:46:27Z | 100 |
| `fb1feb800d84d34cb1a3b1bf9980320bb56c175be3d0f347415072c4d3cfefe1` | sha256 | Mirai | threatfox | 2026-10-04T16:46:25Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv` (published as the workflow artifact `threat-intel-output`).</sub>
