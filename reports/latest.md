# Threat Intel Pulse — 2026-10-16

**Window:** last 7 days · **Generated:** 2026-10-16T21:25:12Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 71692 |
| New in window | 23323 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5000 | ok |
| feodo | 5 | ok |
| threatfox | 8618 | ok |
| malwarebazaar | 597 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8709 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 28811 | 12241 |
| sha256 | 13976 | 4538 |
| domain | 12280 | 3219 |
| ipv4 | 11873 | 2181 |
| ipv6 | 3183 | 261 |
| md5 | 797 | 442 |
| sha1 | 772 | 441 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 10846 |
| Exit nodes | 2371 |
| Other relays | 8475 |
| New in window | 1100 |

Sample (20 of 10846, source: Tor Project Onionoo):
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
| Unknown Loader | 5029 | 551 | — |
| Vidar | 4665 | 4296 | T1555, T1071.001, T1567 |
| Mirai | 4544 | 965 | T1498, T1071.001 |
| AsyncRAT | 2309 | 114 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| ClearFake | 1914 | 686 | — |
| IClickFix | 1563 | 664 | — |
| Cobalt Strike | 1344 | 81 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| Unknown malware | 1289 | 645 | — |
| VShell | 876 | 738 | — |
| Unknown Stealer | 630 | 126 | — |
| php.shin_webshell | 577 | 341 | — |
| AMOS | 488 | 293 | — |
| PureRAT | 427 | 59 | — |
| Remcos | 327 | 161 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| Sliver | 316 | 293 | T1071.001, T1573, T1090, T1055 |
| AdaptixC2 | 291 | 29 | — |
| Remus | 239 | 98 | — |
| Unknown RAT | 205 | 34 | — |
| DanaBot | 195 | 132 | T1566.001, T1071.001, T1555, T1041 |
| Formbook | 186 | 97 | T1566.001, T1056.001, T1555, T1071.001, T1567 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1105 | Ingress Tool Transfer | command-and-control | 22920 |
| T1071.001 | Web Protocols | command-and-control | 45366 |
| T1498 | Network Denial of Service | impact | 10264 |
| T1204.002 | Malicious File | execution | 9405 |
| T1027 | Obfuscated Files or Information | defense-evasion | 9243 |
| T1573 | Encrypted Channel | command-and-control | 8734 |
| T1555 | Credentials from Password Stores | credential-access | 7742 |
| T1567 | Exfiltration Over Web Service | exfiltration | 7547 |
| T1566 | Phishing | initial-access | 5727 |
| T1566.002 | Spearphishing Link | initial-access | 5727 |
| T1552.001 | Credentials In Files | credential-access | 4824 |
| T1056.001 | Keylogging | collection, credential-access | 3880 |
| T1566.001 | Spearphishing Attachment | initial-access | 3563 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 2976 |
| T1113 | Screen Capture | collection | 2932 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1908 |
| T1090 | Proxy | command-and-control | 1697 |
| T1059.001 | PowerShell | execution | 1358 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 369 |
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
| [`6dd0443fc8902fcd9daa12d3de222a4c8d2976e1bf44f1d6608c956af810740f`](https://www.virustotal.com/gui/file/6dd0443fc8902fcd9daa12d3de222a4c8d2976e1bf44f1d6608c956af810740f) | sha256 | Mirai | threatfox | 2026-10-16T20:54:13Z | 100 |
| [`e711f3ea58e80cc5345c7040da70e97728ba5ea49ea6e647ce25f2036a7905a7`](https://www.virustotal.com/gui/file/e711f3ea58e80cc5345c7040da70e97728ba5ea49ea6e647ce25f2036a7905a7) | sha256 | Mirai | threatfox, malwarebazaar | 2026-10-16T20:54:12Z | 100 |
| [`f61811f9cd70d6fb833b8a2992bb84aafeacc2e81dbc6ec3f846fcaa81bd2e60`](https://www.virustotal.com/gui/file/f61811f9cd70d6fb833b8a2992bb84aafeacc2e81dbc6ec3f846fcaa81bd2e60) | sha256 | Coinminer | threatfox | 2026-10-16T20:54:11Z | 100 |
| [`3052ea8b43bf40e9d4060c95523c7e194238d1ad941f5df06d01ee04cbdb2985`](https://www.virustotal.com/gui/file/3052ea8b43bf40e9d4060c95523c7e194238d1ad941f5df06d01ee04cbdb2985) | sha256 | Mirai | threatfox | 2026-10-16T20:54:10Z | 100 |
| [`e4593f7938e76dfb40a3fe5358dfae231ef539a02ef3fda35bbccd6d2b7cdc22`](https://www.virustotal.com/gui/file/e4593f7938e76dfb40a3fe5358dfae231ef539a02ef3fda35bbccd6d2b7cdc22) | sha256 | Mirai | threatfox | 2026-10-16T20:54:09Z | 100 |
| [`9b5ce17a9fff3e65adfdffbd381744f119619d2c400e551b99bcfefc9172c88c`](https://www.virustotal.com/gui/file/9b5ce17a9fff3e65adfdffbd381744f119619d2c400e551b99bcfefc9172c88c) | sha256 | Mirai | threatfox | 2026-10-16T20:54:08Z | 100 |
| [`519037610d98b91631793c846e7ee2a362e6a719369711aa35ea05db81d7d83a`](https://www.virustotal.com/gui/file/519037610d98b91631793c846e7ee2a362e6a719369711aa35ea05db81d7d83a) | sha256 | Mirai | threatfox | 2026-10-16T20:54:07Z | 100 |
| [`84163d8d257699b25a80f976070046a072bc9f59e966fbbd63dd1eae7a4f98d1`](https://www.virustotal.com/gui/file/84163d8d257699b25a80f976070046a072bc9f59e966fbbd63dd1eae7a4f98d1) | sha256 | Mirai | threatfox | 2026-10-16T20:54:06Z | 100 |
| [`b4e0a60ab9fedee7f14a96d4656353ea5d69548419af61bb209745a208785e3d`](https://www.virustotal.com/gui/file/b4e0a60ab9fedee7f14a96d4656353ea5d69548419af61bb209745a208785e3d) | sha256 | Mirai | threatfox | 2026-10-16T20:54:05Z | 100 |
| [`67a4109bc91f88723177955cf327e4ad6e75897e57c6e681493a00cb5e89818d`](https://www.virustotal.com/gui/file/67a4109bc91f88723177955cf327e4ad6e75897e57c6e681493a00cb5e89818d) | sha256 | Mirai | threatfox | 2026-10-16T20:54:04Z | 100 |
| [`3617340c66901935db2cdbb6d2e513b8d772144eb20c57ecc1b7eb588f634285`](https://www.virustotal.com/gui/file/3617340c66901935db2cdbb6d2e513b8d772144eb20c57ecc1b7eb588f634285) | sha256 | Mirai | threatfox | 2026-10-16T20:54:03Z | 100 |
| [`57291108166ac8f40e049939f9e1200462792f697bd1fee151df96eba1303eed`](https://www.virustotal.com/gui/file/57291108166ac8f40e049939f9e1200462792f697bd1fee151df96eba1303eed) | sha256 | Mirai | threatfox | 2026-10-16T20:54:02Z | 100 |
| [`71b77cc8813142f076b260e70f5ac5979f6ddd620f9705eb0f3b8db5012dbb8c`](https://www.virustotal.com/gui/file/71b77cc8813142f076b260e70f5ac5979f6ddd620f9705eb0f3b8db5012dbb8c) | sha256 | Mirai | threatfox | 2026-10-16T20:54:01Z | 100 |
| [`cabee0beea41e1b65b4a1fed0f26dd514b4f5518646d241e760bf2b9bb7d9c17`](https://www.virustotal.com/gui/file/cabee0beea41e1b65b4a1fed0f26dd514b4f5518646d241e760bf2b9bb7d9c17) | sha256 | Mirai | threatfox | 2026-10-16T20:54:00Z | 100 |
| [`1ea36fd1287782a96bc746848356a7993d92f6aac8a5f65112fd0d2b97b551ce`](https://www.virustotal.com/gui/file/1ea36fd1287782a96bc746848356a7993d92f6aac8a5f65112fd0d2b97b551ce) | sha256 | Mirai | threatfox | 2026-10-16T20:53:59Z | 100 |
| [`bddf96d519e14dce50aed9c7c539256bddd3888c16da38d2487bfa39596b5ff6`](https://www.virustotal.com/gui/file/bddf96d519e14dce50aed9c7c539256bddd3888c16da38d2487bfa39596b5ff6) | sha256 | Mirai | threatfox | 2026-10-16T20:53:58Z | 100 |
| [`84798233fabd3ce3ad0fc51625578c42445838385078062cc5e9cfd1efc81c0c`](https://www.virustotal.com/gui/file/84798233fabd3ce3ad0fc51625578c42445838385078062cc5e9cfd1efc81c0c) | sha256 | Mirai | threatfox | 2026-10-16T20:53:57Z | 100 |
| [`7c49c82d332a3cc49b9248abf3bb01c31309eaadb558e595f64c9dde0512f716`](https://www.virustotal.com/gui/file/7c49c82d332a3cc49b9248abf3bb01c31309eaadb558e595f64c9dde0512f716) | sha256 | Mirai | threatfox | 2026-10-16T20:53:56Z | 100 |
| [`a9a8cdb6e564a63b2d1c35a40437820627b97f49ae4878acde7695baa645e58d`](https://www.virustotal.com/gui/file/a9a8cdb6e564a63b2d1c35a40437820627b97f49ae4878acde7695baa645e58d) | sha256 | Mirai | threatfox | 2026-10-16T20:53:55Z | 100 |
| [`7f97b172329ca98b049ade4ff8d1f25dbe23007b629d2bf8bfb701b456179e36`](https://www.virustotal.com/gui/file/7f97b172329ca98b049ade4ff8d1f25dbe23007b629d2bf8bfb701b456179e36) | sha256 | Mirai | threatfox | 2026-10-16T20:53:51Z | 100 |
| [`ouiucyh3[.]web-optimizer[.]us`](https://www.virustotal.com/gui/domain/ouiucyh3.web-optimizer.us) | domain | ClearFake | threatfox | 2026-10-16T20:47:05Z | 100 |
| [`vezlp9pr[.]amanahnaga[.]com`](https://www.virustotal.com/gui/domain/vezlp9pr.amanahnaga.com) | domain | ClearFake | threatfox | 2026-10-16T20:40:43Z | 100 |
| [`1c932818d468835c5bdb9277bdbddee4d9acef206a1da5cfd6600cae6ff3926a`](https://www.virustotal.com/gui/file/1c932818d468835c5bdb9277bdbddee4d9acef206a1da5cfd6600cae6ff3926a) | sha256 | Mirai | threatfox, malwarebazaar | 2026-10-16T19:54:14Z | 100 |
| [`932d3d78df3a50c022caecb3a4cce6731e3416ece00ac2a4f596b3335a3930b4`](https://www.virustotal.com/gui/file/932d3d78df3a50c022caecb3a4cce6731e3416ece00ac2a4f596b3335a3930b4) | sha256 | Mirai | threatfox | 2026-10-16T19:54:13Z | 100 |
| [`edfac2aacde2c5ad263d08023383743db8ceab54659ac5cca9d1d39098000bc2`](https://www.virustotal.com/gui/file/edfac2aacde2c5ad263d08023383743db8ceab54659ac5cca9d1d39098000bc2) | sha256 | Mirai | threatfox | 2026-10-16T19:54:12Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
