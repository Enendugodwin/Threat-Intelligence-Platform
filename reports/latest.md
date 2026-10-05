# Threat Intel Pulse — 2026-10-05

**Window:** last 7 days · **Generated:** 2026-10-05T15:01:19Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 29794 |
| New in window | 29794 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 27 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5000 | ok |
| feodo | 5 | ok |
| threatfox | 8523 | ok |
| malwarebazaar | 1158 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8563 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 8695 | 8695 |
| sha256 | 6381 | 6381 |
| url | 6130 | 6130 |
| domain | 5529 | 5529 |
| ipv6 | 2753 | 2753 |
| md5 | 165 | 165 |
| sha1 | 141 | 141 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 8974 |
| Exit nodes | 2084 |
| Other relays | 6890 |
| New in window | 8974 |

Sample (20 of 8974, source: Tor Project Onionoo):
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
| Mirai | 2803 | 2803 | T1498, T1071.001 |
| Unknown Loader | 2672 | 2672 | — |
| AsyncRAT | 2160 | 2160 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| Cobalt Strike | 1232 | 1232 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| Unknown malware | 475 | 475 | — |
| ClearFake | 387 | 387 | — |
| IClickFix | 344 | 344 | — |
| PureRAT | 333 | 333 | — |
| AdaptixC2 | 245 | 245 | — |
| Vidar | 199 | 199 | T1555, T1071.001, T1567 |
| Unknown Stealer | 170 | 170 | — |
| Unknown RAT | 137 | 137 | — |
| AMOS | 116 | 116 | — |
| VShell | 105 | 105 | — |
| Remcos | 103 | 103 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| DCRat | 97 | 97 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| Evilginx | 92 | 92 | — |
| Remus | 90 | 90 | — |
| Havoc | 86 | 86 | — |
| php.shin_webshell | 71 | 71 | — |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1071.001 | Web Protocols | command-and-control | 25580 |
| T1105 | Ingress Tool Transfer | command-and-control | 6690 |
| T1498 | Network Denial of Service | impact | 6295 |
| T1573 | Encrypted Channel | command-and-control | 4505 |
| T1056.001 | Keylogging | collection, credential-access | 2918 |
| T1566.001 | Spearphishing Attachment | initial-access | 2618 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 2421 |
| T1113 | Screen Capture | collection | 2401 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1394 |
| T1090 | Proxy | command-and-control | 1267 |
| T1059.001 | PowerShell | execution | 1244 |
| T1566 | Phishing | initial-access | 684 |
| T1566.002 | Spearphishing Link | initial-access | 684 |
| T1555 | Credentials from Password Stores | credential-access | 652 |
| T1567 | Exfiltration Over Web Service | exfiltration | 589 |
| T1552.001 | Credentials In Files | credential-access | 398 |
| T1027 | Obfuscated Files or Information | defense-evasion | 343 |
| T1204.002 | Malicious File | execution | 343 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 145 |
| T1059.005 | Visual Basic | execution | 59 |
| T1021.001 | Remote Desktop Protocol | lateral-movement | 5 |
| T1189 | Drive-by Compromise | initial-access | 5 |
| T1218 | System Binary Proxy Execution | defense-evasion | 5 |
| T1486 | Data Encrypted for Impact | impact | 5 |
| T1490 | Inhibit System Recovery | impact | 5 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 5 |
| T1003 | OS Credential Dumping | credential-access | 1 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`clouddelivry[.]com`](https://www.virustotal.com/gui/domain/clouddelivry.com) | domain | IClickFix | threatfox | 2026-10-05T14:46:54Z | 100 |
| [`5a068fea365cfeef2c0c6f0999b10b506fa1e0e79b00445ecdef6e4e433f7b5a`](https://www.virustotal.com/gui/file/5a068fea365cfeef2c0c6f0999b10b506fa1e0e79b00445ecdef6e4e433f7b5a) | sha256 | AMOS | threatfox | 2026-10-05T14:38:21Z | 100 |
| [`206[.]123[.]129[.]234`](https://www.virustotal.com/gui/ip-address/206.123.129.234) | ipv4 | Remcos | threatfox | 2026-10-05T14:38:20Z | 100 |
| [`137[.]184[.]108[.]14`](https://www.virustotal.com/gui/ip-address/137.184.108.14) | ipv4 | Remus | threatfox | 2026-10-05T14:38:20Z | 100 |
| [`9080d9c9982190322f8b3a209dd76d54adcb0487b34e16f853307dc9dca646b9`](https://www.virustotal.com/gui/file/9080d9c9982190322f8b3a209dd76d54adcb0487b34e16f853307dc9dca646b9) | sha256 | AMOS | threatfox | 2026-10-05T14:38:19Z | 100 |
| [`134[.]122[.]91[.]85`](https://www.virustotal.com/gui/ip-address/134.122.91.85) | ipv4 | Aisuru | threatfox | 2026-10-05T14:38:17Z | 100 |
| [`138[.]68[.]135[.]200`](https://www.virustotal.com/gui/ip-address/138.68.135.200) | ipv4 | Aisuru | threatfox | 2026-10-05T14:38:17Z | 100 |
| [`164[.]92[.]243[.]20`](https://www.virustotal.com/gui/ip-address/164.92.243.20) | ipv4 | Aisuru | threatfox | 2026-10-05T14:38:17Z | 100 |
| [`5r35llx8[.]deamobros[.]com`](https://www.virustotal.com/gui/domain/5r35llx8.deamobros.com) | domain | ClearFake | threatfox | 2026-10-05T14:07:50Z | 100 |
| [`deamobros[.]com`](https://www.virustotal.com/gui/domain/deamobros.com) | domain | ClearFake | threatfox | 2026-10-05T14:05:08Z | 100 |
| [`sensa138[.]pro`](https://www.virustotal.com/gui/domain/sensa138.pro) | domain | ClearFake | threatfox | 2026-10-05T13:47:31Z | 100 |
| [`hxxps://cdn[.]jsdelivr[.]net/gh/04fb-ff/c19e1173-a40b-4198-b705-b85466f6cde0/119-73c4846d6ec9`](https://www.virustotal.com/gui/search/https%3A%2F%2Fcdn.jsdelivr.net%2Fgh%2F04fb-ff%2Fc19e1173-a40b-4198-b705-b85466f6cde0%2F119-73c4846d6ec9) | url | ClearFake | threatfox | 2026-10-05T13:45:47Z | 100 |
| [`linuxfortravelers[.]com`](https://www.virustotal.com/gui/domain/linuxfortravelers.com) | domain | ClearFake | threatfox | 2026-10-05T13:44:22Z | 100 |
| [`brixtonhomes[.]com[.]au`](https://www.virustotal.com/gui/domain/brixtonhomes.com.au) | domain | ClearFake | threatfox | 2026-10-05T13:36:53Z | 100 |
| [`bizuterdigital[.]com[.]au`](https://www.virustotal.com/gui/domain/bizuterdigital.com.au) | domain | ClearFake | threatfox | 2026-10-05T13:35:42Z | 100 |
| [`bizuter[.]com`](https://www.virustotal.com/gui/domain/bizuter.com) | domain | ClearFake | threatfox | 2026-10-05T13:34:41Z | 100 |
| [`bizuter[.]au`](https://www.virustotal.com/gui/domain/bizuter.au) | domain | ClearFake | threatfox | 2026-10-05T13:31:40Z | 100 |
| [`roxymigurdia[.]wiki`](https://www.virustotal.com/gui/domain/roxymigurdia.wiki) | domain | ClearFake | threatfox | 2026-10-05T13:30:05Z | 100 |
| [`hxxps://cdn[.]jsdelivr[.]net/gh/20fd0ae3e004/0d377d00-78a8-4d8d-90b1-243adcb9e9fd/84e8-38f0a7270d68`](https://www.virustotal.com/gui/search/https%3A%2F%2Fcdn.jsdelivr.net%2Fgh%2F20fd0ae3e004%2F0d377d00-78a8-4d8d-90b1-243adcb9e9fd%2F84e8-38f0a7270d68) | url | ClearFake | threatfox | 2026-10-05T13:29:04Z | 100 |
| [`84df34daa1dd09d5ad5c6a259d3546940b0dec4ffa54966135d341c0692ce828`](https://www.virustotal.com/gui/file/84df34daa1dd09d5ad5c6a259d3546940b0dec4ffa54966135d341c0692ce828) | sha256 | ClearFake | threatfox | 2026-10-05T13:27:18Z | 100 |
| [`businessclassdeals[.]com[.]au`](https://www.virustotal.com/gui/domain/businessclassdeals.com.au) | domain | ClearFake | threatfox | 2026-10-05T13:25:11Z | 100 |
| [`connectcapita[.]com`](https://www.virustotal.com/gui/domain/connectcapita.com) | domain | ClearFake | threatfox | 2026-10-05T13:24:02Z | 100 |
| [`connectcapita[.]com[.]au`](https://www.virustotal.com/gui/domain/connectcapita.com.au) | domain | ClearFake | threatfox | 2026-10-05T13:22:59Z | 100 |
| [`chamomilecanto[.]co`](https://www.virustotal.com/gui/domain/chamomilecanto.co) | domain | SmartApeSG | threatfox | 2026-10-05T13:22:43Z | 100 |
| [`crmplatform[.]com[.]au`](https://www.virustotal.com/gui/domain/crmplatform.com.au) | domain | ClearFake | threatfox | 2026-10-05T13:22:18Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
