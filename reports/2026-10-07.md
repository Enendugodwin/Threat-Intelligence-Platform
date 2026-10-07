# Threat Intel Pulse — 2026-10-07

**Window:** last 7 days · **Generated:** 2026-10-07T23:13:16Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 42858 |
| New in window | 42858 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5000 | ok |
| feodo | 5 | ok |
| threatfox | 8415 | ok |
| malwarebazaar | 1350 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8631 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 13150 | 13150 |
| ipv4 | 9322 | 9322 |
| sha256 | 8665 | 8665 |
| domain | 8228 | 8228 |
| ipv6 | 2883 | 2883 |
| md5 | 317 | 317 |
| sha1 | 293 | 293 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 9492 |
| Exit nodes | 2189 |
| Other relays | 7303 |
| New in window | 9492 |

Sample (20 of 9492, source: Tor Project Onionoo):
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
| Unknown Loader | 4103 | 4103 | — |
| Mirai | 3305 | 3305 | T1498, T1071.001 |
| AsyncRAT | 2184 | 2184 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| Cobalt Strike | 1245 | 1245 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| ClearFake | 1098 | 1098 | — |
| IClickFix | 739 | 739 | — |
| Unknown malware | 563 | 563 | — |
| PureRAT | 360 | 360 | — |
| Unknown Stealer | 340 | 340 | — |
| Vidar | 305 | 305 | T1555, T1071.001, T1567 |
| AdaptixC2 | 254 | 254 | — |
| Unknown RAT | 170 | 170 | — |
| AMOS | 164 | 164 | — |
| Remcos | 147 | 147 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| php.shin_webshell | 142 | 142 | — |
| Remus | 121 | 121 | — |
| VShell | 115 | 115 | — |
| DCRat | 104 | 104 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| Evilginx | 95 | 95 | — |
| Havoc | 91 | 91 | — |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1105 | Ingress Tool Transfer | command-and-control | 13036 |
| T1071.001 | Web Protocols | command-and-control | 30485 |
| T1498 | Network Denial of Service | impact | 7565 |
| T1204.002 | Malicious File | execution | 5488 |
| T1027 | Obfuscated Files or Information | defense-evasion | 5477 |
| T1573 | Encrypted Channel | command-and-control | 4729 |
| T1056.001 | Keylogging | collection, credential-access | 3116 |
| T1566.001 | Spearphishing Attachment | initial-access | 2769 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 2514 |
| T1113 | Screen Capture | collection | 2492 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1431 |
| T1566 | Phishing | initial-access | 1428 |
| T1566.002 | Spearphishing Link | initial-access | 1428 |
| T1090 | Proxy | command-and-control | 1285 |
| T1059.001 | PowerShell | execution | 1258 |
| T1555 | Credentials from Password Stores | credential-access | 1026 |
| T1567 | Exfiltration Over Web Service | exfiltration | 963 |
| T1552.001 | Credentials In Files | credential-access | 632 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 166 |
| T1059.005 | Visual Basic | execution | 61 |
| T1189 | Drive-by Compromise | initial-access | 19 |
| T1218 | System Binary Proxy Execution | defense-evasion | 19 |
| T1021.001 | Remote Desktop Protocol | lateral-movement | 8 |
| T1486 | Data Encrypted for Impact | impact | 8 |
| T1490 | Inhibit System Recovery | impact | 8 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 8 |
| T1003 | OS Credential Dumping | credential-access | 1 |
| T1190 | Exploit Public-Facing Application | initial-access | 1 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`tivex[.]store`](https://www.virustotal.com/gui/domain/tivex.store) | domain | ClearFake | threatfox | 2026-10-07T22:23:32Z | 100 |
| [`63ruwbkm[.]pinke[.]store`](https://www.virustotal.com/gui/domain/63ruwbkm.pinke.store) | domain | ClearFake | threatfox | 2026-10-07T21:42:20Z | 100 |
| [`gy[.]3toto[.]com`](https://www.virustotal.com/gui/domain/gy.3toto.com) | domain | Vidar | threatfox | 2026-10-07T21:35:48Z | 100 |
| [`hxxps://gy[.]3toto[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fgy.3toto.com%2F) | url | Vidar | threatfox | 2026-10-07T21:35:48Z | 100 |
| [`pinke[.]store`](https://www.virustotal.com/gui/domain/pinke.store) | domain | ClearFake | threatfox | 2026-10-07T21:32:05Z | 100 |
| [`gy[.]333vip[.]org`](https://www.virustotal.com/gui/domain/gy.333vip.org) | domain | Vidar | threatfox | 2026-10-07T21:30:48Z | 100 |
| [`hxxps://gy[.]333vip[.]org/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fgy.333vip.org%2F) | url | Vidar | threatfox | 2026-10-07T21:30:48Z | 100 |
| [`196[.]77[.]102[.]208`](https://www.virustotal.com/gui/ip-address/196.77.102.208) | ipv4 | AsyncRAT | threatfox | 2026-10-07T21:05:05Z | 100 |
| [`3d-loft[.]com[.]ua`](https://www.virustotal.com/gui/domain/3d-loft.com.ua) | domain | Unknown Stealer | threatfox | 2026-10-07T20:42:36Z | 100 |
| [`allmotovelo[.]com[.]ua`](https://www.virustotal.com/gui/domain/allmotovelo.com.ua) | domain | Unknown Stealer | threatfox | 2026-10-07T20:42:36Z | 100 |
| [`cosmari[.]com[.]ua`](https://www.virustotal.com/gui/domain/cosmari.com.ua) | domain | Unknown Stealer | threatfox | 2026-10-07T20:42:36Z | 100 |
| [`cosmetea[.]com[.]ua`](https://www.virustotal.com/gui/domain/cosmetea.com.ua) | domain | Unknown Stealer | threatfox | 2026-10-07T20:42:36Z | 100 |
| [`domomoda[.]com`](https://www.virustotal.com/gui/domain/domomoda.com) | domain | Unknown Stealer | threatfox | 2026-10-07T20:42:36Z | 100 |
| [`electro-shop[.]in[.]ua`](https://www.virustotal.com/gui/domain/electro-shop.in.ua) | domain | Unknown Stealer | threatfox | 2026-10-07T20:42:36Z | 100 |
| [`eshoping[.]ua`](https://www.virustotal.com/gui/domain/eshoping.ua) | domain | Unknown Stealer | threatfox | 2026-10-07T20:42:36Z | 100 |
| [`gerts[.]com[.]ua`](https://www.virustotal.com/gui/domain/gerts.com.ua) | domain | Unknown Stealer | threatfox | 2026-10-07T20:42:36Z | 100 |
| [`gigistore[.]com[.]ua`](https://www.virustotal.com/gui/domain/gigistore.com.ua) | domain | Unknown Stealer | threatfox | 2026-10-07T20:42:36Z | 100 |
| [`jrl[.]in[.]ua`](https://www.virustotal.com/gui/domain/jrl.in.ua) | domain | Unknown Stealer | threatfox | 2026-10-07T20:42:36Z | 100 |
| [`kolesa[.]dp[.]ua`](https://www.virustotal.com/gui/domain/kolesa.dp.ua) | domain | Unknown Stealer | threatfox | 2026-10-07T20:42:36Z | 100 |
| [`lbcbooks[.]com[.]ua`](https://www.virustotal.com/gui/domain/lbcbooks.com.ua) | domain | Unknown Stealer | threatfox | 2026-10-07T20:42:36Z | 100 |
| [`marshmallow[.]com[.]ua`](https://www.virustotal.com/gui/domain/marshmallow.com.ua) | domain | Unknown Stealer | threatfox | 2026-10-07T20:42:36Z | 100 |
| [`motos[.]in[.]ua`](https://www.virustotal.com/gui/domain/motos.in.ua) | domain | Unknown Stealer | threatfox | 2026-10-07T20:42:36Z | 100 |
| [`opttime[.]com[.]ua`](https://www.virustotal.com/gui/domain/opttime.com.ua) | domain | Unknown Stealer | threatfox | 2026-10-07T20:42:36Z | 100 |
| [`planetakovrov[.]com`](https://www.virustotal.com/gui/domain/planetakovrov.com) | domain | Unknown Stealer | threatfox | 2026-10-07T20:42:36Z | 100 |
| [`profcare[.]com[.]ua`](https://www.virustotal.com/gui/domain/profcare.com.ua) | domain | Unknown Stealer | threatfox | 2026-10-07T20:42:36Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
