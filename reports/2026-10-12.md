# Threat Intel Pulse — 2026-10-12

**Window:** last 7 days · **Generated:** 2026-10-12T15:46:59Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 56490 |
| New in window | 26696 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5000 | ok |
| feodo | 5 | ok |
| threatfox | 5937 | ok |
| malwarebazaar | 944 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8568 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 20458 | 14328 |
| sha256 | 11069 | 4688 |
| domain | 10518 | 4989 |
| ipv4 | 10491 | 1796 |
| ipv6 | 2979 | 226 |
| md5 | 500 | 335 |
| sha1 | 475 | 334 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 10132 |
| Exit nodes | 2225 |
| Other relays | 7907 |
| New in window | 1158 |

Sample (20 of 10132, source: Tor Project Onionoo):
- `1[.]201[.]176[.]176`
- `1[.]248[.]96[.]163`
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
- `102[.]68[.]99[.]63`

Full list: `dist/tor/tor_nodes.txt` (in the `threat-intel-output` workflow artifact).
## Top malware families

| Family | Indicators | New | ATT&CK (heuristic) |
| --- | --- | --- | --- |
| Unknown Loader | 4569 | 1862 | — |
| Mirai | 3960 | 1146 | T1498, T1071.001 |
| AsyncRAT | 2232 | 72 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| ClearFake | 1698 | 1311 | — |
| IClickFix | 1303 | 959 | — |
| Cobalt Strike | 1284 | 52 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| Unknown malware | 931 | 456 | — |
| Vidar | 785 | 586 | T1555, T1071.001, T1567 |
| Unknown Stealer | 566 | 394 | — |
| PureRAT | 387 | 54 | — |
| php.shin_webshell | 387 | 316 | — |
| VShell | 279 | 174 | — |
| AdaptixC2 | 275 | 30 | — |
| AMOS | 267 | 151 | — |
| Remcos | 196 | 93 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| DanaBot | 192 | 129 | T1566.001, T1071.001, T1555, T1041 |
| Unknown RAT | 185 | 48 | — |
| Remus | 164 | 74 | — |
| DCRat | 110 | 13 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| Jackskid | 104 | 59 | — |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1105 | Ingress Tool Transfer | command-and-control | 17998 |
| T1071.001 | Web Protocols | command-and-control | 36802 |
| T1498 | Network Denial of Service | impact | 9082 |
| T1204.002 | Malicious File | execution | 6419 |
| T1027 | Obfuscated Files or Information | defense-evasion | 6408 |
| T1573 | Encrypted Channel | command-and-control | 5183 |
| T1056.001 | Keylogging | collection, credential-access | 3405 |
| T1566 | Phishing | initial-access | 3382 |
| T1566.002 | Spearphishing Link | initial-access | 3382 |
| T1555 | Credentials from Password Stores | credential-access | 3238 |
| T1566.001 | Spearphishing Attachment | initial-access | 3136 |
| T1567 | Exfiltration Over Web Service | exfiltration | 3046 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 2674 |
| T1113 | Screen Capture | collection | 2642 |
| T1552.001 | Credentials In Files | credential-access | 1652 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1549 |
| T1090 | Proxy | command-and-control | 1371 |
| T1059.001 | PowerShell | execution | 1297 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 333 |
| T1059.005 | Visual Basic | execution | 74 |
| T1189 | Drive-by Compromise | initial-access | 22 |
| T1218 | System Binary Proxy Execution | defense-evasion | 22 |
| T1021.001 | Remote Desktop Protocol | lateral-movement | 8 |
| T1486 | Data Encrypted for Impact | impact | 8 |
| T1490 | Inhibit System Recovery | impact | 8 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 8 |
| T1190 | Exploit Public-Facing Application | initial-access | 2 |
| T1003 | OS Credential Dumping | credential-access | 1 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://bob[.]6666k[.]org`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbob.6666k.org) | url | Vidar | threatfox | 2026-10-12T15:43:10Z | 100 |
| [`bob[.]6666k[.]org`](https://www.virustotal.com/gui/domain/bob.6666k.org) | domain | Vidar | threatfox | 2026-10-12T15:40:48Z | 100 |
| [`hxxps://bob[.]6666k[.]org/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbob.6666k.org%2F) | url | Vidar | threatfox | 2026-10-12T15:40:48Z | 100 |
| [`x3a[.]6666k[.]org`](https://www.virustotal.com/gui/domain/x3a.6666k.org) | domain | Vidar | threatfox | 2026-10-12T15:35:48Z | 100 |
| [`hxxps://x3a[.]6666k[.]org/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fx3a.6666k.org%2F) | url | Vidar | threatfox | 2026-10-12T15:35:48Z | 100 |
| [`hxxps://x3a[.]6666k[.]org`](https://www.virustotal.com/gui/search/https%3A%2F%2Fx3a.6666k.org) | url | Vidar | threatfox | 2026-10-12T15:32:11Z | 100 |
| [`nyr[.]6666k[.]org`](https://www.virustotal.com/gui/domain/nyr.6666k.org) | domain | Vidar | threatfox | 2026-10-12T15:20:48Z | 100 |
| [`hxxps://nyr[.]6666k[.]org/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fnyr.6666k.org%2F) | url | Vidar | threatfox | 2026-10-12T15:20:48Z | 100 |
| [`hxxps://nyr[.]6666k[.]org`](https://www.virustotal.com/gui/search/https%3A%2F%2Fnyr.6666k.org) | url | Vidar | threatfox | 2026-10-12T15:20:31Z | 100 |
| [`139[.]59[.]140[.]128`](https://www.virustotal.com/gui/ip-address/139.59.140.128) | ipv4 | Aisuru | threatfox | 2026-10-12T15:19:38Z | 100 |
| [`147[.]182[.]144[.]201`](https://www.virustotal.com/gui/ip-address/147.182.144.201) | ipv4 | Aisuru | threatfox | 2026-10-12T15:19:38Z | 100 |
| [`157[.]230[.]253[.]1`](https://www.virustotal.com/gui/ip-address/157.230.253.1) | ipv4 | Aisuru | threatfox | 2026-10-12T15:19:38Z | 100 |
| [`165[.]232[.]121[.]229`](https://www.virustotal.com/gui/ip-address/165.232.121.229) | ipv4 | Aisuru | threatfox | 2026-10-12T15:19:38Z | 100 |
| [`168[.]144[.]110[.]142`](https://www.virustotal.com/gui/ip-address/168.144.110.142) | ipv4 | Aisuru | threatfox | 2026-10-12T15:19:38Z | 100 |
| [`68[.]183[.]195[.]109`](https://www.virustotal.com/gui/ip-address/68.183.195.109) | ipv4 | Aisuru | threatfox | 2026-10-12T15:19:38Z | 100 |
| [`palm[.]blueridgekcmo[.]com`](https://www.virustotal.com/gui/domain/palm.blueridgekcmo.com) | domain | ClearFake | threatfox | 2026-10-12T15:09:04Z | 100 |
| [`hxxps://q6[.]6666k[.]org`](https://www.virustotal.com/gui/search/https%3A%2F%2Fq6.6666k.org) | url | Vidar | threatfox | 2026-10-12T15:02:13Z | 100 |
| [`q6[.]6666k[.]org`](https://www.virustotal.com/gui/domain/q6.6666k.org) | domain | Vidar | threatfox | 2026-10-12T15:00:49Z | 100 |
| [`hxxps://q6[.]6666k[.]org/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fq6.6666k.org%2F) | url | Vidar | threatfox | 2026-10-12T15:00:49Z | 100 |
| [`hxxps://104[.]105[.]24[.]45`](https://www.virustotal.com/gui/search/https%3A%2F%2F104.105.24.45) | url | Vidar | threatfox | 2026-10-12T15:00:13Z | 100 |
| [`zpz[.]6666k[.]org`](https://www.virustotal.com/gui/domain/zpz.6666k.org) | domain | Vidar | threatfox | 2026-10-12T14:45:48Z | 100 |
| [`hxxps://zpz[.]6666k[.]org/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fzpz.6666k.org%2F) | url | Vidar | threatfox | 2026-10-12T14:45:48Z | 100 |
| [`a3deb1201b060c502f39795e922c27af0387e84c942fa2539a588ae97091ff39`](https://www.virustotal.com/gui/file/a3deb1201b060c502f39795e922c27af0387e84c942fa2539a588ae97091ff39) | sha256 | AMOS | threatfox | 2026-10-12T14:42:56Z | 100 |
| [`msm[.]6666k[.]org`](https://www.virustotal.com/gui/domain/msm.6666k.org) | domain | Vidar | threatfox | 2026-10-12T14:25:48Z | 100 |
| [`hxxps://msm[.]6666k[.]org/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmsm.6666k.org%2F) | url | Vidar | threatfox | 2026-10-12T14:25:48Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
