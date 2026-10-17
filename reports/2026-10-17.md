# Threat Intel Pulse — 2026-10-17

**Window:** last 7 days · **Generated:** 2026-10-17T10:58:42Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 73536 |
| New in window | 22776 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5000 | ok |
| feodo | 5 | ok |
| threatfox | 8346 | ok |
| malwarebazaar | 658 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8752 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 29476 | 12107 |
| sha256 | 14518 | 4678 |
| domain | 12751 | 2803 |
| ipv4 | 12015 | 2163 |
| ipv6 | 3207 | 273 |
| md5 | 797 | 376 |
| sha1 | 772 | 376 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 10955 |
| Exit nodes | 2379 |
| Other relays | 8576 |
| New in window | 1098 |

Sample (20 of 10955, source: Tor Project Onionoo):
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
| Unknown Loader | 5155 | 593 | — |
| Mirai | 4870 | 1159 | T1498, T1071.001 |
| Vidar | 4750 | 4353 | T1555, T1071.001, T1567 |
| AsyncRAT | 2313 | 108 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| ClearFake | 1944 | 329 | — |
| IClickFix | 1792 | 567 | — |
| Cobalt Strike | 1347 | 82 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| Unknown malware | 1306 | 548 | — |
| VShell | 880 | 697 | — |
| Unknown Stealer | 631 | 84 | — |
| php.shin_webshell | 601 | 329 | — |
| AMOS | 559 | 353 | — |
| PureRAT | 431 | 56 | — |
| Remcos | 330 | 161 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| Sliver | 316 | 293 | T1071.001, T1573, T1090, T1055 |
| AdaptixC2 | 296 | 28 | — |
| Remus | 241 | 95 | — |
| Unknown RAT | 208 | 36 | — |
| DanaBot | 195 | 110 | T1566.001, T1071.001, T1555, T1041 |
| Formbook | 187 | 89 | T1566.001, T1056.001, T1555, T1071.001, T1567 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1105 | Ingress Tool Transfer | command-and-control | 23261 |
| T1071.001 | Web Protocols | command-and-control | 46417 |
| T1498 | Network Denial of Service | impact | 10633 |
| T1204.002 | Malicious File | execution | 9448 |
| T1027 | Obfuscated Files or Information | defense-evasion | 9286 |
| T1573 | Encrypted Channel | command-and-control | 8762 |
| T1555 | Credentials from Password Stores | credential-access | 7932 |
| T1567 | Exfiltration Over Web Service | exfiltration | 7737 |
| T1566 | Phishing | initial-access | 6027 |
| T1566.002 | Spearphishing Link | initial-access | 6027 |
| T1552.001 | Credentials In Files | credential-access | 4933 |
| T1056.001 | Keylogging | collection, credential-access | 3893 |
| T1566.001 | Spearphishing Attachment | initial-access | 3583 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 2986 |
| T1113 | Screen Capture | collection | 2939 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1920 |
| T1090 | Proxy | command-and-control | 1700 |
| T1059.001 | PowerShell | execution | 1361 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 378 |
| T1189 | Drive-by Compromise | initial-access | 178 |
| T1218 | System Binary Proxy Execution | defense-evasion | 178 |
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
| [`hxxps://va[.]8mytogel[.]org/r2/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fva.8mytogel.org%2Fr2%2F) | url | Vidar | threatfox | 2026-10-17T10:45:48Z | 100 |
| [`7d726eba93c51f7156b031ce1c80a6d5bbe9338689da508c2ecce72692264387`](https://www.virustotal.com/gui/file/7d726eba93c51f7156b031ce1c80a6d5bbe9338689da508c2ecce72692264387) | sha256 | AMOS | threatfox | 2026-10-17T10:45:15Z | 100 |
| [`5b015deebcfd8dd242d88ea20354b7907284cb2bb004e463fb18feb36d5d546f`](https://www.virustotal.com/gui/file/5b015deebcfd8dd242d88ea20354b7907284cb2bb004e463fb18feb36d5d546f) | sha256 | AMOS | threatfox | 2026-10-17T10:41:55Z | 100 |
| [`hxxps://va[.]8mytogel[.]org/ap/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fva.8mytogel.org%2Fap%2F) | url | Vidar | threatfox | 2026-10-17T10:40:48Z | 100 |
| [`6f5de2a227a53bbed2d2b5eb1358623bcf2516a469f5fd87a32cc03a0cd02a0c`](https://www.virustotal.com/gui/file/6f5de2a227a53bbed2d2b5eb1358623bcf2516a469f5fd87a32cc03a0cd02a0c) | sha256 | AMOS | threatfox | 2026-10-17T10:37:21Z | 100 |
| [`hxxps://j[.]88mdc[.]org/d/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fj.88mdc.org%2Fd%2F) | url | Vidar | threatfox | 2026-10-17T10:35:48Z | 100 |
| [`hxxps://va[.]8mytogel[.]org/y5/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fva.8mytogel.org%2Fy5%2F) | url | Vidar | threatfox | 2026-10-17T10:35:48Z | 100 |
| [`cb8f15a422c7042992fa0a8ef2477fb3526bee7d52d6ca5f4a3917d46e01373b`](https://www.virustotal.com/gui/file/cb8f15a422c7042992fa0a8ef2477fb3526bee7d52d6ca5f4a3917d46e01373b) | sha256 | AMOS | threatfox | 2026-10-17T10:33:30Z | 100 |
| [`hxxps://va[.]8mytogel[.]org/ha/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fva.8mytogel.org%2Fha%2F) | url | Vidar | threatfox | 2026-10-17T10:30:48Z | 100 |
| [`d62461075ab948cc267d013f737b320a4367f2819024ed7ecdd52d7450b1ec83`](https://www.virustotal.com/gui/file/d62461075ab948cc267d013f737b320a4367f2819024ed7ecdd52d7450b1ec83) | sha256 | AMOS | threatfox | 2026-10-17T10:28:56Z | 100 |
| [`veronicacucco[.]it`](https://www.virustotal.com/gui/domain/veronicacucco.it) | domain | IClickFix | threatfox | 2026-10-17T10:27:29Z | 100 |
| [`verttige[.]tn`](https://www.virustotal.com/gui/domain/verttige.tn) | domain | IClickFix | threatfox | 2026-10-17T10:27:29Z | 100 |
| [`vickymarine[.]com`](https://www.virustotal.com/gui/domain/vickymarine.com) | domain | IClickFix | threatfox | 2026-10-17T10:27:29Z | 100 |
| [`vidieckymakler[.]sk`](https://www.virustotal.com/gui/domain/vidieckymakler.sk) | domain | IClickFix | threatfox | 2026-10-17T10:27:29Z | 100 |
| [`volana[.]io`](https://www.virustotal.com/gui/domain/volana.io) | domain | IClickFix | threatfox | 2026-10-17T10:27:29Z | 100 |
| [`welderswelfare[.]com`](https://www.virustotal.com/gui/domain/welderswelfare.com) | domain | IClickFix | threatfox | 2026-10-17T10:27:29Z | 100 |
| [`wildwood20[.]com`](https://www.virustotal.com/gui/domain/wildwood20.com) | domain | IClickFix | threatfox | 2026-10-17T10:27:29Z | 100 |
| [`yelphelper[.]com`](https://www.virustotal.com/gui/domain/yelphelper.com) | domain | IClickFix | threatfox | 2026-10-17T10:27:29Z | 100 |
| [`yocvn[.]top`](https://www.virustotal.com/gui/domain/yocvn.top) | domain | IClickFix | threatfox | 2026-10-17T10:27:29Z | 100 |
| [`zenequitycapital[.]com`](https://www.virustotal.com/gui/domain/zenequitycapital.com) | domain | IClickFix | threatfox | 2026-10-17T10:27:29Z | 100 |
| [`zlab[.]it`](https://www.virustotal.com/gui/domain/zlab.it) | domain | IClickFix | threatfox | 2026-10-17T10:27:29Z | 100 |
| [`singlefixedmatch[.]com`](https://www.virustotal.com/gui/domain/singlefixedmatch.com) | domain | IClickFix | threatfox | 2026-10-17T10:27:28Z | 100 |
| [`siranrealty[.]com`](https://www.virustotal.com/gui/domain/siranrealty.com) | domain | IClickFix | threatfox | 2026-10-17T10:27:28Z | 100 |
| [`skanbo[.]se`](https://www.virustotal.com/gui/domain/skanbo.se) | domain | IClickFix | threatfox | 2026-10-17T10:27:28Z | 100 |
| [`spanishlessonslosangeles[.]com`](https://www.virustotal.com/gui/domain/spanishlessonslosangeles.com) | domain | IClickFix | threatfox | 2026-10-17T10:27:28Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
