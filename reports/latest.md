# Threat Intel Pulse — 2026-10-16

**Window:** last 7 days · **Generated:** 2026-10-16T04:44:48Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 69076 |
| New in window | 21907 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5000 | ok |
| feodo | 5 | ok |
| threatfox | 8095 | ok |
| malwarebazaar | 1044 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8679 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 27656 | 11865 |
| sha256 | 13238 | 3985 |
| domain | 11921 | 2940 |
| ipv4 | 11606 | 2054 |
| ipv6 | 3168 | 262 |
| md5 | 756 | 401 |
| sha1 | 731 | 400 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 10714 |
| Exit nodes | 2369 |
| Other relays | 8345 |
| New in window | 1071 |

Sample (20 of 10714, source: Tor Project Onionoo):
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
| Unknown Loader | 4996 | 519 | — |
| Mirai | 4268 | 747 | T1498, T1071.001 |
| Vidar | 4184 | 3830 | T1555, T1071.001, T1567 |
| AsyncRAT | 2301 | 109 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| ClearFake | 1886 | 673 | — |
| IClickFix | 1492 | 599 | — |
| Cobalt Strike | 1334 | 85 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| Unknown malware | 1066 | 436 | — |
| VShell | 650 | 523 | — |
| Unknown Stealer | 628 | 221 | — |
| php.shin_webshell | 547 | 338 | — |
| PureRAT | 416 | 49 | — |
| AMOS | 405 | 225 | — |
| Sliver | 307 | 284 | T1071.001, T1573, T1090, T1055 |
| Remcos | 287 | 129 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| AdaptixC2 | 286 | 28 | — |
| Remus | 233 | 98 | — |
| Unknown RAT | 205 | 34 | — |
| DanaBot | 195 | 132 | T1566.001, T1071.001, T1555, T1041 |
| Formbook | 184 | 98 | T1566.001, T1056.001, T1555, T1071.001, T1567 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1105 | Ingress Tool Transfer | command-and-control | 22263 |
| T1071.001 | Web Protocols | command-and-control | 43834 |
| T1498 | Network Denial of Service | impact | 9920 |
| T1204.002 | Malicious File | execution | 9071 |
| T1027 | Obfuscated Files or Information | defense-evasion | 8910 |
| T1573 | Encrypted Channel | command-and-control | 8319 |
| T1555 | Credentials from Password Stores | credential-access | 7133 |
| T1567 | Exfiltration Over Web Service | exfiltration | 6938 |
| T1566 | Phishing | initial-access | 5426 |
| T1566.002 | Spearphishing Link | initial-access | 5426 |
| T1552.001 | Credentials In Files | credential-access | 4397 |
| T1056.001 | Keylogging | collection, credential-access | 3802 |
| T1566.001 | Spearphishing Attachment | initial-access | 3496 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 2916 |
| T1113 | Screen Capture | collection | 2876 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1877 |
| T1090 | Proxy | command-and-control | 1676 |
| T1059.001 | PowerShell | execution | 1347 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 363 |
| T1189 | Drive-by Compromise | initial-access | 176 |
| T1218 | System Binary Proxy Execution | defense-evasion | 176 |
| T1059.005 | Visual Basic | execution | 89 |
| T1021.001 | Remote Desktop Protocol | lateral-movement | 14 |
| T1486 | Data Encrypted for Impact | impact | 14 |
| T1490 | Inhibit System Recovery | impact | 14 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 14 |
| T1190 | Exploit Public-Facing Application | initial-access | 5 |
| T1003 | OS Credential Dumping | credential-access | 4 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://ih[.]888-fw[.]com/ks`](https://www.virustotal.com/gui/search/https%3A%2F%2Fih.888-fw.com%2Fks) | url | Vidar | threatfox | 2026-10-16T04:39:56Z | 100 |
| [`hxxps://ih[.]888-fw[.]com/at`](https://www.virustotal.com/gui/search/https%3A%2F%2Fih.888-fw.com%2Fat) | url | Vidar | threatfox | 2026-10-16T04:36:23Z | 100 |
| [`hxxps://ih[.]888-fw[.]com/e/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fih.888-fw.com%2Fe%2F) | url | Vidar | threatfox | 2026-10-16T04:35:48Z | 100 |
| [`hxxps://ih[.]888-fw[.]com/e`](https://www.virustotal.com/gui/search/https%3A%2F%2Fih.888-fw.com%2Fe) | url | Vidar | threatfox | 2026-10-16T04:34:26Z | 100 |
| [`hxxps://ih[.]888-fw[.]com/yy`](https://www.virustotal.com/gui/search/https%3A%2F%2Fih.888-fw.com%2Fyy) | url | Vidar | threatfox | 2026-10-16T04:31:08Z | 100 |
| [`hxxps://ih[.]888-fw[.]com/yy/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fih.888-fw.com%2Fyy%2F) | url | Vidar | threatfox | 2026-10-16T04:30:48Z | 100 |
| [`hxxps://ih[.]888-fw[.]com/v`](https://www.virustotal.com/gui/search/https%3A%2F%2Fih.888-fw.com%2Fv) | url | Vidar | threatfox | 2026-10-16T04:29:00Z | 100 |
| [`hxxps://ih[.]888-fw[.]com/so`](https://www.virustotal.com/gui/search/https%3A%2F%2Fih.888-fw.com%2Fso) | url | Vidar | threatfox | 2026-10-16T04:26:54Z | 100 |
| [`hxxps://ih[.]888-fw[.]com/su/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fih.888-fw.com%2Fsu%2F) | url | Vidar | threatfox | 2026-10-16T04:25:48Z | 100 |
| [`hxxps://ih[.]888-fw[.]com/su`](https://www.virustotal.com/gui/search/https%3A%2F%2Fih.888-fw.com%2Fsu) | url | Vidar | threatfox | 2026-10-16T04:24:52Z | 100 |
| [`hxxps://ih[.]888-fw[.]com/j`](https://www.virustotal.com/gui/search/https%3A%2F%2Fih.888-fw.com%2Fj) | url | Vidar | threatfox | 2026-10-16T04:23:53Z | 100 |
| [`hxxps://ih[.]888-fw[.]com/ab/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fih.888-fw.com%2Fab%2F) | url | Vidar | threatfox | 2026-10-16T04:20:48Z | 100 |
| [`hxxps://ih[.]888-fw[.]com/ab`](https://www.virustotal.com/gui/search/https%3A%2F%2Fih.888-fw.com%2Fab) | url | Vidar | threatfox | 2026-10-16T04:20:40Z | 100 |
| [`hxxps://ih[.]888-fw[.]com/hqg`](https://www.virustotal.com/gui/search/https%3A%2F%2Fih.888-fw.com%2Fhqg) | url | Vidar | threatfox | 2026-10-16T04:18:36Z | 100 |
| [`46[.]249[.]101[.]141`](https://www.virustotal.com/gui/ip-address/46.249.101.141) | ipv4 | Remus | threatfox | 2026-10-16T04:17:38Z | 100 |
| [`hxxps://ih[.]888-fw[.]com/ufs`](https://www.virustotal.com/gui/search/https%3A%2F%2Fih.888-fw.com%2Fufs) | url | Vidar | threatfox | 2026-10-16T04:16:34Z | 100 |
| [`hxxps://ih[.]888-fw[.]com/py/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fih.888-fw.com%2Fpy%2F) | url | Vidar | threatfox | 2026-10-16T04:15:48Z | 100 |
| [`hxxps://ih[.]888-fw[.]com/py`](https://www.virustotal.com/gui/search/https%3A%2F%2Fih.888-fw.com%2Fpy) | url | Vidar | threatfox | 2026-10-16T04:14:40Z | 100 |
| [`hxxps://ih[.]888-fw[.]com/vu`](https://www.virustotal.com/gui/search/https%3A%2F%2Fih.888-fw.com%2Fvu) | url | Vidar | threatfox | 2026-10-16T04:12:26Z | 100 |
| [`hxxps://ih[.]888-fw[.]com/w2/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fih.888-fw.com%2Fw2%2F) | url | Vidar | threatfox | 2026-10-16T04:10:48Z | 100 |
| [`hxxps://ih[.]888-fw[.]com/w2`](https://www.virustotal.com/gui/search/https%3A%2F%2Fih.888-fw.com%2Fw2) | url | Vidar | threatfox | 2026-10-16T04:10:46Z | 100 |
| [`0jye42ba[.]socop[.]space`](https://www.virustotal.com/gui/domain/0jye42ba.socop.space) | domain | ClearFake | threatfox | 2026-10-16T04:10:18Z | 100 |
| [`hxxps://ih[.]888-fw[.]com/tnb`](https://www.virustotal.com/gui/search/https%3A%2F%2Fih.888-fw.com%2Ftnb) | url | Vidar | threatfox | 2026-10-16T04:08:51Z | 100 |
| [`hxxps://ih[.]888-fw[.]com/lk`](https://www.virustotal.com/gui/search/https%3A%2F%2Fih.888-fw.com%2Flk) | url | Vidar | threatfox | 2026-10-16T04:06:48Z | 100 |
| [`hxxps://ih[.]888-fw[.]com/ev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fih.888-fw.com%2Fev%2F) | url | Vidar | threatfox | 2026-10-16T04:05:47Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
