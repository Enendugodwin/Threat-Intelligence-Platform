# Threat Intel Pulse — 2026-10-19

**Window:** last 7 days · **Generated:** 2026-10-19T13:40:26Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 79894 |
| New in window | 25238 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5000 | ok |
| feodo | 5 | ok |
| threatfox | 6980 | ok |
| malwarebazaar | 1099 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8728 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 32651 | 13320 |
| sha256 | 15946 | 5254 |
| domain | 13576 | 3193 |
| ipv4 | 12622 | 2314 |
| ipv6 | 3279 | 312 |
| md5 | 923 | 423 |
| sha1 | 897 | 422 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 11299 |
| Exit nodes | 2411 |
| Other relays | 8888 |
| New in window | 1216 |

Sample (20 of 11299, source: Tor Project Onionoo):
- `1[.]201[.]176[.]176`
- `1[.]235[.]159[.]83`
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

Full list: `dist/tor/tor_nodes.txt` (in the `threat-intel-output` workflow artifact).
## Top malware families

| Family | Indicators | New | ATT&CK (heuristic) |
| --- | --- | --- | --- |
| Vidar | 5425 | 4722 | T1555, T1071.001, T1567 |
| Unknown Loader | 5417 | 842 | — |
| Mirai | 5076 | 1136 | T1498, T1071.001 |
| AsyncRAT | 2323 | 95 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| IClickFix | 2099 | 809 | — |
| ClearFake | 2014 | 328 | — |
| Unknown malware | 1608 | 715 | — |
| Cobalt Strike | 1362 | 87 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| VShell | 901 | 625 | — |
| AMOS | 774 | 523 | — |
| php.shin_webshell | 669 | 301 | — |
| Unknown Stealer | 641 | 76 | — |
| PureRAT | 450 | 69 | — |
| Sliver | 376 | 316 | T1071.001, T1573, T1090, T1055 |
| Remcos | 352 | 175 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| AdaptixC2 | 303 | 30 | — |
| Remus | 259 | 98 | — |
| Unknown RAT | 228 | 49 | — |
| Formbook | 206 | 102 | T1566.001, T1056.001, T1555, T1071.001, T1567 |
| DanaBot | 195 | 59 | T1566.001, T1071.001, T1555, T1041 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1071.001 | Web Protocols | command-and-control | 50416 |
| T1105 | Ingress Tool Transfer | command-and-control | 24395 |
| T1498 | Network Denial of Service | impact | 12333 |
| T1204.002 | Malicious File | execution | 9544 |
| T1027 | Obfuscated Files or Information | defense-evasion | 9382 |
| T1573 | Encrypted Channel | command-and-control | 8946 |
| T1555 | Credentials from Password Stores | credential-access | 8938 |
| T1567 | Exfiltration Over Web Service | exfiltration | 8743 |
| T1566 | Phishing | initial-access | 7350 |
| T1566.002 | Spearphishing Link | initial-access | 7350 |
| T1552.001 | Credentials In Files | credential-access | 5254 |
| T1056.001 | Keylogging | collection, credential-access | 4007 |
| T1566.001 | Spearphishing Attachment | initial-access | 3690 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 3057 |
| T1113 | Screen Capture | collection | 2996 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 2004 |
| T1090 | Proxy | command-and-control | 1776 |
| T1059.001 | PowerShell | execution | 1376 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 390 |
| T1189 | Drive-by Compromise | initial-access | 178 |
| T1218 | System Binary Proxy Execution | defense-evasion | 178 |
| T1059.005 | Visual Basic | execution | 95 |
| T1021.001 | Remote Desktop Protocol | lateral-movement | 14 |
| T1486 | Data Encrypted for Impact | impact | 14 |
| T1490 | Inhibit System Recovery | impact | 14 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 14 |
| T1190 | Exploit Public-Facing Application | initial-access | 10 |
| T1003 | OS Credential Dumping | credential-access | 4 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://ou[.]9kio[.]org/a/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fou.9kio.org%2Fa%2F) | url | Vidar | threatfox | 2026-10-19T13:30:48Z | 100 |
| [`hxxps://j[.]abalbet[.]com/y/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fj.abalbet.com%2Fy%2F) | url | Vidar | threatfox | 2026-10-19T13:30:48Z | 100 |
| [`hxxps://j[.]abalbet[.]com/u/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fj.abalbet.com%2Fu%2F) | url | Vidar | threatfox | 2026-10-19T13:25:48Z | 100 |
| [`08e7c04e22c51313e5095f2db39e11fcc59adf56a63481ae92d8730e2788edc7`](https://www.virustotal.com/gui/file/08e7c04e22c51313e5095f2db39e11fcc59adf56a63481ae92d8730e2788edc7) | sha256 | AMOS | threatfox | 2026-10-19T13:25:03Z | 100 |
| [`hxxps://groverudder12[.]com/curl/c5iu9pzo7q/luav5qbvsjzop7b9s9[.]dat`](https://www.virustotal.com/gui/search/https%3A%2F%2Fgroverudder12.com%2Fcurl%2Fc5iu9pzo7q%2Fluav5qbvsjzop7b9s9.dat) | url | AMOS | threatfox | 2026-10-19T13:25:03Z | 100 |
| [`hxxps://groverudder12[.]com/f/zpo1fmkdlnwfmgdkv1oi2w/ujdkhkau`](https://www.virustotal.com/gui/search/https%3A%2F%2Fgroverudder12.com%2Ff%2Fzpo1fmkdlnwfmgdkv1oi2w%2Fujdkhkau) | url | AMOS | threatfox | 2026-10-19T13:25:03Z | 100 |
| [`groverudder12[.]com`](https://www.virustotal.com/gui/domain/groverudder12.com) | domain | AMOS | threatfox | 2026-10-19T13:25:03Z | 100 |
| [`d471401d8aee89447a9617a1b62fb393610627f89b6c6e983903479a9e186146`](https://www.virustotal.com/gui/file/d471401d8aee89447a9617a1b62fb393610627f89b6c6e983903479a9e186146) | sha256 | AMOS | threatfox | 2026-10-19T13:25:02Z | 100 |
| [`hxxps://cloud-browse[.]codes`](https://www.virustotal.com/gui/search/https%3A%2F%2Fcloud-browse.codes) | url | Unknown malware | threatfox | 2026-10-19T13:22:00Z | 100 |
| [`hxxps://j[.]abalbet[.]com/e5/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fj.abalbet.com%2Fe5%2F) | url | Vidar | threatfox | 2026-10-19T13:20:48Z | 100 |
| [`hxxps://j[.]abalbet[.]com/o/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fj.abalbet.com%2Fo%2F) | url | Vidar | threatfox | 2026-10-19T13:15:48Z | 100 |
| [`cloud-browse[.]codes`](https://www.virustotal.com/gui/domain/cloud-browse.codes) | domain | IClickFix | threatfox | 2026-10-19T13:14:38Z | 100 |
| [`hxxps://j[.]abalbet[.]com/k53/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fj.abalbet.com%2Fk53%2F) | url | Vidar | threatfox | 2026-10-19T13:10:48Z | 100 |
| [`wifihgu[.]duckdns[.]org`](https://www.virustotal.com/gui/domain/wifihgu.duckdns.org) | domain | MooBot | threatfox | 2026-10-19T13:06:08Z | 100 |
| [`ou[.]9kio[.]org`](https://www.virustotal.com/gui/domain/ou.9kio.org) | domain | Vidar | threatfox | 2026-10-19T13:05:48Z | 100 |
| [`hxxps://ou[.]9kio[.]org/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fou.9kio.org%2F) | url | Vidar | threatfox | 2026-10-19T13:05:48Z | 100 |
| [`hxxps://j[.]abalbet[.]com/mx/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fj.abalbet.com%2Fmx%2F) | url | Vidar | threatfox | 2026-10-19T13:05:48Z | 100 |
| [`43[.]242[.]128[.]210`](https://www.virustotal.com/gui/ip-address/43.242.128.210) | ipv4 | VShell | threatfox | 2026-10-19T13:05:06Z | 100 |
| [`8[.]163[.]76[.]203`](https://www.virustotal.com/gui/ip-address/8.163.76.203) | ipv4 | Unknown malware | threatfox | 2026-10-19T13:05:04Z | 100 |
| [`106[.]12[.]190[.]248`](https://www.virustotal.com/gui/ip-address/106.12.190.248) | ipv4 | Sliver | threatfox | 2026-10-19T13:01:55Z | 100 |
| [`193[.]70[.]100[.]109`](https://www.virustotal.com/gui/ip-address/193.70.100.109) | ipv4 | Sliver | threatfox | 2026-10-19T13:01:54Z | 100 |
| [`38[.]87[.]116[.]68`](https://www.virustotal.com/gui/ip-address/38.87.116.68) | ipv4 | Sliver | threatfox | 2026-10-19T13:01:54Z | 100 |
| [`43[.]160[.]211[.]117`](https://www.virustotal.com/gui/ip-address/43.160.211.117) | ipv4 | Sliver | threatfox | 2026-10-19T13:01:53Z | 100 |
| [`45[.]142[.]140[.]138`](https://www.virustotal.com/gui/ip-address/45.142.140.138) | ipv4 | Sliver | threatfox | 2026-10-19T13:01:53Z | 100 |
| [`46[.]19[.]140[.]45`](https://www.virustotal.com/gui/ip-address/46.19.140.45) | ipv4 | Sliver | threatfox | 2026-10-19T13:01:52Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
