# Threat Intel Pulse — 2026-10-15

**Window:** last 7 days · **Generated:** 2026-10-15T21:33:00Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 68155 |
| New in window | 22346 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5001 | ok |
| feodo | 5 | ok |
| threatfox | 8438 | ok |
| malwarebazaar | 1046 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8711 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 26973 | 11632 |
| sha256 | 13143 | 4188 |
| domain | 11894 | 3344 |
| ipv4 | 11512 | 2057 |
| ipv6 | 3146 | 248 |
| md5 | 756 | 439 |
| sha1 | 731 | 438 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 10607 |
| Exit nodes | 2352 |
| Other relays | 8255 |
| New in window | 1014 |

Sample (20 of 10607, source: Tor Project Onionoo):
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
| Unknown Loader | 4996 | 726 | — |
| Mirai | 4250 | 796 | T1498, T1071.001 |
| Vidar | 3882 | 3555 | T1555, T1071.001, T1567 |
| AsyncRAT | 2300 | 110 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| ClearFake | 1880 | 688 | — |
| IClickFix | 1492 | 680 | — |
| Cobalt Strike | 1333 | 85 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| Unknown malware | 1064 | 471 | — |
| VShell | 647 | 528 | — |
| Unknown Stealer | 628 | 274 | — |
| php.shin_webshell | 531 | 389 | — |
| PureRAT | 416 | 56 | — |
| AMOS | 405 | 229 | — |
| Sliver | 307 | 284 | T1071.001, T1573, T1090, T1055 |
| AdaptixC2 | 286 | 31 | — |
| Remcos | 286 | 130 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| Remus | 231 | 105 | — |
| Unknown RAT | 205 | 34 | — |
| DanaBot | 195 | 132 | T1566.001, T1071.001, T1555, T1041 |
| Formbook | 184 | 109 | T1566.001, T1056.001, T1555, T1071.001, T1567 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1105 | Ingress Tool Transfer | command-and-control | 21964 |
| T1071.001 | Web Protocols | command-and-control | 43347 |
| T1498 | Network Denial of Service | impact | 9877 |
| T1204.002 | Malicious File | execution | 8842 |
| T1027 | Obfuscated Files or Information | defense-evasion | 8681 |
| T1573 | Encrypted Channel | command-and-control | 8100 |
| T1555 | Credentials from Password Stores | credential-access | 6831 |
| T1567 | Exfiltration Over Web Service | exfiltration | 6636 |
| T1566 | Phishing | initial-access | 5126 |
| T1566.002 | Spearphishing Link | initial-access | 5126 |
| T1552.001 | Credentials In Files | credential-access | 4182 |
| T1056.001 | Keylogging | collection, credential-access | 3798 |
| T1566.001 | Spearphishing Attachment | initial-access | 3492 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 2912 |
| T1113 | Screen Capture | collection | 2872 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1875 |
| T1090 | Proxy | command-and-control | 1675 |
| T1059.001 | PowerShell | execution | 1346 |
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
| [`hxxps://m7[.]86idn[.]com/k`](https://www.virustotal.com/gui/search/https%3A%2F%2Fm7.86idn.com%2Fk) | url | Vidar | threatfox | 2026-10-15T21:24:17Z | 100 |
| [`hxxps://m7[.]86idn[.]com/tbe`](https://www.virustotal.com/gui/search/https%3A%2F%2Fm7.86idn.com%2Ftbe) | url | Vidar | threatfox | 2026-10-15T21:22:23Z | 100 |
| [`hxxps://m7[.]86idn[.]com/u`](https://www.virustotal.com/gui/search/https%3A%2F%2Fm7.86idn.com%2Fu) | url | Vidar | threatfox | 2026-10-15T21:21:01Z | 100 |
| [`hxxps://m7[.]86idn[.]com/u/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fm7.86idn.com%2Fu%2F) | url | Vidar | threatfox | 2026-10-15T21:20:48Z | 100 |
| [`hxxps://m7[.]86idn[.]com/x`](https://www.virustotal.com/gui/search/https%3A%2F%2Fm7.86idn.com%2Fx) | url | Vidar | threatfox | 2026-10-15T21:18:32Z | 100 |
| [`hxxps://m7[.]86idn[.]com/bh`](https://www.virustotal.com/gui/search/https%3A%2F%2Fm7.86idn.com%2Fbh) | url | Vidar | threatfox | 2026-10-15T21:16:58Z | 100 |
| [`hxxps://m7[.]86idn[.]com/m`](https://www.virustotal.com/gui/search/https%3A%2F%2Fm7.86idn.com%2Fm) | url | Vidar | threatfox | 2026-10-15T21:16:20Z | 100 |
| [`hxxps://m7[.]86idn[.]com/bh/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fm7.86idn.com%2Fbh%2F) | url | Vidar | threatfox | 2026-10-15T21:15:48Z | 100 |
| [`hxxps://m7[.]86idn[.]com/ku`](https://www.virustotal.com/gui/search/https%3A%2F%2Fm7.86idn.com%2Fku) | url | Vidar | threatfox | 2026-10-15T21:12:14Z | 100 |
| [`hxxps://m7[.]86idn[.]com/mm/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fm7.86idn.com%2Fmm%2F) | url | Vidar | threatfox | 2026-10-15T21:10:48Z | 100 |
| [`hxxps://m7[.]86idn[.]com/mm`](https://www.virustotal.com/gui/search/https%3A%2F%2Fm7.86idn.com%2Fmm) | url | Vidar | threatfox | 2026-10-15T21:10:33Z | 100 |
| [`hxxps://m7[.]86idn[.]com/ih`](https://www.virustotal.com/gui/search/https%3A%2F%2Fm7.86idn.com%2Fih) | url | Vidar | threatfox | 2026-10-15T21:08:16Z | 100 |
| [`hxxps://m7[.]86idn[.]com/ju`](https://www.virustotal.com/gui/search/https%3A%2F%2Fm7.86idn.com%2Fju) | url | Vidar | threatfox | 2026-10-15T21:06:57Z | 100 |
| [`hxxps://m7[.]86idn[.]com/zr/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fm7.86idn.com%2Fzr%2F) | url | Vidar | threatfox | 2026-10-15T21:05:48Z | 100 |
| [`hxxps://m7[.]86idn[.]com/zr`](https://www.virustotal.com/gui/search/https%3A%2F%2Fm7.86idn.com%2Fzr) | url | Vidar | threatfox | 2026-10-15T21:05:19Z | 100 |
| [`hxxps://m7[.]86idn[.]com/p2`](https://www.virustotal.com/gui/search/https%3A%2F%2Fm7.86idn.com%2Fp2) | url | Vidar | threatfox | 2026-10-15T21:03:01Z | 100 |
| [`hxxps://m7[.]86idn[.]com`](https://www.virustotal.com/gui/search/https%3A%2F%2Fm7.86idn.com) | url | Vidar | threatfox | 2026-10-15T21:01:58Z | 100 |
| [`hxxps://q[.]71k[.]org/x`](https://www.virustotal.com/gui/search/https%3A%2F%2Fq.71k.org%2Fx) | url | Vidar | threatfox | 2026-10-15T21:00:57Z | 100 |
| [`hxxps://be[.]86idn[.]com/ox/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbe.86idn.com%2Fox%2F) | url | Vidar | threatfox | 2026-10-15T21:00:49Z | 100 |
| [`hxxps://be[.]86idn[.]com/ze`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbe.86idn.com%2Fze) | url | Vidar | threatfox | 2026-10-15T20:59:19Z | 100 |
| [`hxxps://be[.]86idn[.]com/zd`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbe.86idn.com%2Fzd) | url | Vidar | threatfox | 2026-10-15T20:56:40Z | 100 |
| [`hxxps://be[.]86idn[.]com/fu/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbe.86idn.com%2Ffu%2F) | url | Vidar | threatfox | 2026-10-15T20:55:48Z | 100 |
| [`hxxps://be[.]86idn[.]com/fu`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbe.86idn.com%2Ffu) | url | Vidar | threatfox | 2026-10-15T20:54:27Z | 100 |
| [`hxxps://be[.]86idn[.]com/cn`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbe.86idn.com%2Fcn) | url | Vidar | threatfox | 2026-10-15T20:53:39Z | 100 |
| [`hxxps://be[.]86idn[.]com/ku`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbe.86idn.com%2Fku) | url | Vidar | threatfox | 2026-10-15T20:51:15Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
