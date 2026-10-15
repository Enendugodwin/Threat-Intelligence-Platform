# Threat Intel Pulse — 2026-10-15

**Window:** last 7 days · **Generated:** 2026-10-15T17:12:18Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 67381 |
| New in window | 21572 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5000 | ok |
| feodo | 5 | ok |
| threatfox | 8613 | ok |
| malwarebazaar | 1023 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8702 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 26644 | 11303 |
| sha256 | 13039 | 4084 |
| domain | 11733 | 3183 |
| ipv4 | 11456 | 2001 |
| ipv6 | 3140 | 242 |
| md5 | 697 | 380 |
| sha1 | 672 | 379 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 10587 |
| Exit nodes | 2348 |
| Other relays | 8239 |
| New in window | 994 |

Sample (20 of 10587, source: Tor Project Onionoo):
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
| Unknown Loader | 4907 | 637 | — |
| Mirai | 4231 | 777 | T1498, T1071.001 |
| Vidar | 3684 | 3357 | T1555, T1071.001, T1567 |
| AsyncRAT | 2282 | 92 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| ClearFake | 1878 | 686 | — |
| IClickFix | 1492 | 680 | — |
| Cobalt Strike | 1333 | 85 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| Unknown malware | 1055 | 462 | — |
| VShell | 647 | 528 | — |
| Unknown Stealer | 628 | 274 | — |
| php.shin_webshell | 524 | 382 | — |
| PureRAT | 411 | 51 | — |
| AMOS | 377 | 201 | — |
| Sliver | 298 | 275 | T1071.001, T1573, T1090, T1055 |
| AdaptixC2 | 285 | 30 | — |
| Remcos | 273 | 117 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| Unknown RAT | 204 | 33 | — |
| DanaBot | 194 | 131 | T1566.001, T1071.001, T1555, T1041 |
| Remus | 182 | 56 | — |
| Formbook | 172 | 97 | T1566.001, T1056.001, T1555, T1071.001, T1567 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1105 | Ingress Tool Transfer | command-and-control | 21664 |
| T1071.001 | Web Protocols | command-and-control | 42815 |
| T1498 | Network Denial of Service | impact | 9758 |
| T1204.002 | Malicious File | execution | 8695 |
| T1027 | Obfuscated Files or Information | defense-evasion | 8534 |
| T1573 | Encrypted Channel | command-and-control | 7928 |
| T1555 | Credentials from Password Stores | credential-access | 6523 |
| T1567 | Exfiltration Over Web Service | exfiltration | 6329 |
| T1566 | Phishing | initial-access | 5125 |
| T1566.002 | Spearphishing Link | initial-access | 5125 |
| T1552.001 | Credentials In Files | credential-access | 3960 |
| T1056.001 | Keylogging | collection, credential-access | 3730 |
| T1566.001 | Spearphishing Attachment | initial-access | 3430 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 2869 |
| T1113 | Screen Capture | collection | 2832 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1866 |
| T1090 | Proxy | command-and-control | 1666 |
| T1059.001 | PowerShell | execution | 1346 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 362 |
| T1189 | Drive-by Compromise | initial-access | 175 |
| T1218 | System Binary Proxy Execution | defense-evasion | 175 |
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
| [`hxxps://r4[.]86idn[.]com/a`](https://www.virustotal.com/gui/search/https%3A%2F%2Fr4.86idn.com%2Fa) | url | Vidar | threatfox | 2026-10-15T17:05:01Z | 100 |
| [`hxxps://r4[.]86idn[.]com/p`](https://www.virustotal.com/gui/search/https%3A%2F%2Fr4.86idn.com%2Fp) | url | Vidar | threatfox | 2026-10-15T17:03:17Z | 100 |
| [`hxxps://r4[.]86idn[.]com`](https://www.virustotal.com/gui/search/https%3A%2F%2Fr4.86idn.com) | url | Vidar | threatfox | 2026-10-15T17:02:21Z | 100 |
| [`hxxps://y[.]71k[.]org/u`](https://www.virustotal.com/gui/search/https%3A%2F%2Fy.71k.org%2Fu) | url | Vidar | threatfox | 2026-10-15T17:00:54Z | 100 |
| [`hxxps://ek[.]86idn[.]com/ioc/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fek.86idn.com%2Fioc%2F) | url | Vidar | threatfox | 2026-10-15T17:00:49Z | 100 |
| [`hxxps://ek[.]86idn[.]com/ioc`](https://www.virustotal.com/gui/search/https%3A%2F%2Fek.86idn.com%2Fioc) | url | Vidar | threatfox | 2026-10-15T17:00:35Z | 100 |
| [`hxxps://ek[.]86idn[.]com/s2`](https://www.virustotal.com/gui/search/https%3A%2F%2Fek.86idn.com%2Fs2) | url | Vidar | threatfox | 2026-10-15T16:59:24Z | 100 |
| [`128[.]90[.]102[.]118`](https://www.virustotal.com/gui/ip-address/128.90.102.118) | ipv4 | Remcos | threatfox | 2026-10-15T16:56:44Z | 100 |
| [`hxxps://ek[.]86idn[.]com/pe`](https://www.virustotal.com/gui/search/https%3A%2F%2Fek.86idn.com%2Fpe) | url | Vidar | threatfox | 2026-10-15T16:56:42Z | 100 |
| [`hxxps://ek[.]86idn[.]com/wz/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fek.86idn.com%2Fwz%2F) | url | Vidar | threatfox | 2026-10-15T16:55:48Z | 100 |
| [`hxxps://ek[.]86idn[.]com/wz`](https://www.virustotal.com/gui/search/https%3A%2F%2Fek.86idn.com%2Fwz) | url | Vidar | threatfox | 2026-10-15T16:54:14Z | 100 |
| [`hxxps://ek[.]86idn[.]com/jj5`](https://www.virustotal.com/gui/search/https%3A%2F%2Fek.86idn.com%2Fjj5) | url | Vidar | threatfox | 2026-10-15T16:52:40Z | 100 |
| [`hxxps://ek[.]86idn[.]com/rp`](https://www.virustotal.com/gui/search/https%3A%2F%2Fek.86idn.com%2Frp) | url | Vidar | threatfox | 2026-10-15T16:51:35Z | 100 |
| [`chloesteph[.]com`](https://www.virustotal.com/gui/domain/chloesteph.com) | domain | ClearFake | threatfox | 2026-10-15T16:50:52Z | 100 |
| [`hxxps://ek[.]86idn[.]com/rp/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fek.86idn.com%2Frp%2F) | url | Vidar | threatfox | 2026-10-15T16:50:48Z | 100 |
| [`hxxps://ek[.]86idn[.]com/ue`](https://www.virustotal.com/gui/search/https%3A%2F%2Fek.86idn.com%2Fue) | url | Vidar | threatfox | 2026-10-15T16:48:44Z | 100 |
| [`hxxps://ek[.]86idn[.]com/ig`](https://www.virustotal.com/gui/search/https%3A%2F%2Fek.86idn.com%2Fig) | url | Vidar | threatfox | 2026-10-15T16:46:38Z | 100 |
| [`hxxps://ek[.]86idn[.]com/xp`](https://www.virustotal.com/gui/search/https%3A%2F%2Fek.86idn.com%2Fxp) | url | Vidar | threatfox | 2026-10-15T16:45:58Z | 100 |
| [`hxxps://ek[.]86idn[.]com/xp/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fek.86idn.com%2Fxp%2F) | url | Vidar | threatfox | 2026-10-15T16:45:48Z | 100 |
| [`216[.]9[.]224[.]71`](https://www.virustotal.com/gui/ip-address/216.9.224.71) | ipv4 | XWorm | threatfox | 2026-10-15T16:42:36Z | 100 |
| [`hxxps://ek[.]86idn[.]com/nf`](https://www.virustotal.com/gui/search/https%3A%2F%2Fek.86idn.com%2Fnf) | url | Vidar | threatfox | 2026-10-15T16:42:25Z | 100 |
| [`hxxps://ek[.]86idn[.]com/hf/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fek.86idn.com%2Fhf%2F) | url | Vidar | threatfox | 2026-10-15T16:40:48Z | 100 |
| [`hxxps://ek[.]86idn[.]com/hf`](https://www.virustotal.com/gui/search/https%3A%2F%2Fek.86idn.com%2Fhf) | url | Vidar | threatfox | 2026-10-15T16:40:22Z | 100 |
| [`hxxps://ek[.]86idn[.]com/g`](https://www.virustotal.com/gui/search/https%3A%2F%2Fek.86idn.com%2Fg) | url | Vidar | threatfox | 2026-10-15T16:38:25Z | 100 |
| [`hxxps://ek[.]86idn[.]com/wj`](https://www.virustotal.com/gui/search/https%3A%2F%2Fek.86idn.com%2Fwj) | url | Vidar | threatfox | 2026-10-15T16:36:19Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
