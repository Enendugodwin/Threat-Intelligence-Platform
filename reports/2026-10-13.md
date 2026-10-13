# Threat Intel Pulse — 2026-10-13

**Window:** last 7 days · **Generated:** 2026-10-13T22:56:44Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 61034 |
| New in window | 20565 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5001 | ok |
| feodo | 5 | ok |
| threatfox | 7830 | ok |
| malwarebazaar | 1159 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8584 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 22890 | 10853 |
| sha256 | 11795 | 3610 |
| domain | 11065 | 3219 |
| ipv4 | 11030 | 1959 |
| ipv6 | 3011 | 161 |
| md5 | 634 | 382 |
| sha1 | 609 | 381 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 10290 |
| Exit nodes | 2244 |
| Other relays | 8046 |
| New in window | 961 |

Sample (20 of 10290, source: Tor Project Onionoo):
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
| Unknown Loader | 4865 | 756 | — |
| Mirai | 4144 | 807 | T1498, T1071.001 |
| AsyncRAT | 2261 | 85 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| Vidar | 1933 | 1678 | T1555, T1071.001, T1567 |
| ClearFake | 1808 | 804 | — |
| IClickFix | 1322 | 592 | — |
| Cobalt Strike | 1314 | 73 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| Unknown malware | 991 | 444 | — |
| Unknown Stealer | 624 | 436 | — |
| php.shin_webshell | 442 | 339 | — |
| PureRAT | 404 | 59 | — |
| VShell | 346 | 235 | — |
| AMOS | 299 | 153 | — |
| Sliver | 284 | 262 | T1071.001, T1573, T1090, T1055 |
| AdaptixC2 | 280 | 29 | — |
| Remcos | 223 | 90 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| Unknown RAT | 197 | 30 | — |
| DanaBot | 193 | 130 | T1566.001, T1071.001, T1555, T1041 |
| Remus | 175 | 72 | — |
| Formbook | 131 | 71 | T1566.001, T1056.001, T1555, T1071.001, T1567 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1105 | Ingress Tool Transfer | command-and-control | 19545 |
| T1071.001 | Web Protocols | command-and-control | 39499 |
| T1498 | Network Denial of Service | impact | 9439 |
| T1204.002 | Malicious File | execution | 7233 |
| T1027 | Obfuscated Files or Information | defense-evasion | 7222 |
| T1573 | Encrypted Channel | command-and-control | 6318 |
| T1555 | Credentials from Password Stores | credential-access | 4535 |
| T1567 | Exfiltration Over Web Service | exfiltration | 4342 |
| T1566 | Phishing | initial-access | 3925 |
| T1566.002 | Spearphishing Link | initial-access | 3925 |
| T1056.001 | Keylogging | collection, credential-access | 3551 |
| T1566.001 | Spearphishing Attachment | initial-access | 3247 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 2751 |
| T1113 | Screen Capture | collection | 2716 |
| T1552.001 | Credentials In Files | credential-access | 2532 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1815 |
| T1090 | Proxy | command-and-control | 1632 |
| T1059.001 | PowerShell | execution | 1327 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 337 |
| T1059.005 | Visual Basic | execution | 74 |
| T1189 | Drive-by Compromise | initial-access | 23 |
| T1218 | System Binary Proxy Execution | defense-evasion | 23 |
| T1021.001 | Remote Desktop Protocol | lateral-movement | 14 |
| T1486 | Data Encrypted for Impact | impact | 14 |
| T1490 | Inhibit System Recovery | impact | 14 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 14 |
| T1003 | OS Credential Dumping | credential-access | 4 |
| T1190 | Exploit Public-Facing Application | initial-access | 2 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://xy[.]73kcom[.]org/d5`](https://www.virustotal.com/gui/search/https%3A%2F%2Fxy.73kcom.org%2Fd5) | url | Vidar | threatfox | 2026-10-13T22:48:27Z | 100 |
| [`hxxps://xy[.]73kcom[.]org/s0`](https://www.virustotal.com/gui/search/https%3A%2F%2Fxy.73kcom.org%2Fs0) | url | Vidar | threatfox | 2026-10-13T22:46:22Z | 100 |
| [`hxxps://xy[.]73kcom[.]org/cc/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fxy.73kcom.org%2Fcc%2F) | url | Vidar | threatfox | 2026-10-13T22:45:48Z | 100 |
| [`hxxps://xy[.]73kcom[.]org/cc`](https://www.virustotal.com/gui/search/https%3A%2F%2Fxy.73kcom.org%2Fcc) | url | Vidar | threatfox | 2026-10-13T22:44:26Z | 100 |
| [`hxxps://xy[.]73kcom[.]org/bf`](https://www.virustotal.com/gui/search/https%3A%2F%2Fxy.73kcom.org%2Fbf) | url | Vidar | threatfox | 2026-10-13T22:42:52Z | 100 |
| [`hxxps://xy[.]73kcom[.]org/cr`](https://www.virustotal.com/gui/search/https%3A%2F%2Fxy.73kcom.org%2Fcr) | url | Vidar | threatfox | 2026-10-13T22:41:01Z | 100 |
| [`hxxps://xy[.]73kcom[.]org/cr/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fxy.73kcom.org%2Fcr%2F) | url | Vidar | threatfox | 2026-10-13T22:40:48Z | 100 |
| [`hxxps://xy[.]73kcom[.]org/zb`](https://www.virustotal.com/gui/search/https%3A%2F%2Fxy.73kcom.org%2Fzb) | url | Vidar | threatfox | 2026-10-13T22:38:14Z | 100 |
| [`hxxps://xy[.]73kcom[.]org/f`](https://www.virustotal.com/gui/search/https%3A%2F%2Fxy.73kcom.org%2Ff) | url | Vidar | threatfox | 2026-10-13T22:36:15Z | 100 |
| [`hxxps://xy[.]73kcom[.]org/xp/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fxy.73kcom.org%2Fxp%2F) | url | Vidar | threatfox | 2026-10-13T22:35:48Z | 100 |
| [`hxxps://xy[.]73kcom[.]org/xp`](https://www.virustotal.com/gui/search/https%3A%2F%2Fxy.73kcom.org%2Fxp) | url | Vidar | threatfox | 2026-10-13T22:34:32Z | 100 |
| [`hxxps://xy[.]73kcom[.]org/a4`](https://www.virustotal.com/gui/search/https%3A%2F%2Fxy.73kcom.org%2Fa4) | url | Vidar | threatfox | 2026-10-13T22:32:34Z | 100 |
| [`hxxps://xy[.]73kcom[.]org/ge0/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fxy.73kcom.org%2Fge0%2F) | url | Vidar | threatfox | 2026-10-13T22:30:48Z | 100 |
| [`hxxps://xy[.]73kcom[.]org/ge0`](https://www.virustotal.com/gui/search/https%3A%2F%2Fxy.73kcom.org%2Fge0) | url | Vidar | threatfox | 2026-10-13T22:30:18Z | 100 |
| [`hxxps://xy[.]73kcom[.]org/sfx`](https://www.virustotal.com/gui/search/https%3A%2F%2Fxy.73kcom.org%2Fsfx) | url | Vidar | threatfox | 2026-10-13T22:29:16Z | 100 |
| [`hxxps://xy[.]73kcom[.]org/n2`](https://www.virustotal.com/gui/search/https%3A%2F%2Fxy.73kcom.org%2Fn2) | url | Vidar | threatfox | 2026-10-13T22:26:40Z | 100 |
| [`hxxps://xy[.]73kcom[.]org/moj/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fxy.73kcom.org%2Fmoj%2F) | url | Vidar | threatfox | 2026-10-13T22:25:48Z | 100 |
| [`hxxps://xy[.]73kcom[.]org/moj`](https://www.virustotal.com/gui/search/https%3A%2F%2Fxy.73kcom.org%2Fmoj) | url | Vidar | threatfox | 2026-10-13T22:24:33Z | 100 |
| [`hxxps://xy[.]73kcom[.]org/jk`](https://www.virustotal.com/gui/search/https%3A%2F%2Fxy.73kcom.org%2Fjk) | url | Vidar | threatfox | 2026-10-13T22:22:33Z | 100 |
| [`hxxps://xy[.]73kcom[.]org/i2b`](https://www.virustotal.com/gui/search/https%3A%2F%2Fxy.73kcom.org%2Fi2b) | url | Vidar | threatfox | 2026-10-13T22:21:06Z | 100 |
| [`hxxps://xy[.]73kcom[.]org/i2b/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fxy.73kcom.org%2Fi2b%2F) | url | Vidar | threatfox | 2026-10-13T22:20:48Z | 100 |
| [`hxxps://xy[.]73kcom[.]org/hc`](https://www.virustotal.com/gui/search/https%3A%2F%2Fxy.73kcom.org%2Fhc) | url | Vidar | threatfox | 2026-10-13T22:18:30Z | 100 |
| [`hxxps://xy[.]73kcom[.]org/v9f`](https://www.virustotal.com/gui/search/https%3A%2F%2Fxy.73kcom.org%2Fv9f) | url | Vidar | threatfox | 2026-10-13T22:16:27Z | 100 |
| [`hxxps://xy[.]73kcom[.]org/m2/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fxy.73kcom.org%2Fm2%2F) | url | Vidar | threatfox | 2026-10-13T22:15:49Z | 100 |
| [`hxxps://xy[.]73kcom[.]org/m2`](https://www.virustotal.com/gui/search/https%3A%2F%2Fxy.73kcom.org%2Fm2) | url | Vidar | threatfox | 2026-10-13T22:15:39Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
