# Threat Intel Pulse — 2026-10-13

**Window:** last 7 days · **Generated:** 2026-10-13T00:54:02Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 57904 |
| New in window | 26624 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5000 | ok |
| feodo | 5 | ok |
| threatfox | 6419 | ok |
| malwarebazaar | 1029 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8556 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 21131 | 14524 |
| sha256 | 11295 | 4358 |
| ipv4 | 10805 | 1997 |
| domain | 10569 | 4741 |
| ipv6 | 2985 | 191 |
| md5 | 572 | 407 |
| sha1 | 547 | 406 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 10171 |
| Exit nodes | 2231 |
| Other relays | 7940 |
| New in window | 1065 |

Sample (20 of 10171, source: Tor Project Onionoo):
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
| Unknown Loader | 4576 | 1867 | — |
| Mirai | 3985 | 817 | T1498, T1071.001 |
| AsyncRAT | 2246 | 81 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| ClearFake | 1710 | 1046 | — |
| IClickFix | 1312 | 965 | — |
| Cobalt Strike | 1307 | 74 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| Vidar | 1008 | 794 | T1555, T1071.001, T1567 |
| Unknown malware | 964 | 477 | — |
| Unknown Stealer | 567 | 394 | — |
| php.shin_webshell | 403 | 323 | — |
| PureRAT | 397 | 57 | — |
| Sliver | 281 | 261 | T1071.001, T1573, T1090, T1055 |
| VShell | 280 | 173 | — |
| AdaptixC2 | 276 | 30 | — |
| AMOS | 275 | 156 | — |
| Remcos | 202 | 95 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| DanaBot | 193 | 130 | T1566.001, T1071.001, T1555, T1041 |
| Unknown RAT | 188 | 49 | — |
| Remus | 165 | 75 | — |
| Formbook | 121 | 82 | T1566.001, T1056.001, T1555, T1071.001, T1567 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1105 | Ingress Tool Transfer | command-and-control | 18331 |
| T1071.001 | Web Protocols | command-and-control | 37501 |
| T1498 | Network Denial of Service | impact | 9149 |
| T1204.002 | Malicious File | execution | 6575 |
| T1027 | Obfuscated Files or Information | defense-evasion | 6564 |
| T1573 | Encrypted Channel | command-and-control | 5593 |
| T1566 | Phishing | initial-access | 3682 |
| T1566.002 | Spearphishing Link | initial-access | 3682 |
| T1555 | Credentials from Password Stores | credential-access | 3503 |
| T1056.001 | Keylogging | collection, credential-access | 3462 |
| T1567 | Exfiltration Over Web Service | exfiltration | 3310 |
| T1566.001 | Spearphishing Attachment | initial-access | 3183 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 2700 |
| T1113 | Screen Capture | collection | 2668 |
| T1552.001 | Credentials In Files | credential-access | 1803 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1800 |
| T1090 | Proxy | command-and-control | 1622 |
| T1059.001 | PowerShell | execution | 1320 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 334 |
| T1059.005 | Visual Basic | execution | 74 |
| T1189 | Drive-by Compromise | initial-access | 23 |
| T1218 | System Binary Proxy Execution | defense-evasion | 23 |
| T1021.001 | Remote Desktop Protocol | lateral-movement | 11 |
| T1486 | Data Encrypted for Impact | impact | 11 |
| T1490 | Inhibit System Recovery | impact | 11 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 11 |
| T1003 | OS Credential Dumping | credential-access | 4 |
| T1190 | Exploit Public-Facing Application | initial-access | 2 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://m[.]6r6r6[.]org/fg`](https://www.virustotal.com/gui/search/https%3A%2F%2Fm.6r6r6.org%2Ffg) | url | Vidar | threatfox | 2026-10-13T00:48:42Z | 100 |
| [`hxxps://m[.]6r6r6[.]org/ax`](https://www.virustotal.com/gui/search/https%3A%2F%2Fm.6r6r6.org%2Fax) | url | Vidar | threatfox | 2026-10-13T00:47:13Z | 100 |
| [`hxxps://m[.]6r6r6[.]org/yi/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fm.6r6r6.org%2Fyi%2F) | url | Vidar | threatfox | 2026-10-13T00:45:48Z | 100 |
| [`hxxps://m[.]6r6r6[.]org/yi`](https://www.virustotal.com/gui/search/https%3A%2F%2Fm.6r6r6.org%2Fyi) | url | Vidar | threatfox | 2026-10-13T00:44:15Z | 100 |
| [`hxxps://m[.]6r6r6[.]org/y2`](https://www.virustotal.com/gui/search/https%3A%2F%2Fm.6r6r6.org%2Fy2) | url | Vidar | threatfox | 2026-10-13T00:43:37Z | 100 |
| [`hxxps://m[.]6r6r6[.]org/t`](https://www.virustotal.com/gui/search/https%3A%2F%2Fm.6r6r6.org%2Ft) | url | Vidar | threatfox | 2026-10-13T00:41:14Z | 100 |
| [`hxxps://m[.]6r6r6[.]org/t/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fm.6r6r6.org%2Ft%2F) | url | Vidar | threatfox | 2026-10-13T00:40:48Z | 100 |
| [`hxxps://m[.]6r6r6[.]org/j3`](https://www.virustotal.com/gui/search/https%3A%2F%2Fm.6r6r6.org%2Fj3) | url | Vidar | threatfox | 2026-10-13T00:38:17Z | 100 |
| [`hxxps://m[.]6r6r6[.]org/ib`](https://www.virustotal.com/gui/search/https%3A%2F%2Fm.6r6r6.org%2Fib) | url | Vidar | threatfox | 2026-10-13T00:36:36Z | 100 |
| [`hxxps://m[.]6r6r6[.]org/kxz/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fm.6r6r6.org%2Fkxz%2F) | url | Vidar | threatfox | 2026-10-13T00:35:48Z | 100 |
| [`hxxps://m[.]6r6r6[.]org/kxz`](https://www.virustotal.com/gui/search/https%3A%2F%2Fm.6r6r6.org%2Fkxz) | url | Vidar | threatfox | 2026-10-13T00:35:23Z | 100 |
| [`hxxps://m[.]6r6r6[.]org/fz`](https://www.virustotal.com/gui/search/https%3A%2F%2Fm.6r6r6.org%2Ffz) | url | Vidar | threatfox | 2026-10-13T00:32:57Z | 100 |
| [`hxxps://m[.]6r6r6[.]org/eh/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fm.6r6r6.org%2Feh%2F) | url | Vidar | threatfox | 2026-10-13T00:30:48Z | 100 |
| [`hxxps://m[.]6r6r6[.]org/eh`](https://www.virustotal.com/gui/search/https%3A%2F%2Fm.6r6r6.org%2Feh) | url | Vidar | threatfox | 2026-10-13T00:30:37Z | 100 |
| [`hxxps://m[.]6r6r6[.]org/v92`](https://www.virustotal.com/gui/search/https%3A%2F%2Fm.6r6r6.org%2Fv92) | url | Vidar | threatfox | 2026-10-13T00:28:55Z | 100 |
| [`hxxps://m[.]6r6r6[.]org/xz`](https://www.virustotal.com/gui/search/https%3A%2F%2Fm.6r6r6.org%2Fxz) | url | Vidar | threatfox | 2026-10-13T00:26:21Z | 100 |
| [`hxxps://m[.]6r6r6[.]org/b43/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fm.6r6r6.org%2Fb43%2F) | url | Vidar | threatfox | 2026-10-13T00:25:48Z | 100 |
| [`hxxps://m[.]6r6r6[.]org/b43`](https://www.virustotal.com/gui/search/https%3A%2F%2Fm.6r6r6.org%2Fb43) | url | Vidar | threatfox | 2026-10-13T00:24:57Z | 100 |
| [`hxxps://m[.]6r6r6[.]org/ih3`](https://www.virustotal.com/gui/search/https%3A%2F%2Fm.6r6r6.org%2Fih3) | url | Vidar | threatfox | 2026-10-13T00:22:15Z | 100 |
| [`hxxps://m[.]6r6r6[.]org/qu/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fm.6r6r6.org%2Fqu%2F) | url | Vidar | threatfox | 2026-10-13T00:20:48Z | 100 |
| [`hxxps://m[.]6r6r6[.]org/qu`](https://www.virustotal.com/gui/search/https%3A%2F%2Fm.6r6r6.org%2Fqu) | url | Vidar | threatfox | 2026-10-13T00:20:34Z | 100 |
| [`hxxps://m[.]6r6r6[.]org/w`](https://www.virustotal.com/gui/search/https%3A%2F%2Fm.6r6r6.org%2Fw) | url | Vidar | threatfox | 2026-10-13T00:19:38Z | 100 |
| [`hxxps://m[.]6r6r6[.]org/ru`](https://www.virustotal.com/gui/search/https%3A%2F%2Fm.6r6r6.org%2Fru) | url | Vidar | threatfox | 2026-10-13T00:16:20Z | 100 |
| [`hxxps://m[.]6r6r6[.]org/d8/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fm.6r6r6.org%2Fd8%2F) | url | Vidar | threatfox | 2026-10-13T00:15:48Z | 100 |
| [`hxxps://m[.]6r6r6[.]org/d8`](https://www.virustotal.com/gui/search/https%3A%2F%2Fm.6r6r6.org%2Fd8) | url | Vidar | threatfox | 2026-10-13T00:14:18Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
