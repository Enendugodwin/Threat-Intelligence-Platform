# Threat Intel Pulse — 2026-10-15

**Window:** last 7 days · **Generated:** 2026-10-15T04:53:59Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 65537 |
| New in window | 22679 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5000 | ok |
| feodo | 5 | ok |
| threatfox | 8161 | ok |
| malwarebazaar | 1259 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8691 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 25663 | 12513 |
| sha256 | 12633 | 3968 |
| domain | 11419 | 3191 |
| ipv4 | 11323 | 2001 |
| ipv6 | 3130 | 247 |
| md5 | 697 | 380 |
| sha1 | 672 | 379 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 10536 |
| Exit nodes | 2345 |
| Other relays | 8191 |
| New in window | 1044 |

Sample (20 of 10536, source: Tor Project Onionoo):
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
| Unknown Loader | 4901 | 782 | — |
| Mirai | 4215 | 842 | T1498, T1071.001 |
| Vidar | 3185 | 2876 | T1555, T1071.001, T1567 |
| AsyncRAT | 2274 | 90 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| ClearFake | 1861 | 763 | — |
| IClickFix | 1333 | 593 | — |
| Cobalt Strike | 1325 | 80 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| Unknown malware | 1038 | 471 | — |
| Unknown Stealer | 628 | 284 | — |
| php.shin_webshell | 503 | 361 | — |
| PureRAT | 409 | 49 | — |
| VShell | 354 | 238 | — |
| AMOS | 339 | 175 | — |
| Sliver | 297 | 274 | T1071.001, T1573, T1090, T1055 |
| AdaptixC2 | 283 | 29 | — |
| Remcos | 259 | 112 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| Unknown RAT | 204 | 34 | — |
| DanaBot | 194 | 131 | T1566.001, T1071.001, T1555, T1041 |
| Remus | 180 | 59 | — |
| Formbook | 172 | 103 | T1566.001, T1056.001, T1555, T1071.001, T1567 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1105 | Ingress Tool Transfer | command-and-control | 21132 |
| T1071.001 | Web Protocols | command-and-control | 41797 |
| T1498 | Network Denial of Service | impact | 9702 |
| T1204.002 | Malicious File | execution | 8192 |
| T1027 | Obfuscated Files or Information | defense-evasion | 8181 |
| T1573 | Encrypted Channel | command-and-control | 7343 |
| T1555 | Credentials from Password Stores | credential-access | 5985 |
| T1567 | Exfiltration Over Web Service | exfiltration | 5791 |
| T1566 | Phishing | initial-access | 4825 |
| T1566.002 | Spearphishing Link | initial-access | 4825 |
| T1056.001 | Keylogging | collection, credential-access | 3698 |
| T1552.001 | Credentials In Files | credential-access | 3571 |
| T1566.001 | Spearphishing Attachment | initial-access | 3403 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 2841 |
| T1113 | Screen Capture | collection | 2806 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1855 |
| T1090 | Proxy | command-and-control | 1657 |
| T1059.001 | PowerShell | execution | 1338 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 362 |
| T1059.005 | Visual Basic | execution | 87 |
| T1189 | Drive-by Compromise | initial-access | 24 |
| T1218 | System Binary Proxy Execution | defense-evasion | 24 |
| T1021.001 | Remote Desktop Protocol | lateral-movement | 14 |
| T1486 | Data Encrypted for Impact | impact | 14 |
| T1490 | Inhibit System Recovery | impact | 14 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 14 |
| T1190 | Exploit Public-Facing Application | initial-access | 5 |
| T1003 | OS Credential Dumping | credential-access | 4 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://jx[.]78royal[.]org/n0`](https://www.virustotal.com/gui/search/https%3A%2F%2Fjx.78royal.org%2Fn0) | url | Vidar | threatfox | 2026-10-15T04:45:03Z | 100 |
| [`hxxps://jx[.]78royal[.]org/yam`](https://www.virustotal.com/gui/search/https%3A%2F%2Fjx.78royal.org%2Fyam) | url | Vidar | threatfox | 2026-10-15T04:42:55Z | 100 |
| [`hxxps://jx[.]78royal[.]org/ct`](https://www.virustotal.com/gui/search/https%3A%2F%2Fjx.78royal.org%2Fct) | url | Vidar | threatfox | 2026-10-15T04:41:04Z | 100 |
| [`hxxps://jx[.]78royal[.]org/ct/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fjx.78royal.org%2Fct%2F) | url | Vidar | threatfox | 2026-10-15T04:40:48Z | 100 |
| [`hxxps://jx[.]78royal[.]org/gz5`](https://www.virustotal.com/gui/search/https%3A%2F%2Fjx.78royal.org%2Fgz5) | url | Vidar | threatfox | 2026-10-15T04:38:20Z | 100 |
| [`hxxps://jx[.]78royal[.]org/mr`](https://www.virustotal.com/gui/search/https%3A%2F%2Fjx.78royal.org%2Fmr) | url | Vidar | threatfox | 2026-10-15T04:37:17Z | 100 |
| [`hxxps://jx[.]78royal[.]org/af/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fjx.78royal.org%2Faf%2F) | url | Vidar | threatfox | 2026-10-15T04:35:48Z | 100 |
| [`hxxps://jx[.]78royal[.]org/af`](https://www.virustotal.com/gui/search/https%3A%2F%2Fjx.78royal.org%2Faf) | url | Vidar | threatfox | 2026-10-15T04:34:30Z | 100 |
| [`hxxps://jx[.]78royal[.]org/xnd`](https://www.virustotal.com/gui/search/https%3A%2F%2Fjx.78royal.org%2Fxnd) | url | Vidar | threatfox | 2026-10-15T04:32:24Z | 100 |
| [`hxxps://jx[.]78royal[.]org/zw`](https://www.virustotal.com/gui/search/https%3A%2F%2Fjx.78royal.org%2Fzw) | url | Vidar | threatfox | 2026-10-15T04:32:07Z | 100 |
| [`hxxps://jx[.]78royal[.]org/zw/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fjx.78royal.org%2Fzw%2F) | url | Vidar | threatfox | 2026-10-15T04:30:48Z | 100 |
| [`hxxps://jx[.]78royal[.]org/iz`](https://www.virustotal.com/gui/search/https%3A%2F%2Fjx.78royal.org%2Fiz) | url | Vidar | threatfox | 2026-10-15T04:28:23Z | 100 |
| [`hxxps://jx[.]78royal[.]org/v`](https://www.virustotal.com/gui/search/https%3A%2F%2Fjx.78royal.org%2Fv) | url | Vidar | threatfox | 2026-10-15T04:26:58Z | 100 |
| [`hxxps://jx[.]78royal[.]org/eb9/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fjx.78royal.org%2Feb9%2F) | url | Vidar | threatfox | 2026-10-15T04:25:48Z | 100 |
| [`hxxps://jx[.]78royal[.]org/eb9`](https://www.virustotal.com/gui/search/https%3A%2F%2Fjx.78royal.org%2Feb9) | url | Vidar | threatfox | 2026-10-15T04:24:45Z | 100 |
| [`hxxps://jx[.]78royal[.]org/xj0`](https://www.virustotal.com/gui/search/https%3A%2F%2Fjx.78royal.org%2Fxj0) | url | Vidar | threatfox | 2026-10-15T04:23:16Z | 100 |
| [`hxxps://jx[.]78royal[.]org/mt`](https://www.virustotal.com/gui/search/https%3A%2F%2Fjx.78royal.org%2Fmt) | url | Vidar | threatfox | 2026-10-15T04:21:01Z | 100 |
| [`hxxps://jx[.]78royal[.]org/mt/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fjx.78royal.org%2Fmt%2F) | url | Vidar | threatfox | 2026-10-15T04:20:48Z | 100 |
| [`hxxps://jx[.]78royal[.]org/dou`](https://www.virustotal.com/gui/search/https%3A%2F%2Fjx.78royal.org%2Fdou) | url | Vidar | threatfox | 2026-10-15T04:18:32Z | 100 |
| [`w8cyew46[.]metricsdataapi[.]com`](https://www.virustotal.com/gui/domain/w8cyew46.metricsdataapi.com) | domain | ClearFake | threatfox | 2026-10-15T04:16:37Z | 100 |
| [`hxxps://jx[.]78royal[.]org/zi`](https://www.virustotal.com/gui/search/https%3A%2F%2Fjx.78royal.org%2Fzi) | url | Vidar | threatfox | 2026-10-15T04:16:32Z | 100 |
| [`hxxps://jx[.]78royal[.]org/qm2/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fjx.78royal.org%2Fqm2%2F) | url | Vidar | threatfox | 2026-10-15T04:15:48Z | 100 |
| [`hxxps://jx[.]78royal[.]org/pe`](https://www.virustotal.com/gui/search/https%3A%2F%2Fjx.78royal.org%2Fpe) | url | Vidar | threatfox | 2026-10-15T04:12:26Z | 100 |
| [`hxxps://jx[.]78royal[.]org/ndf`](https://www.virustotal.com/gui/search/https%3A%2F%2Fjx.78royal.org%2Fndf) | url | Vidar | threatfox | 2026-10-15T04:10:51Z | 100 |
| [`hxxps://jx[.]78royal[.]org/ndf/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fjx.78royal.org%2Fndf%2F) | url | Vidar | threatfox | 2026-10-15T04:10:48Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
