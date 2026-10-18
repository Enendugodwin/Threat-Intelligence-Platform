# Threat Intel Pulse — 2026-10-18

**Window:** last 7 days · **Generated:** 2026-10-18T04:47:44Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 75622 |
| New in window | 23536 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5000 | ok |
| feodo | 5 | ok |
| threatfox | 7916 | ok |
| malwarebazaar | 801 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8755 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 30612 | 12602 |
| sha256 | 14939 | 4783 |
| domain | 13001 | 2935 |
| ipv4 | 12162 | 2185 |
| ipv6 | 3233 | 289 |
| md5 | 850 | 371 |
| sha1 | 825 | 371 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 11085 |
| Exit nodes | 2390 |
| Other relays | 8695 |
| New in window | 1171 |

Sample (20 of 11085, source: Tor Project Onionoo):
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
| Unknown Loader | 5160 | 595 | — |
| Vidar | 5000 | 4549 | T1555, T1071.001, T1567 |
| Mirai | 4921 | 1093 | T1498, T1071.001 |
| AsyncRAT | 2317 | 106 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| ClearFake | 1959 | 314 | — |
| IClickFix | 1918 | 676 | — |
| Unknown malware | 1463 | 674 | — |
| Cobalt Strike | 1348 | 79 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| VShell | 883 | 646 | — |
| Unknown Stealer | 635 | 77 | — |
| php.shin_webshell | 628 | 325 | — |
| AMOS | 624 | 404 | — |
| PureRAT | 437 | 58 | — |
| Remcos | 331 | 161 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| Sliver | 321 | 287 | T1071.001, T1573, T1090, T1055 |
| AdaptixC2 | 298 | 28 | — |
| Remus | 245 | 94 | — |
| Unknown RAT | 212 | 36 | — |
| DanaBot | 195 | 100 | T1566.001, T1071.001, T1555, T1041 |
| Formbook | 187 | 89 | T1566.001, T1056.001, T1555, T1071.001, T1567 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1105 | Ingress Tool Transfer | command-and-control | 23525 |
| T1071.001 | Web Protocols | command-and-control | 47275 |
| T1498 | Network Denial of Service | impact | 10754 |
| T1204.002 | Malicious File | execution | 9458 |
| T1027 | Obfuscated Files or Information | defense-evasion | 9296 |
| T1573 | Encrypted Channel | command-and-control | 8784 |
| T1555 | Credentials from Password Stores | credential-access | 8272 |
| T1567 | Exfiltration Over Web Service | exfiltration | 8077 |
| T1566 | Phishing | initial-access | 6597 |
| T1566.002 | Spearphishing Link | initial-access | 6597 |
| T1552.001 | Credentials In Files | credential-access | 5027 |
| T1056.001 | Keylogging | collection, credential-access | 3908 |
| T1566.001 | Spearphishing Attachment | initial-access | 3594 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 2996 |
| T1113 | Screen Capture | collection | 2947 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1927 |
| T1090 | Proxy | command-and-control | 1706 |
| T1059.001 | PowerShell | execution | 1362 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 379 |
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
| [`hxxps://hm[.]9nawin[.]org/x5/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhm.9nawin.org%2Fx5%2F) | url | Vidar | threatfox | 2026-10-18T04:35:48Z | 100 |
| [`hxxps://hm[.]9nawin[.]org/mf/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhm.9nawin.org%2Fmf%2F) | url | Vidar | threatfox | 2026-10-18T04:30:48Z | 100 |
| [`hxxps://hm[.]9nawin[.]org/sg/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhm.9nawin.org%2Fsg%2F) | url | Vidar | threatfox | 2026-10-18T04:25:48Z | 100 |
| [`hxxps://hm[.]9nawin[.]org/tx/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhm.9nawin.org%2Ftx%2F) | url | Vidar | threatfox | 2026-10-18T04:20:48Z | 100 |
| [`hxxps://hm[.]9nawin[.]org/d6/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhm.9nawin.org%2Fd6%2F) | url | Vidar | threatfox | 2026-10-18T04:15:48Z | 100 |
| [`hxxps://hm[.]9nawin[.]org/kv/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhm.9nawin.org%2Fkv%2F) | url | Vidar | threatfox | 2026-10-18T04:10:48Z | 100 |
| [`verifing-server[.]codes`](https://www.virustotal.com/gui/domain/verifing-server.codes) | domain | IClickFix | threatfox | 2026-10-18T04:09:29Z | 100 |
| [`travelley[.]health`](https://www.virustotal.com/gui/domain/travelley.health) | domain | ClearFake | threatfox | 2026-10-18T04:09:21Z | 100 |
| [`hxxps://hm[.]9nawin[.]org/eo/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhm.9nawin.org%2Feo%2F) | url | Vidar | threatfox | 2026-10-18T04:05:48Z | 100 |
| [`hxxps://igb[.]9nawin[.]org/hz/`](https://www.virustotal.com/gui/search/https%3A%2F%2Figb.9nawin.org%2Fhz%2F) | url | Vidar | threatfox | 2026-10-18T04:00:49Z | 100 |
| [`web-optimizer[.]us`](https://www.virustotal.com/gui/domain/web-optimizer.us) | domain | ClearFake | threatfox | 2026-10-18T03:59:25Z | 100 |
| [`hxxps://igb[.]9nawin[.]org/rt/`](https://www.virustotal.com/gui/search/https%3A%2F%2Figb.9nawin.org%2Frt%2F) | url | Vidar | threatfox | 2026-10-18T03:55:48Z | 100 |
| [`hxxps://igb[.]9nawin[.]org/uy/`](https://www.virustotal.com/gui/search/https%3A%2F%2Figb.9nawin.org%2Fuy%2F) | url | Vidar | threatfox | 2026-10-18T03:45:48Z | 100 |
| [`hxxps://igb[.]9nawin[.]org/vx/`](https://www.virustotal.com/gui/search/https%3A%2F%2Figb.9nawin.org%2Fvx%2F) | url | Vidar | threatfox | 2026-10-18T03:40:48Z | 100 |
| [`hxxps://igb[.]9nawin[.]org/hh/`](https://www.virustotal.com/gui/search/https%3A%2F%2Figb.9nawin.org%2Fhh%2F) | url | Vidar | threatfox | 2026-10-18T03:35:48Z | 100 |
| [`hxxps://igb[.]9nawin[.]org/e6/`](https://www.virustotal.com/gui/search/https%3A%2F%2Figb.9nawin.org%2Fe6%2F) | url | Vidar | threatfox | 2026-10-18T03:30:48Z | 100 |
| [`hxxps://igb[.]9nawin[.]org/x/`](https://www.virustotal.com/gui/search/https%3A%2F%2Figb.9nawin.org%2Fx%2F) | url | Vidar | threatfox | 2026-10-18T03:25:48Z | 100 |
| [`hxxps://igb[.]9nawin[.]org/h/`](https://www.virustotal.com/gui/search/https%3A%2F%2Figb.9nawin.org%2Fh%2F) | url | Vidar | threatfox | 2026-10-18T03:20:48Z | 100 |
| [`hxxps://igb[.]9nawin[.]org/pk/`](https://www.virustotal.com/gui/search/https%3A%2F%2Figb.9nawin.org%2Fpk%2F) | url | Vidar | threatfox | 2026-10-18T03:15:48Z | 100 |
| [`hxxps://igb[.]9nawin[.]org/k9/`](https://www.virustotal.com/gui/search/https%3A%2F%2Figb.9nawin.org%2Fk9%2F) | url | Vidar | threatfox | 2026-10-18T03:10:48Z | 100 |
| [`hxxps://igb[.]9nawin[.]org/gs/`](https://www.virustotal.com/gui/search/https%3A%2F%2Figb.9nawin.org%2Fgs%2F) | url | Vidar | threatfox | 2026-10-18T03:05:48Z | 100 |
| [`39[.]105[.]111[.]104`](https://www.virustotal.com/gui/ip-address/39.105.111.104) | ipv4 | VShell | threatfox | 2026-10-18T03:05:06Z | 100 |
| [`hxxps://gc[.]9nawin[.]org/rh/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fgc.9nawin.org%2Frh%2F) | url | Vidar | threatfox | 2026-10-18T03:00:49Z | 100 |
| [`hxxps://gc[.]9nawin[.]org/l7/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fgc.9nawin.org%2Fl7%2F) | url | Vidar | threatfox | 2026-10-18T02:55:48Z | 100 |
| [`hxxps://gc[.]9nawin[.]org/g2/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fgc.9nawin.org%2Fg2%2F) | url | Vidar | threatfox | 2026-10-18T02:50:48Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
