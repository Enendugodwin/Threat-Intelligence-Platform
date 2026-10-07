# Threat Intel Pulse — 2026-10-07

**Window:** last 7 days · **Generated:** 2026-10-07T13:44:58Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 41698 |
| New in window | 41698 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | — | error: ConnectionError: HTTPSConnectionPool(host='urlhaus.abuse.ch', port=443): Max retries exceeded with url: /downloads/csv_recent/ (Caused by ReadTimeoutError("HTTPSConnectionPool(host='urlhaus.abuse.ch', port=443): Read timed out. (read timeout=90)")) |
| feodo | 5 | ok |
| threatfox | 8518 | ok |
| malwarebazaar | 1375 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8631 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 12691 | 12691 |
| ipv4 | 9235 | 9235 |
| sha256 | 8438 | 8438 |
| domain | 7986 | 7986 |
| ipv6 | 2868 | 2868 |
| md5 | 252 | 252 |
| sha1 | 228 | 228 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 9441 |
| Exit nodes | 2186 |
| Other relays | 7255 |
| New in window | 9441 |

Sample (20 of 9441, source: Tor Project Onionoo):
- `1[.]201[.]176[.]176`
- `1[.]248[.]96[.]163`
- `100[.]1[.]157[.]56`
- `100[.]2[.]63[.]41`
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
- `103[.]105[.]21[.]2`

Full list: `dist/tor/tor_nodes.txt` (in the `threat-intel-output` workflow artifact).
## Top malware families

| Family | Indicators | New | ATT&CK (heuristic) |
| --- | --- | --- | --- |
| Unknown Loader | 4095 | 4095 | — |
| Mirai | 3305 | 3305 | T1498, T1071.001 |
| AsyncRAT | 2178 | 2178 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| Cobalt Strike | 1243 | 1243 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| ClearFake | 1059 | 1059 | — |
| IClickFix | 733 | 733 | — |
| Unknown malware | 557 | 557 | — |
| PureRAT | 353 | 353 | — |
| Vidar | 274 | 274 | T1555, T1071.001, T1567 |
| AdaptixC2 | 251 | 251 | — |
| Unknown Stealer | 186 | 186 | — |
| Unknown RAT | 168 | 168 | — |
| AMOS | 160 | 160 | — |
| Remcos | 143 | 143 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| php.shin_webshell | 130 | 130 | — |
| VShell | 114 | 114 | — |
| Remus | 109 | 109 | — |
| DCRat | 104 | 104 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| Evilginx | 94 | 94 | — |
| Havoc | 90 | 90 | — |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1105 | Ingress Tool Transfer | command-and-control | 12605 |
| T1071.001 | Web Protocols | command-and-control | 29876 |
| T1498 | Network Denial of Service | impact | 7339 |
| T1204.002 | Malicious File | execution | 5467 |
| T1027 | Obfuscated Files or Information | defense-evasion | 5456 |
| T1573 | Encrypted Channel | command-and-control | 4682 |
| T1056.001 | Keylogging | collection, credential-access | 3073 |
| T1566.001 | Spearphishing Attachment | initial-access | 2743 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 2502 |
| T1113 | Screen Capture | collection | 2480 |
| T1566 | Phishing | initial-access | 1428 |
| T1566.002 | Spearphishing Link | initial-access | 1428 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1425 |
| T1090 | Proxy | command-and-control | 1281 |
| T1059.001 | PowerShell | execution | 1255 |
| T1555 | Credentials from Password Stores | credential-access | 915 |
| T1567 | Exfiltration Over Web Service | exfiltration | 852 |
| T1552.001 | Credentials In Files | credential-access | 571 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 163 |
| T1059.005 | Visual Basic | execution | 59 |
| T1189 | Drive-by Compromise | initial-access | 18 |
| T1218 | System Binary Proxy Execution | defense-evasion | 18 |
| T1021.001 | Remote Desktop Protocol | lateral-movement | 5 |
| T1486 | Data Encrypted for Impact | impact | 5 |
| T1490 | Inhibit System Recovery | impact | 5 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 5 |
| T1003 | OS Credential Dumping | credential-access | 1 |
| T1190 | Exploit Public-Facing Application | initial-access | 1 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`49[.]234[.]48[.]58`](https://www.virustotal.com/gui/ip-address/49.234.48.58) | ipv4 | VShell | threatfox | 2026-10-07T13:05:06Z | 100 |
| [`102[.]117[.]168[.]65`](https://www.virustotal.com/gui/ip-address/102.117.168.65) | ipv4 | Unknown malware | threatfox | 2026-10-07T13:05:05Z | 100 |
| [`137[.]220[.]224[.]26`](https://www.virustotal.com/gui/ip-address/137.220.224.26) | ipv4 | Unknown RAT | threatfox | 2026-10-07T12:32:56Z | 100 |
| [`hxxps://kb[.]3toto[.]com`](https://www.virustotal.com/gui/search/https%3A%2F%2Fkb.3toto.com) | url | Vidar | threatfox | 2026-10-07T12:32:56Z | 100 |
| [`b0a61e0d2b769b06c8e83cd7529c6d31ddcf30bd6dae83cae0452f098e069df0`](https://www.virustotal.com/gui/file/b0a61e0d2b769b06c8e83cd7529c6d31ddcf30bd6dae83cae0452f098e069df0) | sha256 | AMOS | threatfox | 2026-10-07T12:32:56Z | 100 |
| [`sarmo[.]store`](https://www.virustotal.com/gui/domain/sarmo.store) | domain | ClearFake | threatfox | 2026-10-07T12:22:07Z | 100 |
| [`apexfd[.]click`](https://www.virustotal.com/gui/domain/apexfd.click) | domain | Remus | threatfox | 2026-10-07T11:56:18Z | 100 |
| [`cryonex[.]sbs`](https://www.virustotal.com/gui/domain/cryonex.sbs) | domain | Remus | threatfox | 2026-10-07T11:56:18Z | 100 |
| [`cfcher[.]biz`](https://www.virustotal.com/gui/domain/cfcher.biz) | domain | Remus | threatfox | 2026-10-07T11:56:18Z | 100 |
| [`103[.]83[.]86[.]40`](https://www.virustotal.com/gui/ip-address/103.83.86.40) | ipv4 | Remcos | threatfox | 2026-10-07T11:44:51Z | 100 |
| [`6111a10b82cc1bf6bac1082bc8ffa36e9f3123f0feb811aac281278a7fe63e13`](https://www.virustotal.com/gui/file/6111a10b82cc1bf6bac1082bc8ffa36e9f3123f0feb811aac281278a7fe63e13) | sha256 | AMOS | threatfox | 2026-10-07T11:44:51Z | 100 |
| [`kb[.]3toto[.]com`](https://www.virustotal.com/gui/domain/kb.3toto.com) | domain | Vidar | threatfox | 2026-10-07T11:40:48Z | 100 |
| [`hxxps://kb[.]3toto[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fkb.3toto.com%2F) | url | Vidar | threatfox | 2026-10-07T11:40:48Z | 100 |
| [`7wlvj9nh[.]lezo[.]store`](https://www.virustotal.com/gui/domain/7wlvj9nh.lezo.store) | domain | ClearFake | threatfox | 2026-10-07T11:39:14Z | 100 |
| [`lh5yl7g0[.]pegy[.]store`](https://www.virustotal.com/gui/domain/lh5yl7g0.pegy.store) | domain | ClearFake | threatfox | 2026-10-07T11:33:37Z | 100 |
| [`pegy[.]store`](https://www.virustotal.com/gui/domain/pegy.store) | domain | ClearFake | threatfox | 2026-10-07T11:31:20Z | 100 |
| [`49f19199c38499498aa4dead3e19102c6679192fe282e72ec024b19191d8ae63`](https://www.virustotal.com/gui/file/49f19199c38499498aa4dead3e19102c6679192fe282e72ec024b19191d8ae63) | sha256 | AMOS | threatfox | 2026-10-07T11:08:02Z | 100 |
| [`hxxps://95[.]182[.]97[.]240`](https://www.virustotal.com/gui/search/https%3A%2F%2F95.182.97.240) | url | Vidar | threatfox | 2026-10-07T11:08:02Z | 100 |
| [`260120[.]vercel[.]app`](https://www.virustotal.com/gui/domain/260120.vercel.app) | domain | ContagiousDrop | threatfox | 2026-10-07T10:38:36Z | 100 |
| [`coreviewer[.]vercel[.]app`](https://www.virustotal.com/gui/domain/coreviewer.vercel.app) | domain | ContagiousDrop | threatfox | 2026-10-07T10:38:35Z | 100 |
| [`ext-checkedin[.]vercel[.]app`](https://www.virustotal.com/gui/domain/ext-checkedin.vercel.app) | domain | ContagiousDrop | threatfox | 2026-10-07T10:38:35Z | 100 |
| [`tailwind-version-4[.]vercel[.]app`](https://www.virustotal.com/gui/domain/tailwind-version-4.vercel.app) | domain | ContagiousDrop | threatfox | 2026-10-07T10:38:34Z | 100 |
| [`thopywork[.]vercel[.]app`](https://www.virustotal.com/gui/domain/thopywork.vercel.app) | domain | ContagiousDrop | threatfox | 2026-10-07T10:38:34Z | 100 |
| [`valid-dep[.]vercel[.]app`](https://www.virustotal.com/gui/domain/valid-dep.vercel.app) | domain | ContagiousDrop | threatfox | 2026-10-07T10:38:34Z | 100 |
| [`vscode-bootstrapper[.]vercel[.]app`](https://www.virustotal.com/gui/domain/vscode-bootstrapper.vercel.app) | domain | ContagiousDrop | threatfox | 2026-10-07T10:38:33Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
