# Threat Intel Pulse — 2026-10-11

**Window:** last 7 days · **Generated:** 2026-10-11T13:08:26Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 53296 |
| New in window | 53296 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5000 | ok |
| feodo | 5 | ok |
| threatfox | 6969 | ok |
| malwarebazaar | 835 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8600 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 18720 | 18720 |
| sha256 | 10349 | 10349 |
| domain | 10219 | 10219 |
| ipv4 | 10118 | 10118 |
| ipv6 | 2957 | 2957 |
| md5 | 479 | 479 |
| sha1 | 454 | 454 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 9996 |
| Exit nodes | 2218 |
| Other relays | 7778 |
| New in window | 9996 |

Sample (20 of 9996, source: Tor Project Onionoo):
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
| Unknown Loader | 4560 | 4560 | — |
| Mirai | 3802 | 3802 | T1498, T1071.001 |
| AsyncRAT | 2215 | 2215 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| ClearFake | 1667 | 1667 | — |
| IClickFix | 1289 | 1289 | — |
| Cobalt Strike | 1272 | 1272 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| Unknown malware | 849 | 849 | — |
| Unknown Stealer | 560 | 560 | — |
| Vidar | 464 | 464 | T1555, T1071.001, T1567 |
| PureRAT | 381 | 381 | — |
| php.shin_webshell | 336 | 336 | — |
| AdaptixC2 | 272 | 272 | — |
| VShell | 252 | 252 | — |
| AMOS | 238 | 238 | — |
| Unknown RAT | 179 | 179 | — |
| Remcos | 173 | 173 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| Remus | 160 | 160 | — |
| DCRat | 109 | 109 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| Formbook | 97 | 97 | T1566.001, T1056.001, T1555, T1071.001, T1567 |
| DanaBot | 96 | 96 | T1566.001, T1071.001, T1555, T1041 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1105 | Ingress Tool Transfer | command-and-control | 16712 |
| T1071.001 | Web Protocols | command-and-control | 34964 |
| T1498 | Network Denial of Service | impact | 8796 |
| T1204.002 | Malicious File | execution | 5672 |
| T1027 | Obfuscated Files or Information | defense-evasion | 5661 |
| T1573 | Encrypted Channel | command-and-control | 4994 |
| T1056.001 | Keylogging | collection, credential-access | 3315 |
| T1566 | Phishing | initial-access | 3042 |
| T1566.002 | Spearphishing Link | initial-access | 3042 |
| T1566.001 | Spearphishing Attachment | initial-access | 2950 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 2616 |
| T1113 | Screen Capture | collection | 2584 |
| T1555 | Credentials from Password Stores | credential-access | 2126 |
| T1567 | Exfiltration Over Web Service | exfiltration | 2030 |
| T1552.001 | Credentials In Files | credential-access | 1503 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1493 |
| T1090 | Proxy | command-and-control | 1328 |
| T1059.001 | PowerShell | execution | 1285 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 219 |
| T1059.005 | Visual Basic | execution | 70 |
| T1189 | Drive-by Compromise | initial-access | 22 |
| T1218 | System Binary Proxy Execution | defense-evasion | 22 |
| T1021.001 | Remote Desktop Protocol | lateral-movement | 8 |
| T1486 | Data Encrypted for Impact | impact | 8 |
| T1490 | Inhibit System Recovery | impact | 8 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 8 |
| T1003 | OS Credential Dumping | credential-access | 1 |
| T1190 | Exploit Public-Facing Application | initial-access | 1 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`bnr1b90s[.]kaarenorge[.]com`](https://www.virustotal.com/gui/domain/bnr1b90s.kaarenorge.com) | domain | ClearFake | threatfox | 2026-10-11T12:30:21Z | 100 |
| [`yrfxbtcx[.]mawos[.]store`](https://www.virustotal.com/gui/domain/yrfxbtcx.mawos.store) | domain | ClearFake | threatfox | 2026-10-11T11:43:12Z | 100 |
| [`calderonsjump[.]com`](https://www.virustotal.com/gui/domain/calderonsjump.com) | domain | IClickFix | threatfox | 2026-10-11T11:17:06Z | 100 |
| [`easternhardware[.]com[.]bd`](https://www.virustotal.com/gui/domain/easternhardware.com.bd) | domain | IClickFix | threatfox | 2026-10-11T11:17:06Z | 100 |
| [`grantifygroup[.]com`](https://www.virustotal.com/gui/domain/grantifygroup.com) | domain | IClickFix | threatfox | 2026-10-11T11:17:06Z | 100 |
| [`20[.]111[.]19[.]203`](https://www.virustotal.com/gui/ip-address/20.111.19.203) | ipv4 | AdaptixC2 | threatfox | 2026-10-11T11:05:04Z | 100 |
| [`framework-css-styles-js[.]beer`](https://www.virustotal.com/gui/domain/framework-css-styles-js.beer) | domain | IClickFix | threatfox | 2026-10-11T10:44:18Z | 100 |
| [`clpcentr[.]world`](https://www.virustotal.com/gui/domain/clpcentr.world) | domain | IClickFix | threatfox | 2026-10-11T10:44:17Z | 100 |
| [`clpuanmeserver[.]shop`](https://www.virustotal.com/gui/domain/clpuanmeserver.shop) | domain | IClickFix | threatfox | 2026-10-11T10:44:17Z | 100 |
| [`braimzaii-rook[.]pro`](https://www.virustotal.com/gui/domain/braimzaii-rook.pro) | domain | IClickFix | threatfox | 2026-10-11T10:20:18Z | 100 |
| [`thistle-godbriaum[.]pro`](https://www.virustotal.com/gui/domain/thistle-godbriaum.pro) | domain | IClickFix | threatfox | 2026-10-11T10:20:18Z | 100 |
| [`hs[.]4-win[.]org`](https://www.virustotal.com/gui/domain/hs.4-win.org) | domain | Vidar | threatfox | 2026-10-11T10:05:48Z | 100 |
| [`hxxps://hs[.]4-win[.]org/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhs.4-win.org%2F) | url | Vidar | threatfox | 2026-10-11T10:05:48Z | 100 |
| [`146[.]190[.]106[.]155`](https://www.virustotal.com/gui/ip-address/146.190.106.155) | ipv4 | AsyncRAT | threatfox | 2026-10-11T10:05:04Z | 100 |
| [`hxxps://hs[.]54toto[.]org/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhs.54toto.org%2F) | url | Vidar | threatfox | 2026-10-11T10:00:49Z | 100 |
| [`hs[.]54toto[.]org`](https://www.virustotal.com/gui/domain/hs.54toto.org) | domain | Vidar | threatfox | 2026-10-11T10:00:48Z | 100 |
| [`rtpk86sport-happy[.]click`](https://www.virustotal.com/gui/domain/rtpk86sport-happy.click) | domain | ClearFake | threatfox | 2026-10-11T09:20:05Z | 100 |
| [`zj9s97wb[.]jp168amp-super[.]com`](https://www.virustotal.com/gui/domain/zj9s97wb.jp168amp-super.com) | domain | ClearFake | threatfox | 2026-10-11T08:10:51Z | 100 |
| [`103[.]170[.]217[.]147`](https://www.virustotal.com/gui/ip-address/103.170.217.147) | ipv4 | Quasar RAT | threatfox | 2026-10-11T08:05:04Z | 100 |
| [`c86b8aa9e16084a67783ec19f6e574abae1413399fc2b219e5a6dfb5e924ea50`](https://www.virustotal.com/gui/file/c86b8aa9e16084a67783ec19f6e574abae1413399fc2b219e5a6dfb5e924ea50) | sha256 | AMOS | threatfox | 2026-10-11T07:39:13Z | 100 |
| [`7aigp3my[.]lunza[.]store`](https://www.virustotal.com/gui/domain/7aigp3my.lunza.store) | domain | ClearFake | threatfox | 2026-10-11T07:23:15Z | 100 |
| [`137[.]220[.]153[.]128`](https://www.virustotal.com/gui/ip-address/137.220.153.128) | ipv4 | Unknown malware | threatfox | 2026-10-11T07:05:04Z | 100 |
| [`hxxps://fh[.]4-win[.]org`](https://www.virustotal.com/gui/search/https%3A%2F%2Ffh.4-win.org) | url | Vidar | threatfox | 2026-10-11T07:02:58Z | 100 |
| [`34c9f78b4ef541baac4a6e84d4f832a7[.]lol`](https://www.virustotal.com/gui/domain/34c9f78b4ef541baac4a6e84d4f832a7.lol) | domain | Unknown malware | threatfox | 2026-10-11T07:02:57Z | 100 |
| [`605394ec700b60b94fb028048834cb89d7627b35af50382e7f42c5c4c8f61c60`](https://www.virustotal.com/gui/file/605394ec700b60b94fb028048834cb89d7627b35af50382e7f42c5c4c8f61c60) | sha256 | AMOS | threatfox | 2026-10-11T07:02:56Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
