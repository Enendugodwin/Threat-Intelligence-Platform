# Threat Intel Pulse — 2026-10-06

**Window:** last 7 days · **Generated:** 2026-10-06T06:34:36Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 34579 |
| New in window | 34579 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 27 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5000 | ok |
| feodo | 5 | ok |
| threatfox | 8913 | ok |
| malwarebazaar | 1076 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8596 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 9179 | 9179 |
| ipv4 | 8891 | 8891 |
| sha256 | 7339 | 7339 |
| domain | 6064 | 6064 |
| ipv6 | 2800 | 2800 |
| md5 | 165 | 165 |
| sha1 | 141 | 141 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 9168 |
| Exit nodes | 2106 |
| Other relays | 7062 |
| New in window | 9168 |

Sample (20 of 9168, source: Tor Project Onionoo):
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
| Mirai | 3284 | 3284 | T1498, T1071.001 |
| Unknown Loader | 2792 | 2792 | — |
| AsyncRAT | 2163 | 2163 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| Cobalt Strike | 1235 | 1235 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| ClearFake | 855 | 855 | — |
| Unknown malware | 511 | 511 | — |
| IClickFix | 384 | 384 | — |
| PureRAT | 340 | 340 | — |
| AdaptixC2 | 245 | 245 | — |
| Vidar | 216 | 216 | T1555, T1071.001, T1567 |
| Unknown Stealer | 174 | 174 | — |
| Unknown RAT | 157 | 157 | — |
| AMOS | 132 | 132 | — |
| Remcos | 109 | 109 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| VShell | 109 | 109 | — |
| DCRat | 97 | 97 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| Evilginx | 93 | 93 | — |
| Remus | 93 | 93 | — |
| php.shin_webshell | 89 | 89 | — |
| Havoc | 88 | 88 | — |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1071.001 | Web Protocols | command-and-control | 27111 |
| T1105 | Ingress Tool Transfer | command-and-control | 9590 |
| T1498 | Network Denial of Service | impact | 6984 |
| T1573 | Encrypted Channel | command-and-control | 4579 |
| T1056.001 | Keylogging | collection, credential-access | 2958 |
| T1204.002 | Malicious File | execution | 2951 |
| T1027 | Obfuscated Files or Information | defense-evasion | 2940 |
| T1566.001 | Spearphishing Attachment | initial-access | 2642 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 2434 |
| T1113 | Screen Capture | collection | 2412 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1410 |
| T1090 | Proxy | command-and-control | 1270 |
| T1059.001 | PowerShell | execution | 1247 |
| T1566 | Phishing | initial-access | 857 |
| T1566.002 | Spearphishing Link | initial-access | 857 |
| T1555 | Credentials from Password Stores | credential-access | 722 |
| T1567 | Exfiltration Over Web Service | exfiltration | 659 |
| T1552.001 | Credentials In Files | credential-access | 454 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 157 |
| T1059.005 | Visual Basic | execution | 59 |
| T1189 | Drive-by Compromise | initial-access | 17 |
| T1218 | System Binary Proxy Execution | defense-evasion | 17 |
| T1021.001 | Remote Desktop Protocol | lateral-movement | 5 |
| T1486 | Data Encrypted for Impact | impact | 5 |
| T1490 | Inhibit System Recovery | impact | 5 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 5 |
| T1003 | OS Credential Dumping | credential-access | 1 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`marblegrove[.]cfd`](https://www.virustotal.com/gui/domain/marblegrove.cfd) | domain | Unknown Loader | threatfox | 2026-10-06T06:18:43Z | 100 |
| [`rovgruien[.]pro`](https://www.virustotal.com/gui/domain/rovgruien.pro) | domain | IClickFix | threatfox | 2026-10-06T05:52:51Z | 100 |
| [`176[.]97[.]114[.]125`](https://www.virustotal.com/gui/ip-address/176.97.114.125) | ipv4 | Jackskid | threatfox | 2026-10-06T05:52:13Z | 100 |
| [`176[.]97[.]114[.]132`](https://www.virustotal.com/gui/ip-address/176.97.114.132) | ipv4 | Jackskid | threatfox | 2026-10-06T05:52:12Z | 100 |
| [`176[.]97[.]114[.]170`](https://www.virustotal.com/gui/ip-address/176.97.114.170) | ipv4 | Jackskid | threatfox | 2026-10-06T05:52:11Z | 100 |
| [`176[.]97[.]114[.]177`](https://www.virustotal.com/gui/ip-address/176.97.114.177) | ipv4 | Jackskid | threatfox | 2026-10-06T05:52:11Z | 100 |
| [`176[.]97[.]114[.]243`](https://www.virustotal.com/gui/ip-address/176.97.114.243) | ipv4 | Jackskid | threatfox | 2026-10-06T05:52:10Z | 100 |
| [`176[.]97[.]114[.]29`](https://www.virustotal.com/gui/ip-address/176.97.114.29) | ipv4 | Jackskid | threatfox | 2026-10-06T05:52:09Z | 100 |
| [`gnfelg66[.]succeswithpaul[.]com`](https://www.virustotal.com/gui/domain/gnfelg66.succeswithpaul.com) | domain | ClearFake | threatfox | 2026-10-06T05:30:30Z | 100 |
| [`succeswithpaul[.]com`](https://www.virustotal.com/gui/domain/succeswithpaul.com) | domain | ClearFake | threatfox | 2026-10-06T05:29:03Z | 100 |
| [`hxxps://ohhhhhmoney[.]com/fF2`](https://www.virustotal.com/gui/search/https%3A%2F%2Fohhhhhmoney.com%2FfF2) | url | HijackLoader | threatfox | 2026-10-06T05:28:16Z | 100 |
| [`hxxps://fu[.]333pwk[.]org`](https://www.virustotal.com/gui/search/https%3A%2F%2Ffu.333pwk.org) | url | Vidar | threatfox | 2026-10-06T05:28:13Z | 100 |
| [`hxxps://fu[.]396zk[.]net`](https://www.virustotal.com/gui/search/https%3A%2F%2Ffu.396zk.net) | url | Vidar | threatfox | 2026-10-06T05:28:12Z | 100 |
| [`165[.]22[.]244[.]100`](https://www.virustotal.com/gui/ip-address/165.22.244.100) | ipv4 | Aisuru | threatfox | 2026-10-06T05:28:08Z | 100 |
| [`46[.]101[.]164[.]65`](https://www.virustotal.com/gui/ip-address/46.101.164.65) | ipv4 | Aisuru | threatfox | 2026-10-06T05:28:06Z | 100 |
| [`7cfe5781ebb844a267300fbc9f343d293d774bab9b0a530cc49262ddc083c5ed`](https://www.virustotal.com/gui/file/7cfe5781ebb844a267300fbc9f343d293d774bab9b0a530cc49262ddc083c5ed) | sha256 | AMOS | threatfox | 2026-10-06T05:28:05Z | 100 |
| [`147[.]139[.]168[.]67`](https://www.virustotal.com/gui/ip-address/147.139.168.67) | ipv4 | Jackskid | threatfox | 2026-10-06T05:28:04Z | 100 |
| [`198[.]11[.]174[.]58`](https://www.virustotal.com/gui/ip-address/198.11.174.58) | ipv4 | Jackskid | threatfox | 2026-10-06T05:28:00Z | 100 |
| [`134[.]122[.]22[.]105`](https://www.virustotal.com/gui/ip-address/134.122.22.105) | ipv4 | Aisuru | threatfox | 2026-10-06T05:27:59Z | 100 |
| [`45[.]91[.]52[.]45`](https://www.virustotal.com/gui/ip-address/45.91.52.45) | ipv4 | Unknown RAT | threatfox | 2026-10-06T05:27:59Z | 100 |
| [`159[.]89[.]95[.]185`](https://www.virustotal.com/gui/ip-address/159.89.95.185) | ipv4 | Aisuru | threatfox | 2026-10-06T05:27:55Z | 100 |
| [`aa00225f01e1f8542d8275adb88936111ce387e8ec529b1566ff2532369737da`](https://www.virustotal.com/gui/file/aa00225f01e1f8542d8275adb88936111ce387e8ec529b1566ff2532369737da) | sha256 | AMOS | threatfox | 2026-10-06T05:27:52Z | 100 |
| [`128[.]90[.]108[.]163`](https://www.virustotal.com/gui/ip-address/128.90.108.163) | ipv4 | Remcos | threatfox | 2026-10-06T05:27:51Z | 100 |
| [`hxxps://heavenproject[.]lgbt/api/connect`](https://www.virustotal.com/gui/search/https%3A%2F%2Fheavenproject.lgbt%2Fapi%2Fconnect) | url | Unknown RAT | threatfox | 2026-10-06T05:27:46Z | 100 |
| [`hxxps://heavenproject[.]lgbt/api/heartbeat`](https://www.virustotal.com/gui/search/https%3A%2F%2Fheavenproject.lgbt%2Fapi%2Fheartbeat) | url | Unknown RAT | threatfox | 2026-10-06T05:27:44Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
