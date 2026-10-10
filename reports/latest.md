# Threat Intel Pulse — 2026-10-10

**Window:** last 7 days · **Generated:** 2026-10-10T12:45:26Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 51437 |
| New in window | 51437 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5000 | ok |
| feodo | 5 | ok |
| threatfox | 7286 | ok |
| malwarebazaar | 906 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8629 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 17782 | 17782 |
| domain | 10006 | 10006 |
| sha256 | 9958 | 9958 |
| ipv4 | 9936 | 9936 |
| ipv6 | 2938 | 2938 |
| md5 | 421 | 421 |
| sha1 | 396 | 396 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 9883 |
| Exit nodes | 2215 |
| Other relays | 7668 |
| New in window | 9883 |

Sample (20 of 9883, source: Tor Project Onionoo):
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
| Unknown Loader | 4551 | 4551 | — |
| Mirai | 3710 | 3710 | T1498, T1071.001 |
| AsyncRAT | 2208 | 2208 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| ClearFake | 1633 | 1633 | — |
| Cobalt Strike | 1268 | 1268 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| IClickFix | 1238 | 1238 | — |
| Unknown malware | 771 | 771 | — |
| Unknown Stealer | 555 | 555 | — |
| Vidar | 416 | 416 | T1555, T1071.001, T1567 |
| PureRAT | 375 | 375 | — |
| php.shin_webshell | 286 | 286 | — |
| AdaptixC2 | 268 | 268 | — |
| AMOS | 215 | 215 | — |
| VShell | 184 | 184 | — |
| Unknown RAT | 172 | 172 | — |
| Remcos | 170 | 170 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| Remus | 148 | 148 | — |
| DCRat | 107 | 107 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| Formbook | 97 | 97 | T1566.001, T1056.001, T1555, T1071.001, T1567 |
| Evilginx | 95 | 95 | — |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1105 | Ingress Tool Transfer | command-and-control | 16182 |
| T1071.001 | Web Protocols | command-and-control | 34264 |
| T1498 | Network Denial of Service | impact | 8589 |
| T1204.002 | Malicious File | execution | 5638 |
| T1027 | Obfuscated Files or Information | defense-evasion | 5627 |
| T1573 | Encrypted Channel | command-and-control | 4940 |
| T1056.001 | Keylogging | collection, credential-access | 3270 |
| T1566.001 | Spearphishing Attachment | initial-access | 2919 |
| T1566 | Phishing | initial-access | 2679 |
| T1566.002 | Spearphishing Link | initial-access | 2679 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 2591 |
| T1113 | Screen Capture | collection | 2559 |
| T1555 | Credentials from Password Stores | credential-access | 2027 |
| T1567 | Exfiltration Over Web Service | exfiltration | 1934 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1485 |
| T1552.001 | Credentials In Files | credential-access | 1452 |
| T1090 | Proxy | command-and-control | 1321 |
| T1059.001 | PowerShell | execution | 1281 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 213 |
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
| [`jp168amp-super[.]com`](https://www.virustotal.com/gui/domain/jp168amp-super.com) | domain | ClearFake | threatfox | 2026-10-10T12:15:36Z | 100 |
| [`160[.]191[.]52[.]105`](https://www.virustotal.com/gui/ip-address/160.191.52.105) | ipv4 | Cobalt Strike | threatfox | 2026-10-10T12:05:05Z | 100 |
| [`tpp6b30z[.]kulonprogo[.]org`](https://www.virustotal.com/gui/domain/tpp6b30z.kulonprogo.org) | domain | ClearFake | threatfox | 2026-10-10T11:29:35Z | 100 |
| [`hxxp://118[.]69[.]157[.]212:9111/sshd`](https://www.virustotal.com/gui/search/http%3A%2F%2F118.69.157.212%3A9111%2Fsshd) | url | SSHDoor | threatfox | 2026-10-10T11:09:45Z | 100 |
| [`108[.]165[.]147[.]226`](https://www.virustotal.com/gui/ip-address/108.165.147.226) | ipv4 | VShell | threatfox | 2026-10-10T11:05:04Z | 100 |
| [`v6k91pk4[.]truenarrator[.]com`](https://www.virustotal.com/gui/domain/v6k91pk4.truenarrator.com) | domain | ClearFake | threatfox | 2026-10-10T10:55:45Z | 100 |
| [`mdtupbnx[.]mawos[.]store`](https://www.virustotal.com/gui/domain/mdtupbnx.mawos.store) | domain | ClearFake | threatfox | 2026-10-10T10:21:50Z | 100 |
| [`64[.]176[.]36[.]63`](https://www.virustotal.com/gui/ip-address/64.176.36.63) | ipv4 | AsyncRAT | threatfox | 2026-10-10T10:05:05Z | 100 |
| [`38[.]190[.]196[.]26`](https://www.virustotal.com/gui/ip-address/38.190.196.26) | ipv4 | VShell | threatfox | 2026-10-10T10:05:04Z | 100 |
| [`38[.]246[.]73[.]29`](https://www.virustotal.com/gui/ip-address/38.246.73.29) | ipv4 | VShell | threatfox | 2026-10-10T10:05:04Z | 100 |
| [`dominiaband[.]com`](https://www.virustotal.com/gui/domain/dominiaband.com) | domain | ClearFake | threatfox | 2026-10-10T09:55:11Z | 100 |
| [`n2dypmy2[.]smanbotu[.]com`](https://www.virustotal.com/gui/domain/n2dypmy2.smanbotu.com) | domain | ClearFake | threatfox | 2026-10-10T09:53:00Z | 100 |
| [`smanbotu[.]com`](https://www.virustotal.com/gui/domain/smanbotu.com) | domain | ClearFake | threatfox | 2026-10-10T09:49:11Z | 100 |
| [`188[.]245[.]3[.]116`](https://www.virustotal.com/gui/ip-address/188.245.3.116) | ipv4 | Vidar | threatfox | 2026-10-10T09:46:31Z | 100 |
| [`167[.]233[.]107[.]104`](https://www.virustotal.com/gui/ip-address/167.233.107.104) | ipv4 | Vidar | threatfox | 2026-10-10T09:46:31Z | 100 |
| [`217[.]60[.]102[.]185`](https://www.virustotal.com/gui/ip-address/217.60.102.185) | ipv4 | Vidar | threatfox | 2026-10-10T09:46:31Z | 100 |
| [`188[.]245[.]114[.]219`](https://www.virustotal.com/gui/ip-address/188.245.114.219) | ipv4 | Vidar | threatfox | 2026-10-10T09:46:31Z | 100 |
| [`188[.]245[.]11[.]133`](https://www.virustotal.com/gui/ip-address/188.245.11.133) | ipv4 | Vidar | threatfox | 2026-10-10T09:46:31Z | 100 |
| [`212[.]147[.]244[.]162`](https://www.virustotal.com/gui/ip-address/212.147.244.162) | ipv4 | Vidar | threatfox | 2026-10-10T09:46:31Z | 100 |
| [`77[.]42[.]10[.]33`](https://www.virustotal.com/gui/ip-address/77.42.10.33) | ipv4 | Vidar | threatfox | 2026-10-10T09:46:31Z | 100 |
| [`94[.]237[.]14[.]115`](https://www.virustotal.com/gui/ip-address/94.237.14.115) | ipv4 | Vidar | threatfox | 2026-10-10T09:46:31Z | 100 |
| [`xt[.]33pedia[.]org`](https://www.virustotal.com/gui/domain/xt.33pedia.org) | domain | Vidar | threatfox | 2026-10-10T09:45:43Z | 100 |
| [`xt[.]4toto[.]net`](https://www.virustotal.com/gui/domain/xt.4toto.net) | domain | Vidar | threatfox | 2026-10-10T09:45:43Z | 100 |
| [`hxxps://188[.]245[.]3[.]116/`](https://www.virustotal.com/gui/search/https%3A%2F%2F188.245.3.116%2F) | url | Vidar | threatfox | 2026-10-10T09:45:22Z | 100 |
| [`hxxps://167[.]233[.]107[.]104/`](https://www.virustotal.com/gui/search/https%3A%2F%2F167.233.107.104%2F) | url | Vidar | threatfox | 2026-10-10T09:45:22Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
