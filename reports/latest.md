# Threat Intel Pulse — 2026-10-10

**Window:** last 7 days · **Generated:** 2026-10-10T21:53:34Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 52086 |
| New in window | 52086 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5000 | ok |
| feodo | 5 | ok |
| threatfox | 6834 | ok |
| malwarebazaar | 842 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8618 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 18010 | 18010 |
| sha256 | 10156 | 10156 |
| domain | 10066 | 10066 |
| ipv4 | 9977 | 9977 |
| ipv6 | 2944 | 2944 |
| md5 | 479 | 479 |
| sha1 | 454 | 454 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 9913 |
| Exit nodes | 2217 |
| Other relays | 7696 |
| New in window | 9913 |

Sample (20 of 9913, source: Tor Project Onionoo):
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
| Unknown Loader | 4558 | 4558 | — |
| Mirai | 3761 | 3761 | T1498, T1071.001 |
| AsyncRAT | 2211 | 2211 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| ClearFake | 1645 | 1645 | — |
| Cobalt Strike | 1269 | 1269 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| IClickFix | 1242 | 1242 | — |
| Unknown malware | 788 | 788 | — |
| Unknown Stealer | 558 | 558 | — |
| Vidar | 449 | 449 | T1555, T1071.001, T1567 |
| PureRAT | 379 | 379 | — |
| php.shin_webshell | 303 | 303 | — |
| AdaptixC2 | 270 | 270 | — |
| VShell | 235 | 235 | — |
| AMOS | 220 | 220 | — |
| Unknown RAT | 176 | 176 | — |
| Remcos | 170 | 170 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| Remus | 151 | 151 | — |
| DCRat | 108 | 108 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| Formbook | 97 | 97 | T1566.001, T1056.001, T1555, T1071.001, T1567 |
| Havoc | 96 | 96 | — |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1105 | Ingress Tool Transfer | command-and-control | 16389 |
| T1071.001 | Web Protocols | command-and-control | 34523 |
| T1498 | Network Denial of Service | impact | 8683 |
| T1204.002 | Malicious File | execution | 5648 |
| T1027 | Obfuscated Files or Information | defense-evasion | 5637 |
| T1573 | Encrypted Channel | command-and-control | 4964 |
| T1056.001 | Keylogging | collection, credential-access | 3295 |
| T1566.001 | Spearphishing Attachment | initial-access | 2932 |
| T1566 | Phishing | initial-access | 2679 |
| T1566.002 | Spearphishing Link | initial-access | 2679 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 2602 |
| T1113 | Screen Capture | collection | 2570 |
| T1555 | Credentials from Password Stores | credential-access | 2080 |
| T1567 | Exfiltration Over Web Service | exfiltration | 1985 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1486 |
| T1552.001 | Credentials In Files | credential-access | 1468 |
| T1090 | Proxy | command-and-control | 1322 |
| T1059.001 | PowerShell | execution | 1282 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 215 |
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
| [`3cipm334[.]pilkada2017[.]com`](https://www.virustotal.com/gui/domain/3cipm334.pilkada2017.com) | domain | ClearFake | threatfox | 2026-10-10T21:33:51Z | 100 |
| [`apinetsolworkspace[.]network`](https://www.virustotal.com/gui/domain/apinetsolworkspace.network) | domain | Unknown RAT | threatfox | 2026-10-10T21:33:18Z | 100 |
| [`devicehubcloud[.]com`](https://www.virustotal.com/gui/domain/devicehubcloud.com) | domain | Unknown RAT | threatfox | 2026-10-10T21:33:18Z | 100 |
| [`blackcryptknight[.]com`](https://www.virustotal.com/gui/domain/blackcryptknight.com) | domain | Unknown RAT | threatfox | 2026-10-10T21:33:18Z | 100 |
| [`csgroup[.]zip`](https://www.virustotal.com/gui/domain/csgroup.zip) | domain | Unknown Stealer | threatfox | 2026-10-10T20:27:03Z | 100 |
| [`tr[.]4-win[.]org`](https://www.virustotal.com/gui/domain/tr.4-win.org) | domain | Vidar | threatfox | 2026-10-10T19:25:48Z | 100 |
| [`hxxps://tr[.]4-win[.]org/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ftr.4-win.org%2F) | url | Vidar | threatfox | 2026-10-10T19:25:48Z | 100 |
| [`tr[.]54toto[.]org`](https://www.virustotal.com/gui/domain/tr.54toto.org) | domain | Vidar | threatfox | 2026-10-10T19:20:48Z | 100 |
| [`hxxps://tr[.]54toto[.]org/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ftr.54toto.org%2F) | url | Vidar | threatfox | 2026-10-10T19:20:48Z | 100 |
| [`aidigi[.]store`](https://www.virustotal.com/gui/domain/aidigi.store) | domain | ClearFake | threatfox | 2026-10-10T19:16:43Z | 100 |
| [`82[.]202[.]157[.]112`](https://www.virustotal.com/gui/ip-address/82.202.157.112) | ipv4 | Havoc | threatfox | 2026-10-10T19:05:07Z | 100 |
| [`16t38k5v[.]rtp-k86sportop[.]site`](https://www.virustotal.com/gui/domain/16t38k5v.rtp-k86sportop.site) | domain | ClearFake | threatfox | 2026-10-10T18:45:40Z | 100 |
| [`nz[.]54toto[.]org`](https://www.virustotal.com/gui/domain/nz.54toto.org) | domain | Vidar | threatfox | 2026-10-10T18:10:48Z | 100 |
| [`hxxps://nz[.]54toto[.]org/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fnz.54toto.org%2F) | url | Vidar | threatfox | 2026-10-10T18:10:48Z | 100 |
| [`hxxp://77[.]237[.]29[.]219:2027//sshd`](https://www.virustotal.com/gui/search/http%3A%2F%2F77.237.29.219%3A2027%2F%2Fsshd) | url | SSHDoor | threatfox | 2026-10-10T17:06:02Z | 100 |
| [`kelp[.]camp-cantina[.]com`](https://www.virustotal.com/gui/domain/kelp.camp-cantina.com) | domain | IClickFix | threatfox | 2026-10-10T17:02:48Z | 100 |
| [`xo98poker[.]com`](https://www.virustotal.com/gui/domain/xo98poker.com) | domain | ClearFake | threatfox | 2026-10-10T16:56:24Z | 100 |
| [`ffd88db69e131045a5dafd51d65b0ef88a59c032d4e0d79a85bf9c45566510e8`](https://www.virustotal.com/gui/file/ffd88db69e131045a5dafd51d65b0ef88a59c032d4e0d79a85bf9c45566510e8) | sha256 | AMOS | threatfox | 2026-10-10T16:39:16Z | 100 |
| [`hxxps://fh[.]4toto[.]net`](https://www.virustotal.com/gui/search/https%3A%2F%2Ffh.4toto.net) | url | Vidar | threatfox | 2026-10-10T16:39:15Z | 100 |
| [`386ecada87d6348a92eee0a6126c5a2596d14e9362f35ae01857813ffa6ae35f`](https://www.virustotal.com/gui/file/386ecada87d6348a92eee0a6126c5a2596d14e9362f35ae01857813ffa6ae35f) | sha256 | AMOS | threatfox | 2026-10-10T16:39:15Z | 100 |
| [`flingtrainer[.]io`](https://www.virustotal.com/gui/domain/flingtrainer.io) | domain | RemoteControl | threatfox | 2026-10-10T16:39:14Z | 100 |
| [`fling-trainer[.]com`](https://www.virustotal.com/gui/domain/fling-trainer.com) | domain | RemoteControl | threatfox | 2026-10-10T16:39:14Z | 100 |
| [`hxxps://172[.]235[.]183[.]120`](https://www.virustotal.com/gui/search/https%3A%2F%2F172.235.183.120) | url | Vidar | threatfox | 2026-10-10T16:39:13Z | 100 |
| [`4fa6d321714717df4ad7b139ac074b1cac5f4853cc4bfe3f3ca328370cb577d4`](https://www.virustotal.com/gui/file/4fa6d321714717df4ad7b139ac074b1cac5f4853cc4bfe3f3ca328370cb577d4) | sha256 | AMOS | threatfox | 2026-10-10T16:39:13Z | 100 |
| [`9aace0b5aeeb83147b28efd5aebd8c51841afdd17b8f8a73a34dfc1e9d9a4fad`](https://www.virustotal.com/gui/file/9aace0b5aeeb83147b28efd5aebd8c51841afdd17b8f8a73a34dfc1e9d9a4fad) | sha256 | AMOS | threatfox | 2026-10-10T16:39:12Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
