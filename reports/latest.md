# Threat Intel Pulse — 2026-10-09

**Window:** last 7 days · **Generated:** 2026-10-09T22:45:57Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 49944 |
| New in window | 49944 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5000 | ok |
| feodo | 5 | ok |
| threatfox | 7154 | ok |
| malwarebazaar | 860 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8633 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 16870 | 16870 |
| domain | 9915 | 9915 |
| ipv4 | 9780 | 9780 |
| sha256 | 9634 | 9634 |
| ipv6 | 2928 | 2928 |
| md5 | 421 | 421 |
| sha1 | 396 | 396 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 9789 |
| Exit nodes | 2205 |
| Other relays | 7584 |
| New in window | 9789 |

Sample (20 of 9789, source: Tor Project Onionoo):
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
| Unknown Loader | 4551 | 4551 | — |
| Mirai | 3579 | 3579 | T1498, T1071.001 |
| AsyncRAT | 2204 | 2204 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| ClearFake | 1607 | 1607 | — |
| Cobalt Strike | 1264 | 1264 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| IClickFix | 1217 | 1217 | — |
| Unknown malware | 678 | 678 | — |
| Unknown Stealer | 547 | 547 | — |
| Vidar | 392 | 392 | T1555, T1071.001, T1567 |
| PureRAT | 375 | 375 | — |
| AdaptixC2 | 268 | 268 | — |
| php.shin_webshell | 259 | 259 | — |
| AMOS | 205 | 205 | — |
| Unknown RAT | 172 | 172 | — |
| Remcos | 169 | 169 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| VShell | 151 | 151 | — |
| Remus | 146 | 146 | — |
| DCRat | 107 | 107 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| Formbook | 97 | 97 | T1566.001, T1056.001, T1555, T1071.001, T1567 |
| Evilginx | 95 | 95 | — |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1105 | Ingress Tool Transfer | command-and-control | 15830 |
| T1071.001 | Web Protocols | command-and-control | 33709 |
| T1498 | Network Denial of Service | impact | 8376 |
| T1204.002 | Malicious File | execution | 5619 |
| T1027 | Obfuscated Files or Information | defense-evasion | 5608 |
| T1573 | Encrypted Channel | command-and-control | 4903 |
| T1056.001 | Keylogging | collection, credential-access | 3255 |
| T1566.001 | Spearphishing Attachment | initial-access | 2900 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 2584 |
| T1113 | Screen Capture | collection | 2552 |
| T1566 | Phishing | initial-access | 2210 |
| T1566.002 | Spearphishing Link | initial-access | 2210 |
| T1555 | Credentials from Password Stores | credential-access | 1971 |
| T1567 | Exfiltration Over Web Service | exfiltration | 1886 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1464 |
| T1552.001 | Credentials In Files | credential-access | 1426 |
| T1090 | Proxy | command-and-control | 1305 |
| T1059.001 | PowerShell | execution | 1277 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 201 |
| T1059.005 | Visual Basic | execution | 70 |
| T1189 | Drive-by Compromise | initial-access | 21 |
| T1218 | System Binary Proxy Execution | defense-evasion | 21 |
| T1021.001 | Remote Desktop Protocol | lateral-movement | 8 |
| T1486 | Data Encrypted for Impact | impact | 8 |
| T1490 | Inhibit System Recovery | impact | 8 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 8 |
| T1003 | OS Credential Dumping | credential-access | 1 |
| T1190 | Exploit Public-Facing Application | initial-access | 1 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`31[.]56[.]19[.]111`](https://www.virustotal.com/gui/ip-address/31.56.19.111) | ipv4 | Potassium | threatfox | 2026-10-09T22:26:32Z | 100 |
| [`ecned5tg[.]roseanne[.]id`](https://www.virustotal.com/gui/domain/ecned5tg.roseanne.id) | domain | ClearFake | threatfox | 2026-10-09T22:19:43Z | 100 |
| [`76dlzuzd[.]pinke[.]store`](https://www.virustotal.com/gui/domain/76dlzuzd.pinke.store) | domain | ClearFake | threatfox | 2026-10-09T21:57:33Z | 100 |
| [`fern-roam-moss-luio[.]pro`](https://www.virustotal.com/gui/domain/fern-roam-moss-luio.pro) | domain | IClickFix | threatfox | 2026-10-09T21:17:55Z | 100 |
| [`189[.]249[.]195[.]244`](https://www.virustotal.com/gui/ip-address/189.249.195.244) | ipv4 | Unknown malware | threatfox | 2026-10-09T21:05:04Z | 100 |
| [`yauvanpower[.]online`](https://www.virustotal.com/gui/domain/yauvanpower.online) | domain | IClickFix | threatfox | 2026-10-09T21:02:52Z | 100 |
| [`yj2005[.]net`](https://www.virustotal.com/gui/domain/yj2005.net) | domain | IClickFix | threatfox | 2026-10-09T21:02:52Z | 100 |
| [`ylevents[.]com`](https://www.virustotal.com/gui/domain/ylevents.com) | domain | IClickFix | threatfox | 2026-10-09T21:02:52Z | 100 |
| [`ymusic[.]id`](https://www.virustotal.com/gui/domain/ymusic.id) | domain | IClickFix | threatfox | 2026-10-09T21:02:52Z | 100 |
| [`yogitaelegantbeauty[.]com`](https://www.virustotal.com/gui/domain/yogitaelegantbeauty.com) | domain | IClickFix | threatfox | 2026-10-09T21:02:52Z | 100 |
| [`youssefragab[.]com`](https://www.virustotal.com/gui/domain/youssefragab.com) | domain | IClickFix | threatfox | 2026-10-09T21:02:52Z | 100 |
| [`ysense[.]pro`](https://www.virustotal.com/gui/domain/ysense.pro) | domain | IClickFix | threatfox | 2026-10-09T21:02:52Z | 100 |
| [`z5cable[.]com`](https://www.virustotal.com/gui/domain/z5cable.com) | domain | IClickFix | threatfox | 2026-10-09T21:02:52Z | 100 |
| [`zapxa[.]com`](https://www.virustotal.com/gui/domain/zapxa.com) | domain | IClickFix | threatfox | 2026-10-09T21:02:52Z | 100 |
| [`zeus138[.]co`](https://www.virustotal.com/gui/domain/zeus138.co) | domain | IClickFix | threatfox | 2026-10-09T21:02:52Z | 100 |
| [`zeus138[.]ink`](https://www.virustotal.com/gui/domain/zeus138.ink) | domain | IClickFix | threatfox | 2026-10-09T21:02:52Z | 100 |
| [`zeus773jpe[.]online`](https://www.virustotal.com/gui/domain/zeus773jpe.online) | domain | IClickFix | threatfox | 2026-10-09T21:02:52Z | 100 |
| [`zonainfo[.]biz[.]id`](https://www.virustotal.com/gui/domain/zonainfo.biz.id) | domain | IClickFix | threatfox | 2026-10-09T21:02:52Z | 100 |
| [`tusometech[.]com`](https://www.virustotal.com/gui/domain/tusometech.com) | domain | IClickFix | threatfox | 2026-10-09T21:02:51Z | 100 |
| [`ufaxs[.]bet`](https://www.virustotal.com/gui/domain/ufaxs.bet) | domain | IClickFix | threatfox | 2026-10-09T21:02:51Z | 100 |
| [`upsurge[.]solutions`](https://www.virustotal.com/gui/domain/upsurge.solutions) | domain | IClickFix | threatfox | 2026-10-09T21:02:51Z | 100 |
| [`upvod[.]net`](https://www.virustotal.com/gui/domain/upvod.net) | domain | IClickFix | threatfox | 2026-10-09T21:02:51Z | 100 |
| [`uttejpalavai[.]com`](https://www.virustotal.com/gui/domain/uttejpalavai.com) | domain | IClickFix | threatfox | 2026-10-09T21:02:51Z | 100 |
| [`varnixboya[.]com`](https://www.virustotal.com/gui/domain/varnixboya.com) | domain | IClickFix | threatfox | 2026-10-09T21:02:51Z | 100 |
| [`vebiotic[.]com`](https://www.virustotal.com/gui/domain/vebiotic.com) | domain | IClickFix | threatfox | 2026-10-09T21:02:51Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
