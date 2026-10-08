# Threat Intel Pulse — 2026-10-08

**Window:** last 7 days · **Generated:** 2026-10-08T23:30:40Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 47169 |
| New in window | 47169 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5000 | ok |
| feodo | 5 | ok |
| threatfox | 6563 | ok |
| malwarebazaar | 957 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8587 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 15791 | 15791 |
| ipv4 | 9552 | 9552 |
| sha256 | 9253 | 9253 |
| domain | 8981 | 8981 |
| ipv6 | 2906 | 2906 |
| md5 | 355 | 355 |
| sha1 | 331 | 331 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 9643 |
| Exit nodes | 2197 |
| Other relays | 7446 |
| New in window | 9643 |

Sample (20 of 9643, source: Tor Project Onionoo):
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
| Unknown Loader | 4472 | 4472 | — |
| Mirai | 3458 | 3458 | T1498, T1071.001 |
| AsyncRAT | 2191 | 2191 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| Cobalt Strike | 1249 | 1249 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| ClearFake | 1213 | 1213 | — |
| IClickFix | 893 | 893 | — |
| Unknown malware | 628 | 628 | — |
| Unknown Stealer | 405 | 405 | — |
| PureRAT | 367 | 367 | — |
| Vidar | 353 | 353 | T1555, T1071.001, T1567 |
| AdaptixC2 | 257 | 257 | — |
| php.shin_webshell | 209 | 209 | — |
| AMOS | 180 | 180 | — |
| Unknown RAT | 171 | 171 | — |
| Remcos | 158 | 158 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| Remus | 135 | 135 | — |
| VShell | 125 | 125 | — |
| DCRat | 104 | 104 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| Evilginx | 95 | 95 | — |
| Havoc | 93 | 93 | — |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1105 | Ingress Tool Transfer | command-and-control | 15230 |
| T1071.001 | Web Protocols | command-and-control | 32202 |
| T1498 | Network Denial of Service | impact | 8160 |
| T1204.002 | Malicious File | execution | 5572 |
| T1027 | Obfuscated Files or Information | defense-evasion | 5561 |
| T1573 | Encrypted Channel | command-and-control | 4810 |
| T1056.001 | Keylogging | collection, credential-access | 3176 |
| T1566.001 | Spearphishing Attachment | initial-access | 2817 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 2547 |
| T1113 | Screen Capture | collection | 2517 |
| T1566 | Phishing | initial-access | 1843 |
| T1566.002 | Spearphishing Link | initial-access | 1843 |
| T1555 | Credentials from Password Stores | credential-access | 1746 |
| T1567 | Exfiltration Over Web Service | exfiltration | 1683 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1435 |
| T1090 | Proxy | command-and-control | 1289 |
| T1552.001 | Credentials In Files | credential-access | 1271 |
| T1059.001 | PowerShell | execution | 1262 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 171 |
| T1059.005 | Visual Basic | execution | 61 |
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
| [`lezo[.]store`](https://www.virustotal.com/gui/domain/lezo.store) | domain | ClearFake | threatfox | 2026-10-08T22:53:33Z | 100 |
| [`147[.]79[.]20[.]132`](https://www.virustotal.com/gui/ip-address/147.79.20.132) | ipv4 | VShell | threatfox | 2026-10-08T22:45:10Z | 100 |
| [`102[.]220[.]161[.]194`](https://www.virustotal.com/gui/ip-address/102.220.161.194) | ipv4 | CECbot | threatfox | 2026-10-08T21:58:19Z | 100 |
| [`47[.]237[.]95[.]149`](https://www.virustotal.com/gui/ip-address/47.237.95.149) | ipv4 | Jackskid | threatfox | 2026-10-08T21:55:37Z | 100 |
| [`47[.]85[.]194[.]79`](https://www.virustotal.com/gui/ip-address/47.85.194.79) | ipv4 | Jackskid | threatfox | 2026-10-08T21:55:37Z | 100 |
| [`verifiedbmsells[.]com`](https://www.virustotal.com/gui/domain/verifiedbmsells.com) | domain | IClickFix | threatfox | 2026-10-08T21:17:29Z | 100 |
| [`wealthywealth[.]co[.]za`](https://www.virustotal.com/gui/domain/wealthywealth.co.za) | domain | IClickFix | threatfox | 2026-10-08T21:17:29Z | 100 |
| [`www[.]heritagemusical[.]com`](https://www.virustotal.com/gui/domain/www.heritagemusical.com) | domain | IClickFix | threatfox | 2026-10-08T21:17:29Z | 100 |
| [`www[.]smartlivingstyle[.]cat`](https://www.virustotal.com/gui/domain/www.smartlivingstyle.cat) | domain | IClickFix | threatfox | 2026-10-08T21:17:29Z | 100 |
| [`fernandeseneri[.]adv[.]br`](https://www.virustotal.com/gui/domain/fernandeseneri.adv.br) | domain | IClickFix | threatfox | 2026-10-08T21:17:28Z | 100 |
| [`industriafortefibra[.]com[.]br`](https://www.virustotal.com/gui/domain/industriafortefibra.com.br) | domain | IClickFix | threatfox | 2026-10-08T21:17:28Z | 100 |
| [`narowalgymkhana[.]com`](https://www.virustotal.com/gui/domain/narowalgymkhana.com) | domain | IClickFix | threatfox | 2026-10-08T21:17:28Z | 100 |
| [`productpalace[.]pk`](https://www.virustotal.com/gui/domain/productpalace.pk) | domain | IClickFix | threatfox | 2026-10-08T21:17:28Z | 100 |
| [`tesafco[.]ir`](https://www.virustotal.com/gui/domain/tesafco.ir) | domain | IClickFix | threatfox | 2026-10-08T21:17:28Z | 100 |
| [`austin-zhao[.]com`](https://www.virustotal.com/gui/domain/austin-zhao.com) | domain | IClickFix | threatfox | 2026-10-08T21:17:27Z | 100 |
| [`clickfix[.]jordiserrano[.]me`](https://www.virustotal.com/gui/domain/clickfix.jordiserrano.me) | domain | IClickFix | threatfox | 2026-10-08T21:17:27Z | 100 |
| [`ik[.]3toto[.]com`](https://www.virustotal.com/gui/domain/ik.3toto.com) | domain | Vidar | threatfox | 2026-10-08T21:10:48Z | 100 |
| [`hxxps://ik[.]3toto[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fik.3toto.com%2F) | url | Vidar | threatfox | 2026-10-08T21:10:48Z | 100 |
| [`oi41pfmg[.]saok[.]store`](https://www.virustotal.com/gui/domain/oi41pfmg.saok.store) | domain | ClearFake | threatfox | 2026-10-08T21:10:29Z | 100 |
| [`ik[.]333vip[.]org`](https://www.virustotal.com/gui/domain/ik.333vip.org) | domain | Vidar | threatfox | 2026-10-08T21:05:48Z | 100 |
| [`hxxps://ik[.]333vip[.]org/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fik.333vip.org%2F) | url | Vidar | threatfox | 2026-10-08T21:05:48Z | 100 |
| [`176[.]97[.]117[.]157`](https://www.virustotal.com/gui/ip-address/176.97.117.157) | ipv4 | VShell | threatfox | 2026-10-08T21:05:13Z | 100 |
| [`9x1od7j1[.]musux[.]store`](https://www.virustotal.com/gui/domain/9x1od7j1.musux.store) | domain | ClearFake | threatfox | 2026-10-08T21:05:01Z | 100 |
| [`script-six-tawny[.]vercel[.]app`](https://www.virustotal.com/gui/domain/script-six-tawny.vercel.app) | domain | IClickFix | threatfox | 2026-10-08T21:00:08Z | 100 |
| [`43[.]157[.]80[.]29`](https://www.virustotal.com/gui/ip-address/43.157.80.29) | ipv4 | Jackskid | threatfox | 2026-10-08T20:51:26Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
