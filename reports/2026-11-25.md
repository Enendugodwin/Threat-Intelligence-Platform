# Threat Intel Pulse — 2026-11-25

**Window:** last 7 days · **Generated:** 2026-11-25T08:53:35Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 68935 |
| New in window | 13342 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 23 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 314 | ok |
| tor | 10267 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 462 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 575 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 1805 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 43617 | 7602 |
| url | 12956 | 4192 |
| domain | 7653 | 1109 |
| ipv6 | 3830 | 172 |
| sha256 | 714 | 218 |
| md5 | 165 | 49 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 13316 |
| Exit nodes | 2503 |
| Other relays | 10813 |
| New in window | 863 |

Sample (20 of 13316, source: Tor Project Onionoo):
- `1[.]161[.]130[.]49`
- `1[.]201[.]176[.]169`
- `1[.]201[.]176[.]176`
- `1[.]248[.]96[.]163`
- `1[.]34[.]44[.]234`
- `100[.]12[.]167[.]245`
- `100[.]2[.]63[.]41`
- `100[.]35[.]77[.]114`
- `100[.]8[.]164[.]103`
- `100[.]8[.]53[.]153`
- `101[.]186[.]157[.]91`
- `101[.]186[.]183[.]53`
- `101[.]55[.]125[.]10`
- `102[.]130[.]113[.]29`
- `102[.]130[.]113[.]30`
- `102[.]130[.]113[.]42`
- `102[.]130[.]113[.]9`
- `102[.]130[.]115[.]59`
- `102[.]130[.]117[.]167`
- `102[.]130[.]119[.]48`

Full list: `dist/tor/tor_nodes.txt` (in the `threat-intel-output` workflow artifact).
## Top malware families

| Family | Indicators | New | ATT&CK (heuristic) |
| --- | --- | --- | --- |
| ClickFix | 382 | 98 | — |
| cryptoscam | 116 | 10 | — |
| Kimsuky | 80 | 26 | — |
| Formbook | 42 | 0 | T1566.001, T1056.001, T1555, T1071.001, T1567 |
| Vidar | 21 | 0 | T1555, T1071.001, T1567 |
| Remcos | 19 | 4 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| AiTM | 16 | 8 | — |
| infostealer | 12 | 5 | — |
| Cobalt Strike | 9 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| GuLoader | 8 | 0 | T1027, T1059.005, T1055, T1105 |
| Mirai | 7 | 0 | T1498, T1071.001 |
| Unknown malware | 6 | 0 | — |
| ValleyRAT | 5 | 5 | — |
| Evilginx | 4 | 0 | — |
| MustangPanda | 4 | 4 | — |
| QakBot | 4 | 0 | T1566.001, T1204.002, T1055, T1071.001, T1105, T1027, T1041 |
| Sliver | 4 | 0 | T1071.001, T1573, T1090, T1055 |
| Mispadu | 3 | 3 | — |
| PHP2Shell | 3 | 0 | — |
| Hookbot | 2 | 2 | — |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1566 | Phishing | initial-access | 17663 |
| T1566.002 | Spearphishing Link | initial-access | 17663 |
| T1071.001 | Web Protocols | command-and-control | 50374 |
| T1573 | Encrypted Channel | command-and-control | 5744 |
| T1555 | Credentials from Password Stores | credential-access | 159 |
| T1567 | Exfiltration Over Web Service | exfiltration | 159 |
| T1552.001 | Credentials In Files | credential-access | 117 |
| T1486 | Data Encrypted for Impact | impact | 96 |
| T1490 | Inhibit System Recovery | impact | 96 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 96 |
| T1056.001 | Keylogging | collection, credential-access | 94 |
| T1566.001 | Spearphishing Attachment | initial-access | 67 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 26 |
| T1105 | Ingress Tool Transfer | command-and-control | 26 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 20 |
| T1113 | Screen Capture | collection | 19 |
| T1027 | Obfuscated Files or Information | defense-evasion | 14 |
| T1204.002 | Malicious File | execution | 14 |
| T1090 | Proxy | command-and-control | 13 |
| T1059.001 | PowerShell | execution | 9 |
| T1059.005 | Visual Basic | execution | 9 |
| T1498 | Network Denial of Service | impact | 9 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 5 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://f005[.]backblazeb2[.]com/file/0000055/SignintoXfinity[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Ff005.backblazeb2.com%2Ffile%2F0000055%2FSignintoXfinity.html) | url | — | openphish, tweetfeed | 2026-11-23T02:02:14Z | 70 |
| [`hxxp://ns1[.]az/c6/alibaba/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fns1.az%2Fc6%2Falibaba%2F) | url | — | openphish, tweetfeed | 2026-11-22T13:00:57Z | 70 |
| [`hxxps://saratio[.]de/gustafsonltd/download[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsaratio.de%2Fgustafsonltd%2Fdownload.html) | url | — | openphish, tweetfeed | 2026-11-19T18:25:18Z | 70 |
| [`hxxps://auth0-google[.]com/2step[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fauth0-google.com%2F2step.html) | url | AiTM | openphish, tweetfeed | 2026-11-18T17:18:56Z | 70 |
| [`hxxp://booking-ledger-phi[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fbooking-ledger-phi.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://phantomchain[.]github[.]io/paper-wallet`](https://www.virustotal.com/gui/search/http%3A%2F%2Fphantomchain.github.io%2Fpaper-wallet) | url | — | openphish | — | 70 |
| [`hxxps://92394365756[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2F92394365756.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]info-pemenang-shopee17[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.info-pemenang-shopee17.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]infohadiah-shopee66[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.infohadiah-shopee66.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]zcs-adm-auth[.]vercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.zcs-adm-auth.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]shopee-indonesia25[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.shopee-indonesia25.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://ayomide202005[.]github[.]io/interswitch/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fayomide202005.github.io%2Finterswitch%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]shopee-456[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.shopee-456.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]undianshopeebigsale2022[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.undianshopeebigsale2022.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]undianresmishopee77[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.undianresmishopee77.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]pemenangshopee11-11[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.pemenangshopee11-11.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]galery-shopee21[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.galery-shopee21.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]infopemenanghadiahshopee[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.infopemenanghadiahshopee.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]infohadiah-shopee33[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.infohadiah-shopee33.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]infoundian-shopee81[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.infoundian-shopee81.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]info-hadiah-shopee99[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.info-hadiah-shopee99.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]layanan-pemenang57[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.layanan-pemenang57.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]roblox[.]ly/users/770253869/profile`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.roblox.ly%2Fusers%2F770253869%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxps://www[.]info-pemenang-99[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.info-pemenang-99.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://cool98k[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fcool98k.blogspot.com%2F) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
