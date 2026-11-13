# Threat Intel Pulse — 2026-11-13

**Window:** last 7 days · **Generated:** 2026-11-13T19:54:18Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 68565 |
| New in window | 13111 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 23 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 314 | ok |
| tor | 8831 | ok |
| blocklist_de | 0 | ok |
| binarydefense | 343 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 566 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 797 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 42281 | 7648 |
| url | 13212 | 3769 |
| domain | 8639 | 1314 |
| ipv6 | 3826 | 262 |
| sha256 | 500 | 105 |
| md5 | 107 | 13 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 13297 |
| Exit nodes | 2472 |
| Other relays | 10825 |
| New in window | 1151 |

Sample (20 of 13297, source: Tor Project Onionoo):
- `1[.]161[.]130[.]49`
- `1[.]201[.]176[.]169`
- `1[.]201[.]176[.]176`
- `1[.]248[.]96[.]163`
- `1[.]34[.]44[.]234`
- `100[.]12[.]167[.]245`
- `100[.]2[.]63[.]41`
- `100[.]35[.]77[.]114`
- `100[.]8[.]53[.]153`
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
- `102[.]130[.]49[.]203`

Full list: `dist/tor/tor_nodes.txt` (in the `threat-intel-output` workflow artifact).
## Top malware families

| Family | Indicators | New | ATT&CK (heuristic) |
| --- | --- | --- | --- |
| ClickFix | 236 | 70 | — |
| cryptoscam | 104 | 27 | — |
| Formbook | 52 | 40 | T1566.001, T1056.001, T1555, T1071.001, T1567 |
| NetSupport | 32 | 0 | — |
| PHP2Shell | 26 | 0 | — |
| Vidar | 25 | 21 | T1555, T1071.001, T1567 |
| Kimsuky | 24 | 0 | — |
| ValleyRAT | 23 | 0 | — |
| DPRK | 18 | 0 | — |
| Remcos | 15 | 13 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| Sliver | 14 | 0 | T1071.001, T1573, T1090, T1055 |
| Cobalt Strike | 10 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| AiTM | 8 | 0 | — |
| GuLoader | 8 | 0 | T1027, T1059.005, T1055, T1105 |
| Mirai | 8 | 0 | T1498, T1071.001 |
| ClearFake | 7 | 0 | — |
| Unknown malware | 7 | 0 | — |
| Mythic | 6 | 0 | — |
| SpyNote | 6 | 0 | — |
| infostealer | 6 | 4 | — |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1566 | Phishing | initial-access | 19195 |
| T1566.002 | Spearphishing Link | initial-access | 19195 |
| T1071.001 | Web Protocols | command-and-control | 48773 |
| T1573 | Encrypted Channel | command-and-control | 4838 |
| T1555 | Credentials from Password Stores | credential-access | 137 |
| T1567 | Exfiltration Over Web Service | exfiltration | 137 |
| T1056.001 | Keylogging | collection, credential-access | 93 |
| T1552.001 | Credentials In Files | credential-access | 81 |
| T1566.001 | Spearphishing Attachment | initial-access | 73 |
| T1486 | Data Encrypted for Impact | impact | 44 |
| T1490 | Inhibit System Recovery | impact | 44 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 44 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 38 |
| T1105 | Ingress Tool Transfer | command-and-control | 31 |
| T1090 | Proxy | command-and-control | 25 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 16 |
| T1027 | Obfuscated Files or Information | defense-evasion | 15 |
| T1113 | Screen Capture | collection | 15 |
| T1204.002 | Malicious File | execution | 15 |
| T1498 | Network Denial of Service | impact | 11 |
| T1059.001 | PowerShell | execution | 10 |
| T1059.005 | Visual Basic | execution | 9 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 5 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://www[.]roblox[.]com[.]ml/users/206830307895/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.com.ml%2Fusers%2F206830307895%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxps://s4w[.]in/www-roblox-com-users-2068330307895-profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fs4w.in%2Fwww-roblox-com-users-2068330307895-profile) | url | — | openphish | — | 70 |
| [`hxxp://hometown-herbal-ledger-13[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fhometown-herbal-ledger-13.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]rw/users/441698548140/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.rw%2Fusers%2F441698548140%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxps://g5[.]lu/52ecz`](https://www.virustotal.com/gui/search/https%3A%2F%2Fg5.lu%2F52ecz) | url | — | openphish | — | 70 |
| [`hxxps://vaibhavinayak10[.]github[.]io/AmazonProject[.]github[.]io/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fvaibhavinayak10.github.io%2FAmazonProject.github.io%2F) | url | — | openphish | — | 70 |
| [`hxxps://vaibhavinayak10[.]github[.]io/AmazonProject[.]github[.]io`](https://www.virustotal.com/gui/search/https%3A%2F%2Fvaibhavinayak10.github.io%2FAmazonProject.github.io) | url | — | openphish | — | 70 |
| [`hxxps://redysel[.]com/img/TL-WR840N/47684uyjkhv67954[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fredysel.com%2Fimg%2FTL-WR840N%2F47684uyjkhv67954.html) | url | — | openphish | — | 70 |
| [`hxxps://hmilp09kod[.]flazio[.]online/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhmilp09kod.flazio.online%2F) | url | — | openphish | — | 70 |
| [`hxxps://railbuyer[.]sbb[.]b-op[.]com/railbuyer`](https://www.virustotal.com/gui/search/https%3A%2F%2Frailbuyer.sbb.b-op.com%2Frailbuyer) | url | — | openphish | — | 70 |
| [`hxxps://hispeed-ch70[.]jimdofree[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhispeed-ch70.jimdofree.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]shopee77bombastis[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.shopee77bombastis.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://roblox[.]com[.]gr/games/125538696653169/Showdown-Anime-FPS-Jutsu-Shooter`](https://www.virustotal.com/gui/search/https%3A%2F%2Froblox.com.gr%2Fgames%2F125538696653169%2FShowdown-Anime-FPS-Jutsu-Shooter) | url | — | openphish | — | 70 |
| [`hxxps://vaibhavinayak10[.]github[.]io/AmazonDarkMode[.]github[.]io/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fvaibhavinayak10.github.io%2FAmazonDarkMode.github.io%2F) | url | — | openphish | — | 70 |
| [`hxxps://vaibhavinayak10[.]github[.]io/AmazonDarkMode[.]github[.]io`](https://www.virustotal.com/gui/search/https%3A%2F%2Fvaibhavinayak10.github.io%2FAmazonDarkMode.github.io) | url | — | openphish | — | 70 |
| [`hxxps://helpledger[.]live/login[.]php`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhelpledger.live%2Flogin.php) | url | — | openphish | — | 70 |
| [`hxxps://meinhostingfa14r-qqhgpqtwdl[.]live-website[.]com/esat/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmeinhostingfa14r-qqhgpqtwdl.live-website.com%2Fesat%2F) | url | — | openphish | — | 70 |
| [`hxxps://pncverify[.]pagekite[.]me/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fpncverify.pagekite.me%2F) | url | — | openphish | — | 70 |
| [`hxxp://fresh-experiences-537560[.]framer[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Ffresh-experiences-537560.framer.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://pichinch-web--juanpila22222[.]replit[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fpichinch-web--juanpila22222.replit.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://sokiogh[.]kesug[.]com/?naps`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsokiogh.kesug.com%2F%3Fnaps) | url | — | openphish | — | 70 |
| [`hxxps://bjohrtpuy[.]freehosting[.]dev/?naps`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbjohrtpuy.freehosting.dev%2F%3Fnaps) | url | — | openphish | — | 70 |
| [`hxxps://www[.]ptshopeeei[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.ptshopeeei.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]ly/users/7280036217/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.ly%2Fusers%2F7280036217%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxps://kk365756[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fkk365756.com%2F) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
