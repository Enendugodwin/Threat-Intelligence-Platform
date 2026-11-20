# Threat Intel Pulse — 2026-11-20

**Window:** last 7 days · **Generated:** 2026-11-20T20:34:42Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 69129 |
| New in window | 15451 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 23 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 314 | ok |
| tor | 10308 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 320 | ok |
| greensnow | 1856 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 590 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 2393 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 43608 | 8498 |
| url | 13271 | 5087 |
| domain | 7546 | 1269 |
| ipv6 | 3831 | 214 |
| sha256 | 697 | 288 |
| md5 | 176 | 95 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 13401 |
| Exit nodes | 2483 |
| Other relays | 10918 |
| New in window | 989 |

Sample (20 of 13401, source: Tor Project Onionoo):
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
- `101[.]186[.]183[.]53`
- `101[.]55[.]125[.]10`
- `102[.]130[.]113[.]29`
- `102[.]130[.]113[.]30`
- `102[.]130[.]113[.]42`
- `102[.]130[.]113[.]9`
- `102[.]130[.]115[.]59`
- `102[.]130[.]117[.]167`
- `102[.]130[.]119[.]48`
- `102[.]130[.]127[.]117`

Full list: `dist/tor/tor_nodes.txt` (in the `threat-intel-output` workflow artifact).
## Top malware families

| Family | Indicators | New | ATT&CK (heuristic) |
| --- | --- | --- | --- |
| ClickFix | 336 | 134 | — |
| cryptoscam | 111 | 7 | — |
| Kimsuky | 74 | 54 | — |
| Formbook | 42 | 1 | T1566.001, T1056.001, T1555, T1071.001, T1567 |
| Vidar | 25 | 0 | T1555, T1071.001, T1567 |
| DPRK | 18 | 0 | — |
| Remcos | 18 | 4 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| AiTM | 16 | 8 | — |
| PHP2Shell | 11 | 1 | — |
| Cobalt Strike | 9 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| GuLoader | 8 | 0 | T1027, T1059.005, T1055, T1105 |
| Mirai | 8 | 0 | T1498, T1071.001 |
| infostealer | 7 | 1 | — |
| Unknown malware | 6 | 0 | — |
| Sliver | 5 | 0 | T1071.001, T1573, T1090, T1055 |
| ValleyRAT | 5 | 2 | — |
| Evilginx | 4 | 0 | — |
| MustangPanda | 4 | 4 | — |
| QakBot | 4 | 0 | T1566.001, T1204.002, T1055, T1071.001, T1105, T1027, T1041 |
| AdaptixC2 | 2 | 0 | — |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1566 | Phishing | initial-access | 18036 |
| T1566.002 | Spearphishing Link | initial-access | 18036 |
| T1071.001 | Web Protocols | command-and-control | 50198 |
| T1573 | Encrypted Channel | command-and-control | 5381 |
| T1555 | Credentials from Password Stores | credential-access | 149 |
| T1567 | Exfiltration Over Web Service | exfiltration | 149 |
| T1486 | Data Encrypted for Impact | impact | 108 |
| T1490 | Inhibit System Recovery | impact | 108 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 108 |
| T1552.001 | Credentials In Files | credential-access | 103 |
| T1056.001 | Keylogging | collection, credential-access | 91 |
| T1566.001 | Spearphishing Attachment | initial-access | 66 |
| T1105 | Ingress Tool Transfer | command-and-control | 28 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 27 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 19 |
| T1113 | Screen Capture | collection | 18 |
| T1027 | Obfuscated Files or Information | defense-evasion | 15 |
| T1204.002 | Malicious File | execution | 15 |
| T1090 | Proxy | command-and-control | 14 |
| T1498 | Network Denial of Service | impact | 10 |
| T1059.001 | PowerShell | execution | 9 |
| T1059.005 | Visual Basic | execution | 9 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 5 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://saratio[.]de/gustafsonltd/download[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsaratio.de%2Fgustafsonltd%2Fdownload.html) | url | — | openphish, tweetfeed | 2026-11-19T18:25:18Z | 70 |
| [`hxxps://auth0-google[.]com/2step[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fauth0-google.com%2F2step.html) | url | AiTM | openphish, tweetfeed | 2026-11-18T17:18:56Z | 70 |
| [`hxxps://icloudvsmapalocaliza[.]click/isignesp[.]php?correo=-&id=172974`](https://www.virustotal.com/gui/search/https%3A%2F%2Ficloudvsmapalocaliza.click%2Fisignesp.php%3Fcorreo%3D-%26id%3D172974) | url | — | openphish, tweetfeed | 2026-11-18T16:27:54Z | 70 |
| [`hxxp://conatem[.]com/adobeStudio[.]html`](https://www.virustotal.com/gui/search/http%3A%2F%2Fconatem.com%2FadobeStudio.html) | url | — | openphish, tweetfeed | 2026-11-18T03:56:46Z | 70 |
| [`hxxps://lapaca[.]webdirecto[.]com/wp-includes/Text/tdweain/yogsqwj/gmehpir/ggg/adobe/adobe[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Flapaca.webdirecto.com%2Fwp-includes%2FText%2Ftdweain%2Fyogsqwj%2Fgmehpir%2Fggg%2Fadobe%2Fadobe.html) | url | — | openphish, tweetfeed | 2026-11-14T16:01:48Z | 70 |
| [`hxxp://shopee-sale26[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fshopee-sale26.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]program-resmi647[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.program-resmi647.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]hadiahshopeeday88[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.hadiahshopeeday88.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]shopee842[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.shopee842.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]hadiahshopee179[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.hadiahshopee179.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://amazonprime-network[.]fr/pages/login[.]php`](https://www.virustotal.com/gui/search/https%3A%2F%2Famazonprime-network.fr%2Fpages%2Flogin.php) | url | — | openphish | — | 70 |
| [`hxxp://safefile-edocu[.]innovaagencia[.]com[.]co/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsafefile-edocu.innovaagencia.com.co%2F) | url | — | openphish | — | 70 |
| [`hxxps://eup-ravan[.]net/az/`](https://www.virustotal.com/gui/search/https%3A%2F%2Feup-ravan.net%2Faz%2F) | url | — | openphish | — | 70 |
| [`hxxp://ptshopee-69[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fptshopee-69.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://undian-shopee-mart[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fundian-shopee-mart.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://program-resmi888[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fprogram-resmi888.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]com[.]ss/games/13621938427/untitled-boxing-game?privateServerLinkCode=95388447005431092484134632311458`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.com.ss%2Fgames%2F13621938427%2Funtitled-boxing-game%3FprivateServerLinkCode%3D95388447005431092484134632311458) | url | — | openphish | — | 70 |
| [`hxxp://shopee0927[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fshopee0927.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://g5[.]lu/hg32r`](https://www.virustotal.com/gui/search/https%3A%2F%2Fg5.lu%2Fhg32r) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]rw/users/333100482737/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.rw%2Fusers%2F333100482737%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxp://robloxv[.]com/games/134026357772960/Barber-Simulator?gameSetTypeId=100000003&homePageSessionInfo=5d228721-24bf-4302-a481-c1801e137b45&isAd=false&newGameEnum_analyticsData=0&numberOfLoadedTiles=34&page=homePage&placeId=134026357772960&playContext=homePage&position=1&positionInRow=1&rowOnPage=3&sortPos=2&sortSubId=&universeId=10770932189`](https://www.virustotal.com/gui/search/http%3A%2F%2Frobloxv.com%2Fgames%2F134026357772960%2FBarber-Simulator%3FgameSetTypeId%3D100000003%26homePageSessionInfo%3D5d228721-24bf-4302-a481-c1801e137b45%26isAd%3Dfalse%26newGameEnum_analyticsData%3D0%26numberOfLoadedTiles%3D34%26page%3DhomePage%26placeId%3D134026357772960%26playContext%3DhomePage%26position%3D1%26positionInRow%3D1%26rowOnPage%3D3%26sortPos%3D2%26sortSubId%3D%26universeId%3D10770932189) | url | — | openphish | — | 70 |
| [`hxxps://podular[.]site/?msclkid=11e0cc087d6c1d97b686a6ffe5234382`](https://www.virustotal.com/gui/search/https%3A%2F%2Fpodular.site%2F%3Fmsclkid%3D11e0cc087d6c1d97b686a6ffe5234382) | url | — | openphish | — | 70 |
| [`hxxps://www[.]etereacouture[.]it/aa/ubsMoula25/ubs/ubs[.]ch_login-id_url=9505f60ac1aaef5a5c92a2ec19b09807`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.etereacouture.it%2Faa%2FubsMoula25%2Fubs%2Fubs.ch_login-id_url%3D9505f60ac1aaef5a5c92a2ec19b09807) | url | — | openphish | — | 70 |
| [`hxxp://www[.]etereacouture[.]it/aa/ubsMoula25/ubs/ubs[.]ch_login-id_url=9505f60ac1aaef5a5c92a2ec19b09807/Select/login[.]php`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.etereacouture.it%2Faa%2FubsMoula25%2Fubs%2Fubs.ch_login-id_url%3D9505f60ac1aaef5a5c92a2ec19b09807%2FSelect%2Flogin.php) | url | — | openphish | — | 70 |
| [`hxxp://shopee1218[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fshopee1218.blogspot.com%2F) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
