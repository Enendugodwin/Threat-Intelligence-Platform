# Threat Intel Pulse — 2026-11-21

**Window:** last 7 days · **Generated:** 2026-11-21T07:27:24Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 68740 |
| New in window | 15398 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 23 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 314 | ok |
| tor | 10325 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 467 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 596 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 2334 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 43562 | 8427 |
| url | 13011 | 5101 |
| domain | 7469 | 1262 |
| ipv6 | 3825 | 214 |
| sha256 | 704 | 298 |
| md5 | 169 | 96 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 13368 |
| Exit nodes | 2489 |
| Other relays | 10879 |
| New in window | 992 |

Sample (20 of 13368, source: Tor Project Onionoo):
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
| T1566 | Phishing | initial-access | 17716 |
| T1566.002 | Spearphishing Link | initial-access | 17716 |
| T1071.001 | Web Protocols | command-and-control | 50133 |
| T1573 | Encrypted Channel | command-and-control | 5601 |
| T1555 | Credentials from Password Stores | credential-access | 149 |
| T1567 | Exfiltration Over Web Service | exfiltration | 149 |
| T1486 | Data Encrypted for Impact | impact | 106 |
| T1490 | Inhibit System Recovery | impact | 106 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 106 |
| T1552.001 | Credentials In Files | credential-access | 103 |
| T1056.001 | Keylogging | collection, credential-access | 92 |
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
| [`hxxps://now-13-11-26[.]shop/rxxgABqn`](https://www.virustotal.com/gui/search/https%3A%2F%2Fnow-13-11-26.shop%2FrxxgABqn) | url | — | openphish | — | 70 |
| [`hxxps://kiocoixlogen[.]gitbook[.]io/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fkiocoixlogen.gitbook.io%2F) | url | — | openphish | — | 70 |
| [`hxxp://explore-trustextension[.]apper[.]so/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fexplore-trustextension.apper.so%2F) | url | — | openphish | — | 70 |
| [`hxxps://ql4488[.]craftum[.]io/page2`](https://www.virustotal.com/gui/search/https%3A%2F%2Fql4488.craftum.io%2Fpage2) | url | — | openphish | — | 70 |
| [`hxxps://gemini-lugin[.]gitbook[.]io/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fgemini-lugin.gitbook.io%2F) | url | — | openphish | — | 70 |
| [`hxxps://codedetrichelattaquedeszombieroblox[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fcodedetrichelattaquedeszombieroblox.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://kukoinzlogen[.]gitbook[.]io/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fkukoinzlogen.gitbook.io%2F) | url | — | openphish | — | 70 |
| [`hxxps://supercauchoabanto[.]com/96627c/RE025486658/CR/card[.]php`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsupercauchoabanto.com%2F96627c%2FRE025486658%2FCR%2Fcard.php) | url | — | openphish | — | 70 |
| [`hxxps://mydpd[.]slpfr[.]help/track-ch`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmydpd.slpfr.help%2Ftrack-ch) | url | — | openphish | — | 70 |
| [`hxxp://exoweb-six[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fexoweb-six.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://shopee4777[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fshopee4777.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]shopee4777[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.shopee4777.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]com[.]ss/games/82205993156224/Walk-10000-Stairs-for-Neko-Girl?privateServerLinkCode=74694492389540449011183778202558`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.com.ss%2Fgames%2F82205993156224%2FWalk-10000-Stairs-for-Neko-Girl%3FprivateServerLinkCode%3D74694492389540449011183778202558) | url | — | openphish | — | 70 |
| [`hxxp://support-live-ledgr-usa[.]square[.]site/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsupport-live-ledgr-usa.square.site%2F) | url | — | openphish | — | 70 |
| [`hxxps://securetechnologies[.]ae/pv/pv/#tanix@ff14bf3f4a16da423dbce5442cacdabf3217[.]net`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsecuretechnologies.ae%2Fpv%2Fpv%2F%23tanix%40ff14bf3f4a16da423dbce5442cacdabf3217.net) | url | — | openphish | — | 70 |
| [`hxxp://shopee-jkt11[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fshopee-jkt11.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://soporte-de-renovacion[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsoporte-de-renovacion.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://metamaskiologii[.]gitbook[.]io/us`](https://www.virustotal.com/gui/search/http%3A%2F%2Fmetamaskiologii.gitbook.io%2Fus) | url | — | openphish | — | 70 |
| [`hxxp://tr[.]ee/YtrA15`](https://www.virustotal.com/gui/search/http%3A%2F%2Ftr.ee%2FYtrA15) | url | — | openphish | — | 70 |
| [`hxxps://larrysteaks[.]com/groupe-dms`](https://www.virustotal.com/gui/search/https%3A%2F%2Flarrysteaks.com%2Fgroupe-dms) | url | — | openphish | — | 70 |
| [`hxxp://welcome-ndx-portal-io[.]typedream[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwelcome-ndx-portal-io.typedream.app%2F) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
