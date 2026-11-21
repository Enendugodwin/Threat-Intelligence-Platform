# Threat Intel Pulse — 2026-11-21

**Window:** last 7 days · **Generated:** 2026-11-21T19:31:50Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 69628 |
| New in window | 15713 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 23 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 314 | ok |
| tor | 10326 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 467 | ok |
| greensnow | 1922 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 596 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 2521 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 43971 | 8585 |
| url | 13389 | 5200 |
| domain | 7548 | 1312 |
| ipv6 | 3834 | 216 |
| sha256 | 716 | 308 |
| md5 | 170 | 92 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 13392 |
| Exit nodes | 2492 |
| Other relays | 10900 |
| New in window | 994 |

Sample (20 of 13392, source: Tor Project Onionoo):
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
| ClickFix | 365 | 163 | — |
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
| T1566 | Phishing | initial-access | 18100 |
| T1566.002 | Spearphishing Link | initial-access | 18100 |
| T1071.001 | Web Protocols | command-and-control | 50624 |
| T1573 | Encrypted Channel | command-and-control | 5601 |
| T1555 | Credentials from Password Stores | credential-access | 150 |
| T1567 | Exfiltration Over Web Service | exfiltration | 150 |
| T1486 | Data Encrypted for Impact | impact | 106 |
| T1490 | Inhibit System Recovery | impact | 106 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 106 |
| T1552.001 | Credentials In Files | credential-access | 104 |
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
| [`hxxps://kuconlgzn[.]gitbook[.]io/us`](https://www.virustotal.com/gui/search/https%3A%2F%2Fkuconlgzn.gitbook.io%2Fus) | url | — | openphish | — | 70 |
| [`hxxps://kuconlogen16[.]gitbook[.]io/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fkuconlogen16.gitbook.io%2F) | url | — | openphish | — | 70 |
| [`hxxp://akshitofficials[.]github[.]io/Spotify-clone`](https://www.virustotal.com/gui/search/http%3A%2F%2Fakshitofficials.github.io%2FSpotify-clone) | url | — | openphish | — | 70 |
| [`hxxps://www[.]jah-delta[.]vercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.jah-delta.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]shopee-002[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.shopee-002.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://all4youherebux[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fall4youherebux.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://thr-shopee227[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fthr-shopee227.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://shopee-inc2023[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fshopee-inc2023.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]fxvfvbbvff[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.fxvfvbbvff.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://fxvfvbbvff[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Ffxvfvbbvff.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://apple[.]absalomdonald[.]dpdns[.]org/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fapple.absalomdonald.dpdns.org%2F) | url | — | openphish | — | 70 |
| [`hxxps://shopee7677[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fshopee7677.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]shopee7677[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.shopee7677.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://netflixaccount119[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fnetflixaccount119.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://m[.]coinbase-svip[.]com/h5/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fm.coinbase-svip.com%2Fh5%2F) | url | — | openphish | — | 70 |
| [`hxxp://bradsaidso[.]com/wp-includes/indcx[.]html`](https://www.virustotal.com/gui/search/http%3A%2F%2Fbradsaidso.com%2Fwp-includes%2Findcx.html) | url | — | openphish | — | 70 |
| [`hxxp://xfinifydattabasemeasureuxux[.]weebly[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fxfinifydattabasemeasureuxux.weebly.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]com[.]et/users/4925259156/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.com.et%2Fusers%2F4925259156%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxps://facebookaccountrecovery[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ffacebookaccountrecovery.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]r[.]oblox[.]com[.]et/users/3167626725/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.r.oblox.com.et%2Fusers%2F3167626725%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxp://couriersplease[.]addliaz[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fcouriersplease.addliaz.com%2F) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
