# Threat Intel Pulse — 2026-11-20

**Window:** last 7 days · **Generated:** 2026-11-20T07:31:40Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 68416 |
| New in window | 15063 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 23 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 314 | ok |
| tor | 10312 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 320 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 590 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 2266 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 43281 | 8200 |
| url | 12937 | 5047 |
| domain | 7536 | 1250 |
| ipv6 | 3822 | 214 |
| sha256 | 675 | 268 |
| md5 | 165 | 84 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 13355 |
| Exit nodes | 2464 |
| Other relays | 10891 |
| New in window | 981 |

Sample (20 of 13355, source: Tor Project Onionoo):
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
| Kimsuky | 72 | 52 | — |
| Formbook | 42 | 1 | T1566.001, T1056.001, T1555, T1071.001, T1567 |
| Vidar | 25 | 0 | T1555, T1071.001, T1567 |
| DPRK | 18 | 0 | — |
| Remcos | 18 | 13 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| AiTM | 16 | 8 | — |
| PHP2Shell | 12 | 1 | — |
| Cobalt Strike | 9 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| GuLoader | 8 | 0 | T1027, T1059.005, T1055, T1105 |
| Mirai | 8 | 0 | T1498, T1071.001 |
| infostealer | 7 | 1 | — |
| Unknown malware | 6 | 0 | — |
| Sliver | 5 | 0 | T1071.001, T1573, T1090, T1055 |
| Evilginx | 4 | 2 | — |
| MustangPanda | 4 | 4 | — |
| QakBot | 4 | 0 | T1566.001, T1204.002, T1055, T1071.001, T1105, T1027, T1041 |
| ValleyRAT | 3 | 0 | — |
| AdaptixC2 | 2 | 0 | — |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1566 | Phishing | initial-access | 17746 |
| T1566.002 | Spearphishing Link | initial-access | 17746 |
| T1071.001 | Web Protocols | command-and-control | 49807 |
| T1573 | Encrypted Channel | command-and-control | 5375 |
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
| [`hxxp://luskasdev[.]github[.]io/Phishing`](https://www.virustotal.com/gui/search/http%3A%2F%2Fluskasdev.github.io%2FPhishing) | url | — | openphish | — | 70 |
| [`hxxp://boosterhub[.]shop/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fboosterhub.shop%2F) | url | — | openphish | — | 70 |
| [`hxxps://135461223[.]site/et/1784/3ea2bfc3-7bc2-4bd0-bb97-64f1bb59b647/766428/x`](https://www.virustotal.com/gui/search/https%3A%2F%2F135461223.site%2Fet%2F1784%2F3ea2bfc3-7bc2-4bd0-bb97-64f1bb59b647%2F766428%2Fx) | url | — | openphish | — | 70 |
| [`hxxps://135461223[.]site/1784/3ea2bfc3-7bc2-4bd0-bb97-64f1bb59b647/766428`](https://www.virustotal.com/gui/search/https%3A%2F%2F135461223.site%2F1784%2F3ea2bfc3-7bc2-4bd0-bb97-64f1bb59b647%2F766428) | url | — | openphish | — | 70 |
| [`hxxps://135461223[.]site/et/1784/3ea2bfc3-7bc2-4bd0-bb97-64f1bb59b647/766428`](https://www.virustotal.com/gui/search/https%3A%2F%2F135461223.site%2Fet%2F1784%2F3ea2bfc3-7bc2-4bd0-bb97-64f1bb59b647%2F766428) | url | — | openphish | — | 70 |
| [`hxxp://808[.]top-qwe123-asd456-zxc789[.]365649[.]top/`](https://www.virustotal.com/gui/search/http%3A%2F%2F808.top-qwe123-asd456-zxc789.365649.top%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]pt-shopee0779[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.pt-shopee0779.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://asesoriadebeneficios-relit[.]github[.]io/REPLIT`](https://www.virustotal.com/gui/search/http%3A%2F%2Fasesoriadebeneficios-relit.github.io%2FREPLIT) | url | — | openphish | — | 70 |
| [`hxxp://365[.]qwe123-asd456-zxc789[.]365667[.]top/m/home`](https://www.virustotal.com/gui/search/http%3A%2F%2F365.qwe123-asd456-zxc789.365667.top%2Fm%2Fhome) | url | — | openphish | — | 70 |
| [`hxxp://www[.]roundcubenewupdateserviceverificati[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.roundcubenewupdateserviceverificati.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://metaskmsckwlt[.]gitbook[.]io/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmetaskmsckwlt.gitbook.io%2F) | url | — | openphish | — | 70 |
| [`hxxps://hadiah-shopee576[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhadiah-shopee576.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]hadiah-shopee576[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.hadiah-shopee576.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://pemenang-shopee778[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fpemenang-shopee778.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://thesacredprayer[.]online/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fthesacredprayer.online%2F) | url | — | openphish | — | 70 |
| [`hxxps://shopeepay-599[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fshopeepay-599.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://9000-firebase-ree-1781589806336[.]cluster-l2bgochoazbomqgfmlhuvdvgiy[.]cloudworkstations[.]dev/?monospaceUid=672379#serospro@93e0442818bc7a42e12774e1b60ff6320a0c[.]org`](https://www.virustotal.com/gui/search/https%3A%2F%2F9000-firebase-ree-1781589806336.cluster-l2bgochoazbomqgfmlhuvdvgiy.cloudworkstations.dev%2F%3FmonospaceUid%3D672379%23serospro%4093e0442818bc7a42e12774e1b60ff6320a0c.org) | url | — | openphish | — | 70 |
| [`hxxps://shopeepay-55[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fshopeepay-55.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://binance-marketstore[.]github[.]io/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fbinance-marketstore.github.io%2F) | url | — | openphish | — | 70 |
| [`hxxp://web-uphld-log[.]square[.]site/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fweb-uphld-log.square.site%2F) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
