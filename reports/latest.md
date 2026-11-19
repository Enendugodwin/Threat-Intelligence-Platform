# Threat Intel Pulse — 2026-11-19

**Window:** last 7 days · **Generated:** 2026-11-19T20:49:50Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 69542 |
| New in window | 14929 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 23 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 314 | ok |
| tor | 10369 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 722 | ok |
| greensnow | 1798 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 588 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 2232 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 43862 | 8207 |
| url | 13308 | 4979 |
| domain | 7729 | 1210 |
| ipv6 | 3821 | 209 |
| sha256 | 662 | 248 |
| md5 | 160 | 76 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 13356 |
| Exit nodes | 2458 |
| Other relays | 10898 |
| New in window | 965 |

Sample (20 of 13356, source: Tor Project Onionoo):
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
| ClickFix | 288 | 86 | — |
| cryptoscam | 111 | 7 | — |
| Kimsuky | 72 | 52 | — |
| Formbook | 42 | 1 | T1566.001, T1056.001, T1555, T1071.001, T1567 |
| Vidar | 25 | 0 | T1555, T1071.001, T1567 |
| DPRK | 18 | 0 | — |
| Remcos | 18 | 13 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| AiTM | 16 | 8 | — |
| PHP2Shell | 12 | 1 | — |
| Cobalt Strike | 9 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| NetSupport | 9 | 0 | — |
| GuLoader | 8 | 0 | T1027, T1059.005, T1055, T1105 |
| Mirai | 8 | 0 | T1498, T1071.001 |
| infostealer | 7 | 1 | — |
| Unknown malware | 6 | 0 | — |
| Sliver | 5 | 0 | T1071.001, T1573, T1090, T1055 |
| Evilginx | 4 | 2 | — |
| MustangPanda | 4 | 4 | — |
| QakBot | 4 | 0 | T1566.001, T1204.002, T1055, T1071.001, T1105, T1027, T1041 |
| ValleyRAT | 3 | 0 | — |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1566 | Phishing | initial-access | 17990 |
| T1566.002 | Spearphishing Link | initial-access | 17990 |
| T1071.001 | Web Protocols | command-and-control | 50705 |
| T1573 | Encrypted Channel | command-and-control | 5577 |
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
| [`hxxp://airbnb[.]frngrgqb46[.]workers[.]dev/help/article/1320`](https://www.virustotal.com/gui/search/http%3A%2F%2Fairbnb.frngrgqb46.workers.dev%2Fhelp%2Farticle%2F1320) | url | — | openphish | — | 70 |
| [`hxxp://www[.]shopeemidyer[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.shopeemidyer.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]layanan-pemenang59[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.layanan-pemenang59.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]hadiahshopee3434[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.hadiahshopee3434.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://atendimentopj[.]vercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fatendimentopj.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://weilsfagosevic[.]okzk[.]com/ql34/02kja/signin[.]php`](https://www.virustotal.com/gui/search/https%3A%2F%2Fweilsfagosevic.okzk.com%2Fql34%2F02kja%2Fsignin.php) | url | — | openphish | — | 70 |
| [`hxxp://www[.]btyytytttttttttttooouuiiuu[.]weebly[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.btyytytttttttttttooouuiiuu.weebly.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://fpagesiterbx0nline[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Ffpagesiterbx0nline.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://shopee7547[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fshopee7547.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://thrshopee111[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fthrshopee111.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://zarnel-privex-biz-holvik-santor-fdp1912[.]pages[.]dev/heartily_welcome?id=130566103479224&page_name=%D7%91%D7%99%D7%9E%D7%AA%20%D7%94%D7%A0%D7%95%D7%A2%D7%A8%20%D7%A8%D7%97%D7%95%D7%91%D7%95%D7%AA%20%D7%94%D7%A8%D7%A9%D7%9E%D7%99appeals%2Fsubmit-appeal-form%2Freturn%2F/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fzarnel-privex-biz-holvik-santor-fdp1912.pages.dev%2Fheartily_welcome%3Fid%3D130566103479224%26page_name%3D%25D7%2591%25D7%2599%25D7%259E%25D7%25AA%2520%25D7%2594%25D7%25A0%25D7%2595%25D7%25A2%25D7%25A8%2520%25D7%25A8%25D7%2597%25D7%2595%25D7%2591%25D7%2595%25D7%25AA%2520%25D7%2594%25D7%25A8%25D7%25A9%25D7%259E%25D7%2599appeals%252Fsubmit-appeal-form%252Freturn%252F%2F) | url | — | openphish | — | 70 |
| [`hxxp://hwcps29vwp-qnkxzqwe-4k7j8d-hwc613-mtvlj85nhr[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fhwcps29vwp-qnkxzqwe-4k7j8d-hwc613-mtvlj85nhr.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://bgrfd63mwp-hwcpsfyn-5i9j2g-bgr814-mtvlj85xlo-qnkxz49[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbgrfd63mwp-hwcpsfyn-5i9j2g-bgr814-mtvlj85xlo-qnkxz49.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://hwcps87mnp-zlkytqwe-5i3j9d-hwc534-qnkxz72vlo[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fhwcps87mnp-zlkytqwe-5i3j9d-hwc534-qnkxz72vlo.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://mtvlj92wkp-qnkxz728-5j8k1g-mtv364-hwcps64nlo-zlkyt38[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmtvlj92wkp-qnkxz728-5j8k1g-mtv364-hwcps64nlo-zlkyt38.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://mtvlj47vnp-zlkyt728-6i3j2g-mtv859-qnkxz91xdo[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fmtvlj47vnp-zlkyt728-6i3j2g-mtv859-qnkxz91xdo.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://apple-crknjn[.]pages[.]dev/en/#/main`](https://www.virustotal.com/gui/search/https%3A%2F%2Fapple-crknjn.pages.dev%2Fen%2F%23%2Fmain) | url | — | openphish | — | 70 |
| [`hxxps://bgrfd71nlo-mtvljplx-3k7j5g-bgr926-qnkxz48whr[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbgrfd71nlo-mtvljplx-3k7j5g-bgr926-qnkxz48whr.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://sp29ct-tavun-biz-zemri-felko[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsp29ct-tavun-biz-zemri-felko.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://sp12ct10-melvani-biz-zulreko[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsp12ct10-melvani-biz-zulreko.pages.dev%2F) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
