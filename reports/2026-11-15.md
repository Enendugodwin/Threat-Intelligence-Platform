# Threat Intel Pulse — 2026-11-15

**Window:** last 7 days · **Generated:** 2026-11-15T06:51:11Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 70847 |
| New in window | 13035 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 23 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 314 | ok |
| tor | 8791 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 752 | ok |
| greensnow | - | error: RetryError: HTTPSConnectionPool(host='blocklist.greensnow.co', port=443): Max retries exceeded with url: /greensnow.txt (Caused by ResponseError('too many 503 error responses')) |
| phishing_army | 3000 | ok |
| et_compromised | 584 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 1184 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 44105 | 7418 |
| url | 13423 | 4027 |
| domain | 8907 | 1213 |
| ipv6 | 3760 | 226 |
| sha256 | 533 | 126 |
| md5 | 119 | 25 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 13212 |
| Exit nodes | 2421 |
| Other relays | 10791 |
| New in window | 1010 |

Sample (20 of 13212, source: Tor Project Onionoo):
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
| ClickFix | 238 | 72 | — |
| cryptoscam | 104 | 27 | — |
| Formbook | 53 | 41 | T1566.001, T1056.001, T1555, T1071.001, T1567 |
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
| T1566 | Phishing | initial-access | 19544 |
| T1566.002 | Spearphishing Link | initial-access | 19544 |
| T1071.001 | Web Protocols | command-and-control | 50659 |
| T1573 | Encrypted Channel | command-and-control | 5152 |
| T1555 | Credentials from Password Stores | credential-access | 142 |
| T1567 | Exfiltration Over Web Service | exfiltration | 142 |
| T1056.001 | Keylogging | collection, credential-access | 98 |
| T1552.001 | Credentials In Files | credential-access | 85 |
| T1566.001 | Spearphishing Attachment | initial-access | 74 |
| T1486 | Data Encrypted for Impact | impact | 67 |
| T1490 | Inhibit System Recovery | impact | 67 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 67 |
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
| [`hxxps://lapaca[.]webdirecto[.]com/wp-includes/Text/tdweain/yogsqwj/gmehpir/ggg/adobe/adobe[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Flapaca.webdirecto.com%2Fwp-includes%2FText%2Ftdweain%2Fyogsqwj%2Fgmehpir%2Fggg%2Fadobe%2Fadobe.html) | url | — | openphish, tweetfeed | 2026-11-14T16:01:48Z | 70 |
| [`hxxps://mifidelidad[.]click/bac[.]pa`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmifidelidad.click%2Fbac.pa) | url | — | openphish, tweetfeed | 2026-11-12T01:03:17Z | 70 |
| [`hxxp://camposaparthotelcamposaparthotel[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fcamposaparthotelcamposaparthotel.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://wyshtap[.]cc/webchat/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwyshtap.cc%2Fwebchat%2F) | url | — | openphish | — | 70 |
| [`hxxps://wyshtap[.]cc/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwyshtap.cc%2F) | url | — | openphish | — | 70 |
| [`hxxp://serwerk[.]uber[.]space/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fserwerk.uber.space%2F) | url | — | openphish | — | 70 |
| [`hxxp://excellx[.]techsofttips[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fexcellx.techsofttips.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://hwcps19xdo-mtvljqwe-5k7j2g-hwc863[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fhwcps19xdo-mtvljqwe-5k7j2g-hwc863.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://r[.]xmas1225usa[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fr.xmas1225usa.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://facebook[.]xmas1225usa[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ffacebook.xmas1225usa.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://verify-session-ochre[.]vercel[.]app/accounts-center`](https://www.virustotal.com/gui/search/https%3A%2F%2Fverify-session-ochre.vercel.app%2Faccounts-center) | url | — | openphish | — | 70 |
| [`hxxps://verify-session-ochre[.]vercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fverify-session-ochre.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://ldgrr-live-desktop[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fldgrr-live-desktop.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]tbybit-trade[.]lol/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.tbybit-trade.lol%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]lexcontrol-sso[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.lexcontrol-sso.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://president[.]petition[.]co[.]ua/i%D0%BDst%D0%B0gr%D0%B0%D0%BC/login`](https://www.virustotal.com/gui/search/https%3A%2F%2Fpresident.petition.co.ua%2Fi%25D0%25BDst%25D0%25B0gr%25D0%25B0%25D0%25BC%2Flogin) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]com[.]ml/users/390783638810/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.com.ml%2Fusers%2F390783638810%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxp://854938-icloud[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2F854938-icloud.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://uv-bitli-compo[.]pages[.]dev/help/contact/843850237211513appeals/submit-appeal-form/return`](https://www.virustotal.com/gui/search/https%3A%2F%2Fuv-bitli-compo.pages.dev%2Fhelp%2Fcontact%2F843850237211513appeals%2Fsubmit-appeal-form%2Freturn) | url | — | openphish | — | 70 |
| [`hxxps://parcelagent[.]xyz/login`](https://www.virustotal.com/gui/search/https%3A%2F%2Fparcelagent.xyz%2Flogin) | url | — | openphish | — | 70 |
| [`hxxp://parcelagent[.]xyz/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fparcelagent.xyz%2F) | url | — | openphish | — | 70 |
| [`hxxp://xmas1225usa[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fxmas1225usa.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]oxxw[.]best/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.oxxw.best%2F) | url | — | openphish | — | 70 |
| [`hxxps://tokininx-cdn18-hk78[.]lol/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ftokininx-cdn18-hk78.lol%2F) | url | — | openphish | — | 70 |
| [`hxxps://d33wubrfki0l68[.]cloudfront[.]net/749f3d33-ff14-4545-889d-c586baf38eda/auth365[.]html##reniolab@1fb327c1a450b29d1699a8ca34420bd4e640[.]net`](https://www.virustotal.com/gui/search/https%3A%2F%2Fd33wubrfki0l68.cloudfront.net%2F749f3d33-ff14-4545-889d-c586baf38eda%2Fauth365.html%23%23reniolab%401fb327c1a450b29d1699a8ca34420bd4e640.net) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
