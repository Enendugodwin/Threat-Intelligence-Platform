# Threat Intel Pulse — 2026-11-10

**Window:** last 7 days · **Generated:** 2026-11-10T19:53:08Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 65540 |
| New in window | 14814 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 23 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 614 | ok |
| tor | 8811 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 626 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 506 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 1647 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 39852 | 8710 |
| url | 13150 | 4069 |
| domain | 8230 | 1575 |
| ipv6 | 3757 | 234 |
| sha256 | 448 | 197 |
| md5 | 103 | 29 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 13165 |
| Exit nodes | 2452 |
| Other relays | 10713 |
| New in window | 1147 |

Sample (20 of 13165, source: Tor Project Onionoo):
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
- `102[.]205[.]44[.]36`

Full list: `dist/tor/tor_nodes.txt` (in the `threat-intel-output` workflow artifact).
## Top malware families

| Family | Indicators | New | ATT&CK (heuristic) |
| --- | --- | --- | --- |
| ClickFix | 228 | 122 | — |
| cryptoscam | 104 | 51 | — |
| NetSupport | 32 | 0 | — |
| PHP2Shell | 26 | 0 | — |
| Vidar | 25 | 21 | T1555, T1071.001, T1567 |
| Kimsuky | 24 | 8 | — |
| ValleyRAT | 23 | 0 | — |
| DPRK | 18 | 0 | — |
| Formbook | 17 | 5 | T1566.001, T1056.001, T1555, T1071.001, T1567 |
| Sliver | 14 | 2 | T1071.001, T1573, T1090, T1055 |
| Cobalt Strike | 10 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| AiTM | 8 | 8 | — |
| GuLoader | 8 | 8 | T1027, T1059.005, T1055, T1105 |
| Mirai | 8 | 0 | T1498, T1071.001 |
| ClearFake | 7 | 0 | — |
| Unknown malware | 7 | 0 | — |
| Mythic | 6 | 0 | — |
| SpyNote | 6 | 0 | — |
| Remcos | 5 | 3 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| QakBot | 4 | 0 | T1566.001, T1204.002, T1055, T1071.001, T1105, T1027, T1041 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1566 | Phishing | initial-access | 18860 |
| T1566.002 | Spearphishing Link | initial-access | 18860 |
| T1071.001 | Web Protocols | command-and-control | 46135 |
| T1573 | Encrypted Channel | command-and-control | 4237 |
| T1555 | Credentials from Password Stores | credential-access | 98 |
| T1567 | Exfiltration Over Web Service | exfiltration | 98 |
| T1552.001 | Credentials In Files | credential-access | 77 |
| T1056.001 | Keylogging | collection, credential-access | 48 |
| T1486 | Data Encrypted for Impact | impact | 43 |
| T1490 | Inhibit System Recovery | impact | 43 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 43 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 38 |
| T1105 | Ingress Tool Transfer | command-and-control | 31 |
| T1566.001 | Spearphishing Attachment | initial-access | 28 |
| T1090 | Proxy | command-and-control | 25 |
| T1027 | Obfuscated Files or Information | defense-evasion | 15 |
| T1204.002 | Malicious File | execution | 15 |
| T1498 | Network Denial of Service | impact | 11 |
| T1059.001 | PowerShell | execution | 10 |
| T1059.005 | Visual Basic | execution | 9 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 6 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 5 |
| T1113 | Screen Capture | collection | 5 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://529motors[.]com/homepersonas/`](https://www.virustotal.com/gui/search/https%3A%2F%2F529motors.com%2Fhomepersonas%2F) | url | — | openphish, tweetfeed | 2026-11-05T11:05:08Z | 70 |
| [`hxxps://digitalinv[.]aeronationaviation[.]com/method1/email[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fdigitalinv.aeronationaviation.com%2Fmethod1%2Femail.html) | url | — | openphish | — | 70 |
| [`hxxps://microsoft09-one[.]vercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmicrosoft09-one.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]microsoft09-one[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.microsoft09-one.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]nextwhatsapp[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.nextwhatsapp.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://kerijansenlawgroupcom[.]weupdaa[.]workers[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fkerijansenlawgroupcom.weupdaa.workers.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://ventira[.]life/css/doc/download[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fventira.life%2Fcss%2Fdoc%2Fdownload.html) | url | — | openphish | — | 70 |
| [`hxxp://facebook24-facebook[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Ffacebook24-facebook.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblovx[.]com[.]es/share?code=54408925083919342413887764625210&type=Profile&source=ProfileShare&gameid=8304191830`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblovx.com.es%2Fshare%3Fcode%3D54408925083919342413887764625210%26type%3DProfile%26source%3DProfileShare%26gameid%3D8304191830) | url | — | openphish | — | 70 |
| [`hxxps://www[.]interbank[.]correctcertificate[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.interbank.correctcertificate.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://roblox[.]com[.]ss/communities/838487772/SHOTERKETU-GIVEAWAYS`](https://www.virustotal.com/gui/search/http%3A%2F%2Froblox.com.ss%2Fcommunities%2F838487772%2FSHOTERKETU-GIVEAWAYS) | url | — | openphish | — | 70 |
| [`hxxps://apenasate-hoje2026[.]lat/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fapenasate-hoje2026.lat%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]facebookprofilelinks[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.facebookprofilelinks.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://myfamilyprime-espace[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmyfamilyprime-espace.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://fqg[.]pap[.]temporary[.]site/tricolors/seguro[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Ffqg.pap.temporary.site%2Ftricolors%2Fseguro.html) | url | — | openphish | — | 70 |
| [`hxxps://www[.]xf[.]gdmaoka[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.xf.gdmaoka.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://yrpkw7grzgo-msvlsi-5z4x8b-yrpks45c[.]pages[.]dev/welcome_aboard?welcome=1009568686956370&token248=1009568686956370&name_token136=Trollh%C3%A4ttan%20Classic%20Garage%20AB`](https://www.virustotal.com/gui/search/https%3A%2F%2Fyrpkw7grzgo-msvlsi-5z4x8b-yrpks45c.pages.dev%2Fwelcome_aboard%3Fwelcome%3D1009568686956370%26token248%3D1009568686956370%26name_token136%3DTrollh%25C3%25A4ttan%2520Classic%2520Garage%2520AB) | url | — | openphish | — | 70 |
| [`hxxps://kxlrq08hwu-wptjn36fyn-3y1x8g-yr200c[.]pages[.]dev/appeals/submit-appeal-form/return/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fkxlrq08hwu-wptjn36fyn-3y1x8g-yr200c.pages.dev%2Fappeals%2Fsubmit-appeal-form%2Freturn%2F) | url | — | openphish | — | 70 |
| [`hxxps://yrpkw866lkw-msvwur-5w4x9b-yrpks19p[.]pages[.]dev/send_appeal_request`](https://www.virustotal.com/gui/search/https%3A%2F%2Fyrpkw866lkw-msvwur-5w4x9b-yrpks19p.pages.dev%2Fsend_appeal_request) | url | — | openphish | — | 70 |
| [`hxxps://yrpkw7grzgo-msvlsi-5z4x8b-yrpks45c[.]pages[.]dev/send_appeal_request`](https://www.virustotal.com/gui/search/https%3A%2F%2Fyrpkw7grzgo-msvlsi-5z4x8b-yrpks45c.pages.dev%2Fsend_appeal_request) | url | — | openphish | — | 70 |
| [`hxxps://kxlrq08hwu-wptjn36fyn-3y1x8g-yr200c[.]pages[.]dev/send_appeal_request`](https://www.virustotal.com/gui/search/https%3A%2F%2Fkxlrq08hwu-wptjn36fyn-3y1x8g-yr200c.pages.dev%2Fsend_appeal_request) | url | — | openphish | — | 70 |
| [`hxxps://wptjn078mjw-kxlrqrel-9w6t2g-yr166a[.]pages[.]dev/send_appeal_request`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwptjn078mjw-kxlrqrel-9w6t2g-yr166a.pages.dev%2Fsend_appeal_request) | url | — | openphish | — | 70 |
| [`hxxps://1annj1ab1aaa[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2F1annj1ab1aaa.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://souroabhdubey[.]github[.]io/netflixclonewebsite/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsouroabhdubey.github.io%2Fnetflixclonewebsite%2F) | url | — | openphish | — | 70 |
| [`hxxps://customer-sp-logandaviau1[.]pages[.]dev/help/contact/390849720685817appeals/submit-appeal-formappeals/submit-appeal-form/return/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fcustomer-sp-logandaviau1.pages.dev%2Fhelp%2Fcontact%2F390849720685817appeals%2Fsubmit-appeal-formappeals%2Fsubmit-appeal-form%2Freturn%2F) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
