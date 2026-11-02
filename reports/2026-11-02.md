# Threat Intel Pulse — 2026-11-02

**Window:** last 7 days · **Generated:** 2026-11-02T21:49:12Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 86463 |
| New in window | 17071 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 614 | ok |
| tor | 10185 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 1052 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 518 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 1073 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 34620 | 10535 |
| url | 26815 | 4437 |
| domain | 12447 | 1464 |
| sha256 | 7763 | 141 |
| ipv6 | 3692 | 449 |
| md5 | 599 | 45 |
| sha1 | 527 | 0 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 12896 |
| Exit nodes | 2411 |
| Other relays | 10485 |
| New in window | 1957 |

Sample (20 of 12896, source: Tor Project Onionoo):
- `1[.]161[.]130[.]49`
- `1[.]201[.]176[.]169`
- `1[.]201[.]176[.]176`
- `1[.]235[.]159[.]83`
- `1[.]248[.]96[.]163`
- `1[.]34[.]44[.]234`
- `100[.]2[.]63[.]41`
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
- `102[.]205[.]44[.]5`

Full list: `dist/tor/tor_nodes.txt` (in the `threat-intel-output` workflow artifact).
## Top malware families

| Family | Indicators | New | ATT&CK (heuristic) |
| --- | --- | --- | --- |
| Vidar | 5612 | 4 | T1555, T1071.001, T1567 |
| Mirai | 1711 | 0 | T1498, T1071.001 |
| IClickFix | 1550 | 0 | — |
| Unknown Loader | 1420 | 0 | — |
| Unknown malware | 1343 | 0 | — |
| Cobalt Strike | 1301 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| AMOS | 918 | 0 | — |
| VShell | 773 | 0 | — |
| ClearFake | 468 | 0 | — |
| PureRAT | 389 | 0 | — |
| php.shin_webshell | 382 | 0 | — |
| Sliver | 341 | 0 | T1071.001, T1573, T1090, T1055 |
| Remcos | 308 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| Remus | 299 | 0 | — |
| AsyncRAT | 279 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| AdaptixC2 | 268 | 0 | — |
| MacSync | 256 | 0 | — |
| DanaBot | 187 | 0 | T1566.001, T1071.001, T1555, T1041 |
| SalatStealer | 140 | 0 | — |
| Formbook | 139 | 1 | T1566.001, T1056.001, T1555, T1071.001, T1567 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1071.001 | Web Protocols | command-and-control | 57885 |
| T1566 | Phishing | initial-access | 17548 |
| T1566.002 | Spearphishing Link | initial-access | 17548 |
| T1105 | Ingress Tool Transfer | command-and-control | 12387 |
| T1573 | Encrypted Channel | command-and-control | 8979 |
| T1555 | Credentials from Password Stores | credential-access | 8356 |
| T1567 | Exfiltration Over Web Service | exfiltration | 8165 |
| T1498 | Network Denial of Service | impact | 5064 |
| T1552.001 | Credentials In Files | credential-access | 4556 |
| T1204.002 | Malicious File | execution | 4138 |
| T1027 | Obfuscated Files or Information | defense-evasion | 3986 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1754 |
| T1090 | Proxy | command-and-control | 1676 |
| T1056.001 | Keylogging | collection, credential-access | 1588 |
| T1566.001 | Spearphishing Attachment | initial-access | 1312 |
| T1059.001 | PowerShell | execution | 1311 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 872 |
| T1113 | Screen Capture | collection | 832 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 274 |
| T1189 | Drive-by Compromise | initial-access | 161 |
| T1218 | System Binary Proxy Execution | defense-evasion | 161 |
| T1486 | Data Encrypted for Impact | impact | 40 |
| T1490 | Inhibit System Recovery | impact | 40 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 40 |
| T1059.005 | Visual Basic | execution | 33 |
| T1190 | Exploit Public-Facing Application | initial-access | 21 |
| T1021.001 | Remote Desktop Protocol | lateral-movement | 6 |
| T1003 | OS Credential Dumping | credential-access | 4 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://vemtasbobinaj[.]com/login[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fvemtasbobinaj.com%2Flogin.html) | url | — | openphish, tweetfeed | 2026-11-02T19:27:35Z | 70 |
| [`hxxps://auditormadrid[.]es/wp-content/mu-plugins/iklqzct/iuo/alibaba/?naps`](https://www.virustotal.com/gui/search/https%3A%2F%2Fauditormadrid.es%2Fwp-content%2Fmu-plugins%2Fiklqzct%2Fiuo%2Falibaba%2F%3Fnaps) | url | — | openphish, tweetfeed | 2026-11-01T13:14:43Z | 70 |
| [`hxxps://zoffry[.]qpon/Adb/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fzoffry.qpon%2FAdb%2F) | url | — | openphish, tweetfeed | 2026-10-29T13:22:48Z | 70 |
| [`hxxps://www[.]roblox[.]com[.]et/users/4243002378/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.com.et%2Fusers%2F4243002378%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxp://bofa-login[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fbofa-login.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://chatgpt0005[.]eu[.]org/blog/discord-patch-notes-february-4-2026/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fchatgpt0005.eu.org%2Fblog%2Fdiscord-patch-notes-february-4-2026%2F) | url | — | openphish | — | 70 |
| [`hxxps://chatgpt0005[.]eu[.]org/blog/save-and-display-your-faves-add-discord-shop-marvel-rivals-items-to-your-profiles-wishlist/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fchatgpt0005.eu.org%2Fblog%2Fsave-and-display-your-faves-add-discord-shop-marvel-rivals-items-to-your-profiles-wishlist%2F) | url | — | openphish | — | 70 |
| [`hxxps://chatgpt0005[.]eu[.]org/blog/discord-is-now-on-meta-quest-reach-out-to-your-servers-while-in-vr/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fchatgpt0005.eu.org%2Fblog%2Fdiscord-is-now-on-meta-quest-reach-out-to-your-servers-while-in-vr%2F) | url | — | openphish | — | 70 |
| [`hxxps://chatgpt0005[.]eu[.]org/blog/discord-update-december-13-2023-changelog/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fchatgpt0005.eu.org%2Fblog%2Fdiscord-update-december-13-2023-changelog%2F) | url | — | openphish | — | 70 |
| [`hxxps://chatgpt0005[.]eu[.]org/category/community/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fchatgpt0005.eu.org%2Fcategory%2Fcommunity%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]it-supportdesk[.]com/signin?t=eyJhbGciOiJIUzI1NiJ9[.]eyJ0cmFja2luZ190b2tlbiI6ImJhNDFiOWE1LTUxMDgtNDhhZC1hN2YzLTZhNjRkNTUxNDI4OCIsImNlbGwiOiJodHRwczovLzIxZzZqZnZoeTYuZXhlY3V0ZS1hcGkudXMtZWFzdC0yLmFtYXpvbmF3cy5jb20vcHJvZC9hcGkvcGhpc2hpbmdjYW1wYWlnbiIsImNhbXBhaWduX3Rva2VuIjoiNWZmNTE3ZTItNWI4NS00ZjU3LTk4ODYtY2UwMzAzZTBiNzlhIiwidGVzdF90b2tlbiI6ZmFsc2UsImV4dGVybmFsX3RyYWluaW5nIjpmYWxzZSwiZGlyZWN0X2RlbGl2ZXJ5Ijp0cnVlLCJpYXQiOjE3OTI5NDUzMjYsImlzcyI6Imh0dHBzOi8vYXBwLnBoaXNodGhyZWF0LmNvbSIsImV4cCI6MTgwMDcyMTMyNn0[.]ZjE0oQrgVuD_L_gTWb-i1UIT1dFmj2B1X3BuZ2dXeUw`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.it-supportdesk.com%2Fsignin%3Ft%3DeyJhbGciOiJIUzI1NiJ9.eyJ0cmFja2luZ190b2tlbiI6ImJhNDFiOWE1LTUxMDgtNDhhZC1hN2YzLTZhNjRkNTUxNDI4OCIsImNlbGwiOiJodHRwczovLzIxZzZqZnZoeTYuZXhlY3V0ZS1hcGkudXMtZWFzdC0yLmFtYXpvbmF3cy5jb20vcHJvZC9hcGkvcGhpc2hpbmdjYW1wYWlnbiIsImNhbXBhaWduX3Rva2VuIjoiNWZmNTE3ZTItNWI4NS00ZjU3LTk4ODYtY2UwMzAzZTBiNzlhIiwidGVzdF90b2tlbiI6ZmFsc2UsImV4dGVybmFsX3RyYWluaW5nIjpmYWxzZSwiZGlyZWN0X2RlbGl2ZXJ5Ijp0cnVlLCJpYXQiOjE3OTI5NDUzMjYsImlzcyI6Imh0dHBzOi8vYXBwLnBoaXNodGhyZWF0LmNvbSIsImV4cCI6MTgwMDcyMTMyNn0.ZjE0oQrgVuD_L_gTWb-i1UIT1dFmj2B1X3BuZ2dXeUw) | url | — | openphish | — | 70 |
| [`hxxps://www[.]id-cms[.]work/verify/xug2eay6d3ompbaha`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.id-cms.work%2Fverify%2Fxug2eay6d3ompbaha) | url | — | openphish | — | 70 |
| [`hxxps://www[.]id-cms[.]work/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.id-cms.work%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]et/users/6765120257/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.et%2Fusers%2F6765120257%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxps://comptecaweb-001-site1[.]ktempurl[.]com/Agris-Webconnexions/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fcomptecaweb-001-site1.ktempurl.com%2FAgris-Webconnexions%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]mlnk[.]vn/asuar/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.mlnk.vn%2Fasuar%2F) | url | — | openphish | — | 70 |
| [`hxxps://statelawfirm[.]weupdaa[.]workers[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fstatelawfirm.weupdaa.workers.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://1url[.]at/www/robloxuser-951099195-profile`](https://www.virustotal.com/gui/search/https%3A%2F%2F1url.at%2Fwww%2Frobloxuser-951099195-profile) | url | — | openphish | — | 70 |
| [`hxxp://pub-cf8243e496b946db82fa4374d900d030[.]r2[.]dev/30064354gs4[.]html`](https://www.virustotal.com/gui/search/http%3A%2F%2Fpub-cf8243e496b946db82fa4374d900d030.r2.dev%2F30064354gs4.html) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]com[.]et/users/4486801085/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.com.et%2Fusers%2F4486801085%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxps://1kak1anzas[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2F1kak1anzas.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://amuento-3278--aumento35[.]replit[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Famuento-3278--aumento35.replit.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://confrmpges-pgesacct[.]github[.]io/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fconfrmpges-pgesacct.github.io%2F) | url | — | openphish | — | 70 |
| [`hxxps://ajeetkumaryadav565-hue[.]github[.]io/Netflix-clone/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fajeetkumaryadav565-hue.github.io%2FNetflix-clone%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]16156655[.]com/m/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.16156655.com%2Fm%2F) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
