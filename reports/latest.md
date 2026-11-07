# Threat Intel Pulse — 2026-11-07

**Window:** last 7 days · **Generated:** 2026-11-07T06:16:04Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 80482 |
| New in window | 15480 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 27 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 614 | ok |
| tor | 10215 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 1332 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 511 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 1792 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 39002 | 9350 |
| url | 20937 | 4192 |
| domain | 11236 | 1236 |
| sha256 | 5113 | 203 |
| ipv6 | 3736 | 472 |
| md5 | 277 | 27 |
| sha1 | 181 | 0 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 13063 |
| Exit nodes | 2430 |
| Other relays | 10633 |
| New in window | 2072 |

Sample (20 of 13063, source: Tor Project Onionoo):
- `1[.]161[.]130[.]49`
- `1[.]201[.]176[.]169`
- `1[.]201[.]176[.]176`
- `1[.]235[.]159[.]83`
- `1[.]248[.]96[.]163`
- `1[.]34[.]44[.]234`
- `100[.]12[.]167[.]245`
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

Full list: `dist/tor/tor_nodes.txt` (in the `threat-intel-output` workflow artifact).
## Top malware families

| Family | Indicators | New | ATT&CK (heuristic) |
| --- | --- | --- | --- |
| Vidar | 1733 | 0 | T1555, T1071.001, T1567 |
| IClickFix | 1267 | 0 | — |
| Cobalt Strike | 1221 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| Mirai | 1221 | 0 | T1498, T1071.001 |
| Unknown malware | 962 | 0 | — |
| Unknown Loader | 741 | 0 | — |
| AMOS | 706 | 0 | — |
| VShell | 403 | 0 | — |
| PureRAT | 358 | 0 | — |
| MacSync | 253 | 0 | — |
| AdaptixC2 | 246 | 0 | — |
| ClearFake | 227 | 0 | — |
| Remus | 224 | 0 | — |
| Remcos | 200 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| AsyncRAT | 189 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| DanaBot | 181 | 0 | T1566.001, T1071.001, T1555, T1041 |
| php.shin_webshell | 179 | 0 | — |
| ClickFix | 166 | 72 | — |
| Sliver | 100 | 2 | T1071.001, T1573, T1090, T1055 |
| Evilginx | 95 | 2 | — |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1566 | Phishing | initial-access | 18308 |
| T1566.002 | Spearphishing Link | initial-access | 18308 |
| T1071.001 | Web Protocols | command-and-control | 55326 |
| T1105 | Ingress Tool Transfer | command-and-control | 7506 |
| T1573 | Encrypted Channel | command-and-control | 6720 |
| T1498 | Network Denial of Service | impact | 3951 |
| T1555 | Credentials from Password Stores | credential-access | 3881 |
| T1567 | Exfiltration Over Web Service | exfiltration | 3696 |
| T1552.001 | Credentials In Files | credential-access | 1507 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1405 |
| T1090 | Proxy | command-and-control | 1351 |
| T1204.002 | Malicious File | execution | 1235 |
| T1027 | Obfuscated Files or Information | defense-evasion | 1234 |
| T1059.001 | PowerShell | execution | 1231 |
| T1056.001 | Keylogging | collection, credential-access | 1113 |
| T1566.001 | Spearphishing Attachment | initial-access | 861 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 564 |
| T1113 | Screen Capture | collection | 529 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 227 |
| T1486 | Data Encrypted for Impact | impact | 43 |
| T1490 | Inhibit System Recovery | impact | 43 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 43 |
| T1059.005 | Visual Basic | execution | 28 |
| T1190 | Exploit Public-Facing Application | initial-access | 20 |
| T1189 | Drive-by Compromise | initial-access | 6 |
| T1218 | System Binary Proxy Execution | defense-evasion | 6 |
| T1003 | OS Credential Dumping | credential-access | 1 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://529motors[.]com/homepersonas/`](https://www.virustotal.com/gui/search/https%3A%2F%2F529motors.com%2Fhomepersonas%2F) | url | — | openphish, tweetfeed | 2026-11-05T11:05:08Z | 70 |
| [`hxxps://vemtasbobinaj[.]com/login[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fvemtasbobinaj.com%2Flogin.html) | url | — | openphish, tweetfeed | 2026-11-02T19:27:35Z | 70 |
| [`hxxps://auditormadrid[.]es/wp-content/mu-plugins/iklqzct/iuo/alibaba/?naps`](https://www.virustotal.com/gui/search/https%3A%2F%2Fauditormadrid.es%2Fwp-content%2Fmu-plugins%2Fiklqzct%2Fiuo%2Falibaba%2F%3Fnaps) | url | — | openphish, tweetfeed | 2026-11-01T13:14:43Z | 70 |
| [`hxxp://facebook[.]webmau[.]vn/`](https://www.virustotal.com/gui/search/http%3A%2F%2Ffacebook.webmau.vn%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]com[.]kz/users/137614935/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.com.kz%2Fusers%2F137614935%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxp://xmqrb724nhw-zdcynfyn-2d9e0f-pj388a[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fxmqrb724nhw-zdcynfyn-2d9e0f-pj388a.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://8s1q2g-qw999agreg-mbtz1m8p9z2-fsgc12[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2F8s1q2g-qw999agreg-mbtz1m8p9z2-fsgc12.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://2u8m1c-qw144c84y-mbtz8m9p1z2-qwxk[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2F2u8m1c-qw144c84y-mbtz8m9p1z2-qwxk.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://fylrk4c01pl-bxzgcyhy-1l8j2g-sw511a[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ffylrk4c01pl-bxzgcyhy-1l8j2g-sw511a.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://divace-coinsquare[.]zapier[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fdivace-coinsquare.zapier.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://track[.]map-app[.]my[.]id/gZh`](https://www.virustotal.com/gui/search/http%3A%2F%2Ftrack.map-app.my.id%2FgZh) | url | — | openphish | — | 70 |
| [`hxxps://hklogin[.]uat[.]mizuhoscfglobal[.]com/oauth2/authorize?response_type=code&client_id=bca4f495-a205-4cb4-8b0a-07f4d88a7584&scope=openid%20email%20profile&state=eDcYeukV-Yqf6Phtrq0XmoQEi3qWjB4ZJVQKd1b3FLQ%3D&redirect_uri=https://hk[.]uat[.]mizuhoscfglobal[.]com/scf/login/oauth2/code/fusionauth&nonce=iKCQAqN9jgh-qbCgvqmDhVVdnmtR3jPBaOvRdNDTzhA&code_challenge=OD8gH4TYyaheiXEdbZvm8F3jH3IIxiWPhce5ThiUTg4&code_challenge_method=S256`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhklogin.uat.mizuhoscfglobal.com%2Foauth2%2Fauthorize%3Fresponse_type%3Dcode%26client_id%3Dbca4f495-a205-4cb4-8b0a-07f4d88a7584%26scope%3Dopenid%2520email%2520profile%26state%3DeDcYeukV-Yqf6Phtrq0XmoQEi3qWjB4ZJVQKd1b3FLQ%253D%26redirect_uri%3Dhttps%3A%2F%2Fhk.uat.mizuhoscfglobal.com%2Fscf%2Flogin%2Foauth2%2Fcode%2Ffusionauth%26nonce%3DiKCQAqN9jgh-qbCgvqmDhVVdnmtR3jPBaOvRdNDTzhA%26code_challenge%3DOD8gH4TYyaheiXEdbZvm8F3jH3IIxiWPhce5ThiUTg4%26code_challenge_method%3DS256) | url | — | openphish | — | 70 |
| [`hxxps://hk[.]uat[.]mizuhoscfglobal[.]com/scf/login/oauth2/code/fusionauth`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhk.uat.mizuhoscfglobal.com%2Fscf%2Flogin%2Foauth2%2Fcode%2Ffusionauth) | url | — | openphish | — | 70 |
| [`hxxps://secureprofiles2026-indol[.]vercel[.]app/careers[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsecureprofiles2026-indol.vercel.app%2Fcareers.html) | url | — | openphish | — | 70 |
| [`hxxp://www[.]a[.]colombiascol[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.a.colombiascol.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]fuzzy-giggle-eta[.]vercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.fuzzy-giggle-eta.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://ashi130-cell[.]github[.]io/INSTAGRAM-LOGIN-DEMO`](https://www.virustotal.com/gui/search/https%3A%2F%2Fashi130-cell.github.io%2FINSTAGRAM-LOGIN-DEMO) | url | — | openphish | — | 70 |
| [`hxxps://sp1ct10-lavviro-biz-zanleko[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsp1ct10-lavviro-biz-zanleko.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://sp1ct10-zelmiko-biz-vemleko[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsp1ct10-zelmiko-biz-vemleko.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://sp30ct-qurik-biz-vemol-nadex[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsp30ct-qurik-biz-vemol-nadex.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://vormora-gld-lartemi-p3t7kh25[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fvormora-gld-lartemi-p3t7kh25.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://sp1ct10-zorvilo-biz-kavreko[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsp1ct10-zorvilo-biz-kavreko.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://sp1ct10-lavzaro-biz-korvuni[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsp1ct10-lavzaro-biz-korvuni.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://9u8m1c-qw333agreg-mbtz1m8p9z2-qwxk[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2F9u8m1c-qw333agreg-mbtz1m8p9z2-qwxk.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://8s1q9g-1v2m8p9a-mbtz1p8m9z2-fsgc[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2F8s1q9g-1v2m8p9a-mbtz1p8m9z2-fsgc.pages.dev%2F) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
