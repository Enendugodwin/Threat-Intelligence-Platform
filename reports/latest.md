# Threat Intel Pulse — 2026-11-03

**Window:** last 7 days · **Generated:** 2026-11-03T07:00:45Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 85667 |
| New in window | 15902 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 614 | ok |
| tor | 10199 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 344 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 518 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 961 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 34818 | 9665 |
| url | 26245 | 4333 |
| domain | 12347 | 1303 |
| sha256 | 7447 | 120 |
| ipv6 | 3684 | 444 |
| md5 | 599 | 37 |
| sha1 | 527 | 0 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 12861 |
| Exit nodes | 2414 |
| Other relays | 10447 |
| New in window | 1935 |

Sample (20 of 12861, source: Tor Project Onionoo):
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
| Vidar | 5484 | 0 | T1555, T1071.001, T1567 |
| Mirai | 1605 | 0 | T1498, T1071.001 |
| IClickFix | 1538 | 0 | — |
| Unknown Loader | 1412 | 0 | — |
| Unknown malware | 1329 | 0 | — |
| Cobalt Strike | 1299 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| AMOS | 882 | 0 | — |
| VShell | 754 | 0 | — |
| ClearFake | 450 | 0 | — |
| PureRAT | 382 | 0 | — |
| php.shin_webshell | 357 | 0 | — |
| Sliver | 341 | 0 | T1071.001, T1573, T1090, T1055 |
| Remus | 296 | 0 | — |
| Remcos | 291 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| AsyncRAT | 273 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| AdaptixC2 | 268 | 0 | — |
| MacSync | 255 | 0 | — |
| DanaBot | 187 | 0 | T1566.001, T1071.001, T1555, T1041 |
| SalatStealer | 140 | 0 | — |
| Formbook | 139 | 1 | T1566.001, T1056.001, T1555, T1071.001, T1567 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1071.001 | Web Protocols | command-and-control | 57692 |
| T1566 | Phishing | initial-access | 17298 |
| T1566.002 | Spearphishing Link | initial-access | 17298 |
| T1105 | Ingress Tool Transfer | command-and-control | 12164 |
| T1573 | Encrypted Channel | command-and-control | 8957 |
| T1555 | Credentials from Password Stores | credential-access | 8142 |
| T1567 | Exfiltration Over Web Service | exfiltration | 7951 |
| T1498 | Network Denial of Service | impact | 4895 |
| T1552.001 | Credentials In Files | credential-access | 4439 |
| T1204.002 | Malicious File | execution | 4074 |
| T1027 | Obfuscated Files or Information | defense-evasion | 3922 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1743 |
| T1090 | Proxy | command-and-control | 1674 |
| T1056.001 | Keylogging | collection, credential-access | 1557 |
| T1059.001 | PowerShell | execution | 1309 |
| T1566.001 | Spearphishing Attachment | initial-access | 1279 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 848 |
| T1113 | Screen Capture | collection | 808 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 265 |
| T1189 | Drive-by Compromise | initial-access | 161 |
| T1218 | System Binary Proxy Execution | defense-evasion | 161 |
| T1486 | Data Encrypted for Impact | impact | 44 |
| T1490 | Inhibit System Recovery | impact | 44 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 44 |
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
| [`hxxp://make-troll-318071[.]framer[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fmake-troll-318071.framer.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://avdveulfdasxf[.]square[.]site/`](https://www.virustotal.com/gui/search/http%3A%2F%2Favdveulfdasxf.square.site%2F) | url | — | openphish | — | 70 |
| [`hxxp://himorhis[.]square[.]site/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fhimorhis.square.site%2F) | url | — | openphish | — | 70 |
| [`hxxps://facebookloginuser[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ffacebookloginuser.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]facebookloginuser[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.facebookloginuser.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://facebook-login0[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ffacebook-login0.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://wtrkb8bskra-pfxmzwur-5l2i7d-yk000a[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwtrkb8bskra-pfxmzwur-5l2i7d-yk000a.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://tokinlm-cdn2-hk51[.]xyz/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ftokinlm-cdn2-hk51.xyz%2F) | url | — | openphish | — | 70 |
| [`hxxps://jakxwo-x4hmh1og[.]vercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fjakxwo-x4hmh1og.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://statensveagvesenno[.]whf[.]bz/eika`](https://www.virustotal.com/gui/search/https%3A%2F%2Fstatensveagvesenno.whf.bz%2Feika) | url | — | openphish | — | 70 |
| [`hxxps://review102-account-activity286[.]weebly[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Freview102-account-activity286.weebly.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://tinyurl[.]com/mtmka79f`](https://www.virustotal.com/gui/search/https%3A%2F%2Ftinyurl.com%2Fmtmka79f) | url | — | openphish | — | 70 |
| [`hxxps://fb-meta-verified-36592[.]vercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ffb-meta-verified-36592.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://hoamiigaytooss[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fhoamiigaytooss.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://photos-instagram[.]vercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fphotos-instagram.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://sp29ct-korvi-biz-nurak-felto[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsp29ct-korvi-biz-nurak-felto.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://business-verification-help186[.]vercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbusiness-verification-help186.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]posta-beige[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.posta-beige.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]navercorp-green[.]vercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.navercorp-green.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://sp20ct10-kumvex-biz-lorima[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsp20ct10-kumvex-biz-lorima.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://roblox[.]fo/users/587848719/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Froblox.fo%2Fusers%2F587848719%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]com[.]ss/games/114055952820658/Kick-a-Baddie?privateServerLinkCode=13102152397451739216744224867473`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.com.ss%2Fgames%2F114055952820658%2FKick-a-Baddie%3FprivateServerLinkCode%3D13102152397451739216744224867473) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
