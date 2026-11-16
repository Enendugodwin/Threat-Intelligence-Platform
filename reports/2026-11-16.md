# Threat Intel Pulse — 2026-11-16

**Window:** last 7 days · **Generated:** 2026-11-16T06:51:12Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 69599 |
| New in window | 13838 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 23 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 314 | ok |
| tor | 8770 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 1100 | ok |
| greensnow | - | error: RetryError: HTTPSConnectionPool(host='blocklist.greensnow.co', port=443): Max retries exceeded with url: /greensnow.txt (Caused by ResponseError('too many 503 error responses')) |
| phishing_army | 3000 | ok |
| et_compromised | 584 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 1481 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 44070 | 7803 |
| url | 12860 | 4444 |
| domain | 8245 | 1185 |
| ipv6 | 3758 | 224 |
| sha256 | 526 | 130 |
| md5 | 140 | 52 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 13201 |
| Exit nodes | 2417 |
| Other relays | 10784 |
| New in window | 1019 |

Sample (20 of 13201, source: Tor Project Onionoo):
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
| ClickFix | 259 | 63 | — |
| cryptoscam | 104 | 9 | — |
| Formbook | 53 | 41 | T1566.001, T1056.001, T1555, T1071.001, T1567 |
| NetSupport | 32 | 0 | — |
| PHP2Shell | 26 | 0 | — |
| Vidar | 25 | 21 | T1555, T1071.001, T1567 |
| Kimsuky | 20 | 0 | — |
| ValleyRAT | 19 | 0 | — |
| DPRK | 18 | 0 | — |
| Remcos | 15 | 13 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| Sliver | 10 | 0 | T1071.001, T1573, T1090, T1055 |
| Cobalt Strike | 9 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| AiTM | 8 | 0 | — |
| GuLoader | 8 | 0 | T1027, T1059.005, T1055, T1105 |
| Mirai | 8 | 0 | T1498, T1071.001 |
| ClearFake | 7 | 0 | — |
| Unknown malware | 7 | 0 | — |
| infostealer | 7 | 3 | — |
| SpyNote | 6 | 0 | — |
| Evilginx | 4 | 2 | — |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1566 | Phishing | initial-access | 18203 |
| T1566.002 | Spearphishing Link | initial-access | 18203 |
| T1071.001 | Web Protocols | command-and-control | 50741 |
| T1573 | Encrypted Channel | command-and-control | 5137 |
| T1555 | Credentials from Password Stores | credential-access | 143 |
| T1567 | Exfiltration Over Web Service | exfiltration | 143 |
| T1056.001 | Keylogging | collection, credential-access | 93 |
| T1552.001 | Credentials In Files | credential-access | 86 |
| T1566.001 | Spearphishing Attachment | initial-access | 74 |
| T1486 | Data Encrypted for Impact | impact | 65 |
| T1490 | Inhibit System Recovery | impact | 65 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 65 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 33 |
| T1105 | Ingress Tool Transfer | command-and-control | 30 |
| T1090 | Proxy | command-and-control | 20 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 16 |
| T1027 | Obfuscated Files or Information | defense-evasion | 15 |
| T1113 | Screen Capture | collection | 15 |
| T1204.002 | Malicious File | execution | 15 |
| T1498 | Network Denial of Service | impact | 11 |
| T1059.001 | PowerShell | execution | 9 |
| T1059.005 | Visual Basic | execution | 9 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 5 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://lapaca[.]webdirecto[.]com/wp-includes/Text/tdweain/yogsqwj/gmehpir/ggg/adobe/adobe[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Flapaca.webdirecto.com%2Fwp-includes%2FText%2Ftdweain%2Fyogsqwj%2Fgmehpir%2Fggg%2Fadobe%2Fadobe.html) | url | — | openphish, tweetfeed | 2026-11-14T16:01:48Z | 70 |
| [`hxxps://mifidelidad[.]click/bac[.]pa`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmifidelidad.click%2Fbac.pa) | url | — | openphish, tweetfeed | 2026-11-12T01:03:17Z | 70 |
| [`hxxps://www[.]r[.]oblox[.]com[.]et/users/893593163/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.r.oblox.com.et%2Fusers%2F893593163%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxps://hkdiscord[.]antsoon[.]com/blog/iwd-2023-two-women-owned-servers`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhkdiscord.antsoon.com%2Fblog%2Fiwd-2023-two-women-owned-servers) | url | — | openphish | — | 70 |
| [`hxxps://hkdiscord[.]antsoon[.]com/blog/how-we-used-discord-to-build-a-dream-community-for-our-game-descenders`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhkdiscord.antsoon.com%2Fblog%2Fhow-we-used-discord-to-build-a-dream-community-for-our-game-descenders) | url | — | openphish | — | 70 |
| [`hxxps://hkdiscord[.]antsoon[.]com/blog/how-discord-celebrated-pride-month-2024`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhkdiscord.antsoon.com%2Fblog%2Fhow-discord-celebrated-pride-month-2024) | url | — | openphish | — | 70 |
| [`hxxps://hkdiscord[.]antsoon[.]com/ads/quests-success-stories`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhkdiscord.antsoon.com%2Fads%2Fquests-success-stories) | url | — | openphish | — | 70 |
| [`hxxps://hkdiscord[.]antsoon[.]com/company`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhkdiscord.antsoon.com%2Fcompany) | url | — | openphish | — | 70 |
| [`hxxps://hkdiscord[.]antsoon[.]com/terms`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhkdiscord.antsoon.com%2Fterms) | url | — | openphish | — | 70 |
| [`hxxps://hkdiscord[.]antsoon[.]com/category/how-to-discord`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhkdiscord.antsoon.com%2Fcategory%2Fhow-to-discord) | url | — | openphish | — | 70 |
| [`hxxps://hkdiscord[.]antsoon[.]com/press-releases/wicked-saints-turns-players-into-irl-superheroes-with-e-l-f-beauty-and-discord`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhkdiscord.antsoon.com%2Fpress-releases%2Fwicked-saints-turns-players-into-irl-superheroes-with-e-l-f-beauty-and-discord) | url | — | openphish | — | 70 |
| [`hxxps://hkdiscord[.]antsoon[.]com/press-releases/discord-zach-cregger-resident-evil-missions-quest-activation`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhkdiscord.antsoon.com%2Fpress-releases%2Fdiscord-zach-cregger-resident-evil-missions-quest-activation) | url | — | openphish | — | 70 |
| [`hxxps://hkdiscord[.]antsoon[.]com/press-releases/discord-launches-teen-by-default-settings-globally`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhkdiscord.antsoon.com%2Fpress-releases%2Fdiscord-launches-teen-by-default-settings-globally) | url | — | openphish | — | 70 |
| [`hxxps://hkdiscord[.]antsoon[.]com/download`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhkdiscord.antsoon.com%2Fdownload) | url | — | openphish | — | 70 |
| [`hxxps://hkdiscord[.]antsoon[.]com/safety-privacy`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhkdiscord.antsoon.com%2Fsafety-privacy) | url | — | openphish | — | 70 |
| [`hxxps://hkdiscord[.]antsoon[.]com/safety-transparency`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhkdiscord.antsoon.com%2Fsafety-transparency) | url | — | openphish | — | 70 |
| [`hxxp://sp29ct-zamvi-biz-felun-rakti[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsp29ct-zamvi-biz-felun-rakti.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://instanoreply11-sudo[.]github[.]io/instagramweb`](https://www.virustotal.com/gui/search/https%3A%2F%2Finstanoreply11-sudo.github.io%2Finstagramweb) | url | — | openphish | — | 70 |
| [`hxxps://steanmcomnnunituy[.]ru/id/765678242749728`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsteanmcomnnunituy.ru%2Fid%2F765678242749728) | url | — | openphish | — | 70 |
| [`hxxps://is[.]gd/steamcommunity765678242749728`](https://www.virustotal.com/gui/search/https%3A%2F%2Fis.gd%2Fsteamcommunity765678242749728) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]com[.]ml/users/237525484580/profile/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.com.ml%2Fusers%2F237525484580%2Fprofile%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]j115f[.]vip/downapp`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.j115f.vip%2Fdownapp) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]com[.]et/users/7295399954/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.com.et%2Fusers%2F7295399954%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxps://newbreedlifearts[.]org//[.]well-known/acme-challenge/content/korea[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fnewbreedlifearts.org%2F%2F.well-known%2Facme-challenge%2Fcontent%2Fkorea.html) | url | — | openphish | — | 70 |
| [`hxxps://tsxcfr[.]vtcgh[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ftsxcfr.vtcgh.com%2F) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
