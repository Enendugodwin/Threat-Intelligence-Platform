# Threat Intel Pulse — 2026-11-06

**Window:** last 7 days · **Generated:** 2026-11-06T19:34:26Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 81570 |
| New in window | 15789 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 27 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 614 | ok |
| tor | 10240 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 993 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 511 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 1805 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 38492 | 9566 |
| url | 21958 | 4235 |
| domain | 11424 | 1293 |
| sha256 | 5382 | 201 |
| ipv6 | 3731 | 466 |
| md5 | 339 | 28 |
| sha1 | 244 | 0 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 13042 |
| Exit nodes | 2427 |
| Other relays | 10615 |
| New in window | 2032 |

Sample (20 of 13042, source: Tor Project Onionoo):
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
| Vidar | 2371 | 0 | T1555, T1071.001, T1567 |
| IClickFix | 1332 | 0 | — |
| Mirai | 1255 | 0 | T1498, T1071.001 |
| Cobalt Strike | 1230 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| Unknown malware | 1170 | 0 | — |
| AMOS | 745 | 0 | — |
| Unknown Loader | 742 | 0 | — |
| VShell | 410 | 0 | — |
| PureRAT | 364 | 0 | — |
| ClearFake | 261 | 0 | — |
| MacSync | 253 | 0 | — |
| AdaptixC2 | 247 | 0 | — |
| Remus | 225 | 0 | — |
| Remcos | 210 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| php.shin_webshell | 209 | 0 | — |
| AsyncRAT | 203 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| DanaBot | 181 | 0 | T1566.001, T1071.001, T1555, T1041 |
| ClickFix | 166 | 72 | — |
| Sliver | 102 | 2 | T1071.001, T1573, T1090, T1055 |
| Evilginx | 95 | 2 | — |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1566 | Phishing | initial-access | 18213 |
| T1566.002 | Spearphishing Link | initial-access | 18213 |
| T1071.001 | Web Protocols | command-and-control | 55909 |
| T1105 | Ingress Tool Transfer | command-and-control | 8320 |
| T1573 | Encrypted Channel | command-and-control | 6924 |
| T1555 | Credentials from Password Stores | credential-access | 4582 |
| T1567 | Exfiltration Over Web Service | exfiltration | 4397 |
| T1498 | Network Denial of Service | impact | 4073 |
| T1552.001 | Credentials In Files | credential-access | 1991 |
| T1204.002 | Malicious File | execution | 1688 |
| T1027 | Obfuscated Files or Information | defense-evasion | 1686 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1421 |
| T1090 | Proxy | command-and-control | 1363 |
| T1059.001 | PowerShell | execution | 1240 |
| T1056.001 | Keylogging | collection, credential-access | 1160 |
| T1566.001 | Spearphishing Attachment | initial-access | 902 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 599 |
| T1113 | Screen Capture | collection | 561 |
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
| [`hxxp://jkstr12wsed-htpmqskr-8m4h7g-jks91c378[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fjkstr12wsed-htpmqskr-8m4h7g-jks91c378.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://skrab-zflon-vstyk-3b82fc-yjbw-vlasco[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fskrab-zflon-vstyk-3b82fc-yjbw-vlasco.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://admin-suport-update-com[.]weebly[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fadmin-suport-update-com.weebly.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]admin-suport-update-com[.]weebly[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.admin-suport-update-com.weebly.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://client[.]tkchost[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fclient.tkchost.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://umairali69[.]github[.]io/FB_page/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fumairali69.github.io%2FFB_page%2F) | url | — | openphish | — | 70 |
| [`hxxps://xdigitalxflnltyappsute-web[.]vercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fxdigitalxflnltyappsute-web.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://shopeeakhirtahun172[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fshopeeakhirtahun172.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://pomarosahotel[.]com/Adobe_Installer[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fpomarosahotel.com%2FAdobe_Installer.html) | url | — | openphish | — | 70 |
| [`hxxps://midas-shops[.]ww-event[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmidas-shops.ww-event.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://0authac9-common-authyclientemailprotection-ac9a8c0[.]live-document-m365092[.]workers[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2F0authac9-common-authyclientemailprotection-ac9a8c0.live-document-m365092.workers.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://secureprofiles2026-indol[.]vercel[.]app/required[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsecureprofiles2026-indol.vercel.app%2Frequired.html) | url | — | openphish | — | 70 |
| [`hxxps://basar-saint-ave[.]fr/ar//`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbasar-saint-ave.fr%2Far%2F%2F) | url | — | openphish | — | 70 |
| [`hxxps://isupport-locationet[.]com/1GI5S2`](https://www.virustotal.com/gui/search/https%3A%2F%2Fisupport-locationet.com%2F1GI5S2) | url | — | openphish | — | 70 |
| [`hxxps://datum-ingenier-a[.]p-m1p9u16n[.]workers[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fdatum-ingenier-a.p-m1p9u16n.workers.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://s3[.]us-east-1[.]amazonaws[.]com/violet[.]omega[.]logic/index[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fs3.us-east-1.amazonaws.com%2Fviolet.omega.logic%2Findex.html) | url | — | openphish | — | 70 |
| [`hxxp://l[.]shortlink[.]es/l/1cdbce272119e87371798f8ceb20a0c3cf059b97/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fl.shortlink.es%2Fl%2F1cdbce272119e87371798f8ceb20a0c3cf059b97%2F) | url | — | openphish | — | 70 |
| [`hxxps://8u2m4c-qw644c24y-1k9z8p2m4s-qwxk[.]pages[.]dev/send_appeal_request`](https://www.virustotal.com/gui/search/https%3A%2F%2F8u2m4c-qw644c24y-1k9z8p2m4s-qwxk.pages.dev%2Fsend_appeal_request) | url | — | openphish | — | 70 |
| [`hxxps://s4w[.]in/www-roblox-com-Anime-AdventuresprivateServerLinkCode=4460350768291503441077018644550`](https://www.virustotal.com/gui/search/https%3A%2F%2Fs4w.in%2Fwww-roblox-com-Anime-AdventuresprivateServerLinkCode%3D4460350768291503441077018644550) | url | — | openphish | — | 70 |
| [`hxxp://s[.]team-zm[.]com/lp/kma-mhc/foofvybf/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fs.team-zm.com%2Flp%2Fkma-mhc%2Ffoofvybf%2F) | url | — | openphish | — | 70 |
| [`hxxp://s[.]team-d[.]my/p/raiv-hpce/mocqktib/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fs.team-d.my%2Fp%2Fraiv-hpce%2Fmocqktib%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]quesoschila[.]com[.]mx/awg-aero/us[.]html`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.quesoschila.com.mx%2Fawg-aero%2Fus.html) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
