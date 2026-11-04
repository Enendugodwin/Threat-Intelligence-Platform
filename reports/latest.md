# Threat Intel Pulse — 2026-11-04

**Window:** last 7 days · **Generated:** 2026-11-04T19:54:59Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 84308 |
| New in window | 16033 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 614 | ok |
| tor | 8793 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 758 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 519 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 1111 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 36544 | 9944 |
| url | 24531 | 4138 |
| domain | 11860 | 1288 |
| sha256 | 6722 | 188 |
| ipv6 | 3700 | 448 |
| md5 | 514 | 27 |
| sha1 | 437 | 0 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 12924 |
| Exit nodes | 2416 |
| Other relays | 10508 |
| New in window | 1971 |

Sample (20 of 12924, source: Tor Project Onionoo):
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
| Vidar | 4388 | 0 | T1555, T1071.001, T1567 |
| IClickFix | 1516 | 0 | — |
| Mirai | 1380 | 0 | T1498, T1071.001 |
| Cobalt Strike | 1252 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| Unknown malware | 1249 | 0 | — |
| Unknown Loader | 985 | 0 | — |
| AMOS | 849 | 0 | — |
| VShell | 666 | 0 | — |
| PureRAT | 378 | 0 | — |
| ClearFake | 336 | 0 | — |
| php.shin_webshell | 297 | 0 | — |
| Remus | 287 | 0 | — |
| Remcos | 266 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| AdaptixC2 | 262 | 0 | — |
| MacSync | 255 | 0 | — |
| AsyncRAT | 254 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| DanaBot | 185 | 0 | T1566.001, T1071.001, T1555, T1041 |
| ClickFix | 166 | 72 | — |
| SalatStealer | 133 | 0 | — |
| Coruna | 132 | 0 | — |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1566 | Phishing | initial-access | 17586 |
| T1566.002 | Spearphishing Link | initial-access | 17586 |
| T1071.001 | Web Protocols | command-and-control | 57157 |
| T1105 | Ingress Tool Transfer | command-and-control | 10607 |
| T1573 | Encrypted Channel | command-and-control | 8197 |
| T1555 | Credentials from Password Stores | credential-access | 6922 |
| T1567 | Exfiltration Over Web Service | exfiltration | 6733 |
| T1498 | Network Denial of Service | impact | 4350 |
| T1552.001 | Credentials In Files | credential-access | 3610 |
| T1204.002 | Malicious File | execution | 3321 |
| T1027 | Obfuscated Files or Information | defense-evasion | 3169 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1476 |
| T1056.001 | Keylogging | collection, credential-access | 1438 |
| T1090 | Proxy | command-and-control | 1411 |
| T1059.001 | PowerShell | execution | 1262 |
| T1566.001 | Spearphishing Attachment | initial-access | 1173 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 768 |
| T1113 | Screen Capture | collection | 728 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 255 |
| T1189 | Drive-by Compromise | initial-access | 160 |
| T1218 | System Binary Proxy Execution | defense-evasion | 160 |
| T1486 | Data Encrypted for Impact | impact | 44 |
| T1490 | Inhibit System Recovery | impact | 44 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 44 |
| T1059.005 | Visual Basic | execution | 33 |
| T1190 | Exploit Public-Facing Application | initial-access | 21 |
| T1021.001 | Remote Desktop Protocol | lateral-movement | 3 |
| T1003 | OS Credential Dumping | credential-access | 1 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://vemtasbobinaj[.]com/login[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fvemtasbobinaj.com%2Flogin.html) | url | — | openphish, tweetfeed | 2026-11-02T19:27:35Z | 70 |
| [`hxxps://auditormadrid[.]es/wp-content/mu-plugins/iklqzct/iuo/alibaba/?naps`](https://www.virustotal.com/gui/search/https%3A%2F%2Fauditormadrid.es%2Fwp-content%2Fmu-plugins%2Fiklqzct%2Fiuo%2Falibaba%2F%3Fnaps) | url | — | openphish, tweetfeed | 2026-11-01T13:14:43Z | 70 |
| [`hxxps://zoffry[.]qpon/Adb/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fzoffry.qpon%2FAdb%2F) | url | — | openphish, tweetfeed | 2026-10-29T13:22:48Z | 70 |
| [`hxxps://signin[.]broker/E[.]-hMc2FZ9GQs9hA`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsignin.broker%2FE.-hMc2FZ9GQs9hA) | url | — | openphish | — | 70 |
| [`hxxps://rbcode[.]net/v/0b972db75a826160df8877b137bc6039`](https://www.virustotal.com/gui/search/https%3A%2F%2Frbcode.net%2Fv%2F0b972db75a826160df8877b137bc6039) | url | — | openphish | — | 70 |
| [`hxxps://my-aol-account[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmy-aol-account.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]my-aol-account[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.my-aol-account.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://constant-standard-cris[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fconstant-standard-cris.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://roblox[.]ss/communities/6464021279/CLOTHING`](https://www.virustotal.com/gui/search/http%3A%2F%2Froblox.ss%2Fcommunities%2F6464021279%2FCLOTHING) | url | — | openphish | — | 70 |
| [`hxxps://mcodashop[.]topup-diamonds[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmcodashop.topup-diamonds.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]constant-standard-cris[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.constant-standard-cris.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]ly/users/1458147996/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.ly%2Fusers%2F1458147996%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxps://portal[.]cod-indigenouslocalknowledge[.]org/adoc/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fportal.cod-indigenouslocalknowledge.org%2Fadoc%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]systemtupdate[.]vercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.systemtupdate.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://yhgwyqom[.]elementor[.]cloud/es/SPAIN/es/arg/Aa/A/ES/argentina/ar/ES9D303ESS/ESS4Z3499SES/82CFGU2554/index[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fyhgwyqom.elementor.cloud%2Fes%2FSPAIN%2Fes%2Farg%2FAa%2FA%2FES%2Fargentina%2Far%2FES9D303ESS%2FESS4Z3499SES%2F82CFGU2554%2Findex.html) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]com[.]ss/users/2922440158/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.com.ss%2Fusers%2F2922440158%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxp://www[.]pnfp[.]lol/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.pnfp.lol%2F) | url | — | openphish | — | 70 |
| [`hxxps://accountprotectonmicrsoftclo[.]silverveilvalley[.]de/JiOex?e=neletsys@090019cbe7396c95280cc516762413f31f2e[.]org`](https://www.virustotal.com/gui/search/https%3A%2F%2Faccountprotectonmicrsoftclo.silverveilvalley.de%2FJiOex%3Fe%3Dneletsys%40090019cbe7396c95280cc516762413f31f2e.org) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]com[.]kz/users/600806000/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.com.kz%2Fusers%2F600806000%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxps://hameem[.]net/adobe[.]live/index[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhameem.net%2Fadobe.live%2Findex.html) | url | — | openphish | — | 70 |
| [`hxxps://sgplay[.]speciallshop[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsgplay.speciallshop.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://updatepasswrd-23l7[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fupdatepasswrd-23l7.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://antonovcarov97-hub[.]github[.]io/WhatsApp`](https://www.virustotal.com/gui/search/https%3A%2F%2Fantonovcarov97-hub.github.io%2FWhatsApp) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]com[.]ss/games/920587237/Adopt-Me?privateServerLinkCode=74110515050800712324209952985974`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.com.ss%2Fgames%2F920587237%2FAdopt-Me%3FprivateServerLinkCode%3D74110515050800712324209952985974) | url | — | openphish | — | 70 |
| [`hxxps://5qi-h5p-cessk-wn5y-rly7h[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2F5qi-h5p-cessk-wn5y-rly7h.pages.dev%2F) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
