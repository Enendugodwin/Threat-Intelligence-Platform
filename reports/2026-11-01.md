# Threat Intel Pulse — 2026-11-01

**Window:** last 7 days · **Generated:** 2026-11-01T22:13:27Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 85369 |
| New in window | 32830 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 614 | ok |
| tor | 8754 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 731 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 542 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 1056 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 33096 | 21229 |
| url | 27080 | 5636 |
| domain | 12491 | 5515 |
| sha256 | 8107 | 189 |
| ipv6 | 3431 | 193 |
| md5 | 617 | 68 |
| sha1 | 547 | 0 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 11990 |
| Exit nodes | 2286 |
| Other relays | 9704 |
| New in window | 1048 |

Sample (20 of 11990, source: Tor Project Onionoo):
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
- `102[.]211[.]56[.]20`
- `102[.]211[.]56[.]25`

Full list: `dist/tor/tor_nodes.txt` (in the `threat-intel-output` workflow artifact).
## Top malware families

| Family | Indicators | New | ATT&CK (heuristic) |
| --- | --- | --- | --- |
| Vidar | 5825 | 4 | T1555, T1071.001, T1567 |
| Mirai | 1750 | 0 | T1498, T1071.001 |
| IClickFix | 1581 | 0 | — |
| Unknown Loader | 1424 | 0 | — |
| Unknown malware | 1412 | 0 | — |
| Cobalt Strike | 1313 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| AMOS | 942 | 0 | — |
| VShell | 836 | 0 | — |
| ClearFake | 489 | 0 | — |
| php.shin_webshell | 431 | 0 | — |
| PureRAT | 399 | 0 | — |
| Sliver | 365 | 0 | T1071.001, T1573, T1090, T1055 |
| Remcos | 311 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| Remus | 306 | 0 | — |
| AsyncRAT | 290 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| AdaptixC2 | 274 | 0 | — |
| MacSync | 256 | 0 | — |
| DanaBot | 190 | 0 | T1566.001, T1071.001, T1555, T1041 |
| SalatStealer | 150 | 0 | — |
| Formbook | 139 | 12 | T1566.001, T1056.001, T1555, T1071.001, T1567 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1071.001 | Web Protocols | command-and-control | 56402 |
| T1566 | Phishing | initial-access | 17279 |
| T1566.002 | Spearphishing Link | initial-access | 17279 |
| T1105 | Ingress Tool Transfer | command-and-control | 12811 |
| T1573 | Encrypted Channel | command-and-control | 8872 |
| T1555 | Credentials from Password Stores | credential-access | 8738 |
| T1567 | Exfiltration Over Web Service | exfiltration | 8544 |
| T1498 | Network Denial of Service | impact | 5134 |
| T1552.001 | Credentials In Files | credential-access | 4818 |
| T1204.002 | Malicious File | execution | 4261 |
| T1027 | Obfuscated Files or Information | defense-evasion | 4109 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1792 |
| T1090 | Proxy | command-and-control | 1713 |
| T1056.001 | Keylogging | collection, credential-access | 1628 |
| T1566.001 | Spearphishing Attachment | initial-access | 1345 |
| T1059.001 | PowerShell | execution | 1323 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 897 |
| T1113 | Screen Capture | collection | 857 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 282 |
| T1189 | Drive-by Compromise | initial-access | 161 |
| T1218 | System Binary Proxy Execution | defense-evasion | 161 |
| T1486 | Data Encrypted for Impact | impact | 38 |
| T1490 | Inhibit System Recovery | impact | 38 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 38 |
| T1059.005 | Visual Basic | execution | 33 |
| T1190 | Exploit Public-Facing Application | initial-access | 21 |
| T1021.001 | Remote Desktop Protocol | lateral-movement | 6 |
| T1003 | OS Credential Dumping | credential-access | 4 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://auditormadrid[.]es/wp-content/mu-plugins/iklqzct/iuo/alibaba/?naps`](https://www.virustotal.com/gui/search/https%3A%2F%2Fauditormadrid.es%2Fwp-content%2Fmu-plugins%2Fiklqzct%2Fiuo%2Falibaba%2F%3Fnaps) | url | — | openphish, tweetfeed | 2026-11-01T13:14:43Z | 70 |
| [`hxxps://zoffry[.]qpon/Adb/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fzoffry.qpon%2FAdb%2F) | url | — | openphish, tweetfeed | 2026-10-29T13:22:48Z | 70 |
| [`hxxps://allegrolokalnie[.]aukcja865637302[.]cfd/oferta/1984-mz-etz-250/80344`](https://www.virustotal.com/gui/search/https%3A%2F%2Fallegrolokalnie.aukcja865637302.cfd%2Foferta%2F1984-mz-etz-250%2F80344) | url | — | openphish, tweetfeed | 2026-10-27T05:18:21Z | 70 |
| [`hxxps://s4w[.]in/jZlxQ`](https://www.virustotal.com/gui/search/https%3A%2F%2Fs4w.in%2FjZlxQ) | url | — | openphish | — | 70 |
| [`hxxp://xfinityhelplogin[.]weebly[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fxfinityhelplogin.weebly.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]rw/games/88738945340571/Would-You-Rather-Countryball-Tower?privateServerLinkCode=11040290185766545005746312904812&game_id=88738945340571&game_name=Would-You-Rather-Countryball-Tower`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.rw%2Fgames%2F88738945340571%2FWould-You-Rather-Countryball-Tower%3FprivateServerLinkCode%3D11040290185766545005746312904812%26game_id%3D88738945340571%26game_name%3DWould-You-Rather-Countryball-Tower) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]rw/games/84107034759866/UPD-Countryball-Simulator?privateServerLinkCode=11040290185766545005746312904812&game_id=84107034759866&game_name=UPD-Countryball-Simulator`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.rw%2Fgames%2F84107034759866%2FUPD-Countryball-Simulator%3FprivateServerLinkCode%3D11040290185766545005746312904812%26game_id%3D84107034759866%26game_name%3DUPD-Countryball-Simulator) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]rw/games/9391468976/HIRED-KILLER-Jujutsu-Shenanigans?privateServerLinkCode=11040290185766545005746312904812&game_id=9391468976&game_name=HIRED-KILLER-Jujutsu-Shenanigans`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.rw%2Fgames%2F9391468976%2FHIRED-KILLER-Jujutsu-Shenanigans%3FprivateServerLinkCode%3D11040290185766545005746312904812%26game_id%3D9391468976%26game_name%3DHIRED-KILLER-Jujutsu-Shenanigans) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]rw/games/107778070777162/Steal-An-Egg?privateServerLinkCode=11040290185766545005746312904812&game_id=107778070777162&game_name=Steal-An-Egg`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.rw%2Fgames%2F107778070777162%2FSteal-An-Egg%3FprivateServerLinkCode%3D11040290185766545005746312904812%26game_id%3D107778070777162%26game_name%3DSteal-An-Egg) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]rw/games/15269951959/SHINJI-Legends-Battlegrounds?privateServerLinkCode=11040290185766545005746312904812&game_id=15269951959&game_name=SHINJI-Legends-Battlegrounds`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.rw%2Fgames%2F15269951959%2FSHINJI-Legends-Battlegrounds%3FprivateServerLinkCode%3D11040290185766545005746312904812%26game_id%3D15269951959%26game_name%3DSHINJI-Legends-Battlegrounds) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]rw/games/13076380114/Heroes-Battlegrounds?privateServerLinkCode=11040290185766545005746312904812&game_id=13076380114&game_name=Heroes-Battlegrounds`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.rw%2Fgames%2F13076380114%2FHeroes-Battlegrounds%3FprivateServerLinkCode%3D11040290185766545005746312904812%26game_id%3D13076380114%26game_name%3DHeroes-Battlegrounds) | url | — | openphish | — | 70 |
| [`hxxp://conncast[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fconncast.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://494145-coinbase[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2F494145-coinbase.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://cont17ct-davuri-biz-kelom-ravta[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fcont17ct-davuri-biz-kelom-ravta.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]dashboard[.]adobeexperience[.]com[.]br/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.dashboard.adobeexperience.com.br%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]instagarm[.]vercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.instagarm.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]rw/games/77182599101794/-4nn1s-place?privateServerLinkCode=29443536713818717471407919220012`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.rw%2Fgames%2F77182599101794%2F-4nn1s-place%3FprivateServerLinkCode%3D29443536713818717471407919220012) | url | — | openphish | — | 70 |
| [`hxxps://lsdryfg-xgbjsrdtgh[.]pages[.]dev/index[.]htm`](https://www.virustotal.com/gui/search/https%3A%2F%2Flsdryfg-xgbjsrdtgh.pages.dev%2Findex.htm) | url | — | openphish | — | 70 |
| [`hxxps://ppss123[.]shop/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fppss123.shop%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]newhorizonsrehab[.]ke/arm/amnd/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.newhorizonsrehab.ke%2Farm%2Famnd%2F) | url | — | openphish | — | 70 |
| [`hxxps://suite[.]zapier[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsuite.zapier.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://netflix-ui-clone-vikas[.]vercel[.]app/login`](https://www.virustotal.com/gui/search/https%3A%2F%2Fnetflix-ui-clone-vikas.vercel.app%2Flogin) | url | — | openphish | — | 70 |
| [`hxxps://elettrotecnica-branchi-s-r-l-s[.]p-s9bbs8qw[.]workers[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Felettrotecnica-branchi-s-r-l-s.p-s9bbs8qw.workers.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://isecion822-cyber[.]github[.]io/prueba-/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fisecion822-cyber.github.io%2Fprueba-%2F) | url | — | openphish | — | 70 |
| [`hxxps://isecion822-cyber[.]github[.]io/facebook-/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fisecion822-cyber.github.io%2Ffacebook-%2F) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
