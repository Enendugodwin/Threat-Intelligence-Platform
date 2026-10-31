# Threat Intel Pulse — 2026-10-31

**Window:** last 7 days · **Generated:** 2026-10-31T12:50:16Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 87877 |
| New in window | 31498 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 614 | ok |
| tor | 8700 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 372 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 542 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 1034 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 31993 | 20008 |
| url | 28409 | 5715 |
| domain | 13770 | 5318 |
| sha256 | 8939 | 180 |
| ipv6 | 3405 | 211 |
| md5 | 715 | 66 |
| sha1 | 646 | 0 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 11913 |
| Exit nodes | 2265 |
| Other relays | 9648 |
| New in window | 1008 |

Sample (20 of 11913, source: Tor Project Onionoo):
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
| Vidar | 5936 | 4 | T1555, T1071.001, T1567 |
| Mirai | 2012 | 0 | T1498, T1071.001 |
| IClickFix | 1975 | 0 | — |
| Unknown Loader | 1827 | 0 | — |
| Unknown malware | 1584 | 0 | — |
| Cobalt Strike | 1327 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| AMOS | 967 | 0 | — |
| ClearFake | 950 | 0 | — |
| VShell | 870 | 0 | — |
| php.shin_webshell | 504 | 0 | — |
| PureRAT | 410 | 0 | — |
| Sliver | 375 | 0 | T1071.001, T1573, T1090, T1055 |
| Remus | 319 | 0 | — |
| Remcos | 315 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| AsyncRAT | 305 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| AdaptixC2 | 286 | 0 | — |
| MacSync | 256 | 0 | — |
| Unknown Stealer | 225 | 0 | — |
| DanaBot | 190 | 0 | T1566.001, T1071.001, T1555, T1041 |
| Formbook | 166 | 11 | T1566.001, T1056.001, T1555, T1071.001, T1567 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1071.001 | Web Protocols | command-and-control | 57378 |
| T1566 | Phishing | initial-access | 17139 |
| T1566.002 | Spearphishing Link | initial-access | 17139 |
| T1105 | Ingress Tool Transfer | command-and-control | 13940 |
| T1555 | Credentials from Password Stores | credential-access | 9362 |
| T1567 | Exfiltration Over Web Service | exfiltration | 9168 |
| T1573 | Encrypted Channel | command-and-control | 8659 |
| T1498 | Network Denial of Service | impact | 5508 |
| T1552.001 | Credentials In Files | credential-access | 5305 |
| T1204.002 | Malicious File | execution | 4324 |
| T1027 | Obfuscated Files or Information | defense-evasion | 4172 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1827 |
| T1090 | Proxy | command-and-control | 1737 |
| T1056.001 | Keylogging | collection, credential-access | 1707 |
| T1566.001 | Spearphishing Attachment | initial-access | 1413 |
| T1059.001 | PowerShell | execution | 1337 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 928 |
| T1113 | Screen Capture | collection | 887 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 293 |
| T1189 | Drive-by Compromise | initial-access | 162 |
| T1218 | System Binary Proxy Execution | defense-evasion | 162 |
| T1059.005 | Visual Basic | execution | 36 |
| T1486 | Data Encrypted for Impact | impact | 36 |
| T1490 | Inhibit System Recovery | impact | 36 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 36 |
| T1190 | Exploit Public-Facing Application | initial-access | 21 |
| T1021.001 | Remote Desktop Protocol | lateral-movement | 6 |
| T1003 | OS Credential Dumping | credential-access | 4 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://zoffry[.]qpon/Adb/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fzoffry.qpon%2FAdb%2F) | url | — | openphish, tweetfeed | 2026-10-29T13:22:48Z | 70 |
| [`hxxps://allegrolokalnie[.]aukcja865637302[.]cfd/oferta/1984-mz-etz-250/80344`](https://www.virustotal.com/gui/search/https%3A%2F%2Fallegrolokalnie.aukcja865637302.cfd%2Foferta%2F1984-mz-etz-250%2F80344) | url | — | openphish, tweetfeed | 2026-10-27T05:18:21Z | 70 |
| [`hxxp://www[.]indesx-mauve[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.indesx-mauve.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://bellsouth-att-sign-in-99dd87[.]webflow[.]io/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fbellsouth-att-sign-in-99dd87.webflow.io%2F) | url | — | openphish | — | 70 |
| [`hxxps://instagram[.]82[.]165[.]110[.]7[.]backname[.]io/accounts/login/`](https://www.virustotal.com/gui/search/https%3A%2F%2Finstagram.82.165.110.7.backname.io%2Faccounts%2Flogin%2F) | url | — | openphish | — | 70 |
| [`hxxps://lnstagrarn-reel-paoa2oajo[.]vercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Flnstagrarn-reel-paoa2oajo.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://instagram[.]82[.]165[.]110[.]7[.]backname[.]io/`](https://www.virustotal.com/gui/search/https%3A%2F%2Finstagram.82.165.110.7.backname.io%2F) | url | — | openphish | — | 70 |
| [`hxxp://sp26ct10-zanvako-biz-rumeli[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsp26ct10-zanvako-biz-rumeli.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://caphaibuvoice[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fcaphaibuvoice.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://tevxorin-lak294816573[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Ftevxorin-lak294816573.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://giveshopee889[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fgiveshopee889.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://bluecheckservices-gold[.]vercel[.]app/privacy-centers[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbluecheckservices-gold.vercel.app%2Fprivacy-centers.html) | url | — | openphish | — | 70 |
| [`hxxps://azogue[.]org/index1[.]html?eta=administracion@naturinda[.]com`](https://www.virustotal.com/gui/search/https%3A%2F%2Fazogue.org%2Findex1.html%3Feta%3Dadministracion%40naturinda.com) | url | — | openphish | — | 70 |
| [`hxxps://tokanlm-cdn12-hk12[.]autos/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ftokanlm-cdn12-hk12.autos%2F) | url | — | openphish | — | 70 |
| [`hxxps://s4w[.]in/https-roblox-com-users-4468694066profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fs4w.in%2Fhttps-roblox-com-users-4468694066profile) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]com[.]et/users/1382998579/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.com.et%2Fusers%2F1382998579%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxps://caphaibuvoice[.]vercel[.]app/index1[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fcaphaibuvoice.vercel.app%2Findex1.html) | url | — | openphish | — | 70 |
| [`hxxps://d33wubrfki0l68[.]cloudfront[.]net/a24ce9fe-3a25-440e-923c-70c96b668dc8/dhl123[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fd33wubrfki0l68.cloudfront.net%2Fa24ce9fe-3a25-440e-923c-70c96b668dc8%2Fdhl123.html) | url | — | openphish | — | 70 |
| [`hxxp://metamask-docs-keec0mi8n-consensys-ddffed67[.]vercel[.]app/developer-tools/dashboard/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fmetamask-docs-keec0mi8n-consensys-ddffed67.vercel.app%2Fdeveloper-tools%2Fdashboard%2F) | url | — | openphish | — | 70 |
| [`hxxp://metamask-docs-keec0mi8n-consensys-ddffed67[.]vercel[.]app/smart-accounts-kit/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fmetamask-docs-keec0mi8n-consensys-ddffed67.vercel.app%2Fsmart-accounts-kit%2F) | url | — | openphish | — | 70 |
| [`hxxp://metamask-docs-keec0mi8n-consensys-ddffed67[.]vercel[.]app/embedded-wallets/sdk/node`](https://www.virustotal.com/gui/search/http%3A%2F%2Fmetamask-docs-keec0mi8n-consensys-ddffed67.vercel.app%2Fembedded-wallets%2Fsdk%2Fnode) | url | — | openphish | — | 70 |
| [`hxxp://metamask-docs-keec0mi8n-consensys-ddffed67[.]vercel[.]app/metamask-connect/evm`](https://www.virustotal.com/gui/search/http%3A%2F%2Fmetamask-docs-keec0mi8n-consensys-ddffed67.vercel.app%2Fmetamask-connect%2Fevm) | url | — | openphish | — | 70 |
| [`hxxp://metamask-docs-keec0mi8n-consensys-ddffed67[.]vercel[.]app/metamask-connect/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fmetamask-docs-keec0mi8n-consensys-ddffed67.vercel.app%2Fmetamask-connect%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]com[.]am/users/173714336421/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.com.am%2Fusers%2F173714336421%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxps://shortme[.]id/98fgk`](https://www.virustotal.com/gui/search/https%3A%2F%2Fshortme.id%2F98fgk) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
