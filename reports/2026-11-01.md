# Threat Intel Pulse — 2026-11-01

**Window:** last 7 days · **Generated:** 2026-11-01T06:27:33Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 85259 |
| New in window | 32195 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 614 | ok |
| tor | 8742 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 731 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 542 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 1002 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 32633 | 20786 |
| url | 27185 | 5535 |
| domain | 12451 | 5430 |
| sha256 | 8276 | 184 |
| ipv6 | 3418 | 192 |
| md5 | 683 | 68 |
| sha1 | 613 | 0 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 11943 |
| Exit nodes | 2270 |
| Other relays | 9673 |
| New in window | 1053 |

Sample (20 of 11943, source: Tor Project Onionoo):
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
| Vidar | 5857 | 4 | T1555, T1071.001, T1567 |
| Mirai | 1771 | 0 | T1498, T1071.001 |
| IClickFix | 1590 | 0 | — |
| Unknown Loader | 1426 | 0 | — |
| Unknown malware | 1420 | 0 | — |
| Cobalt Strike | 1313 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| AMOS | 946 | 0 | — |
| VShell | 854 | 0 | — |
| ClearFake | 500 | 0 | — |
| php.shin_webshell | 445 | 0 | — |
| PureRAT | 403 | 0 | — |
| Sliver | 365 | 0 | T1071.001, T1573, T1090, T1055 |
| Remcos | 311 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| Remus | 307 | 0 | — |
| AsyncRAT | 299 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| AdaptixC2 | 283 | 0 | — |
| MacSync | 256 | 0 | — |
| DanaBot | 190 | 0 | T1566.001, T1071.001, T1555, T1041 |
| SalatStealer | 150 | 0 | — |
| Formbook | 148 | 12 | T1566.001, T1056.001, T1555, T1071.001, T1567 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1071.001 | Web Protocols | command-and-control | 56033 |
| T1566 | Phishing | initial-access | 17201 |
| T1566.002 | Spearphishing Link | initial-access | 17201 |
| T1105 | Ingress Tool Transfer | command-and-control | 12920 |
| T1573 | Encrypted Channel | command-and-control | 8891 |
| T1555 | Credentials from Password Stores | credential-access | 8824 |
| T1567 | Exfiltration Over Web Service | exfiltration | 8630 |
| T1498 | Network Denial of Service | impact | 5158 |
| T1552.001 | Credentials In Files | credential-access | 4868 |
| T1204.002 | Malicious File | execution | 4281 |
| T1027 | Obfuscated Files or Information | defense-evasion | 4129 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1795 |
| T1090 | Proxy | command-and-control | 1713 |
| T1056.001 | Keylogging | collection, credential-access | 1656 |
| T1566.001 | Spearphishing Attachment | initial-access | 1371 |
| T1059.001 | PowerShell | execution | 1323 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 911 |
| T1113 | Screen Capture | collection | 871 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 285 |
| T1189 | Drive-by Compromise | initial-access | 161 |
| T1218 | System Binary Proxy Execution | defense-evasion | 161 |
| T1486 | Data Encrypted for Impact | impact | 38 |
| T1490 | Inhibit System Recovery | impact | 38 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 38 |
| T1059.005 | Visual Basic | execution | 36 |
| T1190 | Exploit Public-Facing Application | initial-access | 21 |
| T1021.001 | Remote Desktop Protocol | lateral-movement | 6 |
| T1003 | OS Credential Dumping | credential-access | 4 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://zoffry[.]qpon/Adb/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fzoffry.qpon%2FAdb%2F) | url | — | openphish, tweetfeed | 2026-10-29T13:22:48Z | 70 |
| [`hxxps://allegrolokalnie[.]aukcja865637302[.]cfd/oferta/1984-mz-etz-250/80344`](https://www.virustotal.com/gui/search/https%3A%2F%2Fallegrolokalnie.aukcja865637302.cfd%2Foferta%2F1984-mz-etz-250%2F80344) | url | — | openphish, tweetfeed | 2026-10-27T05:18:21Z | 70 |
| [`hxxps://ldgr-lives-app[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fldgr-lives-app.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://nav-ledgr-eng[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fnav-ledgr-eng.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://5985n9mff-funfn994784ecd853-8478h84[.]netlify[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2F5985n9mff-funfn994784ecd853-8478h84.netlify.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://ip3dev[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fip3dev.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://netflix-clone-seven-liard[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fnetflix-clone-seven-liard.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://nutradiabs-whatsapp[.]orderyuk[.]info/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fnutradiabs-whatsapp.orderyuk.info%2F) | url | — | openphish | — | 70 |
| [`hxxp://v2238[.]ig-verifica[.]freemyip[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fv2238.ig-verifica.freemyip.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://community-policy-info[.]vercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fcommunity-policy-info.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://instagram-groupe-invite[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Finstagram-groupe-invite.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]instagram-clone-master-three[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.instagram-clone-master-three.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://verifiedbadgehub[.]vercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fverifiedbadgehub.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://roblox[.]ss/users/1051870473/profile`](https://www.virustotal.com/gui/search/http%3A%2F%2Froblox.ss%2Fusers%2F1051870473%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxps://mydpd[.]yjbow[.]top/track-ch/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmydpd.yjbow.top%2Ftrack-ch%2F) | url | — | openphish | — | 70 |
| [`hxxps://upcmail-hispeed-ch[.]jimdofree[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fupcmail-hispeed-ch.jimdofree.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]upc-websrv-updt[.]weebly[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.upc-websrv-updt.weebly.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]sunrise0041[.]flazio[.]online/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.sunrise0041.flazio.online%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]com[.]ml/users/187621307399/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.com.ml%2Fusers%2F187621307399%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxps://my[.]gov[.]addllr[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmy.gov.addllr.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://br[.]ngtwr[.]shop/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fbr.ngtwr.shop%2F) | url | — | openphish | — | 70 |
| [`hxxps://osmelhoresprecos[.]com/produto/8444634`](https://www.virustotal.com/gui/search/https%3A%2F%2Fosmelhoresprecos.com%2Fproduto%2F8444634) | url | — | openphish | — | 70 |
| [`hxxps://1url[.]at/www/robloxusers-951099594-profile`](https://www.virustotal.com/gui/search/https%3A%2F%2F1url.at%2Fwww%2Frobloxusers-951099594-profile) | url | — | openphish | — | 70 |
| [`hxxp://vakeusplay[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fvakeusplay.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://1xlite-78173[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2F1xlite-78173.com%2F) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
