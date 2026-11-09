# Threat Intel Pulse — 2026-11-09

**Window:** last 7 days · **Generated:** 2026-11-09T22:32:37Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 77570 |
| New in window | 14951 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 27 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 614 | ok |
| tor | 10222 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 1921 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 506 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 1841 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 41520 | 8956 |
| url | 18559 | 4054 |
| domain | 10412 | 1487 |
| ipv6 | 3762 | 235 |
| sha256 | 2997 | 192 |
| md5 | 210 | 27 |
| sha1 | 110 | 0 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 13154 |
| Exit nodes | 2450 |
| Other relays | 10704 |
| New in window | 1163 |

Sample (20 of 13154, source: Tor Project Onionoo):
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
| Cobalt Strike | 1188 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| Vidar | 885 | 0 | T1555, T1071.001, T1567 |
| IClickFix | 696 | 0 | — |
| Unknown malware | 634 | 0 | — |
| Mirai | 456 | 0 | T1498, T1071.001 |
| AMOS | 427 | 0 | — |
| PureRAT | 335 | 0 | — |
| Unknown Loader | 328 | 0 | — |
| MacSync | 251 | 0 | — |
| AdaptixC2 | 238 | 0 | — |
| ClickFix | 212 | 112 | — |
| Remus | 206 | 0 | — |
| DanaBot | 178 | 0 | T1566.001, T1071.001, T1555, T1041 |
| AsyncRAT | 173 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| Remcos | 155 | 3 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| VShell | 116 | 0 | — |
| cryptoscam | 104 | 60 | — |
| ClearFake | 98 | 0 | — |
| Evilginx | 93 | 0 | — |
| php.shin_webshell | 79 | 0 | — |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1566 | Phishing | initial-access | 18518 |
| T1566.002 | Spearphishing Link | initial-access | 18518 |
| T1071.001 | Web Protocols | command-and-control | 54004 |
| T1573 | Encrypted Channel | command-and-control | 6835 |
| T1105 | Ingress Tool Transfer | command-and-control | 6146 |
| T1498 | Network Denial of Service | impact | 2932 |
| T1555 | Credentials from Password Stores | credential-access | 2059 |
| T1567 | Exfiltration Over Web Service | exfiltration | 1877 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1287 |
| T1090 | Proxy | command-and-control | 1258 |
| T1059.001 | PowerShell | execution | 1198 |
| T1552.001 | Credentials In Files | credential-access | 1038 |
| T1056.001 | Keylogging | collection, credential-access | 969 |
| T1566.001 | Spearphishing Attachment | initial-access | 726 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 468 |
| T1113 | Screen Capture | collection | 440 |
| T1204.002 | Malicious File | execution | 407 |
| T1027 | Obfuscated Files or Information | defense-evasion | 406 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 199 |
| T1486 | Data Encrypted for Impact | impact | 43 |
| T1490 | Inhibit System Recovery | impact | 43 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 43 |
| T1059.005 | Visual Basic | execution | 20 |
| T1190 | Exploit Public-Facing Application | initial-access | 20 |
| T1189 | Drive-by Compromise | initial-access | 4 |
| T1218 | System Binary Proxy Execution | defense-evasion | 4 |
| T1003 | OS Credential Dumping | credential-access | 1 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://529motors[.]com/homepersonas/`](https://www.virustotal.com/gui/search/https%3A%2F%2F529motors.com%2Fhomepersonas%2F) | url | — | openphish, tweetfeed | 2026-11-05T11:05:08Z | 70 |
| [`hxxps://www[.]roblox[.]com[.]et/users/7280036217/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.com.et%2Fusers%2F7280036217%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxps://s4w[.]in/recwU`](https://www.virustotal.com/gui/search/https%3A%2F%2Fs4w.in%2FrecwU) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]com[.]et/users/2977314015/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.com.et%2Fusers%2F2977314015%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxps://s4w[.]in/gHboQ`](https://www.virustotal.com/gui/search/https%3A%2F%2Fs4w.in%2FgHboQ) | url | — | openphish | — | 70 |
| [`hxxps://www[.]robiox[.]com[.]gr/users/8070655915/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.robiox.com.gr%2Fusers%2F8070655915%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxps://yukoncloud[.]cloud/Adobe_Installer[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fyukoncloud.cloud%2FAdobe_Installer.html) | url | — | openphish | — | 70 |
| [`hxxps://compositura[.]com/js/indexe[.]html#lawrence`](https://www.virustotal.com/gui/search/https%3A%2F%2Fcompositura.com%2Fjs%2Findexe.html%23lawrence) | url | — | openphish | — | 70 |
| [`hxxps://robloxr[.]com[.]es/users/775450188/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Frobloxr.com.es%2Fusers%2F775450188%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxps://steomcomnmunity[.]ru/765678242749772`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsteomcomnmunity.ru%2F765678242749772) | url | — | openphish | — | 70 |
| [`hxxps://is[.]gd/steamcommunity765678242749772`](https://www.virustotal.com/gui/search/https%3A%2F%2Fis.gd%2Fsteamcommunity765678242749772) | url | — | openphish | — | 70 |
| [`hxxp://app[.]shopledgerapp[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fapp.shopledgerapp.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://wquie-eiiow201113[.]pages[.]dev/help/contact/292730103411180appeals/submit-appeal-form/return`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwquie-eiiow201113.pages.dev%2Fhelp%2Fcontact%2F292730103411180appeals%2Fsubmit-appeal-form%2Freturn) | url | — | openphish | — | 70 |
| [`hxxps://platform-policy-help-phi[.]vercel[.]app/required[.]html/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fplatform-policy-help-phi.vercel.app%2Frequired.html%2F) | url | — | openphish | — | 70 |
| [`hxxps://qr-codes[.]io/j8aWFr`](https://www.virustotal.com/gui/search/https%3A%2F%2Fqr-codes.io%2Fj8aWFr) | url | — | openphish | — | 70 |
| [`hxxp://www[.]coastalrealtyconnections[.]com/wp-content/uploads/2026/10/bible-readings-1[.]html#lorixpro@532a50b8bfb6dfe5bd534e5def05c5e17816[.]com`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.coastalrealtyconnections.com%2Fwp-content%2Fuploads%2F2026%2F10%2Fbible-readings-1.html%23lorixpro%40532a50b8bfb6dfe5bd534e5def05c5e17816.com) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]com[.]et/users/643208279/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.com.et%2Fusers%2F643208279%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxps://s4w[.]in/www-roblox-com-users-64208279-profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fs4w.in%2Fwww-roblox-com-users-64208279-profile) | url | — | openphish | — | 70 |
| [`hxxps://yhgwyqom[.]elementor[.]cloud/1/es/SPAIN/es/arg/Aa/A/ES/argentina/ar/ES9D303ESS/ESS4Z3499SES/82CFGU2554/index[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fyhgwyqom.elementor.cloud%2F1%2Fes%2FSPAIN%2Fes%2Farg%2FAa%2FA%2FES%2Fargentina%2Far%2FES9D303ESS%2FESS4Z3499SES%2F82CFGU2554%2Findex.html) | url | — | openphish | — | 70 |
| [`hxxps://mplays[.]topup-diamonds[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmplays.topup-diamonds.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://aliferlopess[.]site/new/`](https://www.virustotal.com/gui/search/https%3A%2F%2Faliferlopess.site%2Fnew%2F) | url | — | openphish | — | 70 |
| [`hxxps://allegro[.]21812989hio54[.]pics/oferta/iphone-14-pro-max-128gb-czarny-kolor-zresetowany?id=al$2Q1r2V7N7Z3F`](https://www.virustotal.com/gui/search/https%3A%2F%2Fallegro.21812989hio54.pics%2Foferta%2Fiphone-14-pro-max-128gb-czarny-kolor-zresetowany%3Fid%3Dal%242Q1r2V7N7Z3F) | url | — | openphish | — | 70 |
| [`hxxps://discord-api[.]domiyoung[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fdiscord-api.domiyoung.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://roblox[.]com[.]kz/users/1643902205/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Froblox.com.kz%2Fusers%2F1643902205%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]et/users/9921604017/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.et%2Fusers%2F9921604017%2Fprofile) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
