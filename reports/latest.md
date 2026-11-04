# Threat Intel Pulse — 2026-11-04

**Window:** last 7 days · **Generated:** 2026-11-04T06:44:19Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 85165 |
| New in window | 15776 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 614 | ok |
| tor | 8820 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 758 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 519 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 902 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 35981 | 9727 |
| url | 25340 | 4211 |
| domain | 12298 | 1241 |
| sha256 | 6900 | 124 |
| ipv6 | 3695 | 443 |
| md5 | 514 | 30 |
| sha1 | 437 | 0 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 12895 |
| Exit nodes | 2414 |
| Other relays | 10481 |
| New in window | 1951 |

Sample (20 of 12895, source: Tor Project Onionoo):
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
| Vidar | 4797 | 0 | T1555, T1071.001, T1567 |
| IClickFix | 1520 | 0 | — |
| Mirai | 1488 | 0 | T1498, T1071.001 |
| Unknown Loader | 1403 | 0 | — |
| Unknown malware | 1260 | 0 | — |
| Cobalt Strike | 1253 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| AMOS | 859 | 0 | — |
| VShell | 666 | 0 | — |
| ClearFake | 425 | 0 | — |
| PureRAT | 380 | 0 | — |
| php.shin_webshell | 314 | 0 | — |
| Remus | 288 | 0 | — |
| Remcos | 276 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| AdaptixC2 | 266 | 0 | — |
| AsyncRAT | 256 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| MacSync | 255 | 0 | — |
| DanaBot | 185 | 0 | T1566.001, T1071.001, T1555, T1041 |
| SalatStealer | 134 | 0 | — |
| Coruna | 132 | 0 | — |
| Sliver | 124 | 0 | T1071.001, T1573, T1090, T1055 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1566 | Phishing | initial-access | 17600 |
| T1566.002 | Spearphishing Link | initial-access | 17600 |
| T1071.001 | Web Protocols | command-and-control | 57630 |
| T1105 | Ingress Tool Transfer | command-and-control | 11200 |
| T1573 | Encrypted Channel | command-and-control | 8504 |
| T1555 | Credentials from Password Stores | credential-access | 7392 |
| T1567 | Exfiltration Over Web Service | exfiltration | 7203 |
| T1498 | Network Denial of Service | impact | 4514 |
| T1552.001 | Credentials In Files | credential-access | 3963 |
| T1204.002 | Malicious File | execution | 3614 |
| T1027 | Obfuscated Files or Information | defense-evasion | 3462 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1476 |
| T1056.001 | Keylogging | collection, credential-access | 1456 |
| T1090 | Proxy | command-and-control | 1411 |
| T1059.001 | PowerShell | execution | 1263 |
| T1566.001 | Spearphishing Attachment | initial-access | 1190 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 785 |
| T1113 | Screen Capture | collection | 745 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 255 |
| T1189 | Drive-by Compromise | initial-access | 160 |
| T1218 | System Binary Proxy Execution | defense-evasion | 160 |
| T1486 | Data Encrypted for Impact | impact | 43 |
| T1490 | Inhibit System Recovery | impact | 43 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 43 |
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
| [`hxxps://intellectual-transform-624217[.]framer[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fintellectual-transform-624217.framer.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]roblox[.]ly/users/8231296959/profile/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.roblox.ly%2Fusers%2F8231296959%2Fprofile%2F) | url | — | openphish | — | 70 |
| [`hxxp://home-cry-com[.]square[.]site/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fhome-cry-com.square.site%2F) | url | — | openphish | — | 70 |
| [`hxxp://tokinim-cdng-hkj[.]lol/`](https://www.virustotal.com/gui/search/http%3A%2F%2Ftokinim-cdng-hkj.lol%2F) | url | — | openphish | — | 70 |
| [`hxxp://ncapmmda-ncr[.]cfd/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fncapmmda-ncr.cfd%2F) | url | — | openphish | — | 70 |
| [`hxxp://straightforward-griffin-592982[.]framer[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fstraightforward-griffin-592982.framer.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://divinedownload[.]com/eov[.]php?id=f1b0775946bc0329b35b823b86eeb5f5`](https://www.virustotal.com/gui/search/https%3A%2F%2Fdivinedownload.com%2Feov.php%3Fid%3Df1b0775946bc0329b35b823b86eeb5f5) | url | — | openphish | — | 70 |
| [`hxxps://divinedownload[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fdivinedownload.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://team-center-feature-update[.]vercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fteam-center-feature-update.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://netflixph[.]vercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fnetflixph.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]ph-tg77[.]net/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.ph-tg77.net%2F) | url | — | openphish | — | 70 |
| [`hxxps://auth[.]properties/E[.]aUtDFan446dX?/microsoftonline/mailbox/upgrade&userid=75468973984785978212312307887543`](https://www.virustotal.com/gui/search/https%3A%2F%2Fauth.properties%2FE.aUtDFan446dX%3F%2Fmicrosoftonline%2Fmailbox%2Fupgrade%26userid%3D75468973984785978212312307887543) | url | — | openphish | — | 70 |
| [`hxxps://www[.]flhealthlicense-tawny[.]vercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.flhealthlicense-tawny.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://mydpd[.]kpokm[.]top/track-ch`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmydpd.kpokm.top%2Ftrack-ch) | url | — | openphish | — | 70 |
| [`hxxps://mydpd[.]rwcwv[.]xyz/track-ch`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmydpd.rwcwv.xyz%2Ftrack-ch) | url | — | openphish | — | 70 |
| [`hxxps://mydpd[.]odqdn[.]top/track-ch`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmydpd.odqdn.top%2Ftrack-ch) | url | — | openphish | — | 70 |
| [`hxxps://mydpd[.]wrhsi[.]cc/track-ch`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmydpd.wrhsi.cc%2Ftrack-ch) | url | — | openphish | — | 70 |
| [`hxxps://mydpd[.]sztdt[.]help/track-ch`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmydpd.sztdt.help%2Ftrack-ch) | url | — | openphish | — | 70 |
| [`hxxps://www[.]htautenticacionbcgatorrr[.]info/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.htautenticacionbcgatorrr.info%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]updatepasswrd-23l7[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.updatepasswrd-23l7.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://swiss-post-ch[.]com/pages/ban[.]php`](https://www.virustotal.com/gui/search/https%3A%2F%2Fswiss-post-ch.com%2Fpages%2Fban.php) | url | — | openphish | — | 70 |
| [`hxxps://swiss-post-ch[.]com/pages/carte[.]php`](https://www.virustotal.com/gui/search/https%3A%2F%2Fswiss-post-ch.com%2Fpages%2Fcarte.php) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
