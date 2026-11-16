# Threat Intel Pulse — 2026-11-16

**Window:** last 7 days · **Generated:** 2026-11-16T22:22:07Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 70628 |
| New in window | 14356 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 23 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 314 | ok |
| tor | 8791 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 1100 | ok |
| greensnow | 1175 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 579 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 1851 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 44493 | 7916 |
| url | 13273 | 4661 |
| domain | 8311 | 1260 |
| ipv6 | 3777 | 235 |
| sha256 | 628 | 227 |
| md5 | 146 | 57 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 13246 |
| Exit nodes | 2419 |
| Other relays | 10827 |
| New in window | 1023 |

Sample (20 of 13246, source: Tor Project Onionoo):
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
| ClickFix | 304 | 108 | — |
| cryptoscam | 104 | 9 | — |
| Formbook | 53 | 41 | T1566.001, T1056.001, T1555, T1071.001, T1567 |
| NetSupport | 32 | 0 | — |
| Kimsuky | 30 | 10 | — |
| Vidar | 25 | 21 | T1555, T1071.001, T1567 |
| PHP2Shell | 23 | 0 | — |
| ValleyRAT | 19 | 0 | — |
| DPRK | 18 | 0 | — |
| Remcos | 16 | 14 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
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
| T1566 | Phishing | initial-access | 18549 |
| T1566.002 | Spearphishing Link | initial-access | 18549 |
| T1071.001 | Web Protocols | command-and-control | 51318 |
| T1573 | Encrypted Channel | command-and-control | 5144 |
| T1555 | Credentials from Password Stores | credential-access | 156 |
| T1567 | Exfiltration Over Web Service | exfiltration | 156 |
| T1552.001 | Credentials In Files | credential-access | 99 |
| T1056.001 | Keylogging | collection, credential-access | 98 |
| T1566.001 | Spearphishing Attachment | initial-access | 75 |
| T1486 | Data Encrypted for Impact | impact | 65 |
| T1490 | Inhibit System Recovery | impact | 65 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 65 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 33 |
| T1105 | Ingress Tool Transfer | command-and-control | 30 |
| T1090 | Proxy | command-and-control | 20 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 17 |
| T1113 | Screen Capture | collection | 16 |
| T1027 | Obfuscated Files or Information | defense-evasion | 15 |
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
| [`hxxps://testlanigs[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ftestlanigs.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://s4w[.]in/Wgtsg`](https://www.virustotal.com/gui/search/https%3A%2F%2Fs4w.in%2FWgtsg) | url | — | openphish | — | 70 |
| [`hxxps://www[.]instagram-real[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.instagram-real.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://startq-trzr-bridge[.]pages[.]dev/appeals/submit-appeal-form/return`](https://www.virustotal.com/gui/search/https%3A%2F%2Fstartq-trzr-bridge.pages.dev%2Fappeals%2Fsubmit-appeal-form%2Freturn) | url | — | openphish | — | 70 |
| [`hxxps://sp30ct-kemix-biz-zadul-noval[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsp30ct-kemix-biz-zadul-noval.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://t43ut-cyg-o7av-od3l1-11-09-2026-hh[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Ft43ut-cyg-o7av-od3l1-11-09-2026-hh.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://bubu-new[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fbubu-new.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://jsivok-brund-8pu59a-cjbyh-1rs238[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fjsivok-brund-8pu59a-cjbyh-1rs238.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://sp10ct11-kavluni-biz-zermavo[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsp10ct11-kavluni-biz-zermavo.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://promocaooficial[.]github[.]io/shopeone/inicio[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fpromocaooficial.github.io%2Fshopeone%2Finicio.html) | url | — | openphish | — | 70 |
| [`hxxps://jst-someone[.]github[.]io/Spotify-clone`](https://www.virustotal.com/gui/search/https%3A%2F%2Fjst-someone.github.io%2FSpotify-clone) | url | — | openphish | — | 70 |
| [`hxxps://www[.]sena-facebook[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.sena-facebook.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://tokinexn-cdn7-hk2[.]lol/`](https://www.virustotal.com/gui/search/http%3A%2F%2Ftokinexn-cdn7-hk2.lol%2F) | url | — | openphish | — | 70 |
| [`hxxps://instagram-real[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Finstagram-real.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://walangforeve01[.]weebly[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwalangforeve01.weebly.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://hkdiscord[.]antsoon[.]com/category/engineering`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhkdiscord.antsoon.com%2Fcategory%2Fengineering) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]ly/users/4536663053/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.ly%2Fusers%2F4536663053%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxps://instagram-tip[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Finstagram-tip.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://christianbased[.]org/owa[.]auth[.]logo[.]aspx/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fchristianbased.org%2Fowa.auth.logo.aspx%2F) | url | — | openphish | — | 70 |
| [`hxxp://christianbased[.]org/owa[.]auth[.]logo[.]aspx`](https://www.virustotal.com/gui/search/http%3A%2F%2Fchristianbased.org%2Fowa.auth.logo.aspx) | url | — | openphish | — | 70 |
| [`hxxp://tokanimer-cdn6-hk3[.]xyz/`](https://www.virustotal.com/gui/search/http%3A%2F%2Ftokanimer-cdn6-hk3.xyz%2F) | url | — | openphish | — | 70 |
| [`hxxps://yt2mp3api[.]ofismall[.]az/ProcessValidation/view-pr-do/plugin-read-mail/d20xODcybTU3MA**/attach-viewer-main/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fyt2mp3api.ofismall.az%2FProcessValidation%2Fview-pr-do%2Fplugin-read-mail%2Fd20xODcybTU3MA%2A%2A%2Fattach-viewer-main%2F) | url | — | openphish | — | 70 |
| [`hxxps://doer-min[.]alwaysdata[.]net/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fdoer-min.alwaysdata.net%2F) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
