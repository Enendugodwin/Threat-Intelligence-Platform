# Threat Intel Pulse — 2026-11-22

**Window:** last 7 days · **Generated:** 2026-11-22T07:10:30Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 69346 |
| New in window | 15014 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 23 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 314 | ok |
| tor | 10339 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 888 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 596 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 2335 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 43871 | 8219 |
| url | 13262 | 5020 |
| domain | 7511 | 1186 |
| ipv6 | 3820 | 212 |
| sha256 | 710 | 290 |
| md5 | 172 | 87 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 13338 |
| Exit nodes | 2489 |
| Other relays | 10849 |
| New in window | 974 |

Sample (20 of 13338, source: Tor Project Onionoo):
- `1[.]161[.]130[.]49`
- `1[.]201[.]176[.]169`
- `1[.]201[.]176[.]176`
- `1[.]248[.]96[.]163`
- `1[.]34[.]44[.]234`
- `100[.]12[.]167[.]245`
- `100[.]2[.]63[.]41`
- `100[.]35[.]77[.]114`
- `100[.]8[.]164[.]103`
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

Full list: `dist/tor/tor_nodes.txt` (in the `threat-intel-output` workflow artifact).
## Top malware families

| Family | Indicators | New | ATT&CK (heuristic) |
| --- | --- | --- | --- |
| ClickFix | 381 | 178 | — |
| cryptoscam | 111 | 7 | — |
| Kimsuky | 74 | 54 | — |
| Formbook | 42 | 0 | T1566.001, T1056.001, T1555, T1071.001, T1567 |
| Vidar | 21 | 0 | T1555, T1071.001, T1567 |
| Remcos | 19 | 5 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| DPRK | 18 | 0 | — |
| AiTM | 16 | 8 | — |
| Cobalt Strike | 9 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| GuLoader | 8 | 0 | T1027, T1059.005, T1055, T1105 |
| Mirai | 7 | 0 | T1498, T1071.001 |
| infostealer | 7 | 1 | — |
| PHP2Shell | 6 | 1 | — |
| Unknown malware | 6 | 0 | — |
| Evilginx | 4 | 0 | — |
| MustangPanda | 4 | 4 | — |
| QakBot | 4 | 0 | T1566.001, T1204.002, T1055, T1071.001, T1105, T1027, T1041 |
| Sliver | 4 | 0 | T1071.001, T1573, T1090, T1055 |
| AdaptixC2 | 2 | 0 | — |
| INCRansom | 2 | 0 | — |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1566 | Phishing | initial-access | 17957 |
| T1566.002 | Spearphishing Link | initial-access | 17957 |
| T1071.001 | Web Protocols | command-and-control | 50485 |
| T1573 | Encrypted Channel | command-and-control | 5844 |
| T1555 | Credentials from Password Stores | credential-access | 153 |
| T1567 | Exfiltration Over Web Service | exfiltration | 153 |
| T1552.001 | Credentials In Files | credential-access | 111 |
| T1486 | Data Encrypted for Impact | impact | 104 |
| T1490 | Inhibit System Recovery | impact | 104 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 104 |
| T1056.001 | Keylogging | collection, credential-access | 94 |
| T1566.001 | Spearphishing Attachment | initial-access | 67 |
| T1105 | Ingress Tool Transfer | command-and-control | 28 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 26 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 20 |
| T1113 | Screen Capture | collection | 19 |
| T1027 | Obfuscated Files or Information | defense-evasion | 15 |
| T1204.002 | Malicious File | execution | 15 |
| T1090 | Proxy | command-and-control | 13 |
| T1059.001 | PowerShell | execution | 9 |
| T1059.005 | Visual Basic | execution | 9 |
| T1498 | Network Denial of Service | impact | 9 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 5 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://saratio[.]de/gustafsonltd/download[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsaratio.de%2Fgustafsonltd%2Fdownload.html) | url | — | openphish, tweetfeed | 2026-11-19T18:25:18Z | 70 |
| [`hxxps://auth0-google[.]com/2step[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fauth0-google.com%2F2step.html) | url | AiTM | openphish, tweetfeed | 2026-11-18T17:18:56Z | 70 |
| [`hxxps://icloudvsmapalocaliza[.]click/isignesp[.]php?correo=-&id=172974`](https://www.virustotal.com/gui/search/https%3A%2F%2Ficloudvsmapalocaliza.click%2Fisignesp.php%3Fcorreo%3D-%26id%3D172974) | url | — | openphish, tweetfeed | 2026-11-18T16:27:54Z | 70 |
| [`hxxp://conatem[.]com/adobeStudio[.]html`](https://www.virustotal.com/gui/search/http%3A%2F%2Fconatem.com%2FadobeStudio.html) | url | — | openphish, tweetfeed | 2026-11-18T03:56:46Z | 70 |
| [`hxxp://www[.]sscoinabaseggh[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.sscoinabaseggh.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://y8w2f1-1me006kno-arcadawebapps2[.]vercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fy8w2f1-1me006kno-arcadawebapps2.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://telquro-kxt-felqani-a3x8hq27[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Ftelquro-kxt-felqani-a3x8hq27.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://y8w2f1-arcadawebapps2[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fy8w2f1-arcadawebapps2.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://instagram-login-page-mockup[.]amanda-vencimento[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Finstagram-login-page-mockup.amanda-vencimento.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://baqwrd[.]newlogjt[.]de5[.]net/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fbaqwrd.newlogjt.de5.net%2F) | url | — | openphish | — | 70 |
| [`hxxp://jtd64-1yp-0rr9-3sinb-23-09-2026-aa[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fjtd64-1yp-0rr9-3sinb-23-09-2026-aa.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://marnavi-kxt-zenqumi-c2x8hk19[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fmarnavi-kxt-zenqumi-c2x8hk19.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://sp19ct-nelo-biz-vura-kati[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsp19ct-nelo-biz-vura-kati.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://metayasdogrulamasistemi[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fmetayasdogrulamasistemi.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://terqelo-mpt-zanfavi-a8x1ka94[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fterqelo-mpt-zanfavi-a8x1ka94.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://muqm1-wxc-o6pe-qpyw7-10-09-2026-hh[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fmuqm1-wxc-o6pe-qpyw7-10-09-2026-hh.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://y8w2f1[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fy8w2f1.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://lorqumi-kxt-zemvani-r8t6hk42[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Florqumi-kxt-zemvani-r8t6hk42.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://newlogjt[.]cc[.]cd/jp`](https://www.virustotal.com/gui/search/https%3A%2F%2Fnewlogjt.cc.cd%2Fjp) | url | — | openphish | — | 70 |
| [`hxxps://www[.]facebook-pt[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.facebook-pt.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://start-ledger-com-web-cdn[.]typedream[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fstart-ledger-com-web-cdn.typedream.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://hadkjjjjjkoo[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fhadkjjjjjkoo.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]shopee0199[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.shopee0199.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]undian-shopeeid2020[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.undian-shopeeid2020.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://cfg[.]me/glfts`](https://www.virustotal.com/gui/search/https%3A%2F%2Fcfg.me%2Fglfts) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
