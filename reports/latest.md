# Threat Intel Pulse — 2026-11-14

**Window:** last 7 days · **Generated:** 2026-11-14T22:37:33Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 70199 |
| New in window | 13068 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 23 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 314 | ok |
| tor | 8771 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 324 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 584 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 1312 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 43585 | 7486 |
| url | 13338 | 3946 |
| domain | 8865 | 1244 |
| ipv6 | 3761 | 240 |
| sha256 | 531 | 127 |
| md5 | 119 | 25 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 13200 |
| Exit nodes | 2424 |
| Other relays | 10776 |
| New in window | 1050 |

Sample (20 of 13200, source: Tor Project Onionoo):
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
- `102[.]130[.]49[.]203`

Full list: `dist/tor/tor_nodes.txt` (in the `threat-intel-output` workflow artifact).
## Top malware families

| Family | Indicators | New | ATT&CK (heuristic) |
| --- | --- | --- | --- |
| ClickFix | 238 | 72 | — |
| cryptoscam | 104 | 27 | — |
| Formbook | 53 | 41 | T1566.001, T1056.001, T1555, T1071.001, T1567 |
| NetSupport | 32 | 0 | — |
| PHP2Shell | 26 | 0 | — |
| Vidar | 25 | 21 | T1555, T1071.001, T1567 |
| Kimsuky | 24 | 0 | — |
| ValleyRAT | 23 | 0 | — |
| DPRK | 18 | 0 | — |
| Remcos | 15 | 13 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| Sliver | 14 | 0 | T1071.001, T1573, T1090, T1055 |
| Cobalt Strike | 10 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| AiTM | 8 | 0 | — |
| GuLoader | 8 | 0 | T1027, T1059.005, T1055, T1105 |
| Mirai | 8 | 0 | T1498, T1071.001 |
| ClearFake | 7 | 0 | — |
| Unknown malware | 7 | 0 | — |
| Mythic | 6 | 0 | — |
| SpyNote | 6 | 0 | — |
| infostealer | 6 | 4 | — |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1566 | Phishing | initial-access | 19420 |
| T1566.002 | Spearphishing Link | initial-access | 19420 |
| T1071.001 | Web Protocols | command-and-control | 50137 |
| T1573 | Encrypted Channel | command-and-control | 4919 |
| T1555 | Credentials from Password Stores | credential-access | 142 |
| T1567 | Exfiltration Over Web Service | exfiltration | 142 |
| T1056.001 | Keylogging | collection, credential-access | 98 |
| T1552.001 | Credentials In Files | credential-access | 85 |
| T1566.001 | Spearphishing Attachment | initial-access | 74 |
| T1486 | Data Encrypted for Impact | impact | 65 |
| T1490 | Inhibit System Recovery | impact | 65 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 65 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 38 |
| T1105 | Ingress Tool Transfer | command-and-control | 31 |
| T1090 | Proxy | command-and-control | 25 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 16 |
| T1027 | Obfuscated Files or Information | defense-evasion | 15 |
| T1113 | Screen Capture | collection | 15 |
| T1204.002 | Malicious File | execution | 15 |
| T1498 | Network Denial of Service | impact | 11 |
| T1059.001 | PowerShell | execution | 10 |
| T1059.005 | Visual Basic | execution | 9 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 5 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://lapaca[.]webdirecto[.]com/wp-includes/Text/tdweain/yogsqwj/gmehpir/ggg/adobe/adobe[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Flapaca.webdirecto.com%2Fwp-includes%2FText%2Ftdweain%2Fyogsqwj%2Fgmehpir%2Fggg%2Fadobe%2Fadobe.html) | url | — | openphish, tweetfeed | 2026-11-14T16:01:48Z | 70 |
| [`hxxps://mifidelidad[.]click/bac[.]pa`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmifidelidad.click%2Fbac.pa) | url | — | openphish, tweetfeed | 2026-11-12T01:03:17Z | 70 |
| [`hxxps://www[.]ucsg365[.]vercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.ucsg365.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]365973[.]top/downapp`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.365973.top%2Fdownapp) | url | — | openphish | — | 70 |
| [`hxxps://sprl[.]me/aZlTSEN`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsprl.me%2FaZlTSEN) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]com[.]ss/users/5757654538/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.com.ss%2Fusers%2F5757654538%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxps://icloud-jp8[.]xyz/apple-jp-card/jp/login[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Ficloud-jp8.xyz%2Fapple-jp-card%2Fjp%2Flogin.html) | url | — | openphish | — | 70 |
| [`hxxps://eng-coinsquare[.]apper[.]so/`](https://www.virustotal.com/gui/search/https%3A%2F%2Feng-coinsquare.apper.so%2F) | url | — | openphish | — | 70 |
| [`hxxps://p56e[.]top/downapp/r/p56e[.]top/r/p56e[.]topr/p56e[.]top`](https://www.virustotal.com/gui/search/https%3A%2F%2Fp56e.top%2Fdownapp%2Fr%2Fp56e.top%2Fr%2Fp56e.topr%2Fp56e.top) | url | — | openphish | — | 70 |
| [`hxxps://p56e[.]top/downapp/r/p56e[.]top/r/p56e[.]top`](https://www.virustotal.com/gui/search/https%3A%2F%2Fp56e.top%2Fdownapp%2Fr%2Fp56e.top%2Fr%2Fp56e.top) | url | — | openphish | — | 70 |
| [`hxxps://p56e[.]top/downapp/r/p56e[.]top/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fp56e.top%2Fdownapp%2Fr%2Fp56e.top%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]com[.]ml/users/118673527115/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.com.ml%2Fusers%2F118673527115%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxps://dashboard[.]phantom-wallet[.]to/home/import/index[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fdashboard.phantom-wallet.to%2Fhome%2Fimport%2Findex.html) | url | — | openphish | — | 70 |
| [`hxxps://systemecuzen--sistemeculo[.]replit[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsystemecuzen--sistemeculo.replit.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://server-security-page-2--barbnone[.]replit[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fserver-security-page-2--barbnone.replit.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://neuricardo[.]click/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fneuricardo.click%2F) | url | — | openphish | — | 70 |
| [`hxxp://promocaoblackdaamazon-h9b5ceb6fghgbtdr[.]eastus2-01[.]azurewebsites[.]net/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fpromocaoblackdaamazon-h9b5ceb6fghgbtdr.eastus2-01.azurewebsites.net%2F) | url | — | openphish | — | 70 |
| [`hxxps://store[.]communitycharts[.]com/workshop/Brassbounds-Fury/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fstore.communitycharts.com%2Fworkshop%2FBrassbounds-Fury%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]16654422[.]com/403[.]html?i=164[.]92[.]212[.]136&c=NL`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.16654422.com%2F403.html%3Fi%3D164.92.212.136%26c%3DNL) | url | — | openphish | — | 70 |
| [`hxxps://16654422[.]com/m/`](https://www.virustotal.com/gui/search/https%3A%2F%2F16654422.com%2Fm%2F) | url | — | openphish | — | 70 |
| [`hxxps://8r5p6e-qw644c24y-7k1z9p8m2s-2s9m[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2F8r5p6e-qw644c24y-7k1z9p8m2s-2s9m.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://088wk-ete-fhrc-8tho6-10-09-2026-hh[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2F088wk-ete-fhrc-8tho6-10-09-2026-hh.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://f7m93-qcr-kv7u-7gxjf-07-09-2026-hh[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ff7m93-qcr-kv7u-7gxjf-07-09-2026-hh.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://sp10ct10-dormani-biz-zorkelo[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsp10ct10-dormani-biz-zorkelo.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://pynkj78rfv1-wlzgbwur-2m1m3b-pynk63p[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fpynkj78rfv1-wlzgbwur-2m1m3b-pynk63p.pages.dev%2F) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
