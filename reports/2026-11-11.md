# Threat Intel Pulse — 2026-11-11

**Window:** last 7 days · **Generated:** 2026-11-11T19:44:39Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 66796 |
| New in window | 15529 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 23 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 614 | ok |
| tor | 8867 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 653 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 491 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 1581 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 40852 | 9060 |
| url | 13138 | 4228 |
| domain | 8402 | 1697 |
| ipv6 | 3808 | 293 |
| sha256 | 490 | 221 |
| md5 | 106 | 30 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 13278 |
| Exit nodes | 2458 |
| Other relays | 10820 |
| New in window | 1297 |

Sample (20 of 13278, source: Tor Project Onionoo):
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
| ClickFix | 236 | 130 | — |
| cryptoscam | 104 | 47 | — |
| Formbook | 52 | 40 | T1566.001, T1056.001, T1555, T1071.001, T1567 |
| NetSupport | 32 | 0 | — |
| PHP2Shell | 26 | 0 | — |
| Vidar | 25 | 21 | T1555, T1071.001, T1567 |
| Kimsuky | 24 | 8 | — |
| ValleyRAT | 23 | 0 | — |
| DPRK | 18 | 0 | — |
| Sliver | 14 | 2 | T1071.001, T1573, T1090, T1055 |
| Cobalt Strike | 10 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| AiTM | 8 | 8 | — |
| GuLoader | 8 | 8 | T1027, T1059.005, T1055, T1105 |
| Mirai | 8 | 0 | T1498, T1071.001 |
| ClearFake | 7 | 0 | — |
| Unknown malware | 7 | 0 | — |
| Mythic | 6 | 0 | — |
| SpyNote | 6 | 0 | — |
| Remcos | 5 | 3 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| QakBot | 4 | 0 | T1566.001, T1204.002, T1055, T1071.001, T1105, T1027, T1041 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1566 | Phishing | initial-access | 18927 |
| T1566.002 | Spearphishing Link | initial-access | 18927 |
| T1071.001 | Web Protocols | command-and-control | 47287 |
| T1573 | Encrypted Channel | command-and-control | 4516 |
| T1555 | Credentials from Password Stores | credential-access | 133 |
| T1567 | Exfiltration Over Web Service | exfiltration | 133 |
| T1056.001 | Keylogging | collection, credential-access | 83 |
| T1552.001 | Credentials In Files | credential-access | 77 |
| T1566.001 | Spearphishing Attachment | initial-access | 63 |
| T1486 | Data Encrypted for Impact | impact | 44 |
| T1490 | Inhibit System Recovery | impact | 44 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 44 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 38 |
| T1105 | Ingress Tool Transfer | command-and-control | 31 |
| T1090 | Proxy | command-and-control | 25 |
| T1027 | Obfuscated Files or Information | defense-evasion | 15 |
| T1204.002 | Malicious File | execution | 15 |
| T1498 | Network Denial of Service | impact | 11 |
| T1059.001 | PowerShell | execution | 10 |
| T1059.005 | Visual Basic | execution | 9 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 6 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 5 |
| T1113 | Screen Capture | collection | 5 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://529motors[.]com/homepersonas/`](https://www.virustotal.com/gui/search/https%3A%2F%2F529motors.com%2Fhomepersonas%2F) | url | — | openphish, tweetfeed | 2026-11-05T11:05:08Z | 70 |
| [`hxxp://whatsapp[.]nlabstech[.]in/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwhatsapp.nlabstech.in%2F) | url | — | openphish | — | 70 |
| [`hxxps://zw9403[.]craftum[.]io/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fzw9403.craftum.io%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]qrfy[.]io/lQFpMKHkB9/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.qrfy.io%2FlQFpMKHkB9%2F) | url | — | openphish | — | 70 |
| [`hxxp://delinea[.]ar/dfg/index[.]html`](https://www.virustotal.com/gui/search/http%3A%2F%2Fdelinea.ar%2Fdfg%2Findex.html) | url | — | openphish | — | 70 |
| [`hxxp://obontezip--danielsplurnbin[.]replit[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fobontezip--danielsplurnbin.replit.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://asyncport500-bsrf[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fasyncport500-bsrf.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://idzone472-ynwj[.]blogspot[.]com/?m=1`](https://www.virustotal.com/gui/search/https%3A%2F%2Fidzone472-ynwj.blogspot.com%2F%3Fm%3D1) | url | — | openphish | — | 70 |
| [`hxxps://shadow-fox-e-commerce[.]vercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fshadow-fox-e-commerce.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://sharemyhtml[.]com/p/EeCIqjrBUO`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsharemyhtml.com%2Fp%2FEeCIqjrBUO) | url | — | openphish | — | 70 |
| [`hxxps://login[.]eu[.]verifypass[.]pw/9c33ed/e1d275de-fdef-4946-abc8-2fce538a8a44%23pt_content/`](https://www.virustotal.com/gui/search/https%3A%2F%2Flogin.eu.verifypass.pw%2F9c33ed%2Fe1d275de-fdef-4946-abc8-2fce538a8a44%2523pt_content%2F) | url | — | openphish | — | 70 |
| [`hxxps://domipa[.]s3[.]us-east-1[.]amazonaws[.]com/NuEw[.]html#elel8@1698b4a6237f1bd27d8714c71e02fd658a4e[.]org`](https://www.virustotal.com/gui/search/https%3A%2F%2Fdomipa.s3.us-east-1.amazonaws.com%2FNuEw.html%23elel8%401698b4a6237f1bd27d8714c71e02fd658a4e.org) | url | — | openphish | — | 70 |
| [`hxxps://mymailjunoupdate[.]weeblysite[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmymailjunoupdate.weeblysite.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://wtrgert[.]uber[.]space/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwtrgert.uber.space%2F) | url | — | openphish | — | 70 |
| [`hxxp://2s8q1g-2v9m1p8a-mbtz1p8m9z2-fsgc[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2F2s8q1g-2v9m1p8a-mbtz1p8m9z2-fsgc.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://coda-changrx[.]ezzzyy[.]de/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fcoda-changrx.ezzzyy.de%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]com[.]ss/communities/3537850946/Roblox-PLUS-EVENT`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.com.ss%2Fcommunities%2F3537850946%2FRoblox-PLUS-EVENT) | url | — | openphish | — | 70 |
| [`hxxps://www[.]donateblox-here[.]blogspot[.]com/?m=1`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.donateblox-here.blogspot.com%2F%3Fm%3D1) | url | — | openphish | — | 70 |
| [`hxxps://donateblox-here[.]blogspot[.]com/?m=1`](https://www.virustotal.com/gui/search/https%3A%2F%2Fdonateblox-here.blogspot.com%2F%3Fm%3D1) | url | — | openphish | — | 70 |
| [`hxxps://www[.]instagram-login-user[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.instagram-login-user.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://instagram-login-user[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Finstagram-login-user.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://amazonblackdossonhos[.]com[.]br/`](https://www.virustotal.com/gui/search/http%3A%2F%2Famazonblackdossonhos.com.br%2F) | url | — | openphish | — | 70 |
| [`hxxps://mydpd[.]yhtho[.]top/track-ch/#%252Findex`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmydpd.yhtho.top%2Ftrack-ch%2F%23%25252Findex) | url | — | openphish | — | 70 |
| [`hxxps://mydpd[.]xwfku[.]top/track-ch`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmydpd.xwfku.top%2Ftrack-ch) | url | — | openphish | — | 70 |
| [`hxxps://mydpd[.]dljlo[.]xyz/track-ch`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmydpd.dljlo.xyz%2Ftrack-ch) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
