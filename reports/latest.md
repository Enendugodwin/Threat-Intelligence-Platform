# Threat Intel Pulse — 2026-11-12

**Window:** last 7 days · **Generated:** 2026-11-12T07:26:58Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 67311 |
| New in window | 14242 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 23 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 314 | ok |
| tor | 8869 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 1001 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 487 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 1209 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 41289 | 8199 |
| url | 13149 | 4008 |
| domain | 8465 | 1585 |
| ipv6 | 3808 | 279 |
| sha256 | 494 | 142 |
| md5 | 106 | 29 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 13259 |
| Exit nodes | 2459 |
| Other relays | 10800 |
| New in window | 1227 |

Sample (20 of 13259, source: Tor Project Onionoo):
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
| ClickFix | 236 | 70 | — |
| cryptoscam | 104 | 40 | — |
| Formbook | 52 | 40 | T1566.001, T1056.001, T1555, T1071.001, T1567 |
| NetSupport | 32 | 0 | — |
| PHP2Shell | 26 | 0 | — |
| Vidar | 25 | 21 | T1555, T1071.001, T1567 |
| Kimsuky | 24 | 8 | — |
| ValleyRAT | 23 | 0 | — |
| DPRK | 18 | 0 | — |
| Sliver | 14 | 0 | T1071.001, T1573, T1090, T1055 |
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
| T1566 | Phishing | initial-access | 18985 |
| T1566.002 | Spearphishing Link | initial-access | 18985 |
| T1071.001 | Web Protocols | command-and-control | 47740 |
| T1573 | Encrypted Channel | command-and-control | 4755 |
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
| [`hxxp://www[.]metamaskchromeextensionn[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.metamaskchromeextensionn.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]sideaapliccacccionn[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.sideaapliccacccionn.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://indexxjjo[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Findexxjjo.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]upgraded-dollop-omega[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.upgraded-dollop-omega.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://quatangchoem[.]vercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fquatangchoem.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://social-lift-five[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsocial-lift-five.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]89237892[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.89237892.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://loginmsftcheck[.]com/?email=ravorz@7e616df70469bb02bfc535bb792babf9ee6a[.]net`](https://www.virustotal.com/gui/search/https%3A%2F%2Floginmsftcheck.com%2F%3Femail%3Dravorz%407e616df70469bb02bfc535bb792babf9ee6a.net) | url | — | openphish | — | 70 |
| [`hxxps://www[.]vaegryyde[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.vaegryyde.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://portail-mlcrosoft[.]fr/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fportail-mlcrosoft.fr%2F) | url | — | openphish | — | 70 |
| [`hxxp://sp13ct-torek-biz-furon-kalem[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsp13ct-torek-biz-furon-kalem.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://metumasckgnn[.]gitbook[.]io/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmetumasckgnn.gitbook.io%2F) | url | — | openphish | — | 70 |
| [`hxxps://boadashboard-com[.]cercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fboadashboard-com.cercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://roblox[.]ss/communities/2437546919/CaramelPanda420`](https://www.virustotal.com/gui/search/http%3A%2F%2Froblox.ss%2Fcommunities%2F2437546919%2FCaramelPanda420) | url | — | openphish | — | 70 |
| [`hxxp://send-dt-bsc[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsend-dt-bsc.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://tokemie-cdn6-hk1[.]cfd/`](https://www.virustotal.com/gui/search/http%3A%2F%2Ftokemie-cdn6-hk1.cfd%2F) | url | — | openphish | — | 70 |
| [`hxxps://mydpd[.]xzphm[.]top/track-ch`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmydpd.xzphm.top%2Ftrack-ch) | url | — | openphish | — | 70 |
| [`hxxps://b6a2f96c[.]hyt65chn[.]pages[.]dev/requiredpo`](https://www.virustotal.com/gui/search/https%3A%2F%2Fb6a2f96c.hyt65chn.pages.dev%2Frequiredpo) | url | — | openphish | — | 70 |
| [`hxxp://b6a2f96c[.]hyt65chn[.]pages[.]dev/requiredpo[.]html`](https://www.virustotal.com/gui/search/http%3A%2F%2Fb6a2f96c.hyt65chn.pages.dev%2Frequiredpo.html) | url | — | openphish | — | 70 |
| [`hxxp://qsc6f02dr-zptrkpli-0u1s5g-qsc63c[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fqsc6f02dr-zptrkpli-0u1s5g-qsc63c.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://mydpd[.]udovl[.]top/track-ch`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmydpd.udovl.top%2Ftrack-ch) | url | — | openphish | — | 70 |
| [`hxxps://mydpd[.]orauw[.]help/track-ch/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmydpd.orauw.help%2Ftrack-ch%2F) | url | — | openphish | — | 70 |
| [`hxxps://mfacebookk[.]com[.]vn/luvdvawoepl?v6`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmfacebookk.com.vn%2Fluvdvawoepl%3Fv6) | url | — | openphish | — | 70 |
| [`hxxps://rb922[.]top/`](https://www.virustotal.com/gui/search/https%3A%2F%2Frb922.top%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]paypall-login[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.paypall-login.blogspot.com%2F) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
