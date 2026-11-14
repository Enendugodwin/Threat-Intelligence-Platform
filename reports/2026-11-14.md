# Threat Intel Pulse — 2026-11-14

**Window:** last 7 days · **Generated:** 2026-11-14T06:46:01Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 69229 |
| New in window | 12988 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 23 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 314 | ok |
| tor | 8823 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 324 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 584 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 718 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 42802 | 7585 |
| url | 13307 | 3782 |
| domain | 8685 | 1258 |
| ipv6 | 3828 | 253 |
| sha256 | 500 | 97 |
| md5 | 107 | 13 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 13285 |
| Exit nodes | 2472 |
| Other relays | 10813 |
| New in window | 1104 |

Sample (20 of 13285, source: Tor Project Onionoo):
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
| ClickFix | 236 | 70 | — |
| cryptoscam | 104 | 27 | — |
| Formbook | 52 | 40 | T1566.001, T1056.001, T1555, T1071.001, T1567 |
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
| T1566 | Phishing | initial-access | 19336 |
| T1566.002 | Spearphishing Link | initial-access | 19336 |
| T1071.001 | Web Protocols | command-and-control | 49296 |
| T1573 | Encrypted Channel | command-and-control | 4900 |
| T1555 | Credentials from Password Stores | credential-access | 137 |
| T1567 | Exfiltration Over Web Service | exfiltration | 137 |
| T1056.001 | Keylogging | collection, credential-access | 93 |
| T1552.001 | Credentials In Files | credential-access | 81 |
| T1566.001 | Spearphishing Attachment | initial-access | 73 |
| T1486 | Data Encrypted for Impact | impact | 44 |
| T1490 | Inhibit System Recovery | impact | 44 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 44 |
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
| [`hxxps://www[.]rbx1000dfthfhhfhu[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.rbx1000dfthfhhfhu.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://nilsondebona1790684375357[.]2090313[.]meusitehostgator[.]com[.]br/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fnilsondebona1790684375357.2090313.meusitehostgator.com.br%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]adobesign-coral[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.adobesign-coral.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]omis-gules[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.omis-gules.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]adobesign-review[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.adobesign-review.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://vpcs-loltrauxaokhe[.]netlify[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fvpcs-loltrauxaokhe.netlify.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://snaply-khadir-salims-projects[.]vercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsnaply-khadir-salims-projects.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://instagram-clone-konstantindev1[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Finstagram-clone-konstantindev1.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://c07m[.]top/downappr/c07m[.]topr/c07m[.]top/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fc07m.top%2Fdownappr%2Fc07m.topr%2Fc07m.top%2F) | url | — | openphish | — | 70 |
| [`hxxps://c07m[.]top/downappr/c07m[.]top/r/c07m[.]top`](https://www.virustotal.com/gui/search/https%3A%2F%2Fc07m.top%2Fdownappr%2Fc07m.top%2Fr%2Fc07m.top) | url | — | openphish | — | 70 |
| [`hxxps://c07m[.]top/downappr/c07m[.]top/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fc07m.top%2Fdownappr%2Fc07m.top%2F) | url | — | openphish | — | 70 |
| [`hxxps://prasadmhetre2005[.]github[.]io/Spotify-Clone/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fprasadmhetre2005.github.io%2FSpotify-Clone%2F) | url | — | openphish | — | 70 |
| [`hxxp://m3tamsklognx[.]gitbook[.]io/us`](https://www.virustotal.com/gui/search/http%3A%2F%2Fm3tamsklognx.gitbook.io%2Fus) | url | — | openphish | — | 70 |
| [`hxxp://ar24-five[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Far24-five.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]f60c[.]top/downapp/r/www[.]f60c[.]top`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.f60c.top%2Fdownapp%2Fr%2Fwww.f60c.top) | url | — | openphish | — | 70 |
| [`hxxp://www[.]f60c[.]top/downapp`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.f60c.top%2Fdownapp) | url | — | openphish | — | 70 |
| [`hxxps://s4w[.]in/www-roblox-com-user-1404516341-profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fs4w.in%2Fwww-roblox-com-user-1404516341-profile) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]com[.]et/users/1404516348/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.com.et%2Fusers%2F1404516348%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxps://www[.]33881565[.]com:1565/403[.]html?i=164[.]92[.]212[.]136&c=NL`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.33881565.com%3A1565%2F403.html%3Fi%3D164.92.212.136%26c%3DNL) | url | — | openphish | — | 70 |
| [`hxxp://33881565[.]com/m`](https://www.virustotal.com/gui/search/http%3A%2F%2F33881565.com%2Fm) | url | — | openphish | — | 70 |
| [`hxxps://atomic-en[.]uncody[.]site/en-us/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fatomic-en.uncody.site%2Fen-us%2F) | url | — | openphish | — | 70 |
| [`hxxps://m[.]365bet944[.]com/eng/home/index`](https://www.virustotal.com/gui/search/https%3A%2F%2Fm.365bet944.com%2Feng%2Fhome%2Findex) | url | — | openphish | — | 70 |
| [`hxxps://m[.]365bet511[.]com/eng/home/index`](https://www.virustotal.com/gui/search/https%3A%2F%2Fm.365bet511.com%2Feng%2Fhome%2Findex) | url | — | openphish | — | 70 |
| [`hxxps://www[.]22771565[.]com:1565/403[.]html?i=164[.]92[.]212[.]136&c=NL`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.22771565.com%3A1565%2F403.html%3Fi%3D164.92.212.136%26c%3DNL) | url | — | openphish | — | 70 |
| [`hxxp://22771565[.]com/m`](https://www.virustotal.com/gui/search/http%3A%2F%2F22771565.com%2Fm) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
