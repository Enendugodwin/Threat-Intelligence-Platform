# Threat Intel Pulse — 2026-11-08

**Window:** last 7 days · **Generated:** 2026-11-08T13:43:01Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 78974 |
| New in window | 16437 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 27 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 614 | ok |
| tor | 8762 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 1630 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 511 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 1850 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 40522 | 9859 |
| url | 19978 | 4381 |
| domain | 10765 | 1489 |
| ipv6 | 3757 | 476 |
| sha256 | 3586 | 207 |
| md5 | 231 | 25 |
| sha1 | 135 | 0 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 13139 |
| Exit nodes | 2430 |
| Other relays | 10709 |
| New in window | 2017 |

Sample (20 of 13139, source: Tor Project Onionoo):
- `1[.]161[.]130[.]49`
- `1[.]201[.]176[.]169`
- `1[.]201[.]176[.]176`
- `1[.]235[.]159[.]83`
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

Full list: `dist/tor/tor_nodes.txt` (in the `threat-intel-output` workflow artifact).
## Top malware families

| Family | Indicators | New | ATT&CK (heuristic) |
| --- | --- | --- | --- |
| Vidar | 1291 | 0 | T1555, T1071.001, T1567 |
| Cobalt Strike | 1203 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| IClickFix | 879 | 0 | — |
| Unknown malware | 760 | 0 | — |
| Mirai | 606 | 0 | T1498, T1071.001 |
| Unknown Loader | 580 | 0 | — |
| AMOS | 549 | 0 | — |
| PureRAT | 345 | 0 | — |
| MacSync | 253 | 0 | — |
| AdaptixC2 | 241 | 0 | — |
| Remus | 214 | 0 | — |
| ClickFix | 200 | 104 | — |
| DanaBot | 179 | 0 | T1566.001, T1071.001, T1555, T1041 |
| Remcos | 178 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| AsyncRAT | 176 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| ClearFake | 164 | 0 | — |
| VShell | 127 | 0 | — |
| php.shin_webshell | 122 | 0 | — |
| cryptoscam | 95 | 87 | — |
| Evilginx | 94 | 2 | — |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1566 | Phishing | initial-access | 18691 |
| T1566.002 | Spearphishing Link | initial-access | 18691 |
| T1071.001 | Web Protocols | command-and-control | 54580 |
| T1105 | Ingress Tool Transfer | command-and-control | 6809 |
| T1573 | Encrypted Channel | command-and-control | 6711 |
| T1498 | Network Denial of Service | impact | 3131 |
| T1555 | Credentials from Password Stores | credential-access | 3083 |
| T1567 | Exfiltration Over Web Service | exfiltration | 2900 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1359 |
| T1090 | Proxy | command-and-control | 1320 |
| T1059.001 | PowerShell | execution | 1213 |
| T1552.001 | Credentials In Files | credential-access | 1190 |
| T1056.001 | Keylogging | collection, credential-access | 1038 |
| T1204.002 | Malicious File | execution | 903 |
| T1027 | Obfuscated Files or Information | defense-evasion | 902 |
| T1566.001 | Spearphishing Attachment | initial-access | 779 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 504 |
| T1113 | Screen Capture | collection | 476 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 206 |
| T1486 | Data Encrypted for Impact | impact | 43 |
| T1490 | Inhibit System Recovery | impact | 43 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 43 |
| T1059.005 | Visual Basic | execution | 28 |
| T1190 | Exploit Public-Facing Application | initial-access | 20 |
| T1189 | Drive-by Compromise | initial-access | 4 |
| T1218 | System Binary Proxy Execution | defense-evasion | 4 |
| T1003 | OS Credential Dumping | credential-access | 1 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://529motors[.]com/homepersonas/`](https://www.virustotal.com/gui/search/https%3A%2F%2F529motors.com%2Fhomepersonas%2F) | url | — | openphish, tweetfeed | 2026-11-05T11:05:08Z | 70 |
| [`hxxps://vemtasbobinaj[.]com/login[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fvemtasbobinaj.com%2Flogin.html) | url | — | openphish, tweetfeed | 2026-11-02T19:27:35Z | 70 |
| [`hxxps://instagram-cloud[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Finstagram-cloud.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]instagram-cloud[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.instagram-cloud.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://mvdcy1ekqlo-qwbrmlos-8e1f2b-mvd83w[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fmvdcy1ekqlo-qwbrmlos-8e1f2b-mvd83w.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]faccbook[.]vercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.faccbook.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://sp3ct10-melvuni-biz-kavzelo[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsp3ct10-melvuni-biz-kavzelo.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://support-service-portal[.]vercel[.]app/accounts-center`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsupport-service-portal.vercel.app%2Faccounts-center) | url | — | openphish | — | 70 |
| [`hxxp://instagramcom-weld[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Finstagramcom-weld.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://2s9q1g-qw444agreg-mbtz9x1p8m2-fsgc[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2F2s9q1g-qw444agreg-mbtz9x1p8m2-fsgc.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://jpxqn5c80sk-kvtrmwur-9p4m6d-py611a[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fjpxqn5c80sk-kvtrmwur-9p4m6d-py611a.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://bdf88-172dr-lpr47-172lp-8b1c3d-lpr47-172a[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fbdf88-172dr-lpr47-172lp-8b1c3d-lpr47-172a.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://twydc9e48kq-xhrmwlos-9f8f4b-twy31w[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Ftwydc9e48kq-xhrmwlos-9f8f4b-twy31w.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://yktpm220bf-lhjndskr-1k8f5g-ykk05c[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fyktpm220bf-lhjndskr-1k8f5g-ykk05c.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://support-service-portal[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsupport-service-portal.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://njlgp3bdrun-thkprpli-2c9d3g-njq79c[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fnjlgp3bdrun-thkprpli-2c9d3g-njq79c.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://wlzgb5avstr-fscdhmja-1o8m3g-wlq20c[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwlzgb5avstr-fscdhmja-1o8m3g-wlq20c.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://sp30ct10-korlevo-biz-zurelo[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsp30ct10-korlevo-biz-zurelo.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://ydktr02kww-rvljh38wur-0r5s7b-rvl82x[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fydktr02kww-rvljh38wur-0r5s7b-rvl82x.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://sp1ct10-ravlevo-biz-kavmiko[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsp1ct10-ravlevo-biz-kavmiko.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://sp1ct10-zulreko-biz-kavmari[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsp1ct10-zulreko-biz-kavmari.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://sp3ct10-kelzemi-biz-dorvako[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsp3ct10-kelzemi-biz-dorvako.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://s4w[.]in/roblox-com-games-2753915549-Blox-FruitsprivateServerLinkCode=15587938948810815525436529981288`](https://www.virustotal.com/gui/search/https%3A%2F%2Fs4w.in%2Froblox-com-games-2753915549-Blox-FruitsprivateServerLinkCode%3D15587938948810815525436529981288) | url | — | openphish | — | 70 |
| [`hxxps://wf5159[.]craftum[.]io/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwf5159.craftum.io%2F) | url | — | openphish | — | 70 |
| [`hxxp://vermillion-scone-6c2d87[.]netlify[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fvermillion-scone-6c2d87.netlify.app%2F) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
