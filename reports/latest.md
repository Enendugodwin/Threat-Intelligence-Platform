# Threat Intel Pulse — 2026-11-26

**Window:** last 7 days · **Generated:** 2026-11-26T08:38:57Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 69471 |
| New in window | 12981 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 23 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 314 | ok |
| tor | 10206 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 475 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 568 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 1745 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 43960 | 7211 |
| url | 13098 | 4208 |
| domain | 7691 | 1139 |
| ipv6 | 3818 | 151 |
| sha256 | 733 | 214 |
| md5 | 171 | 58 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 13288 |
| Exit nodes | 2477 |
| Other relays | 10811 |
| New in window | 802 |

Sample (20 of 13288, source: Tor Project Onionoo):
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
| ClickFix | 411 | 126 | — |
| cryptoscam | 108 | 10 | — |
| Kimsuky | 82 | 26 | — |
| Formbook | 58 | 16 | T1566.001, T1056.001, T1555, T1071.001, T1567 |
| AiTM | 29 | 13 | — |
| Vidar | 21 | 0 | T1555, T1071.001, T1567 |
| Remcos | 19 | 4 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| ValleyRAT | 12 | 12 | — |
| infostealer | 12 | 5 | — |
| Cobalt Strike | 8 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| GuLoader | 8 | 0 | T1027, T1059.005, T1055, T1105 |
| Mirai | 7 | 0 | T1498, T1071.001 |
| Unknown malware | 6 | 0 | — |
| Evilginx | 4 | 0 | — |
| MustangPanda | 4 | 0 | — |
| QakBot | 4 | 0 | T1566.001, T1204.002, T1055, T1071.001, T1105, T1027, T1041 |
| Sliver | 4 | 0 | T1071.001, T1573, T1090, T1055 |
| Mispadu | 3 | 3 | — |
| PHP2Shell | 3 | 0 | — |
| Xworm | 3 | 2 | — |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1566 | Phishing | initial-access | 17790 |
| T1566.002 | Spearphishing Link | initial-access | 17790 |
| T1071.001 | Web Protocols | command-and-control | 50766 |
| T1573 | Encrypted Channel | command-and-control | 5861 |
| T1555 | Credentials from Password Stores | credential-access | 180 |
| T1567 | Exfiltration Over Web Service | exfiltration | 180 |
| T1552.001 | Credentials In Files | credential-access | 122 |
| T1056.001 | Keylogging | collection, credential-access | 111 |
| T1486 | Data Encrypted for Impact | impact | 90 |
| T1490 | Inhibit System Recovery | impact | 90 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 90 |
| T1566.001 | Spearphishing Attachment | initial-access | 83 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 25 |
| T1105 | Ingress Tool Transfer | command-and-control | 25 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 20 |
| T1113 | Screen Capture | collection | 19 |
| T1027 | Obfuscated Files or Information | defense-evasion | 14 |
| T1204.002 | Malicious File | execution | 14 |
| T1090 | Proxy | command-and-control | 12 |
| T1059.005 | Visual Basic | execution | 9 |
| T1498 | Network Denial of Service | impact | 9 |
| T1059.001 | PowerShell | execution | 8 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 5 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://bgbmail-gov[.]dgfiprotocolbd[.]workers[.]dev/login/?dhsfiourewjdfjgkfdgkldfjiorejfdjgfdgjkdfjgreioo=1`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbgbmail-gov.dgfiprotocolbd.workers.dev%2Flogin%2F%3Fdhsfiourewjdfjgkfdgkldfjiorejfdjgfdgjkdfjgreioo%3D1) | url | — | openphish, tweetfeed | 2026-11-25T17:46:08Z | 70 |
| [`hxxps://f005[.]backblazeb2[.]com/file/0000055/SignintoXfinity[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Ff005.backblazeb2.com%2Ffile%2F0000055%2FSignintoXfinity.html) | url | — | openphish, tweetfeed | 2026-11-23T02:02:14Z | 70 |
| [`hxxp://ns1[.]az/c6/alibaba/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fns1.az%2Fc6%2Falibaba%2F) | url | — | openphish, tweetfeed | 2026-11-22T13:00:57Z | 70 |
| [`hxxps://fresh-network-276970[.]framer[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ffresh-network-276970.framer.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://opontocoleta[.]shop/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fopontocoleta.shop%2F) | url | — | openphish | — | 70 |
| [`hxxps://roblox[.]ly/users/3670776404/profilemalwarenetworkurl/`](https://www.virustotal.com/gui/search/https%3A%2F%2Froblox.ly%2Fusers%2F3670776404%2Fprofilemalwarenetworkurl%2F) | url | — | openphish | — | 70 |
| [`hxxps://facebookaccount1234[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ffacebookaccount1234.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://instagram-zeta[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Finstagram-zeta.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://garenafreefireofficialwebsite111[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fgarenafreefireofficialwebsite111.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://1avpc1-cma00uzf0-intelligence-agentic-models[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2F1avpc1-cma00uzf0-intelligence-agentic-models.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://savicafile-masscom[.]wasmer[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsavicafile-masscom.wasmer.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://1avpc1[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2F1avpc1.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://knf9704-crypto[.]github[.]io/redirect-bloxfruits`](https://www.virustotal.com/gui/search/https%3A%2F%2Fknf9704-crypto.github.io%2Fredirect-bloxfruits) | url | — | openphish | — | 70 |
| [`hxxp://www[.]vngiuu[.]top/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.vngiuu.top%2F) | url | — | openphish | — | 70 |
| [`hxxps://facebookhints[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ffacebookhints.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]facebookhints[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.facebookhints.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://agenciaricco[.]com/lang`](https://www.virustotal.com/gui/search/http%3A%2F%2Fagenciaricco.com%2Flang) | url | — | openphish | — | 70 |
| [`hxxp://imtcken[.]cn/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fimtcken.cn%2F) | url | — | openphish | — | 70 |
| [`hxxp://uspsofficialdelivery[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fuspsofficialdelivery.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://connect-live-wallet[.]typedream[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fconnect-live-wallet.typedream.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://sp18ct10-lavrok-biz-zunari[.]pages[.]dev/send_appeal_request/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsp18ct10-lavrok-biz-zunari.pages.dev%2Fsend_appeal_request%2F) | url | — | openphish | — | 70 |
| [`hxxp://customer-sp-logandaviau1[.]pages[.]dev/help/contact/390849720685817appealsappeals/submit-appeal-form/return`](https://www.virustotal.com/gui/search/http%3A%2F%2Fcustomer-sp-logandaviau1.pages.dev%2Fhelp%2Fcontact%2F390849720685817appealsappeals%2Fsubmit-appeal-form%2Freturn) | url | — | openphish | — | 70 |
| [`hxxp://sp21ct-morav-biz-zeli-kupa[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsp21ct-morav-biz-zeli-kupa.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]facebook-esp[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.facebook-esp.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://facebook-esp[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ffacebook-esp.blogspot.com%2F) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
