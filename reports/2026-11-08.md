# Threat Intel Pulse — 2026-11-08

**Window:** last 7 days · **Generated:** 2026-11-08T22:17:15Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 79321 |
| New in window | 15863 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 27 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 614 | ok |
| tor | 10178 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 1630 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 511 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 1925 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 40724 | 9557 |
| url | 20015 | 4110 |
| domain | 10856 | 1495 |
| ipv6 | 3768 | 468 |
| sha256 | 3591 | 207 |
| md5 | 232 | 26 |
| sha1 | 135 | 0 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 13193 |
| Exit nodes | 2434 |
| Other relays | 10759 |
| New in window | 1997 |

Sample (20 of 13193, source: Tor Project Onionoo):
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
| ClickFix | 200 | 102 | — |
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
| T1566 | Phishing | initial-access | 18792 |
| T1566.002 | Spearphishing Link | initial-access | 18792 |
| T1071.001 | Web Protocols | command-and-control | 54821 |
| T1105 | Ingress Tool Transfer | command-and-control | 6809 |
| T1573 | Encrypted Channel | command-and-control | 6718 |
| T1498 | Network Denial of Service | impact | 3131 |
| T1555 | Credentials from Password Stores | credential-access | 3085 |
| T1567 | Exfiltration Over Web Service | exfiltration | 2902 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1359 |
| T1090 | Proxy | command-and-control | 1320 |
| T1059.001 | PowerShell | execution | 1213 |
| T1552.001 | Credentials In Files | credential-access | 1192 |
| T1056.001 | Keylogging | collection, credential-access | 1040 |
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
| [`hxxps://www[.]instagramcom-weld[.]vercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.instagramcom-weld.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]com[.]ml/users/438014914332/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.com.ml%2Fusers%2F438014914332%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxps://skylanai[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fskylanai.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://internationaldatasystems[.]ca/speed/`](https://www.virustotal.com/gui/search/https%3A%2F%2Finternationaldatasystems.ca%2Fspeed%2F) | url | — | openphish | — | 70 |
| [`hxxp://connect[.]mytonwallet[.]org/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fconnect.mytonwallet.org%2F) | url | — | openphish | — | 70 |
| [`hxxp://vpn[.]spheremama[.]com/index[.]html`](https://www.virustotal.com/gui/search/http%3A%2F%2Fvpn.spheremama.com%2Findex.html) | url | — | openphish | — | 70 |
| [`hxxp://jacog60r[.]spheremama[.]com/index[.]html`](https://www.virustotal.com/gui/search/http%3A%2F%2Fjacog60r.spheremama.com%2Findex.html) | url | — | openphish | — | 70 |
| [`hxxps://vendors[.]spheremama[.]com/index[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fvendors.spheremama.com%2Findex.html) | url | — | openphish | — | 70 |
| [`hxxps://operator[.]zh5-app-ayxsports[.]com/index[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Foperator.zh5-app-ayxsports.com%2Findex.html) | url | — | openphish | — | 70 |
| [`hxxps://qtlm[.]spheremama[.]com/index[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fqtlm.spheremama.com%2Findex.html) | url | — | openphish | — | 70 |
| [`hxxp://6tg19ha5[.]sanpinjia[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2F6tg19ha5.sanpinjia.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://231mbutu5udwntnq[.]spheremama[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2F231mbutu5udwntnq.spheremama.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://z28ae00t218otkz2[.]spheremama[.]com/index[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fz28ae00t218otkz2.spheremama.com%2Findex.html) | url | — | openphish | — | 70 |
| [`hxxp://567787[.]spheremama[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2F567787.spheremama.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://promo[.]sanpinjia[.]com/index[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fpromo.sanpinjia.com%2Findex.html) | url | — | openphish | — | 70 |
| [`hxxp://e8y3qufn[.]sanpinjia[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fe8y3qufn.sanpinjia.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://file[.]spheremama[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ffile.spheremama.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]rw/users/696317506556/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.rw%2Fusers%2F696317506556%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxps://g5[.]lu/zdnwx`](https://www.virustotal.com/gui/search/https%3A%2F%2Fg5.lu%2Fzdnwx) | url | — | openphish | — | 70 |
| [`hxxps://etransfer-accept[.]duckdns[.]org/captcha[.]php`](https://www.virustotal.com/gui/search/https%3A%2F%2Fetransfer-accept.duckdns.org%2Fcaptcha.php) | url | — | openphish | — | 70 |
| [`hxxps://kjfycvb5[.]sanpinjia[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fkjfycvb5.sanpinjia.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://g5[.]lu/sqnwb`](https://www.virustotal.com/gui/search/https%3A%2F%2Fg5.lu%2Fsqnwb) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]rw/users/788171715760/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.rw%2Fusers%2F788171715760%2Fprofile) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
