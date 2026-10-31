# Threat Intel Pulse — 2026-10-31

**Window:** last 7 days · **Generated:** 2026-10-31T21:45:50Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 86322 |
| New in window | 31533 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 614 | ok |
| tor | 8695 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 372 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 542 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 1052 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 32202 | 20240 |
| url | 28211 | 5460 |
| domain | 12535 | 5372 |
| sha256 | 8666 | 182 |
| ipv6 | 3412 | 211 |
| md5 | 683 | 68 |
| sha1 | 613 | 0 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 11933 |
| Exit nodes | 2265 |
| Other relays | 9668 |
| New in window | 1018 |

Sample (20 of 11933, source: Tor Project Onionoo):
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
- `102[.]211[.]56[.]20`
- `102[.]211[.]56[.]25`

Full list: `dist/tor/tor_nodes.txt` (in the `threat-intel-output` workflow artifact).
## Top malware families

| Family | Indicators | New | ATT&CK (heuristic) |
| --- | --- | --- | --- |
| Vidar | 5920 | 4 | T1555, T1071.001, T1567 |
| Mirai | 1930 | 0 | T1498, T1071.001 |
| IClickFix | 1632 | 0 | — |
| Unknown malware | 1531 | 0 | — |
| Unknown Loader | 1433 | 0 | — |
| Cobalt Strike | 1321 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| AMOS | 957 | 0 | — |
| VShell | 868 | 0 | — |
| ClearFake | 531 | 0 | — |
| php.shin_webshell | 481 | 0 | — |
| PureRAT | 407 | 0 | — |
| Sliver | 375 | 0 | T1071.001, T1573, T1090, T1055 |
| Remcos | 313 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| Remus | 313 | 0 | — |
| AsyncRAT | 302 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| AdaptixC2 | 284 | 0 | — |
| MacSync | 256 | 0 | — |
| DanaBot | 190 | 0 | T1566.001, T1071.001, T1555, T1041 |
| SalatStealer | 150 | 0 | — |
| Formbook | 148 | 12 | T1566.001, T1056.001, T1555, T1071.001, T1567 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1071.001 | Web Protocols | command-and-control | 56064 |
| T1566 | Phishing | initial-access | 17202 |
| T1566.002 | Spearphishing Link | initial-access | 17202 |
| T1105 | Ingress Tool Transfer | command-and-control | 13748 |
| T1555 | Credentials from Password Stores | credential-access | 9278 |
| T1567 | Exfiltration Over Web Service | exfiltration | 9084 |
| T1573 | Encrypted Channel | command-and-control | 8637 |
| T1498 | Network Denial of Service | impact | 5337 |
| T1552.001 | Credentials In Files | credential-access | 5256 |
| T1204.002 | Malicious File | execution | 4299 |
| T1027 | Obfuscated Files or Information | defense-evasion | 4147 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1818 |
| T1090 | Proxy | command-and-control | 1731 |
| T1056.001 | Keylogging | collection, credential-access | 1673 |
| T1566.001 | Spearphishing Attachment | initial-access | 1382 |
| T1059.001 | PowerShell | execution | 1331 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 918 |
| T1113 | Screen Capture | collection | 878 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 289 |
| T1189 | Drive-by Compromise | initial-access | 162 |
| T1218 | System Binary Proxy Execution | defense-evasion | 162 |
| T1059.005 | Visual Basic | execution | 36 |
| T1486 | Data Encrypted for Impact | impact | 36 |
| T1490 | Inhibit System Recovery | impact | 36 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 36 |
| T1190 | Exploit Public-Facing Application | initial-access | 21 |
| T1021.001 | Remote Desktop Protocol | lateral-movement | 6 |
| T1003 | OS Credential Dumping | credential-access | 4 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://zoffry[.]qpon/Adb/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fzoffry.qpon%2FAdb%2F) | url | — | openphish, tweetfeed | 2026-10-29T13:22:48Z | 70 |
| [`hxxps://allegrolokalnie[.]aukcja865637302[.]cfd/oferta/1984-mz-etz-250/80344`](https://www.virustotal.com/gui/search/https%3A%2F%2Fallegrolokalnie.aukcja865637302.cfd%2Foferta%2F1984-mz-etz-250%2F80344) | url | — | openphish, tweetfeed | 2026-10-27T05:18:21Z | 70 |
| [`hxxps://www[.]roblox[.]ly/users/2112515059/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.ly%2Fusers%2F2112515059%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxps://u[.]gy/QULKD9`](https://www.virustotal.com/gui/search/https%3A%2F%2Fu.gy%2FQULKD9) | url | — | openphish | — | 70 |
| [`hxxp://tokinix-cdn6-jh[.]xyz/`](https://www.virustotal.com/gui/search/http%3A%2F%2Ftokinix-cdn6-jh.xyz%2F) | url | — | openphish | — | 70 |
| [`hxxps://checkforcopyrightinfringement[.]vercel[.]app/verify[.]html/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fcheckforcopyrightinfringement.vercel.app%2Fverify.html%2F) | url | — | openphish | — | 70 |
| [`hxxp://tributosreceita[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Ftributosreceita.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://ukoa0[.]sunny68[.]net/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fukoa0.sunny68.net%2F) | url | — | openphish | — | 70 |
| [`hxxp://blockbook-btc[.]sspwallet[.]io/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fblockbook-btc.sspwallet.io%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]shopee3989[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.shopee3989.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]tevxorin-lak294816573[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.tevxorin-lak294816573.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://seguridad-2026b65782[.]netlify[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fseguridad-2026b65782.netlify.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://wicksappsoauth[.]click/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwicksappsoauth.click%2F) | url | — | openphish | — | 70 |
| [`hxxp://security-server--faifranhondyout[.]replit[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsecurity-server--faifranhondyout.replit.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]caphaibuvoice[.]vercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.caphaibuvoice.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://tokinix-cdn6-hk14[.]xyz/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ftokinix-cdn6-hk14.xyz%2F) | url | — | openphish | — | 70 |
| [`hxxps://ilkevtoplu[.]com/giris[.]php`](https://www.virustotal.com/gui/search/https%3A%2F%2Filkevtoplu.com%2Fgiris.php) | url | — | openphish | — | 70 |
| [`hxxps://hmade40f-del[.]github[.]io/ilnstagram/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhmade40f-del.github.io%2Filnstagram%2F) | url | — | openphish | — | 70 |
| [`hxxps://palmanojit07-cyber[.]github[.]io/Ui-clone/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fpalmanojit07-cyber.github.io%2FUi-clone%2F) | url | — | openphish | — | 70 |
| [`hxxps://cpg47[.]ph23-ph[.]net/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fcpg47.ph23-ph.net%2F) | url | — | openphish | — | 70 |
| [`hxxp://faiceboikonlineshoip[.]cc/`](https://www.virustotal.com/gui/search/http%3A%2F%2Ffaiceboikonlineshoip.cc%2F) | url | — | openphish | — | 70 |
| [`hxxps://page-ledger-cdn[.]typedream[.]app/en-us`](https://www.virustotal.com/gui/search/https%3A%2F%2Fpage-ledger-cdn.typedream.app%2Fen-us) | url | — | openphish | — | 70 |
| [`hxxps://microsoftconfig-3[.]vercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmicrosoftconfig-3.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://tokanim-cdny5-ks[.]sbs/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ftokanim-cdny5-ks.sbs%2F) | url | — | openphish | — | 70 |
| [`hxxps://tokinim-cdn76-hkj[.]xyz/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ftokinim-cdn76-hkj.xyz%2F) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
