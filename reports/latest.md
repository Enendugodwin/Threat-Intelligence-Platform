# Threat Intel Pulse — 2026-10-28

**Window:** last 7 days · **Generated:** 2026-10-28T13:14:58Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 89213 |
| New in window | 26304 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8676 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 525 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 515 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 1316 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 29360 | 5137 |
| ipv4 | 28343 | 16118 |
| domain | 16108 | 4621 |
| sha256 | 10231 | 135 |
| ipv6 | 3408 | 245 |
| md5 | 907 | 48 |
| sha1 | 856 | 0 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 11828 |
| Exit nodes | 2266 |
| Other relays | 9562 |
| New in window | 969 |

Sample (20 of 11828, source: Tor Project Onionoo):
- `1[.]201[.]176[.]176`
- `1[.]235[.]159[.]83`
- `1[.]248[.]96[.]163`
- `1[.]34[.]44[.]234`
- `100[.]1[.]157[.]56`
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

Full list: `dist/tor/tor_nodes.txt` (in the `threat-intel-output` workflow artifact).
## Top malware families

| Family | Indicators | New | ATT&CK (heuristic) |
| --- | --- | --- | --- |
| Vidar | 6103 | 4 | T1555, T1071.001, T1567 |
| Unknown Loader | 3406 | 0 | — |
| IClickFix | 2408 | 0 | — |
| Mirai | 2198 | 0 | T1498, T1071.001 |
| Unknown malware | 1672 | 0 | — |
| ClearFake | 1584 | 0 | — |
| Cobalt Strike | 1342 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| AMOS | 1017 | 0 | — |
| VShell | 896 | 0 | — |
| php.shin_webshell | 642 | 0 | — |
| Unknown Stealer | 492 | 0 | — |
| PureRAT | 431 | 0 | — |
| Sliver | 384 | 0 | T1071.001, T1573, T1090, T1055 |
| Remus | 358 | 0 | — |
| Remcos | 354 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| AsyncRAT | 330 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| AdaptixC2 | 296 | 0 | — |
| MacSync | 256 | 0 | — |
| Formbook | 217 | 11 | T1566.001, T1056.001, T1555, T1071.001, T1567 |
| DanaBot | 192 | 0 | T1566.001, T1071.001, T1555, T1041 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1071.001 | Web Protocols | command-and-control | 57718 |
| T1566 | Phishing | initial-access | 15813 |
| T1566.002 | Spearphishing Link | initial-access | 15813 |
| T1105 | Ingress Tool Transfer | command-and-control | 15466 |
| T1555 | Credentials from Password Stores | credential-access | 9889 |
| T1567 | Exfiltration Over Web Service | exfiltration | 9693 |
| T1573 | Encrypted Channel | command-and-control | 8253 |
| T1498 | Network Denial of Service | impact | 6298 |
| T1552.001 | Credentials In Files | credential-access | 5611 |
| T1204.002 | Malicious File | execution | 4962 |
| T1027 | Obfuscated Files or Information | defense-evasion | 4810 |
| T1056.001 | Keylogging | collection, credential-access | 1910 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1859 |
| T1090 | Proxy | command-and-control | 1763 |
| T1566.001 | Spearphishing Attachment | initial-access | 1572 |
| T1059.001 | PowerShell | execution | 1354 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 1028 |
| T1113 | Screen Capture | collection | 980 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 303 |
| T1189 | Drive-by Compromise | initial-access | 166 |
| T1218 | System Binary Proxy Execution | defense-evasion | 166 |
| T1059.005 | Visual Basic | execution | 38 |
| T1486 | Data Encrypted for Impact | impact | 35 |
| T1490 | Inhibit System Recovery | impact | 35 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 35 |
| T1190 | Exploit Public-Facing Application | initial-access | 21 |
| T1021.001 | Remote Desktop Protocol | lateral-movement | 12 |
| T1003 | OS Credential Dumping | credential-access | 4 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://allegrolokalnie[.]aukcja865637302[.]cfd/oferta/1984-mz-etz-250/80344`](https://www.virustotal.com/gui/search/https%3A%2F%2Fallegrolokalnie.aukcja865637302.cfd%2Foferta%2F1984-mz-etz-250%2F80344) | url | — | openphish, tweetfeed | 2026-10-27T05:18:21Z | 70 |
| [`hxxp://echallan[.]party/install`](https://www.virustotal.com/gui/search/http%3A%2F%2Fechallan.party%2Finstall) | url | — | openphish, tweetfeed | 2026-10-21T19:01:12Z | 70 |
| [`hxxps://www[.]anz-internetbanking[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.anz-internetbanking.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]authenticateuseridentity[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.authenticateuseridentity.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://aminu-gal-expenses[.]netlify[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Faminu-gal-expenses.netlify.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://sp28ct-dureq-biz-qamel-ranek[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsp28ct-dureq-biz-qamel-ranek.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://sp26ct10-zulvako-biz-taremi[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsp26ct10-zulvako-biz-taremi.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://lfax-y8p8-5gbqr3-l2gc4j-89bu[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Flfax-y8p8-5gbqr3-l2gc4j-89bu.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://sp28ct-garem-biz-zumel-qitek[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsp28ct-garem-biz-zumel-qitek.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://murvik-tensha-e4a8d1-gb1504hh-h2406wne[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmurvik-tensha-e4a8d1-gb1504hh-h2406wne.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://sp24ct-nelo-biz-kavor-muki[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsp24ct-nelo-biz-kavor-muki.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://qavfari-mpt-xelzoro-k6d3pe95[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fqavfari-mpt-xelzoro-k6d3pe95.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://b00j6-ec8l0f-kv2u-vfpn-tn4[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fb00j6-ec8l0f-kv2u-vfpn-tn4.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://sp20ct10-korvemo-biz-lunati[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsp20ct10-korvemo-biz-lunati.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://index-catty-neww[.]vercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Findex-catty-neww.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://sp28ct-dunav-biz-zorel-qatek[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsp28ct-dunav-biz-zorel-qatek.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://sp28ct-fanur-biz-qozem-vitek[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsp28ct-fanur-biz-qozem-vitek.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://sp28ct-vunor-biz-qalem-zirek[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsp28ct-vunor-biz-qalem-zirek.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://sp26ct10-davmelo-biz-kunati[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsp26ct10-davmelo-biz-kunati.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://sp26ct10-melvemi-biz-dunaro[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsp26ct10-melvemi-biz-dunaro.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://sp26ct10-rumrako-biz-lumeni[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsp26ct10-rumrako-biz-lumeni.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://sp26ct10-velvako-biz-kumari[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsp26ct10-velvako-biz-kumari.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://sp28ct-murev-biz-qazun-zolek[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsp28ct-murev-biz-qazun-zolek.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://sp28ct-bulem-biz-qazev-zotek[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsp28ct-bulem-biz-qazev-zotek.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://sp26ct10-kavzelo-biz-rumani[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsp26ct10-kavzelo-biz-rumani.pages.dev%2F) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
