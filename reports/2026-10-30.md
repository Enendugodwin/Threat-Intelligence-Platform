# Threat Intel Pulse — 2026-10-30

**Window:** last 7 days · **Generated:** 2026-10-30T13:13:24Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 86714 |
| New in window | 29927 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 614 | ok |
| tor | 8705 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 820 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 536 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 1294 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 30703 | 18688 |
| url | 28526 | 5672 |
| domain | 13659 | 5130 |
| sha256 | 9068 | 173 |
| ipv6 | 3398 | 199 |
| md5 | 714 | 65 |
| sha1 | 646 | 0 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 11806 |
| Exit nodes | 2266 |
| Other relays | 9540 |
| New in window | 915 |

Sample (20 of 11806, source: Tor Project Onionoo):
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
| Vidar | 5945 | 4 | T1555, T1071.001, T1567 |
| Mirai | 2046 | 0 | T1498, T1071.001 |
| IClickFix | 1976 | 0 | — |
| Unknown Loader | 1829 | 0 | — |
| Unknown malware | 1596 | 0 | — |
| Cobalt Strike | 1333 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| AMOS | 979 | 0 | — |
| ClearFake | 963 | 0 | — |
| VShell | 878 | 0 | — |
| php.shin_webshell | 538 | 0 | — |
| PureRAT | 416 | 0 | — |
| Sliver | 375 | 0 | T1071.001, T1573, T1090, T1055 |
| Remus | 327 | 0 | — |
| Unknown Stealer | 326 | 0 | — |
| Remcos | 322 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| AsyncRAT | 306 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| AdaptixC2 | 286 | 0 | — |
| MacSync | 256 | 0 | — |
| DanaBot | 191 | 0 | T1566.001, T1071.001, T1555, T1041 |
| Formbook | 166 | 11 | T1566.001, T1056.001, T1555, T1071.001, T1567 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1071.001 | Web Protocols | command-and-control | 56310 |
| T1566 | Phishing | initial-access | 16714 |
| T1566.002 | Spearphishing Link | initial-access | 16714 |
| T1105 | Ingress Tool Transfer | command-and-control | 14224 |
| T1555 | Credentials from Password Stores | credential-access | 9491 |
| T1567 | Exfiltration Over Web Service | exfiltration | 9296 |
| T1573 | Encrypted Channel | command-and-control | 8610 |
| T1498 | Network Denial of Service | impact | 5674 |
| T1552.001 | Credentials In Files | credential-access | 5425 |
| T1204.002 | Malicious File | execution | 4366 |
| T1027 | Obfuscated Files or Information | defense-evasion | 4214 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1836 |
| T1090 | Proxy | command-and-control | 1743 |
| T1056.001 | Keylogging | collection, credential-access | 1738 |
| T1566.001 | Spearphishing Attachment | initial-access | 1431 |
| T1059.001 | PowerShell | execution | 1343 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 942 |
| T1113 | Screen Capture | collection | 901 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 295 |
| T1189 | Drive-by Compromise | initial-access | 162 |
| T1218 | System Binary Proxy Execution | defense-evasion | 162 |
| T1059.005 | Visual Basic | execution | 38 |
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
| [`hxxps://www[.]in-patrika[.]vercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.in-patrika.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://amiable-someone-703260[.]framer[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Famiable-someone-703260.framer.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://9ervp-qmf-k9yx8-d15udr-omxlc[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2F9ervp-qmf-k9yx8-d15udr-omxlc.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://sp28ct-gurem-biz-qazel-zotek[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsp28ct-gurem-biz-qazel-zotek.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://hopeful-package-333853[.]framer[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhopeful-package-333853.framer.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://sp30ct10-zulreko-biz-kuremi[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsp30ct10-zulreko-biz-kuremi.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://653-f66w-ecv-90xi-rp3ec-ev79[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2F653-f66w-ecv-90xi-rp3ec-ev79.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://amt-hbegzz-vl70jk-gbb-y48ck[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Famt-hbegzz-vl70jk-gbb-y48ck.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://gcc-7f9acq-ppx1t-efke-945[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fgcc-7f9acq-ppx1t-efke-945.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://sp30ct10-ravkilo-biz-zumeti[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsp30ct10-ravkilo-biz-zumeti.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://du8d-0fiet-c1s5-8qwt5-r1f[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fdu8d-0fiet-c1s5-8qwt5-r1f.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://sp30ct10-rumvemi-biz-zakaro[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsp30ct10-rumvemi-biz-zakaro.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://qlq3f-9pwx8-xv2-621ljm-5b49o[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fqlq3f-9pwx8-xv2-621ljm-5b49o.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://sp30ct10-varkilo-biz-kumaro[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsp30ct10-varkilo-biz-kumaro.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://sp30ct10-kavzuni-biz-munelo[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsp30ct10-kavzuni-biz-munelo.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://68v-sr5v7-tjp9z-6t99-cy1[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2F68v-sr5v7-tjp9z-6t99-cy1.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://sp30ct10-varkilo-biz-kuneti[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsp30ct10-varkilo-biz-kuneti.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://sp29ct-vemru-biz-felti-korak[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsp29ct-vemru-biz-felti-korak.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://sp20ct10-davleko-biz-zunima[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsp20ct10-davleko-biz-zunima.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://sp30ct10-zulvemi-biz-zaneti[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsp30ct10-zulvemi-biz-zaneti.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://zbe6-8hqp-x6mwg0-1iefur-p6e[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fzbe6-8hqp-x6mwg0-1iefur-p6e.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://l0qz3-3zztuy-ikl-3fftz-kep[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fl0qz3-3zztuy-ikl-3fftz-kep.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://sp30ct10-lorvako-biz-zunati[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsp30ct10-lorvako-biz-zunati.pages.dev%2F) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
