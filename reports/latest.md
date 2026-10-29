# Threat Intel Pulse — 2026-10-29

**Window:** last 7 days · **Generated:** 2026-10-29T06:03:34Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 87381 |
| New in window | 27553 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8673 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 430 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 524 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 1298 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 29191 | 17018 |
| url | 29158 | 5254 |
| domain | 14072 | 4845 |
| sha256 | 9967 | 146 |
| ipv6 | 3392 | 232 |
| md5 | 831 | 58 |
| sha1 | 770 | 0 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 11789 |
| Exit nodes | 2268 |
| Other relays | 9521 |
| New in window | 948 |

Sample (20 of 11789, source: Tor Project Onionoo):
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
| Vidar | 6045 | 4 | T1555, T1071.001, T1567 |
| Mirai | 2196 | 0 | T1498, T1071.001 |
| IClickFix | 2066 | 0 | — |
| Unknown Loader | 2025 | 0 | — |
| Unknown malware | 1652 | 0 | — |
| Cobalt Strike | 1341 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| ClearFake | 1091 | 0 | — |
| AMOS | 1005 | 0 | — |
| VShell | 887 | 0 | — |
| php.shin_webshell | 620 | 0 | — |
| Unknown Stealer | 492 | 0 | — |
| PureRAT | 429 | 0 | — |
| Sliver | 375 | 0 | T1071.001, T1573, T1090, T1055 |
| Remus | 357 | 0 | — |
| Remcos | 345 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| AsyncRAT | 314 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| AdaptixC2 | 292 | 0 | — |
| MacSync | 256 | 0 | — |
| DanaBot | 192 | 0 | T1566.001, T1071.001, T1555, T1041 |
| Formbook | 184 | 11 | T1566.001, T1056.001, T1555, T1071.001, T1567 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1071.001 | Web Protocols | command-and-control | 56185 |
| T1566 | Phishing | initial-access | 16131 |
| T1566.002 | Spearphishing Link | initial-access | 16131 |
| T1105 | Ingress Tool Transfer | command-and-control | 15115 |
| T1555 | Credentials from Password Stores | credential-access | 9782 |
| T1567 | Exfiltration Over Web Service | exfiltration | 9586 |
| T1573 | Encrypted Channel | command-and-control | 8383 |
| T1498 | Network Denial of Service | impact | 6279 |
| T1552.001 | Credentials In Files | credential-access | 5594 |
| T1204.002 | Malicious File | execution | 4615 |
| T1027 | Obfuscated Files or Information | defense-evasion | 4463 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1847 |
| T1056.001 | Keylogging | collection, credential-access | 1827 |
| T1090 | Proxy | command-and-control | 1753 |
| T1566.001 | Spearphishing Attachment | initial-access | 1499 |
| T1059.001 | PowerShell | execution | 1353 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 989 |
| T1113 | Screen Capture | collection | 941 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 302 |
| T1189 | Drive-by Compromise | initial-access | 165 |
| T1218 | System Binary Proxy Execution | defense-evasion | 165 |
| T1059.005 | Visual Basic | execution | 38 |
| T1486 | Data Encrypted for Impact | impact | 33 |
| T1490 | Inhibit System Recovery | impact | 33 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 33 |
| T1190 | Exploit Public-Facing Application | initial-access | 21 |
| T1021.001 | Remote Desktop Protocol | lateral-movement | 9 |
| T1003 | OS Credential Dumping | credential-access | 4 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://allegrolokalnie[.]aukcja865637302[.]cfd/oferta/1984-mz-etz-250/80344`](https://www.virustotal.com/gui/search/https%3A%2F%2Fallegrolokalnie.aukcja865637302.cfd%2Foferta%2F1984-mz-etz-250%2F80344) | url | — | openphish, tweetfeed | 2026-10-27T05:18:21Z | 70 |
| [`hxxp://echallan[.]party/install`](https://www.virustotal.com/gui/search/http%3A%2F%2Fechallan.party%2Finstall) | url | — | openphish, tweetfeed | 2026-10-21T19:01:12Z | 70 |
| [`hxxps://my-top-juno-webmail-site[.]webflow[.]io/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmy-top-juno-webmail-site.webflow.io%2F) | url | — | openphish | — | 70 |
| [`hxxps://g5[.]lu/tyc4k`](https://www.virustotal.com/gui/search/https%3A%2F%2Fg5.lu%2Ftyc4k) | url | — | openphish | — | 70 |
| [`hxxp://bridge-browser[.]framer[.]website/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fbridge-browser.framer.website%2F) | url | — | openphish | — | 70 |
| [`hxxp://new-indexproject[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fnew-indexproject.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://sp25ct-zunelo-biz-mareku-vorik[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsp25ct-zunelo-biz-mareku-vorik.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://sp28ct-gazur-biz-zemav-vitek[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsp28ct-gazur-biz-zemav-vitek.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://zktp25c80sk-mvrn8wur-1r6p8d-yw611a[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fzktp25c80sk-mvrn8wur-1r6p8d-yw611a.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://trezorbridge[.]framer[.]website/`](https://www.virustotal.com/gui/search/http%3A%2F%2Ftrezorbridge.framer.website%2F) | url | — | openphish | — | 70 |
| [`hxxp://sp28ct-farel-biz-vumel-zitek[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsp28ct-farel-biz-vumel-zitek.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://marlavi-kxt-belfeta-c5x7dp83[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmarlavi-kxt-belfeta-c5x7dp83.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://vnxld71dran-ylktp55lpw-1m3k8d-qj2294m[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fvnxld71dran-ylktp55lpw-1m3k8d-qj2294m.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://qbxj552skrp-ywsd7yw-3p6p0e-qbx99c[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fqbxj552skrp-ywsd7yw-3p6p0e-qbx99c.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://zktp28fdran-ywsd7lpw-1n4l6d-yw288a[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fzktp28fdran-ywsd7lpw-1n4l6d-yw288a.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://sp18ct10-wulvak-biz-qenari[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsp18ct10-wulvak-biz-qenari.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://sp26ct-zumki-biz-rulen-mavko[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsp26ct-zumki-biz-rulen-mavko.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://qbxj52b68dr-ywsd7pli-3n4l8g-qbx29c[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fqbxj52b68dr-ywsd7pli-3n4l8g-qbx29c.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://sp28ct-gunem-biz-zorel-ranek[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsp28ct-gunem-biz-zorel-ranek.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://qbxj54avstr-hlgf4mja-3q2p4g-qbx03c[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fqbxj54avstr-hlgf4mja-3q2p4g-qbx03c.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://mvrn8625nhw-hlgf4fyn-5q0p2g-zk166a[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmvrn8625nhw-hlgf4fyn-5q0p2g-zk166a.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://ql3e20-jmpl91-61tvz-re4o8[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fql3e20-jmpl91-61tvz-re4o8.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://vnxld72cqjr-ylktp64ylk-0q4n2d-bcf51t[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fvnxld72cqjr-ylktp64ylk-0q4n2d-bcf51t.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://quitarhojecomdesconto[.]shop/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fquitarhojecomdesconto.shop%2F) | url | — | openphish | — | 70 |
| [`hxxp://repairing[.]game-en[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Frepairing.game-en.com%2F) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
