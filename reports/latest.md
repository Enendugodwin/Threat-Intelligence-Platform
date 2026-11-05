# Threat Intel Pulse — 2026-11-05

**Window:** last 7 days · **Generated:** 2026-11-05T07:02:47Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 83381 |
| New in window | 15552 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 27 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 614 | ok |
| tor | 8801 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 622 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 514 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 1156 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 37140 | 9710 |
| url | 23648 | 4061 |
| domain | 11616 | 1133 |
| sha256 | 6457 | 185 |
| ipv6 | 3700 | 445 |
| md5 | 449 | 18 |
| sha1 | 371 | 0 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 12913 |
| Exit nodes | 2416 |
| Other relays | 10497 |
| New in window | 1951 |

Sample (20 of 12913, source: Tor Project Onionoo):
- `1[.]161[.]130[.]49`
- `1[.]201[.]176[.]169`
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

Full list: `dist/tor/tor_nodes.txt` (in the `threat-intel-output` workflow artifact).
## Top malware families

| Family | Indicators | New | ATT&CK (heuristic) |
| --- | --- | --- | --- |
| Vidar | 3753 | 0 | T1555, T1071.001, T1567 |
| IClickFix | 1498 | 0 | — |
| Mirai | 1346 | 0 | T1498, T1071.001 |
| Cobalt Strike | 1247 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| Unknown malware | 1209 | 0 | — |
| Unknown Loader | 874 | 0 | — |
| AMOS | 828 | 0 | — |
| VShell | 664 | 0 | — |
| PureRAT | 369 | 0 | — |
| ClearFake | 317 | 0 | — |
| Remus | 283 | 0 | — |
| php.shin_webshell | 273 | 0 | — |
| AdaptixC2 | 259 | 0 | — |
| Remcos | 258 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| MacSync | 255 | 0 | — |
| AsyncRAT | 241 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| DanaBot | 185 | 0 | T1566.001, T1071.001, T1555, T1041 |
| ClickFix | 166 | 72 | — |
| Sliver | 122 | 2 | T1071.001, T1573, T1090, T1055 |
| Formbook | 109 | 1 | T1566.001, T1056.001, T1555, T1071.001, T1567 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1566 | Phishing | initial-access | 17608 |
| T1566.002 | Spearphishing Link | initial-access | 17608 |
| T1071.001 | Web Protocols | command-and-control | 56728 |
| T1105 | Ingress Tool Transfer | command-and-control | 9923 |
| T1573 | Encrypted Channel | command-and-control | 7953 |
| T1555 | Credentials from Password Stores | credential-access | 6199 |
| T1567 | Exfiltration Over Web Service | exfiltration | 6010 |
| T1498 | Network Denial of Service | impact | 4283 |
| T1552.001 | Credentials In Files | credential-access | 3123 |
| T1204.002 | Malicious File | execution | 2863 |
| T1027 | Obfuscated Files or Information | defense-evasion | 2712 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1458 |
| T1090 | Proxy | command-and-control | 1401 |
| T1056.001 | Keylogging | collection, credential-access | 1379 |
| T1059.001 | PowerShell | execution | 1257 |
| T1566.001 | Spearphishing Attachment | initial-access | 1133 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 742 |
| T1113 | Screen Capture | collection | 702 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 255 |
| T1189 | Drive-by Compromise | initial-access | 159 |
| T1218 | System Binary Proxy Execution | defense-evasion | 159 |
| T1486 | Data Encrypted for Impact | impact | 43 |
| T1490 | Inhibit System Recovery | impact | 43 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 43 |
| T1059.005 | Visual Basic | execution | 25 |
| T1190 | Exploit Public-Facing Application | initial-access | 21 |
| T1003 | OS Credential Dumping | credential-access | 1 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://vemtasbobinaj[.]com/login[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fvemtasbobinaj.com%2Flogin.html) | url | — | openphish, tweetfeed | 2026-11-02T19:27:35Z | 70 |
| [`hxxps://auditormadrid[.]es/wp-content/mu-plugins/iklqzct/iuo/alibaba/?naps`](https://www.virustotal.com/gui/search/https%3A%2F%2Fauditormadrid.es%2Fwp-content%2Fmu-plugins%2Fiklqzct%2Fiuo%2Falibaba%2F%3Fnaps) | url | — | openphish, tweetfeed | 2026-11-01T13:14:43Z | 70 |
| [`hxxps://web-ldgrlive-desktop[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fweb-ldgrlive-desktop.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://digitalbr[.]myftp[.]org/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fdigitalbr.myftp.org%2F) | url | — | openphish | — | 70 |
| [`hxxps://free-consultoria[.]services/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ffree-consultoria.services%2F) | url | — | openphish | — | 70 |
| [`hxxps://security-server-page--richardgilbert3[.]replit[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsecurity-server-page--richardgilbert3.replit.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://apple-1xz[.]xyz/S9`](https://www.virustotal.com/gui/search/https%3A%2F%2Fapple-1xz.xyz%2FS9) | url | — | openphish | — | 70 |
| [`hxxps://ulonex-fursa-a7c109-wplm[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fulonex-fursa-a7c109-wplm.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://5m1p8z-8u5m9c-1z9p8m-qw999agreg[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2F5m1p8z-8u5m9c-1z9p8m-qw999agreg.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://sarnex-qulto-8ac913-hfbb-r0307raz[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsarnex-qulto-8ac913-hfbb-r0307raz.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://9k1p8m-8u5m9c-1p9m8z-qw644c24y[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2F9k1p8m-8u5m9c-1p9m8z-qw644c24y.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://3r9p1e-qw344c84y-2k8z1p9m2s-8s1m[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2F3r9p1e-qw344c84y-2k8z1p9m2s-8s1m.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://sp1ct10-hunval-biz-vumqo-zavri[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsp1ct10-hunval-biz-vumqo-zavri.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://marnex-qulto-8ac913-hfbb[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fmarnex-qulto-8ac913-hfbb.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://1s8q9g-qw177a-2z1p8k9m2s-fsgcyyhy[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2F1s8q9g-qw177a-2z1p8k9m2s-fsgcyyhy.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://8s2q8g-qw999agreg-mbtz1p8z9m2-fsgc[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2F8s2q8g-qw999agreg-mbtz1p8z9m2-fsgc.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://wktvz6e23pl-bcjfgyhy-0u7r1g-hp733a[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwktvz6e23pl-bcjfgyhy-0u7r1g-hp733a.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://nypkt6c73gp-sdrmja-2w6u0c-nypks18cf3f3[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fnypkt6c73gp-sdrmja-2w6u0c-nypks18cf3f3.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://sp1ct10-melvani-biz-zarkelo[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsp1ct10-melvani-biz-zarkelo.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://bkstr17asdf-ktpmqskr-5m1h3g-jks93c418[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fbkstr17asdf-ktpmqskr-5m1h3g-jks93c418.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://b26e-dj4-kpbz0-c2c-dukrc[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fb26e-dj4-kpbz0-c2c-dukrc.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://4r9p1e-8v2m9p1a-1k8zp9m2s4-3s8m[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2F4r9p1e-8v2m9p1a-1k8zp9m2s4-3s8m.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://4r1p9e-9v2m8p1a-mbtz1m8p9k2-3p4m[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2F4r1p9e-9v2m8p1a-mbtz1m8p9k2-3p4m.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://xnivok-trelna-2ed83f-vjbyh-6cb712-72o[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fxnivok-trelna-2ed83f-vjbyh-6cb712-72o.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://wtqpl31hwu-axcnh74fyn-4u2t8g-zm177c[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwtqpl31hwu-axcnh74fyn-4u2t8g-zm177c.pages.dev%2F) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
