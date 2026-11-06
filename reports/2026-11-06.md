# Threat Intel Pulse — 2026-11-06

**Window:** last 7 days · **Generated:** 2026-11-06T07:03:08Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 81943 |
| New in window | 15408 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 27 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 614 | ok |
| tor | 10286 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 993 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 511 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 1397 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 38132 | 9539 |
| url | 22343 | 4062 |
| domain | 11505 | 1125 |
| sha256 | 5537 | 188 |
| ipv6 | 3723 | 464 |
| md5 | 398 | 30 |
| sha1 | 305 | 0 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 13002 |
| Exit nodes | 2422 |
| Other relays | 10580 |
| New in window | 2013 |

Sample (20 of 13002, source: Tor Project Onionoo):
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
| Vidar | 2789 | 0 | T1555, T1071.001, T1567 |
| IClickFix | 1333 | 0 | — |
| Mirai | 1278 | 0 | T1498, T1071.001 |
| Cobalt Strike | 1236 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| Unknown malware | 1182 | 0 | — |
| Unknown Loader | 842 | 0 | — |
| AMOS | 776 | 0 | — |
| VShell | 438 | 0 | — |
| PureRAT | 364 | 0 | — |
| ClearFake | 278 | 0 | — |
| Remus | 276 | 0 | — |
| MacSync | 254 | 0 | — |
| AdaptixC2 | 253 | 0 | — |
| php.shin_webshell | 225 | 0 | — |
| AsyncRAT | 222 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| Remcos | 217 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| DanaBot | 182 | 0 | T1566.001, T1071.001, T1555, T1041 |
| ClickFix | 166 | 72 | — |
| Sliver | 111 | 2 | T1071.001, T1573, T1090, T1055 |
| Evilginx | 95 | 2 | — |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1566 | Phishing | initial-access | 17863 |
| T1566.002 | Spearphishing Link | initial-access | 17863 |
| T1071.001 | Web Protocols | command-and-control | 56252 |
| T1105 | Ingress Tool Transfer | command-and-control | 8791 |
| T1573 | Encrypted Channel | command-and-control | 7271 |
| T1555 | Credentials from Password Stores | credential-access | 5116 |
| T1567 | Exfiltration Over Web Service | exfiltration | 4930 |
| T1498 | Network Denial of Service | impact | 4123 |
| T1552.001 | Credentials In Files | credential-access | 2361 |
| T1204.002 | Malicious File | execution | 1992 |
| T1027 | Obfuscated Files or Information | defense-evasion | 1990 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1436 |
| T1090 | Proxy | command-and-control | 1378 |
| T1059.001 | PowerShell | execution | 1246 |
| T1056.001 | Keylogging | collection, credential-access | 1227 |
| T1566.001 | Spearphishing Attachment | initial-access | 973 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 640 |
| T1113 | Screen Capture | collection | 600 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 234 |
| T1486 | Data Encrypted for Impact | impact | 43 |
| T1490 | Inhibit System Recovery | impact | 43 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 43 |
| T1059.005 | Visual Basic | execution | 28 |
| T1190 | Exploit Public-Facing Application | initial-access | 20 |
| T1189 | Drive-by Compromise | initial-access | 7 |
| T1218 | System Binary Proxy Execution | defense-evasion | 7 |
| T1003 | OS Credential Dumping | credential-access | 1 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://529motors[.]com/homepersonas/`](https://www.virustotal.com/gui/search/https%3A%2F%2F529motors.com%2Fhomepersonas%2F) | url | — | openphish, tweetfeed | 2026-11-05T11:05:08Z | 70 |
| [`hxxps://vemtasbobinaj[.]com/login[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fvemtasbobinaj.com%2Flogin.html) | url | — | openphish, tweetfeed | 2026-11-02T19:27:35Z | 70 |
| [`hxxps://auditormadrid[.]es/wp-content/mu-plugins/iklqzct/iuo/alibaba/?naps`](https://www.virustotal.com/gui/search/https%3A%2F%2Fauditormadrid.es%2Fwp-content%2Fmu-plugins%2Fiklqzct%2Fiuo%2Falibaba%2F%3Fnaps) | url | — | openphish, tweetfeed | 2026-11-01T13:14:43Z | 70 |
| [`hxxps://imediachile[.]cl/secupdf/10625[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fimediachile.cl%2Fsecupdf%2F10625.html) | url | — | openphish | — | 70 |
| [`hxxp://hse-review[.]top/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fhse-review.top%2F) | url | — | openphish | — | 70 |
| [`hxxps://phantom-app-4eu8[.]vercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fphantom-app-4eu8.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://doc--exxodus--web3[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fdoc--exxodus--web3.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://decen-tralises-exxod[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fdecen-tralises-exxod.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://vmi3505306[.]contaboserver[.]net/migzone/fix/sen/rena/details[.]php`](https://www.virustotal.com/gui/search/https%3A%2F%2Fvmi3505306.contaboserver.net%2Fmigzone%2Ffix%2Fsen%2Frena%2Fdetails.php) | url | — | openphish | — | 70 |
| [`hxxp://jrqwoukapy[.]1st-assylum[.]org/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fjrqwoukapy.1st-assylum.org%2F) | url | — | openphish | — | 70 |
| [`hxxp://creationstags[.]cfd/verify/897bfd43-7dd7-476a-bc03-12b078e00c00?error=login_required`](https://www.virustotal.com/gui/search/http%3A%2F%2Fcreationstags.cfd%2Fverify%2F897bfd43-7dd7-476a-bc03-12b078e00c00%3Ferror%3Dlogin_required) | url | — | openphish | — | 70 |
| [`hxxps://www[.]start-trezoio[.]teleporthq[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.start-trezoio.teleporthq.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://start-help--metsk[.]gitbook[.]io/us`](https://www.virustotal.com/gui/search/https%3A%2F%2Fstart-help--metsk.gitbook.io%2Fus) | url | — | openphish | — | 70 |
| [`hxxp://start-help--metsk[.]gitbook[.]io/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fstart-help--metsk.gitbook.io%2F) | url | — | openphish | — | 70 |
| [`hxxps://mydpd[.]vjrqv[.]help/track-ch/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmydpd.vjrqv.help%2Ftrack-ch%2F) | url | — | openphish | — | 70 |
| [`hxxps://sweetbrands[.]co/AT&T/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsweetbrands.co%2FAT%26T%2F) | url | — | openphish | — | 70 |
| [`hxxp://codmcp[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fcodmcp.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://mydpd[.]mklzn[.]top/track-ch`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmydpd.mklzn.top%2Ftrack-ch) | url | — | openphish | — | 70 |
| [`hxxps://mydpd[.]qkfpa[.]cc/track-ch`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmydpd.qkfpa.cc%2Ftrack-ch) | url | — | openphish | — | 70 |
| [`hxxp://couriersplease[.]addlic[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fcouriersplease.addlic.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://foptling[.]click/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ffoptling.click%2F) | url | — | openphish | — | 70 |
| [`hxxps://im-token[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fim-token.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://riachaudhary-dev[.]github[.]io/Netflix-landing-Page/`](https://www.virustotal.com/gui/search/https%3A%2F%2Friachaudhary-dev.github.io%2FNetflix-landing-Page%2F) | url | — | openphish | — | 70 |
| [`hxxps://effective-bassoon-u9wtt36t-simedarbyberhadprojects-creator[.]4everland[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Feffective-bassoon-u9wtt36t-simedarbyberhadprojects-creator.4everland.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://robiox[.]com[.]py/users/331781736427/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Frobiox.com.py%2Fusers%2F331781736427%2Fprofile) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
