# Threat Intel Pulse — 2026-11-19

**Window:** last 7 days · **Generated:** 2026-11-19T07:40:32Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 68972 |
| New in window | 14844 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 23 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 314 | ok |
| tor | 10355 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 722 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 588 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 2059 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 43742 | 8236 |
| url | 12934 | 4916 |
| domain | 7692 | 1190 |
| ipv6 | 3817 | 209 |
| sha256 | 631 | 220 |
| md5 | 156 | 73 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 13351 |
| Exit nodes | 2460 |
| Other relays | 10891 |
| New in window | 973 |

Sample (20 of 13351, source: Tor Project Onionoo):
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
- `101[.]186[.]183[.]53`
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
| ClickFix | 286 | 84 | — |
| cryptoscam | 106 | 2 | — |
| Kimsuky | 64 | 44 | — |
| Formbook | 42 | 1 | T1566.001, T1056.001, T1555, T1071.001, T1567 |
| Vidar | 25 | 0 | T1555, T1071.001, T1567 |
| DPRK | 18 | 0 | — |
| AiTM | 16 | 8 | — |
| Remcos | 16 | 10 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| PHP2Shell | 12 | 1 | — |
| Cobalt Strike | 9 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| NetSupport | 9 | 0 | — |
| GuLoader | 8 | 0 | T1027, T1059.005, T1055, T1105 |
| Mirai | 8 | 0 | T1498, T1071.001 |
| infostealer | 7 | 3 | — |
| Unknown malware | 6 | 0 | — |
| Sliver | 5 | 0 | T1071.001, T1573, T1090, T1055 |
| Evilginx | 4 | 2 | — |
| MustangPanda | 4 | 4 | — |
| QakBot | 4 | 0 | T1566.001, T1204.002, T1055, T1071.001, T1105, T1027, T1041 |
| ValleyRAT | 3 | 0 | — |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1566 | Phishing | initial-access | 17687 |
| T1566.002 | Spearphishing Link | initial-access | 17687 |
| T1071.001 | Web Protocols | command-and-control | 50470 |
| T1573 | Encrypted Channel | command-and-control | 5568 |
| T1555 | Credentials from Password Stores | credential-access | 147 |
| T1567 | Exfiltration Over Web Service | exfiltration | 147 |
| T1486 | Data Encrypted for Impact | impact | 108 |
| T1490 | Inhibit System Recovery | impact | 108 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 108 |
| T1552.001 | Credentials In Files | credential-access | 101 |
| T1056.001 | Keylogging | collection, credential-access | 87 |
| T1566.001 | Spearphishing Attachment | initial-access | 64 |
| T1105 | Ingress Tool Transfer | command-and-control | 28 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 27 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 17 |
| T1113 | Screen Capture | collection | 16 |
| T1027 | Obfuscated Files or Information | defense-evasion | 15 |
| T1204.002 | Malicious File | execution | 15 |
| T1090 | Proxy | command-and-control | 14 |
| T1498 | Network Denial of Service | impact | 10 |
| T1059.001 | PowerShell | execution | 9 |
| T1059.005 | Visual Basic | execution | 9 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 5 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://auth0-google[.]com/2step[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fauth0-google.com%2F2step.html) | url | AiTM | openphish, tweetfeed | 2026-11-18T17:18:56Z | 70 |
| [`hxxps://icloudvsmapalocaliza[.]click/isignesp[.]php?correo=-&id=172974`](https://www.virustotal.com/gui/search/https%3A%2F%2Ficloudvsmapalocaliza.click%2Fisignesp.php%3Fcorreo%3D-%26id%3D172974) | url | — | openphish, tweetfeed | 2026-11-18T16:27:54Z | 70 |
| [`hxxp://conatem[.]com/adobeStudio[.]html`](https://www.virustotal.com/gui/search/http%3A%2F%2Fconatem.com%2FadobeStudio.html) | url | — | openphish, tweetfeed | 2026-11-18T03:56:46Z | 70 |
| [`hxxps://lapaca[.]webdirecto[.]com/wp-includes/Text/tdweain/yogsqwj/gmehpir/ggg/adobe/adobe[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Flapaca.webdirecto.com%2Fwp-includes%2FText%2Ftdweain%2Fyogsqwj%2Fgmehpir%2Fggg%2Fadobe%2Fadobe.html) | url | — | openphish, tweetfeed | 2026-11-14T16:01:48Z | 70 |
| [`hxxp://support-center-apple[.]wasmer[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsupport-center-apple.wasmer.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://netflix-ui-clone-vikas[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fnetflix-ui-clone-vikas.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://mystorage-admin-signreview[.]b-cdn[.]net/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmystorage-admin-signreview.b-cdn.net%2F) | url | — | openphish | — | 70 |
| [`hxxps://s4w[.]in/lPLAP`](https://www.virustotal.com/gui/search/https%3A%2F%2Fs4w.in%2FlPLAP) | url | — | openphish | — | 70 |
| [`hxxp://rentzimmer2[.]de/`](https://www.virustotal.com/gui/search/http%3A%2F%2Frentzimmer2.de%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]attmail8566575[.]weebly[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.attmail8566575.weebly.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://pl-payu-paczka[.]biz[.]id/viewer/bWlsbGVubml1bQ/Ml8w/2eDiihr9zO`](https://www.virustotal.com/gui/search/http%3A%2F%2Fpl-payu-paczka.biz.id%2Fviewer%2FbWlsbGVubml1bQ%2FMl8w%2F2eDiihr9zO) | url | — | openphish | — | 70 |
| [`hxxp://pl-payu-paczka[.]web[.]id/viewer/bWlsbGVubml1bQ/Ml8w/2eDiihr9zO`](https://www.virustotal.com/gui/search/http%3A%2F%2Fpl-payu-paczka.web.id%2Fviewer%2FbWlsbGVubml1bQ%2FMl8w%2F2eDiihr9zO) | url | — | openphish | — | 70 |
| [`hxxp://adspageactiveaccount[.]pages[.]dev/creators/appeals/submit-appeal-form/return`](https://www.virustotal.com/gui/search/http%3A%2F%2Fadspageactiveaccount.pages.dev%2Fcreators%2Fappeals%2Fsubmit-appeal-form%2Freturn) | url | — | openphish | — | 70 |
| [`hxxp://ralka-devon-biz-qenmar-soltek-sp9ct12[.]pages[.]dev/appeals/submit-appeal-form/return`](https://www.virustotal.com/gui/search/http%3A%2F%2Fralka-devon-biz-qenmar-soltek-sp9ct12.pages.dev%2Fappeals%2Fsubmit-appeal-form%2Freturn) | url | — | openphish | — | 70 |
| [`hxxps://ralka-devon-biz-qenmar-soltek-sp9ct12[.]pages[.]dev/form_submit_appeal/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fralka-devon-biz-qenmar-soltek-sp9ct12.pages.dev%2Fform_submit_appeal%2F) | url | — | openphish | — | 70 |
| [`hxxp://eristalon[.]pro/`](https://www.virustotal.com/gui/search/http%3A%2F%2Feristalon.pro%2F) | url | — | openphish | — | 70 |
| [`hxxp://helquisto[.]pro/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fhelquisto.pro%2F) | url | — | openphish | — | 70 |
| [`hxxp://dropvault[.]top/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fdropvault.top%2F) | url | — | openphish | — | 70 |
| [`hxxp://pl-payu-paczka[.]eu[.]cc/viewer/bWlsbGVubml1bQ/Ml8w/2eDiihr9zO`](https://www.virustotal.com/gui/search/http%3A%2F%2Fpl-payu-paczka.eu.cc%2Fviewer%2FbWlsbGVubml1bQ%2FMl8w%2F2eDiihr9zO) | url | — | openphish | — | 70 |
| [`hxxp://flonaceri[.]pro/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fflonaceri.pro%2F) | url | — | openphish | — | 70 |
| [`hxxp://pl-payu-paczka[.]shop/viewer/bWlsbGVubml1bQ/Ml8w/2eDiihr9zO`](https://www.virustotal.com/gui/search/http%3A%2F%2Fpl-payu-paczka.shop%2Fviewer%2FbWlsbGVubml1bQ%2FMl8w%2F2eDiihr9zO) | url | — | openphish | — | 70 |
| [`hxxp://pl-payu-paczka[.]qpon/viewer/bWlsbGVubml1bQ/Ml8w/2eDiihr9zO`](https://www.virustotal.com/gui/search/http%3A%2F%2Fpl-payu-paczka.qpon%2Fviewer%2FbWlsbGVubml1bQ%2FMl8w%2F2eDiihr9zO) | url | — | openphish | — | 70 |
| [`hxxp://www[.]supendsvalidmai1oul1[.]xo[.]je/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.supendsvalidmai1oul1.xo.je%2F) | url | — | openphish | — | 70 |
| [`hxxp://mining-auth[.]cfd/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fmining-auth.cfd%2F) | url | — | openphish | — | 70 |
| [`hxxp://pl-payu-paczka[.]buzz/viewer/bWlsbGVubml1bQ/Ml8w/2eDiihr9zO`](https://www.virustotal.com/gui/search/http%3A%2F%2Fpl-payu-paczka.buzz%2Fviewer%2FbWlsbGVubml1bQ%2FMl8w%2F2eDiihr9zO) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
