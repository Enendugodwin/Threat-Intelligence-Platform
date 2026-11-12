# Threat Intel Pulse — 2026-11-12

**Window:** last 7 days · **Generated:** 2026-11-12T20:10:00Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 67860 |
| New in window | 14164 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 23 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 314 | ok |
| tor | 8835 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 1001 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 487 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 1242 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 41728 | 8179 |
| url | 13163 | 3981 |
| domain | 8553 | 1595 |
| ipv6 | 3812 | 266 |
| sha256 | 497 | 128 |
| md5 | 107 | 15 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 13277 |
| Exit nodes | 2462 |
| Other relays | 10815 |
| New in window | 1192 |

Sample (20 of 13277, source: Tor Project Onionoo):
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

Full list: `dist/tor/tor_nodes.txt` (in the `threat-intel-output` workflow artifact).
## Top malware families

| Family | Indicators | New | ATT&CK (heuristic) |
| --- | --- | --- | --- |
| ClickFix | 236 | 70 | — |
| cryptoscam | 104 | 40 | — |
| Formbook | 52 | 40 | T1566.001, T1056.001, T1555, T1071.001, T1567 |
| NetSupport | 32 | 0 | — |
| PHP2Shell | 26 | 0 | — |
| Vidar | 25 | 21 | T1555, T1071.001, T1567 |
| Kimsuky | 24 | 8 | — |
| ValleyRAT | 23 | 0 | — |
| DPRK | 18 | 0 | — |
| Sliver | 14 | 0 | T1071.001, T1573, T1090, T1055 |
| Cobalt Strike | 10 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| AiTM | 8 | 0 | — |
| GuLoader | 8 | 0 | T1027, T1059.005, T1055, T1105 |
| Mirai | 8 | 0 | T1498, T1071.001 |
| ClearFake | 7 | 0 | — |
| Unknown malware | 7 | 0 | — |
| Mythic | 6 | 0 | — |
| SpyNote | 6 | 0 | — |
| infostealer | 6 | 4 | — |
| Remcos | 5 | 3 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1566 | Phishing | initial-access | 19069 |
| T1566.002 | Spearphishing Link | initial-access | 19069 |
| T1071.001 | Web Protocols | command-and-control | 48197 |
| T1573 | Encrypted Channel | command-and-control | 4761 |
| T1555 | Credentials from Password Stores | credential-access | 137 |
| T1567 | Exfiltration Over Web Service | exfiltration | 137 |
| T1056.001 | Keylogging | collection, credential-access | 83 |
| T1552.001 | Credentials In Files | credential-access | 81 |
| T1566.001 | Spearphishing Attachment | initial-access | 63 |
| T1486 | Data Encrypted for Impact | impact | 44 |
| T1490 | Inhibit System Recovery | impact | 44 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 44 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 38 |
| T1105 | Ingress Tool Transfer | command-and-control | 31 |
| T1090 | Proxy | command-and-control | 25 |
| T1027 | Obfuscated Files or Information | defense-evasion | 15 |
| T1204.002 | Malicious File | execution | 15 |
| T1498 | Network Denial of Service | impact | 11 |
| T1059.001 | PowerShell | execution | 10 |
| T1059.005 | Visual Basic | execution | 9 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 6 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 5 |
| T1113 | Screen Capture | collection | 5 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://smcparral[.]com/Xplrs/?gate=031`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsmcparral.com%2FXplrs%2F%3Fgate%3D031) | url | — | openphish | — | 70 |
| [`hxxps://2h[.]ae/eJceI`](https://www.virustotal.com/gui/search/https%3A%2F%2F2h.ae%2FeJceI) | url | — | openphish | — | 70 |
| [`hxxps://ios[.]app-lmaxex[.]top/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fios.app-lmaxex.top%2F) | url | — | openphish | — | 70 |
| [`hxxps://e3x4x3w[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fe3x4x3w.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://394834binance[.]com/icloud/signin?client_id=5d914e33-bf66-4f0e-b`](https://www.virustotal.com/gui/search/https%3A%2F%2F394834binance.com%2Ficloud%2Fsignin%3Fclient_id%3D5d914e33-bf66-4f0e-b) | url | — | openphish | — | 70 |
| [`hxxps://icloud-appleinc[.]com/verify[.]php`](https://www.virustotal.com/gui/search/https%3A%2F%2Ficloud-appleinc.com%2Fverify.php) | url | — | openphish | — | 70 |
| [`hxxps://icloud-appleinc[.]com/Thayna`](https://www.virustotal.com/gui/search/https%3A%2F%2Ficloud-appleinc.com%2FThayna) | url | — | openphish | — | 70 |
| [`hxxp://pmh-ledger[.]pages[.]dev/v/mama`](https://www.virustotal.com/gui/search/http%3A%2F%2Fpmh-ledger.pages.dev%2Fv%2Fmama) | url | — | openphish | — | 70 |
| [`hxxp://pmh-ledger[.]pages[.]dev/v/may-may`](https://www.virustotal.com/gui/search/http%3A%2F%2Fpmh-ledger.pages.dev%2Fv%2Fmay-may) | url | — | openphish | — | 70 |
| [`hxxp://pmh-ledger[.]pages[.]dev/v/papa`](https://www.virustotal.com/gui/search/http%3A%2F%2Fpmh-ledger.pages.dev%2Fv%2Fpapa) | url | — | openphish | — | 70 |
| [`hxxp://pmh-ledger[.]pages[.]dev/v/kyi-kyi`](https://www.virustotal.com/gui/search/http%3A%2F%2Fpmh-ledger.pages.dev%2Fv%2Fkyi-kyi) | url | — | openphish | — | 70 |
| [`hxxp://pmh-ledger[.]pages[.]dev/v/sai-kham`](https://www.virustotal.com/gui/search/http%3A%2F%2Fpmh-ledger.pages.dev%2Fv%2Fsai-kham) | url | — | openphish | — | 70 |
| [`hxxp://zerobit497-zkku[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fzerobit497-zkku.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://help-docs-metamask[.]gitbook[.]io/us`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhelp-docs-metamask.gitbook.io%2Fus) | url | — | openphish | — | 70 |
| [`hxxp://help-docs-metamask[.]gitbook[.]io/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fhelp-docs-metamask.gitbook.io%2F) | url | — | openphish | — | 70 |
| [`hxxps://shared-documents-access[.]shared-object-038572[.]workers[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fshared-documents-access.shared-object-038572.workers.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://web-trezor-io-start-trezor-suite-app-cdn[.]typedream[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fweb-trezor-io-start-trezor-suite-app-cdn.typedream.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://370941383545690465507436650778[.]roomcaronmoons[.]sbs/`](https://www.virustotal.com/gui/search/https%3A%2F%2F370941383545690465507436650778.roomcaronmoons.sbs%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]telstramail-kyc-trial[.]weebly[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.telstramail-kyc-trial.weebly.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://higbkr[.]vercel[.]app/m0c8mn865q9kmkq9/oewxlj34p722d2cr/kr2vd4700wtzunuk/sroh34oautzjs3gl/danor2@8680dc57d9c3e96f6e7ff97bd8d8fe0bc897[.]org`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhigbkr.vercel.app%2Fm0c8mn865q9kmkq9%2Foewxlj34p722d2cr%2Fkr2vd4700wtzunuk%2Fsroh34oautzjs3gl%2Fdanor2%408680dc57d9c3e96f6e7ff97bd8d8fe0bc897.org) | url | — | openphish | — | 70 |
| [`hxxp://dfjhdfjhdf[.]weebly[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fdfjhdfjhdf.weebly.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://wmbrnq[.]eventzones[.]de/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwmbrnq.eventzones.de%2F) | url | — | openphish | — | 70 |
| [`hxxps://instagram-login00[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Finstagram-login00.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://taskportal-aelvorith-475c[.]s2499574[.]workers[.]dev/Trust_Account_Center/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ftaskportal-aelvorith-475c.s2499574.workers.dev%2FTrust_Account_Center%2F) | url | — | openphish | — | 70 |
| [`hxxps://somewhatshreya[.]github[.]io/Amazon_clone/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsomewhatshreya.github.io%2FAmazon_clone%2F) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
