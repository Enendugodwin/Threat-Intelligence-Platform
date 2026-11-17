# Threat Intel Pulse — 2026-11-17

**Window:** last 7 days · **Generated:** 2026-11-17T08:10:22Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 68612 |
| New in window | 13751 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 23 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 314 | ok |
| tor | 10280 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 1401 | ok |
| greensnow | 1613 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 579 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 1755 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 43146 | 7530 |
| url | 12787 | 4527 |
| domain | 8135 | 1176 |
| ipv6 | 3800 | 236 |
| sha256 | 603 | 221 |
| md5 | 141 | 61 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 13315 |
| Exit nodes | 2434 |
| Other relays | 10881 |
| New in window | 1010 |

Sample (20 of 13315, source: Tor Project Onionoo):
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
| ClickFix | 290 | 96 | — |
| cryptoscam | 104 | 0 | — |
| Formbook | 53 | 41 | T1566.001, T1056.001, T1555, T1071.001, T1567 |
| Kimsuky | 50 | 30 | — |
| NetSupport | 32 | 0 | — |
| Vidar | 25 | 21 | T1555, T1071.001, T1567 |
| PHP2Shell | 24 | 1 | — |
| DPRK | 18 | 0 | — |
| Remcos | 16 | 11 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| Cobalt Strike | 9 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| AiTM | 8 | 0 | — |
| GuLoader | 8 | 0 | T1027, T1059.005, T1055, T1105 |
| Mirai | 8 | 0 | T1498, T1071.001 |
| ClearFake | 7 | 0 | — |
| Unknown malware | 7 | 0 | — |
| infostealer | 7 | 3 | — |
| Sliver | 6 | 0 | T1071.001, T1573, T1090, T1055 |
| SpyNote | 6 | 0 | — |
| Evilginx | 4 | 2 | — |
| QakBot | 4 | 0 | T1566.001, T1204.002, T1055, T1071.001, T1105, T1027, T1041 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1566 | Phishing | initial-access | 17912 |
| T1566.002 | Spearphishing Link | initial-access | 17912 |
| T1071.001 | Web Protocols | command-and-control | 49968 |
| T1573 | Encrypted Channel | command-and-control | 5207 |
| T1555 | Credentials from Password Stores | credential-access | 156 |
| T1567 | Exfiltration Over Web Service | exfiltration | 156 |
| T1056.001 | Keylogging | collection, credential-access | 99 |
| T1552.001 | Credentials In Files | credential-access | 99 |
| T1566.001 | Spearphishing Attachment | initial-access | 75 |
| T1486 | Data Encrypted for Impact | impact | 62 |
| T1490 | Inhibit System Recovery | impact | 62 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 62 |
| T1105 | Ingress Tool Transfer | command-and-control | 30 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 29 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 17 |
| T1090 | Proxy | command-and-control | 16 |
| T1113 | Screen Capture | collection | 16 |
| T1027 | Obfuscated Files or Information | defense-evasion | 15 |
| T1204.002 | Malicious File | execution | 15 |
| T1498 | Network Denial of Service | impact | 11 |
| T1059.001 | PowerShell | execution | 9 |
| T1059.005 | Visual Basic | execution | 9 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 5 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://lapaca[.]webdirecto[.]com/wp-includes/Text/tdweain/yogsqwj/gmehpir/ggg/adobe/adobe[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Flapaca.webdirecto.com%2Fwp-includes%2FText%2Ftdweain%2Fyogsqwj%2Fgmehpir%2Fggg%2Fadobe%2Fadobe.html) | url | — | openphish, tweetfeed | 2026-11-14T16:01:48Z | 70 |
| [`hxxps://mifidelidad[.]click/bac[.]pa`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmifidelidad.click%2Fbac.pa) | url | — | openphish, tweetfeed | 2026-11-12T01:03:17Z | 70 |
| [`hxxps://streamlined-three-995346[.]framer[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fstreamlined-three-995346.framer.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://fanpage-case[.]vercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ffanpage-case.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://pagina-inicial-instagram[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fpagina-inicial-instagram.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://pagina-inicial-instagram-anesoledar[.]vercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fpagina-inicial-instagram-anesoledar.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://tokeimx-cdnnode-sg16[.]xyz/`](https://www.virustotal.com/gui/search/http%3A%2F%2Ftokeimx-cdnnode-sg16.xyz%2F) | url | — | openphish | — | 70 |
| [`hxxp://gjmrv53hwu-wznxb81fyn-3e1f8g-dm755c[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fgjmrv53hwu-wznxb81fyn-3e1f8g-dm755c.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://instagram-session[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Finstagram-session.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://chp-courriersdomicile[.]bolt[.]host/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fchp-courriersdomicile.bolt.host%2F) | url | — | openphish | — | 70 |
| [`hxxps://coinbaseplogininin[.]gitbook[.]io/us`](https://www.virustotal.com/gui/search/https%3A%2F%2Fcoinbaseplogininin.gitbook.io%2Fus) | url | — | openphish | — | 70 |
| [`hxxp://coinbaseplogininin[.]gitbook[.]io/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fcoinbaseplogininin.gitbook.io%2F) | url | — | openphish | — | 70 |
| [`hxxps://maiscreditoclt[.]shop/005/renova[.]php`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmaiscreditoclt.shop%2F005%2Frenova.php) | url | — | openphish | — | 70 |
| [`hxxp://binancesync[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fbinancesync.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://suitetrezro-io-en[.]typedream[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsuitetrezro-io-en.typedream.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]my-coinbase[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.my-coinbase.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]exoweb-six[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.exoweb-six.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]basewalletsupport[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.basewalletsupport.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://my-coinbase[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fmy-coinbase.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]coinbase-support-portal[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.coinbase-support-portal.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]coinbase-livesupport[.]vercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.coinbase-livesupport.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]coinbase-supportdesk[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.coinbase-supportdesk.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://outbreak-ledger[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Foutbreak-ledger.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://coinbase-livesupport[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fcoinbase-livesupport.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://coinbase-supportdesk[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fcoinbase-supportdesk.vercel.app%2F) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
