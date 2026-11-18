# Threat Intel Pulse — 2026-11-18

**Window:** last 7 days · **Generated:** 2026-11-18T20:45:01Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 69842 |
| New in window | 14737 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 23 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 314 | ok |
| tor | 10286 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 1775 | ok |
| greensnow | 1768 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 581 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 2157 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 43797 | 8155 |
| url | 13310 | 4900 |
| domain | 8127 | 1203 |
| ipv6 | 3806 | 191 |
| sha256 | 643 | 215 |
| md5 | 159 | 73 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 13344 |
| Exit nodes | 2452 |
| Other relays | 10892 |
| New in window | 928 |

Sample (20 of 13344, source: Tor Project Onionoo):
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
| ClickFix | 299 | 83 | — |
| cryptoscam | 106 | 2 | — |
| Kimsuky | 64 | 44 | — |
| Formbook | 53 | 1 | T1566.001, T1056.001, T1555, T1071.001, T1567 |
| NetSupport | 32 | 0 | — |
| Vidar | 25 | 0 | T1555, T1071.001, T1567 |
| PHP2Shell | 21 | 1 | — |
| DPRK | 18 | 0 | — |
| AiTM | 16 | 8 | — |
| Remcos | 16 | 10 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| Cobalt Strike | 9 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| GuLoader | 8 | 0 | T1027, T1059.005, T1055, T1105 |
| Mirai | 8 | 0 | T1498, T1071.001 |
| ClearFake | 7 | 0 | — |
| Unknown malware | 7 | 0 | — |
| infostealer | 7 | 3 | — |
| Sliver | 5 | 0 | T1071.001, T1573, T1090, T1055 |
| Evilginx | 4 | 2 | — |
| QakBot | 4 | 0 | T1566.001, T1204.002, T1055, T1071.001, T1105, T1027, T1041 |
| ValleyRAT | 3 | 0 | — |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1566 | Phishing | initial-access | 18139 |
| T1566.002 | Spearphishing Link | initial-access | 18139 |
| T1071.001 | Web Protocols | command-and-control | 50890 |
| T1573 | Encrypted Channel | command-and-control | 5353 |
| T1555 | Credentials from Password Stores | credential-access | 158 |
| T1567 | Exfiltration Over Web Service | exfiltration | 158 |
| T1552.001 | Credentials In Files | credential-access | 101 |
| T1056.001 | Keylogging | collection, credential-access | 99 |
| T1486 | Data Encrypted for Impact | impact | 98 |
| T1490 | Inhibit System Recovery | impact | 98 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 98 |
| T1566.001 | Spearphishing Attachment | initial-access | 75 |
| T1105 | Ingress Tool Transfer | command-and-control | 30 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 28 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 17 |
| T1113 | Screen Capture | collection | 16 |
| T1027 | Obfuscated Files or Information | defense-evasion | 15 |
| T1090 | Proxy | command-and-control | 15 |
| T1204.002 | Malicious File | execution | 15 |
| T1498 | Network Denial of Service | impact | 11 |
| T1059.001 | PowerShell | execution | 9 |
| T1059.005 | Visual Basic | execution | 9 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 5 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://icloudvsmapalocaliza[.]click/isignesp[.]php?correo=-&id=172974`](https://www.virustotal.com/gui/search/https%3A%2F%2Ficloudvsmapalocaliza.click%2Fisignesp.php%3Fcorreo%3D-%26id%3D172974) | url | — | openphish, tweetfeed | 2026-11-18T16:27:54Z | 70 |
| [`hxxp://conatem[.]com/adobeStudio[.]html`](https://www.virustotal.com/gui/search/http%3A%2F%2Fconatem.com%2FadobeStudio.html) | url | — | openphish, tweetfeed | 2026-11-18T03:56:46Z | 70 |
| [`hxxps://lapaca[.]webdirecto[.]com/wp-includes/Text/tdweain/yogsqwj/gmehpir/ggg/adobe/adobe[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Flapaca.webdirecto.com%2Fwp-includes%2FText%2Ftdweain%2Fyogsqwj%2Fgmehpir%2Fggg%2Fadobe%2Fadobe.html) | url | — | openphish, tweetfeed | 2026-11-14T16:01:48Z | 70 |
| [`hxxps://mifidelidad[.]click/bac[.]pa`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmifidelidad.click%2Fbac.pa) | url | — | openphish, tweetfeed | 2026-11-12T01:03:17Z | 70 |
| [`hxxp://6oktsarv[.]kcppg[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2F6oktsarv.kcppg.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]robiox[.]com[.]py/users/198471345763/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.robiox.com.py%2Fusers%2F198471345763%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxp://hadiah-shopee329[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fhadiah-shopee329.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]ehay-item[.]pentagrafic[.]mx/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.ehay-item.pentagrafic.mx%2F) | url | — | openphish | — | 70 |
| [`hxxps://getalphacore[.]com/pd/paga/IN2651/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fgetalphacore.com%2Fpd%2Fpaga%2FIN2651%2F) | url | — | openphish | — | 70 |
| [`hxxp://gtalphacore[.]shop/2651`](https://www.virustotal.com/gui/search/http%3A%2F%2Fgtalphacore.shop%2F2651) | url | — | openphish | — | 70 |
| [`hxxp://zavqelo-mpt-fenqari-r5x9pe84[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fzavqelo-mpt-fenqari-r5x9pe84.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]voir-document[.]vercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.voir-document.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://en-start-faqs[.]pages[.]dev/robots[.]txt`](https://www.virustotal.com/gui/search/https%3A%2F%2Fen-start-faqs.pages.dev%2Frobots.txt) | url | — | openphish | — | 70 |
| [`hxxps://loginservice[.]cloud/E[.]ONEXzd-JrR7_NQ?/servus-credit-union%E2%81%84threads%E2%81%84879239875%E2%81%84trk-event-com-thread-click%E2%81%84allow-app-redirect`](https://www.virustotal.com/gui/search/https%3A%2F%2Floginservice.cloud%2FE.ONEXzd-JrR7_NQ%3F%2Fservus-credit-union%25E2%2581%2584threads%25E2%2581%2584879239875%25E2%2581%2584trk-event-com-thread-click%25E2%2581%2584allow-app-redirect) | url | — | openphish | — | 70 |
| [`hxxps://metamask-docs-ctqr7yuof-consensys-ddffed67[.]vercel[.]app/embedded-wallets/sdk/flutter`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmetamask-docs-ctqr7yuof-consensys-ddffed67.vercel.app%2Fembedded-wallets%2Fsdk%2Fflutter) | url | — | openphish | — | 70 |
| [`hxxps://metamask-docs-ctqr7yuof-consensys-ddffed67[.]vercel[.]app/embedded-wallets/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmetamask-docs-ctqr7yuof-consensys-ddffed67.vercel.app%2Fembedded-wallets%2F) | url | — | openphish | — | 70 |
| [`hxxps://aptim[.]us/lookslike/nd/webmail-jp/#danik1@963d793d9758331dd9e30cca0f8c571e9704[.]com`](https://www.virustotal.com/gui/search/https%3A%2F%2Faptim.us%2Flookslike%2Fnd%2Fwebmail-jp%2F%23danik1%40963d793d9758331dd9e30cca0f8c571e9704.com) | url | — | openphish | — | 70 |
| [`hxxps://vb[.]mightybaobab[.]com/fonts/wservices/sc[.]php?lid=danik1@963d793d9758331dd9e30cca0f8c571e9704[.]com`](https://www.virustotal.com/gui/search/https%3A%2F%2Fvb.mightybaobab.com%2Ffonts%2Fwservices%2Fsc.php%3Flid%3Ddanik1%40963d793d9758331dd9e30cca0f8c571e9704.com) | url | — | openphish | — | 70 |
| [`hxxps://www[.]24236936365[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.24236936365.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://overview-start-trezorr[.]pages[.]dev/robots[.]txt`](https://www.virustotal.com/gui/search/https%3A%2F%2Foverview-start-trezorr.pages.dev%2Frobots.txt) | url | — | openphish | — | 70 |
| [`hxxps://start-io-en-trezr[.]pages[.]dev/robots[.]txt`](https://www.virustotal.com/gui/search/https%3A%2F%2Fstart-io-en-trezr.pages.dev%2Frobots.txt) | url | — | openphish | — | 70 |
| [`hxxps://getalphacore[.]com/pd/paga/IN2653/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fgetalphacore.com%2Fpd%2Fpaga%2FIN2653%2F) | url | — | openphish | — | 70 |
| [`hxxp://gtalphacore[.]shop/2653`](https://www.virustotal.com/gui/search/http%3A%2F%2Fgtalphacore.shop%2F2653) | url | — | openphish | — | 70 |
| [`hxxp://2wimhy09[.]mwyry[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2F2wimhy09.mwyry.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://685903[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2F685903.com%2F) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
