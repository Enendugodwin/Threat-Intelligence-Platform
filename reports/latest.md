# Threat Intel Pulse — 2026-11-27

**Window:** last 7 days · **Generated:** 2026-11-27T08:50:11Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 70321 |
| New in window | 13321 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 23 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 314 | ok |
| tor | 10281 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 954 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 578 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 1719 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 44610 | 7652 |
| url | 13228 | 4145 |
| domain | 7718 | 1120 |
| ipv6 | 3818 | 147 |
| sha256 | 773 | 206 |
| md5 | 174 | 51 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 13326 |
| Exit nodes | 2485 |
| Other relays | 10841 |
| New in window | 868 |

Sample (20 of 13326, source: Tor Project Onionoo):
- `1[.]161[.]130[.]49`
- `1[.]161[.]139[.]48`
- `1[.]201[.]176[.]169`
- `1[.]201[.]176[.]176`
- `1[.]248[.]96[.]163`
- `1[.]34[.]44[.]234`
- `100[.]12[.]167[.]245`
- `100[.]2[.]63[.]41`
- `100[.]35[.]77[.]114`
- `100[.]8[.]164[.]103`
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

Full list: `dist/tor/tor_nodes.txt` (in the `threat-intel-output` workflow artifact).
## Top malware families

| Family | Indicators | New | ATT&CK (heuristic) |
| --- | --- | --- | --- |
| ClickFix | 409 | 76 | — |
| cryptoscam | 108 | 5 | — |
| Kimsuky | 84 | 20 | — |
| Formbook | 57 | 16 | T1566.001, T1056.001, T1555, T1071.001, T1567 |
| AiTM | 29 | 13 | — |
| Vidar | 21 | 0 | T1555, T1071.001, T1567 |
| Remcos | 19 | 1 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| GuLoader | 12 | 4 | T1027, T1059.005, T1055, T1105 |
| ValleyRAT | 12 | 12 | — |
| infostealer | 10 | 5 | — |
| Cobalt Strike | 8 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| Mirai | 7 | 0 | T1498, T1071.001 |
| Sliver | 7 | 3 | T1071.001, T1573, T1090, T1055 |
| Unknown malware | 5 | 0 | — |
| Evilginx | 4 | 0 | — |
| MustangPanda | 4 | 0 | — |
| QakBot | 4 | 0 | T1566.001, T1204.002, T1055, T1071.001, T1105, T1027, T1041 |
| Mispadu | 3 | 3 | — |
| PHP2Shell | 3 | 0 | — |
| Xworm | 3 | 2 | — |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1566 | Phishing | initial-access | 17869 |
| T1566.002 | Spearphishing Link | initial-access | 17869 |
| T1071.001 | Web Protocols | command-and-control | 51493 |
| T1573 | Encrypted Channel | command-and-control | 6129 |
| T1555 | Credentials from Password Stores | credential-access | 177 |
| T1567 | Exfiltration Over Web Service | exfiltration | 177 |
| T1552.001 | Credentials In Files | credential-access | 120 |
| T1056.001 | Keylogging | collection, credential-access | 111 |
| T1486 | Data Encrypted for Impact | impact | 91 |
| T1490 | Inhibit System Recovery | impact | 91 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 91 |
| T1566.001 | Spearphishing Attachment | initial-access | 82 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 32 |
| T1105 | Ingress Tool Transfer | command-and-control | 29 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 20 |
| T1113 | Screen Capture | collection | 19 |
| T1027 | Obfuscated Files or Information | defense-evasion | 18 |
| T1204.002 | Malicious File | execution | 18 |
| T1090 | Proxy | command-and-control | 15 |
| T1059.005 | Visual Basic | execution | 13 |
| T1498 | Network Denial of Service | impact | 9 |
| T1059.001 | PowerShell | execution | 8 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 5 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://hsbcau[.]jrni[.]com/login`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhsbcau.jrni.com%2Flogin) | url | — | openphish, tweetfeed | 2026-11-26T14:01:23Z | 70 |
| [`hxxps://php-intesasanpaolo-assistenza[.]wasmer[.]app/noaccount`](https://www.virustotal.com/gui/search/https%3A%2F%2Fphp-intesasanpaolo-assistenza.wasmer.app%2Fnoaccount) | url | — | openphish, tweetfeed | 2026-11-26T06:20:04Z | 70 |
| [`hxxps://bgbmail-gov[.]dgfiprotocolbd[.]workers[.]dev/login/?dhsfiourewjdfjgkfdgkldfjiorejfdjgfdgjkdfjgreioo=1`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbgbmail-gov.dgfiprotocolbd.workers.dev%2Flogin%2F%3Fdhsfiourewjdfjgkfdgkldfjiorejfdjgfdgjkdfjgreioo%3D1) | url | — | openphish, tweetfeed | 2026-11-25T17:46:08Z | 70 |
| [`hxxps://f005[.]backblazeb2[.]com/file/0000055/SignintoXfinity[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Ff005.backblazeb2.com%2Ffile%2F0000055%2FSignintoXfinity.html) | url | — | openphish, tweetfeed | 2026-11-23T02:02:14Z | 70 |
| [`hxxp://ns1[.]az/c6/alibaba/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fns1.az%2Fc6%2Falibaba%2F) | url | — | openphish, tweetfeed | 2026-11-22T13:00:57Z | 70 |
| [`hxxps://metamaskdiuxtension[.]gitbook[.]io/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmetamaskdiuxtension.gitbook.io%2F) | url | — | openphish | — | 70 |
| [`hxxps://cn[.]145manx[.]com/home/forbidden`](https://www.virustotal.com/gui/search/https%3A%2F%2Fcn.145manx.com%2Fhome%2Fforbidden) | url | — | openphish | — | 70 |
| [`hxxps://my-site-108476-100627[.]weeblysite[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmy-site-108476-100627.weeblysite.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://gemini-sailing-charters[.]square[.]site/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fgemini-sailing-charters.square.site%2F) | url | — | openphish | — | 70 |
| [`hxxp://app[.]kucoin108[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fapp.kucoin108.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]supportcrpt-client[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.supportcrpt-client.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://beton88-pikir[.]homes/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbeton88-pikir.homes%2F) | url | — | openphish | — | 70 |
| [`hxxps://cz-facebook[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fcz-facebook.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://perrydoom7-hub[.]github[.]io/chatbot/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fperrydoom7-hub.github.io%2Fchatbot%2F) | url | — | openphish | — | 70 |
| [`hxxps://gjdhdjhjhas[.]square[.]site/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fgjdhdjhjhas.square.site%2F) | url | — | openphish | — | 70 |
| [`hxxp://wmsalves[.]github[.]io/projetoNetflixLogin`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwmsalves.github.io%2FprojetoNetflixLogin) | url | — | openphish | — | 70 |
| [`hxxps://udise[.]emanyatapune[.]org/Z00M[.]US[.]MEET1NG[.]CALENDER/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fudise.emanyatapune.org%2FZ00M.US.MEET1NG.CALENDER%2F) | url | — | openphish | — | 70 |
| [`hxxps://att-10page[.]weeblysite[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fatt-10page.weeblysite.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://calm-queen-ea5a[.]filevis174[.]workers[.]dev/signin`](https://www.virustotal.com/gui/search/http%3A%2F%2Fcalm-queen-ea5a.filevis174.workers.dev%2Fsignin) | url | — | openphish | — | 70 |
| [`hxxp://nptxq84nlo-6m3w9zk-2j7d5g-rv518b[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fnptxq84nlo-6m3w9zk-2j7d5g-rv518b.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://carbaascopeiataa[.]square[.]site/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fcarbaascopeiataa.square.site%2F) | url | — | openphish | — | 70 |
| [`hxxp://thrjjdfvjn[.]weebly[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fthrjjdfvjn.weebly.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://d2sisrr9r7t0z4[.]cloudfront[.]net/gx/index[.]html?phone=%2B1-888-902-2787`](https://www.virustotal.com/gui/search/https%3A%2F%2Fd2sisrr9r7t0z4.cloudfront.net%2Fgx%2Findex.html%3Fphone%3D%252B1-888-902-2787) | url | — | openphish | — | 70 |
| [`hxxps://d3ha0drt130222[.]cloudfront[.]net/gx/index[.]html?phone=%2B1-888-902-2787`](https://www.virustotal.com/gui/search/https%3A%2F%2Fd3ha0drt130222.cloudfront.net%2Fgx%2Findex.html%3Fphone%3D%252B1-888-902-2787) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]com[.]ss/games/142823291/Murder-Mystery-2?privateServerLinkCode=99121229223932217370452874768764`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.com.ss%2Fgames%2F142823291%2FMurder-Mystery-2%3FprivateServerLinkCode%3D99121229223932217370452874768764) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
