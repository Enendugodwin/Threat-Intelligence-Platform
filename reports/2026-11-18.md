# Threat Intel Pulse — 2026-11-18

**Window:** last 7 days · **Generated:** 2026-11-18T07:44:02Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 68679 |
| New in window | 14141 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 23 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 314 | ok |
| tor | 10289 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 1775 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 581 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 1980 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 43025 | 7647 |
| url | 12937 | 4747 |
| domain | 8139 | 1217 |
| ipv6 | 3801 | 239 |
| sha256 | 620 | 220 |
| md5 | 157 | 71 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 13306 |
| Exit nodes | 2436 |
| Other relays | 10870 |
| New in window | 1017 |

Sample (20 of 13306, source: Tor Project Onionoo):
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
| ClickFix | 299 | 91 | — |
| cryptoscam | 106 | 2 | — |
| Kimsuky | 62 | 42 | — |
| Formbook | 53 | 1 | T1566.001, T1056.001, T1555, T1071.001, T1567 |
| NetSupport | 32 | 0 | — |
| Vidar | 25 | 0 | T1555, T1071.001, T1567 |
| PHP2Shell | 21 | 1 | — |
| DPRK | 18 | 0 | — |
| Remcos | 16 | 10 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| Cobalt Strike | 9 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| AiTM | 8 | 0 | — |
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
| T1566 | Phishing | initial-access | 17851 |
| T1566.002 | Spearphishing Link | initial-access | 17851 |
| T1071.001 | Web Protocols | command-and-control | 50051 |
| T1573 | Encrypted Channel | command-and-control | 5348 |
| T1555 | Credentials from Password Stores | credential-access | 158 |
| T1567 | Exfiltration Over Web Service | exfiltration | 158 |
| T1552.001 | Credentials In Files | credential-access | 101 |
| T1056.001 | Keylogging | collection, credential-access | 99 |
| T1486 | Data Encrypted for Impact | impact | 80 |
| T1490 | Inhibit System Recovery | impact | 80 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 80 |
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
| [`hxxp://conatem[.]com/adobeStudio[.]html`](https://www.virustotal.com/gui/search/http%3A%2F%2Fconatem.com%2FadobeStudio.html) | url | — | openphish, tweetfeed | 2026-11-18T03:56:46Z | 70 |
| [`hxxps://lapaca[.]webdirecto[.]com/wp-includes/Text/tdweain/yogsqwj/gmehpir/ggg/adobe/adobe[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Flapaca.webdirecto.com%2Fwp-includes%2FText%2Ftdweain%2Fyogsqwj%2Fgmehpir%2Fggg%2Fadobe%2Fadobe.html) | url | — | openphish, tweetfeed | 2026-11-14T16:01:48Z | 70 |
| [`hxxps://mifidelidad[.]click/bac[.]pa`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmifidelidad.click%2Fbac.pa) | url | — | openphish, tweetfeed | 2026-11-12T01:03:17Z | 70 |
| [`hxxp://netflix-clone-manishbisht123[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fnetflix-clone-manishbisht123.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://phenomenal-gnome-11223a[.]netlify[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fphenomenal-gnome-11223a.netlify.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]v36365[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.v36365.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://808[.]top-qwe123-asd456-zxc789[.]yoqceqmcqoosawsu[.]com/downapp`](https://www.virustotal.com/gui/search/https%3A%2F%2F808.top-qwe123-asd456-zxc789.yoqceqmcqoosawsu.com%2Fdownapp) | url | — | openphish | — | 70 |
| [`hxxps://petsonpoint[.]co[.]uk/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fpetsonpoint.co.uk%2F) | url | — | openphish | — | 70 |
| [`hxxp://finance[.]petsonpoint[.]co[.]uk/`](https://www.virustotal.com/gui/search/http%3A%2F%2Ffinance.petsonpoint.co.uk%2F) | url | — | openphish | — | 70 |
| [`hxxps://365[.]qwe123-asd456-zxc789[.]osqcoyqssguomueq[.]com/downapp`](https://www.virustotal.com/gui/search/https%3A%2F%2F365.qwe123-asd456-zxc789.osqcoyqssguomueq.com%2Fdownapp) | url | — | openphish | — | 70 |
| [`hxxps://365[.]qwe123-asd456-zxc789[.]365666[.]top/downapp`](https://www.virustotal.com/gui/search/https%3A%2F%2F365.qwe123-asd456-zxc789.365666.top%2Fdownapp) | url | — | openphish | — | 70 |
| [`hxxps://808[.]top-qwe123-asd456-zxc789[.]365632[.]top/downapp`](https://www.virustotal.com/gui/search/https%3A%2F%2F808.top-qwe123-asd456-zxc789.365632.top%2Fdownapp) | url | — | openphish | — | 70 |
| [`hxxps://365[.]qwe123-asd456-zxc789[.]365690[.]top/downapp`](https://www.virustotal.com/gui/search/https%3A%2F%2F365.qwe123-asd456-zxc789.365690.top%2Fdownapp) | url | — | openphish | — | 70 |
| [`hxxps://365[.]qwe123-asd456-zxc789[.]365676[.]top/downapp`](https://www.virustotal.com/gui/search/https%3A%2F%2F365.qwe123-asd456-zxc789.365676.top%2Fdownapp) | url | — | openphish | — | 70 |
| [`hxxps://brilliant-tanuki-dd87f9[.]netlify[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbrilliant-tanuki-dd87f9.netlify.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://shopee896[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fshopee896.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://s4w[.]in/SpeoA`](https://www.virustotal.com/gui/search/https%3A%2F%2Fs4w.in%2FSpeoA) | url | — | openphish | — | 70 |
| [`hxxps://uspss[.]pages[.]dev/entreg/LoginAction_input%252CN/A%252Chttps%253A/ship/index[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fuspss.pages.dev%2Fentreg%2FLoginAction_input%25252CN%2FA%25252Chttps%25253A%2Fship%2Findex.html) | url | — | openphish | — | 70 |
| [`hxxps://main[.]foxmarkusa[.]com/public/login[.]php`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmain.foxmarkusa.com%2Fpublic%2Flogin.php) | url | — | openphish | — | 70 |
| [`hxxps://main[.]foxmarkusa[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmain.foxmarkusa.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://hkdiscord[.]antsoon[.]com/blog/discord-patch-notes-march-6-2026`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhkdiscord.antsoon.com%2Fblog%2Fdiscord-patch-notes-march-6-2026) | url | — | openphish | — | 70 |
| [`hxxp://www[.]grandprize121[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.grandprize121.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://ubs-ident-cicga[.]united-signals[.]com/onboarding/form?page=registration&process_context=default`](https://www.virustotal.com/gui/search/https%3A%2F%2Fubs-ident-cicga.united-signals.com%2Fonboarding%2Fform%3Fpage%3Dregistration%26process_context%3Ddefault) | url | — | openphish | — | 70 |
| [`hxxps://ubs-ident-cicga[.]united-signals[.]com/onboarding`](https://www.virustotal.com/gui/search/https%3A%2F%2Fubs-ident-cicga.united-signals.com%2Fonboarding) | url | — | openphish | — | 70 |
| [`hxxp://netlane[.]io/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fnetlane.io%2F) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
