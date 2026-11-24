# Threat Intel Pulse — 2026-11-24

**Window:** last 7 days · **Generated:** 2026-11-24T00:06:45Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 69598 |
| New in window | 14823 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 23 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 314 | ok |
| tor | 10275 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 979 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 569 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 1613 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 44009 | 8326 |
| url | 13317 | 4871 |
| domain | 7596 | 1156 |
| ipv6 | 3822 | 199 |
| sha256 | 700 | 212 |
| md5 | 154 | 59 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 13307 |
| Exit nodes | 2496 |
| Other relays | 10811 |
| New in window | 952 |

Sample (20 of 13307, source: Tor Project Onionoo):
- `1[.]161[.]130[.]49`
- `1[.]201[.]176[.]169`
- `1[.]201[.]176[.]176`
- `1[.]248[.]96[.]163`
- `1[.]34[.]44[.]234`
- `100[.]12[.]167[.]245`
- `100[.]2[.]63[.]41`
- `100[.]35[.]77[.]114`
- `100[.]8[.]164[.]103`
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

Full list: `dist/tor/tor_nodes.txt` (in the `threat-intel-output` workflow artifact).
## Top malware families

| Family | Indicators | New | ATT&CK (heuristic) |
| --- | --- | --- | --- |
| ClickFix | 382 | 109 | — |
| cryptoscam | 111 | 7 | — |
| Kimsuky | 84 | 56 | — |
| Formbook | 42 | 0 | T1566.001, T1056.001, T1555, T1071.001, T1567 |
| Vidar | 21 | 0 | T1555, T1071.001, T1567 |
| Remcos | 19 | 4 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| DPRK | 18 | 0 | — |
| AiTM | 16 | 8 | — |
| Cobalt Strike | 9 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| GuLoader | 8 | 0 | T1027, T1059.005, T1055, T1105 |
| Mirai | 7 | 0 | T1498, T1071.001 |
| infostealer | 7 | 0 | — |
| Unknown malware | 6 | 0 | — |
| Evilginx | 4 | 0 | — |
| MustangPanda | 4 | 4 | — |
| PHP2Shell | 4 | 1 | — |
| QakBot | 4 | 0 | T1566.001, T1204.002, T1055, T1071.001, T1105, T1027, T1041 |
| Sliver | 4 | 0 | T1071.001, T1573, T1090, T1055 |
| Mispadu | 3 | 3 | — |
| AdaptixC2 | 2 | 0 | — |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1566 | Phishing | initial-access | 18082 |
| T1566.002 | Spearphishing Link | initial-access | 18082 |
| T1071.001 | Web Protocols | command-and-control | 50651 |
| T1573 | Encrypted Channel | command-and-control | 5860 |
| T1555 | Credentials from Password Stores | credential-access | 154 |
| T1567 | Exfiltration Over Web Service | exfiltration | 154 |
| T1552.001 | Credentials In Files | credential-access | 112 |
| T1056.001 | Keylogging | collection, credential-access | 94 |
| T1486 | Data Encrypted for Impact | impact | 93 |
| T1490 | Inhibit System Recovery | impact | 93 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 93 |
| T1566.001 | Spearphishing Attachment | initial-access | 67 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 26 |
| T1105 | Ingress Tool Transfer | command-and-control | 26 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 20 |
| T1113 | Screen Capture | collection | 19 |
| T1027 | Obfuscated Files or Information | defense-evasion | 14 |
| T1204.002 | Malicious File | execution | 14 |
| T1090 | Proxy | command-and-control | 13 |
| T1059.001 | PowerShell | execution | 9 |
| T1059.005 | Visual Basic | execution | 9 |
| T1498 | Network Denial of Service | impact | 9 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 5 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://f005[.]backblazeb2[.]com/file/0000055/SignintoXfinity[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Ff005.backblazeb2.com%2Ffile%2F0000055%2FSignintoXfinity.html) | url | — | openphish, tweetfeed | 2026-11-23T02:02:14Z | 70 |
| [`hxxp://ns1[.]az/c6/alibaba/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fns1.az%2Fc6%2Falibaba%2F) | url | — | openphish, tweetfeed | 2026-11-22T13:00:57Z | 70 |
| [`hxxps://saratio[.]de/gustafsonltd/download[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsaratio.de%2Fgustafsonltd%2Fdownload.html) | url | — | openphish, tweetfeed | 2026-11-19T18:25:18Z | 70 |
| [`hxxps://auth0-google[.]com/2step[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fauth0-google.com%2F2step.html) | url | AiTM | openphish, tweetfeed | 2026-11-18T17:18:56Z | 70 |
| [`hxxps://icloudvsmapalocaliza[.]click/isignesp[.]php?correo=-&id=172974`](https://www.virustotal.com/gui/search/https%3A%2F%2Ficloudvsmapalocaliza.click%2Fisignesp.php%3Fcorreo%3D-%26id%3D172974) | url | — | openphish, tweetfeed | 2026-11-18T16:27:54Z | 70 |
| [`hxxp://conatem[.]com/adobeStudio[.]html`](https://www.virustotal.com/gui/search/http%3A%2F%2Fconatem.com%2FadobeStudio.html) | url | — | openphish, tweetfeed | 2026-11-18T03:56:46Z | 70 |
| [`hxxp://megashorkxturtle[.]github[.]io/Netflix__clone`](https://www.virustotal.com/gui/search/http%3A%2F%2Fmegashorkxturtle.github.io%2FNetflix__clone) | url | — | openphish | — | 70 |
| [`hxxps://store[.]workshopcommunitybrowse[.]com/sharedfiles/filesdetails/id=3832495514/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fstore.workshopcommunitybrowse.com%2Fsharedfiles%2Ffilesdetails%2Fid%3D3832495514%2F) | url | — | openphish | — | 70 |
| [`hxxps://eepoint[.]wtwco[.]us/ess/bnpp/Login/Index`](https://www.virustotal.com/gui/search/https%3A%2F%2Feepoint.wtwco.us%2Fess%2Fbnpp%2FLogin%2FIndex) | url | — | openphish | — | 70 |
| [`hxxp://cryptocomappstillcantlogin[.]netlify[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fcryptocomappstillcantlogin.netlify.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://netflix-abonnement[.]com/success[.]php`](https://www.virustotal.com/gui/search/http%3A%2F%2Fnetflix-abonnement.com%2Fsuccess.php) | url | — | openphish | — | 70 |
| [`hxxps://susannesousadasilva[.]github[.]io/Supplies`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsusannesousadasilva.github.io%2FSupplies) | url | — | openphish | — | 70 |
| [`hxxp://php-membr[.]wasmer[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fphp-membr.wasmer.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://hub-open-bxnm[.]p-xxorevv8[.]workers[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fhub-open-bxnm.p-xxorevv8.workers.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]wwrreret264758[.]weebly[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.wwrreret264758.weebly.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://kucinonlogen[.]gitbook[.]io/us`](https://www.virustotal.com/gui/search/https%3A%2F%2Fkucinonlogen.gitbook.io%2Fus) | url | — | openphish | — | 70 |
| [`hxxps://kucinonlogen[.]gitbook[.]io/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fkucinonlogen.gitbook.io%2F) | url | — | openphish | — | 70 |
| [`hxxp://verifynownow[.]webflow[.]io/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fverifynownow.webflow.io%2F) | url | — | openphish | — | 70 |
| [`hxxps://metxmsaklogan[.]gitbook[.]io/us`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmetxmsaklogan.gitbook.io%2Fus) | url | — | openphish | — | 70 |
| [`hxxps://metxmsaklogan[.]gitbook[.]io/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmetxmsaklogan.gitbook.io%2F) | url | — | openphish | — | 70 |
| [`hxxp://plenor-qudrik-f27ab5-thjj-z2406ach[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fplenor-qudrik-f27ab5-thjj-z2406ach.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://databaseserver-sigma[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fdatabaseserver-sigma.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://eng-upholld-en[.]square[.]site/`](https://www.virustotal.com/gui/search/http%3A%2F%2Feng-upholld-en.square.site%2F) | url | — | openphish | — | 70 |
| [`hxxps://roblox[.]com[.]gr/users/757568109566/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Froblox.com.gr%2Fusers%2F757568109566%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxps://roblox[.]com[.]gr/users/269079117221/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Froblox.com.gr%2Fusers%2F269079117221%2Fprofile) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
