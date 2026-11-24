# Threat Intel Pulse — 2026-11-24

**Window:** last 7 days · **Generated:** 2026-11-24T10:08:31Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 69210 |
| New in window | 14074 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 23 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 314 | ok |
| tor | 10260 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 979 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 569 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 1690 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 43788 | 7913 |
| url | 13135 | 4560 |
| domain | 7610 | 1161 |
| ipv6 | 3813 | 167 |
| sha256 | 706 | 216 |
| md5 | 158 | 57 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 13300 |
| Exit nodes | 2498 |
| Other relays | 10802 |
| New in window | 858 |

Sample (20 of 13300, source: Tor Project Onionoo):
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
| Kimsuky | 84 | 36 | — |
| Formbook | 42 | 0 | T1566.001, T1056.001, T1555, T1071.001, T1567 |
| Vidar | 21 | 0 | T1555, T1071.001, T1567 |
| Remcos | 19 | 4 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| DPRK | 18 | 0 | — |
| AiTM | 16 | 8 | — |
| infostealer | 12 | 5 | — |
| Cobalt Strike | 9 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| GuLoader | 8 | 0 | T1027, T1059.005, T1055, T1105 |
| Mirai | 7 | 0 | T1498, T1071.001 |
| Unknown malware | 6 | 0 | — |
| ValleyRAT | 5 | 5 | — |
| Evilginx | 4 | 0 | — |
| MustangPanda | 4 | 4 | — |
| PHP2Shell | 4 | 0 | — |
| QakBot | 4 | 0 | T1566.001, T1204.002, T1055, T1071.001, T1105, T1027, T1041 |
| Sliver | 4 | 0 | T1071.001, T1573, T1090, T1055 |
| Mispadu | 3 | 3 | — |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1566 | Phishing | initial-access | 17893 |
| T1566.002 | Spearphishing Link | initial-access | 17893 |
| T1071.001 | Web Protocols | command-and-control | 50435 |
| T1573 | Encrypted Channel | command-and-control | 5859 |
| T1555 | Credentials from Password Stores | credential-access | 159 |
| T1567 | Exfiltration Over Web Service | exfiltration | 159 |
| T1552.001 | Credentials In Files | credential-access | 117 |
| T1486 | Data Encrypted for Impact | impact | 96 |
| T1490 | Inhibit System Recovery | impact | 96 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 96 |
| T1056.001 | Keylogging | collection, credential-access | 94 |
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
| [`hxxp://ddpay-webpage-vip-login[.]netlify[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fddpay-webpage-vip-login.netlify.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]com[.]gt/games/2753915549/Blox-Fruits?privateServerLinkCode=891451502320159341387206562373`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.com.gt%2Fgames%2F2753915549%2FBlox-Fruits%3FprivateServerLinkCode%3D891451502320159341387206562373) | url | — | openphish | — | 70 |
| [`hxxps://sp12ct10-zemruni-biz-vemlako[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsp12ct10-zemruni-biz-vemlako.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://overview-ledger-live-login-cdn[.]typedream[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Foverview-ledger-live-login-cdn.typedream.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://us-usps[.]homes/DUVzTTavlOw/?redirection=details`](https://www.virustotal.com/gui/search/http%3A%2F%2Fus-usps.homes%2FDUVzTTavlOw%2F%3Fredirection%3Ddetails) | url | — | openphish | — | 70 |
| [`hxxp://us-usps[.]homes/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fus-usps.homes%2F) | url | — | openphish | — | 70 |
| [`hxxp://ifps62-6vu7k2yu9-arcadawebapps2[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fifps62-6vu7k2yu9-arcadawebapps2.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://mrpglq-7d05y5-dd9r-qdcm-idg[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmrpglq-7d05y5-dd9r-qdcm-idg.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://insttagrammoyi[.]netlify[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Finsttagrammoyi.netlify.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://sp25ct11-vunreka-biz-zolpavi[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsp25ct11-vunreka-biz-zolpavi.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://sp25ct11-lazvani-biz-rumkelo[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsp25ct11-lazvani-biz-rumkelo.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://q7nkw-mtvlj82-xp9v4-zlkyt731-hwcps82[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fq7nkw-mtvlj82-xp9v4-zlkyt731-hwcps82.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://nervelo-mpt-felqavo-a8d1ka93[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fnervelo-mpt-felqavo-a8d1ka93.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://roclick[.]cc/`](https://www.virustotal.com/gui/search/http%3A%2F%2Froclick.cc%2F) | url | — | openphish | — | 70 |
| [`hxxp://gamesrobloxstore[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fgamesrobloxstore.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://sharemyhtml[.]com/p/haKddfHRV_?eta=tanarx@6e6b6d03e8e9cfab6b4f43138f5e2449417c[.]org`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsharemyhtml.com%2Fp%2FhaKddfHRV_%3Feta%3Dtanarx%406e6b6d03e8e9cfab6b4f43138f5e2449417c.org) | url | — | openphish | — | 70 |
| [`hxxps://www[.]shopeeid899[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.shopeeid899.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://s[.]teamgfo[.]pro/p/vxg-bps/jmencser/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fs.teamgfo.pro%2Fp%2Fvxg-bps%2Fjmencser%2F) | url | — | openphish | — | 70 |
| [`hxxps://sited3da5c0d[.]htt1p[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsited3da5c0d.htt1p.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]apple-store-woad-delta[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.apple-store-woad-delta.vercel.app%2F) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
