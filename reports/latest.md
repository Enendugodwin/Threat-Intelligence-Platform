# Threat Intel Pulse — 2026-11-17

**Window:** last 7 days · **Generated:** 2026-11-17T21:07:11Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 69091 |
| New in window | 13922 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 23 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 314 | ok |
| tor | 10291 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 1401 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 579 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 2115 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 43034 | 7525 |
| url | 13225 | 4650 |
| domain | 8242 | 1205 |
| ipv6 | 3804 | 241 |
| sha256 | 628 | 228 |
| md5 | 158 | 73 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 13323 |
| Exit nodes | 2432 |
| Other relays | 10891 |
| New in window | 1015 |

Sample (20 of 13323, source: Tor Project Onionoo):
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
| ClickFix | 301 | 91 | — |
| cryptoscam | 106 | 2 | — |
| Kimsuky | 62 | 42 | — |
| Formbook | 53 | 34 | T1566.001, T1056.001, T1555, T1071.001, T1567 |
| NetSupport | 32 | 0 | — |
| Vidar | 25 | 0 | T1555, T1071.001, T1567 |
| PHP2Shell | 23 | 1 | — |
| DPRK | 18 | 0 | — |
| Remcos | 16 | 10 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
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
| T1566 | Phishing | initial-access | 18247 |
| T1566.002 | Spearphishing Link | initial-access | 18247 |
| T1071.001 | Web Protocols | command-and-control | 50064 |
| T1573 | Encrypted Channel | command-and-control | 5211 |
| T1555 | Credentials from Password Stores | credential-access | 158 |
| T1567 | Exfiltration Over Web Service | exfiltration | 158 |
| T1552.001 | Credentials In Files | credential-access | 101 |
| T1056.001 | Keylogging | collection, credential-access | 99 |
| T1566.001 | Spearphishing Attachment | initial-access | 75 |
| T1486 | Data Encrypted for Impact | impact | 70 |
| T1490 | Inhibit System Recovery | impact | 70 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 70 |
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
| [`hxxps://www[.]roblox[.]com[.]et/users/9501717396/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.com.et%2Fusers%2F9501717396%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxps://s4w[.]in/roblox-com-users-9501771396-profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fs4w.in%2Froblox-com-users-9501771396-profile) | url | — | openphish | — | 70 |
| [`hxxps://security-alerters[.]info/we5fe123204/83eeaf9c6c0678753e5eddcc/index[.]php?id=bf6537fa062b87b709041adcb1d85319`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsecurity-alerters.info%2Fwe5fe123204%2F83eeaf9c6c0678753e5eddcc%2Findex.php%3Fid%3Dbf6537fa062b87b709041adcb1d85319) | url | — | openphish | — | 70 |
| [`hxxp://promogiftwinter[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fpromogiftwinter.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://mdi6mb[.]eventzones[.]de/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmdi6mb.eventzones.de%2F) | url | — | openphish | — | 70 |
| [`hxxps://burungkpertu2[.]kamunanya[.]de/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fburungkpertu2.kamunanya.de%2F) | url | — | openphish | — | 70 |
| [`hxxps://https--www--roblox[.]com/login?returnUrl=368542007`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhttps--www--roblox.com%2Flogin%3FreturnUrl%3D368542007) | url | — | openphish | — | 70 |
| [`hxxps://macroxchowchowv5-ctfjecbdg2fde2e7[.]z03[.]azurefd[.]net/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmacroxchowchowv5-ctfjecbdg2fde2e7.z03.azurefd.net%2F) | url | — | openphish | — | 70 |
| [`hxxps://1011fr3-6z19umsj[.]4everland[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2F1011fr3-6z19umsj.4everland.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://hvabuzujvbnm[.]info/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhvabuzujvbnm.info%2F) | url | — | openphish | — | 70 |
| [`hxxps://sharefilem3650[.]documentation-m3650676556[.]workers[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsharefilem3650.documentation-m3650676556.workers.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://eonifyit[.]com/cart`](https://www.virustotal.com/gui/search/https%3A%2F%2Feonifyit.com%2Fcart) | url | — | openphish | — | 70 |
| [`hxxps://bunksatrode[.]hostel[.]town/us/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbunksatrode.hostel.town%2Fus%2F) | url | — | openphish | — | 70 |
| [`hxxps://objectstorage[.]us-phoenix-1[.]oraclecloud[.]com/n/axlnm4hhzeul/b/standard-tiered-messages-are-here/o/index7670964[.]htm?_kx=uEmZeXr7tHqIX1P2rNTM5TLQVJMqyYnAcEMZGx0DwT8[.]Xn5yTR`](https://www.virustotal.com/gui/search/https%3A%2F%2Fobjectstorage.us-phoenix-1.oraclecloud.com%2Fn%2Faxlnm4hhzeul%2Fb%2Fstandard-tiered-messages-are-here%2Fo%2Findex7670964.htm%3F_kx%3DuEmZeXr7tHqIX1P2rNTM5TLQVJMqyYnAcEMZGx0DwT8.Xn5yTR) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]com[.]ml/users/400925685186/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.com.ml%2Fusers%2F400925685186%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxps://millassllc[.]com/include/adobe1/adobe/download[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmillassllc.com%2Finclude%2Fadobe1%2Fadobe%2Fdownload.html) | url | — | openphish | — | 70 |
| [`hxxp://tzbgtm[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Ftzbgtm.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://csmgroup[.]blu-foods[.]com/login?method=signin&mode=secure&client_id=db30ed6-53592-41922-0d22-aaab5901c&privacy=on&sso_reload=true&redirect_urI=https%3A%2F%2Flogin[.]microsoftonline[.]com%2F`](https://www.virustotal.com/gui/search/https%3A%2F%2Fcsmgroup.blu-foods.com%2Flogin%3Fmethod%3Dsignin%26mode%3Dsecure%26client_id%3Ddb30ed6-53592-41922-0d22-aaab5901c%26privacy%3Don%26sso_reload%3Dtrue%26redirect_urI%3Dhttps%253A%252F%252Flogin.microsoftonline.com%252F) | url | — | openphish | — | 70 |
| [`hxxps://csmgroup[.]blu-foods[.]com/go`](https://www.virustotal.com/gui/search/https%3A%2F%2Fcsmgroup.blu-foods.com%2Fgo) | url | — | openphish | — | 70 |
| [`hxxp://trustwallet[.]com-users[.]vip/`](https://www.virustotal.com/gui/search/http%3A%2F%2Ftrustwallet.com-users.vip%2F) | url | — | openphish | — | 70 |
| [`hxxps://scotia-csausa-uat[.]castineapps[.]com/auth/login/local`](https://www.virustotal.com/gui/search/https%3A%2F%2Fscotia-csausa-uat.castineapps.com%2Fauth%2Flogin%2Flocal) | url | — | openphish | — | 70 |
| [`hxxp://scotia-csausa-uat[.]castineapps[.]com/auth/login?1=%2Fauth%2Flogin`](https://www.virustotal.com/gui/search/http%3A%2F%2Fscotia-csausa-uat.castineapps.com%2Fauth%2Flogin%3F1%3D%252Fauth%252Flogin) | url | — | openphish | — | 70 |
| [`hxxps://webproxy[.]goku8[.]workers[.]dev/http:/www[.]wellsfargo[.]com/investing-wealth/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwebproxy.goku8.workers.dev%2Fhttp%3A%2Fwww.wellsfargo.com%2Finvesting-wealth%2F) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
