# Threat Intel Pulse — 2026-11-10

**Window:** last 7 days · **Generated:** 2026-11-10T07:31:15Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 76901 |
| New in window | 15080 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 27 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 614 | ok |
| tor | 10261 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 626 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 506 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 1519 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 41928 | 9137 |
| url | 18040 | 3975 |
| domain | 10420 | 1511 |
| ipv6 | 3761 | 238 |
| sha256 | 2540 | 192 |
| md5 | 156 | 27 |
| sha1 | 56 | 0 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 13175 |
| Exit nodes | 2450 |
| Other relays | 10725 |
| New in window | 1175 |

Sample (20 of 13175, source: Tor Project Onionoo):
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
| Cobalt Strike | 1186 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| Vidar | 824 | 0 | T1555, T1071.001, T1567 |
| IClickFix | 696 | 0 | — |
| Unknown malware | 605 | 0 | — |
| Mirai | 436 | 0 | T1498, T1071.001 |
| AMOS | 396 | 0 | — |
| PureRAT | 330 | 0 | — |
| Unknown Loader | 306 | 0 | — |
| MacSync | 250 | 0 | — |
| AdaptixC2 | 238 | 0 | — |
| ClickFix | 212 | 112 | — |
| Remus | 201 | 0 | — |
| DanaBot | 177 | 0 | T1566.001, T1071.001, T1555, T1041 |
| AsyncRAT | 172 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| Remcos | 145 | 3 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| cryptoscam | 104 | 60 | — |
| VShell | 101 | 0 | — |
| Evilginx | 93 | 0 | — |
| ClearFake | 91 | 0 | — |
| Havoc | 76 | 0 | — |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1566 | Phishing | initial-access | 18524 |
| T1566.002 | Spearphishing Link | initial-access | 18524 |
| T1071.001 | Web Protocols | command-and-control | 54014 |
| T1573 | Encrypted Channel | command-and-control | 6992 |
| T1105 | Ingress Tool Transfer | command-and-control | 5699 |
| T1498 | Network Denial of Service | impact | 2671 |
| T1555 | Credentials from Password Stores | credential-access | 1922 |
| T1567 | Exfiltration Over Web Service | exfiltration | 1741 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1277 |
| T1090 | Proxy | command-and-control | 1249 |
| T1059.001 | PowerShell | execution | 1196 |
| T1552.001 | Credentials In Files | credential-access | 983 |
| T1056.001 | Keylogging | collection, credential-access | 914 |
| T1566.001 | Spearphishing Attachment | initial-access | 672 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 444 |
| T1113 | Screen Capture | collection | 416 |
| T1204.002 | Malicious File | execution | 354 |
| T1027 | Obfuscated Files or Information | defense-evasion | 353 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 191 |
| T1486 | Data Encrypted for Impact | impact | 43 |
| T1490 | Inhibit System Recovery | impact | 43 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 43 |
| T1059.005 | Visual Basic | execution | 19 |
| T1190 | Exploit Public-Facing Application | initial-access | 19 |
| T1189 | Drive-by Compromise | initial-access | 4 |
| T1218 | System Binary Proxy Execution | defense-evasion | 4 |
| T1003 | OS Credential Dumping | credential-access | 1 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://529motors[.]com/homepersonas/`](https://www.virustotal.com/gui/search/https%3A%2F%2F529motors.com%2Fhomepersonas%2F) | url | — | openphish, tweetfeed | 2026-11-05T11:05:08Z | 70 |
| [`hxxp://explorer[.]beta[.]bip300[.]xyz/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fexplorer.beta.bip300.xyz%2F) | url | — | openphish | — | 70 |
| [`hxxp://net-hub-gxqg[.]p-pso2at2d[.]workers[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fnet-hub-gxqg.p-pso2at2d.workers.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://s[.]team-qs[.]com/p/kma-mhc/bwjejeij`](https://www.virustotal.com/gui/search/https%3A%2F%2Fs.team-qs.com%2Fp%2Fkma-mhc%2Fbwjejeij) | url | — | openphish | — | 70 |
| [`hxxps://webasdhf[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwebasdhf.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]gabiasckrss[.]vercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.gabiasckrss.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://lumen-ba[.]com/10302026[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Flumen-ba.com%2F10302026.html) | url | — | openphish | — | 70 |
| [`hxxps://sso-security[.]com/E[.]Cq7P94af46KqmA?=userid&messageid=YWZhNDM0c2RqZjk4MjNmb2lkc2pmKC9DODk4RnNhOShGLyhBU0ZzdWlhaGRma2FzZDIoLw==`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsso-security.com%2FE.Cq7P94af46KqmA%3F%3Duserid%26messageid%3DYWZhNDM0c2RqZjk4MjNmb2lkc2pmKC9DODk4RnNhOShGLyhBU0ZzdWlhaGRma2FzZDIoLw%3D%3D) | url | — | openphish | — | 70 |
| [`hxxps://page-alert[.]vercel[.]app/accounts-center`](https://www.virustotal.com/gui/search/https%3A%2F%2Fpage-alert.vercel.app%2Faccounts-center) | url | — | openphish | — | 70 |
| [`hxxps://page-service[.]vercel[.]app/accounts-center`](https://www.virustotal.com/gui/search/https%3A%2F%2Fpage-service.vercel.app%2Faccounts-center) | url | — | openphish | — | 70 |
| [`hxxps://page-alert[.]vercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fpage-alert.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://page-service[.]vercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fpage-service.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://rbcode[.]net/v/a411129f0d1c60749a84f448852e7d52`](https://www.virustotal.com/gui/search/https%3A%2F%2Frbcode.net%2Fv%2Fa411129f0d1c60749a84f448852e7d52) | url | — | openphish | — | 70 |
| [`hxxp://regularizeseunomegov[.]discloud[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fregularizeseunomegov.discloud.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://homeloans-wellsfargo-com[.]sbx[.]pgsdemo[.]com/HMCtest/mortgage/ca/san-francisco/test-hmc-cd`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhomeloans-wellsfargo-com.sbx.pgsdemo.com%2FHMCtest%2Fmortgage%2Fca%2Fsan-francisco%2Ftest-hmc-cd) | url | — | openphish | — | 70 |
| [`hxxp://poshmarkusashop[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fposhmarkusashop.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://nqhzofzx7b[.]hdply[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fnqhzofzx7b.hdply.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://radiowavesokc[.]homedns[.]org/cgi-bin/index[.]ha/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fradiowavesokc.homedns.org%2Fcgi-bin%2Findex.ha%2F) | url | — | openphish | — | 70 |
| [`hxxp://roblox[.]com[.]et/users/727220164/profile`](https://www.virustotal.com/gui/search/http%3A%2F%2Froblox.com.et%2Fusers%2F727220164%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxps://aminsheikh72[.]github[.]io/microsoft-2/`](https://www.virustotal.com/gui/search/https%3A%2F%2Faminsheikh72.github.io%2Fmicrosoft-2%2F) | url | — | openphish | — | 70 |
| [`hxxps://9u1m2c-qw333agreg-mbtz1z2p8m9-qwxk[.]pages[.]dev/appeals/submit-appeal-form/return/`](https://www.virustotal.com/gui/search/https%3A%2F%2F9u1m2c-qw333agreg-mbtz1z2p8m9-qwxk.pages.dev%2Fappeals%2Fsubmit-appeal-form%2Freturn%2F) | url | — | openphish | — | 70 |
| [`hxxp://ylpxt35zgo-jmks92lsi-0v6t7b-jmk35c[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fylpxt35zgo-jmks92lsi-0v6t7b-jmk35c.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://quintessential-magenta-iu9wrbhh-dph50c8lhhlo[.]edgeone[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fquintessential-magenta-iu9wrbhh-dph50c8lhhlo.edgeone.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://pzxqn05mjwr-lktvrrel-7u0s8g-ds000a[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fpzxqn05mjwr-lktvrrel-7u0s8g-ds000a.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://xelquni-gld-zentavi-r7t5hq42[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fxelquni-gld-zentavi-r7t5hq42.pages.dev%2F) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
