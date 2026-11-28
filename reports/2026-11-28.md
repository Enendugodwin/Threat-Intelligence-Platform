# Threat Intel Pulse — 2026-11-28

**Window:** last 7 days · **Generated:** 2026-11-28T08:10:21Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 70550 |
| New in window | 13281 |
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
| binarydefense | 1286 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 577 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 1604 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 44800 | 7617 |
| url | 13356 | 4110 |
| domain | 7597 | 1151 |
| ipv6 | 3811 | 143 |
| sha256 | 811 | 220 |
| md5 | 175 | 40 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 13253 |
| Exit nodes | 2485 |
| Other relays | 10768 |
| New in window | 835 |

Sample (20 of 13253, source: Tor Project Onionoo):
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
| ClickFix | 407 | 76 | — |
| cryptoscam | 108 | 5 | — |
| Kimsuky | 84 | 18 | — |
| Formbook | 57 | 16 | T1566.001, T1056.001, T1555, T1071.001, T1567 |
| AiTM | 29 | 13 | — |
| Vidar | 21 | 0 | T1555, T1071.001, T1567 |
| Remcos | 19 | 1 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| GuLoader | 12 | 4 | T1027, T1059.005, T1055, T1105 |
| ValleyRAT | 12 | 10 | — |
| infostealer | 10 | 5 | — |
| Cobalt Strike | 7 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
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
| T1566 | Phishing | initial-access | 17867 |
| T1566.002 | Spearphishing Link | initial-access | 17867 |
| T1071.001 | Web Protocols | command-and-control | 51682 |
| T1573 | Encrypted Channel | command-and-control | 6327 |
| T1555 | Credentials from Password Stores | credential-access | 178 |
| T1567 | Exfiltration Over Web Service | exfiltration | 178 |
| T1552.001 | Credentials In Files | credential-access | 121 |
| T1056.001 | Keylogging | collection, credential-access | 106 |
| T1486 | Data Encrypted for Impact | impact | 89 |
| T1490 | Inhibit System Recovery | impact | 89 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 89 |
| T1566.001 | Spearphishing Attachment | initial-access | 82 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 31 |
| T1105 | Ingress Tool Transfer | command-and-control | 28 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 20 |
| T1113 | Screen Capture | collection | 19 |
| T1027 | Obfuscated Files or Information | defense-evasion | 18 |
| T1204.002 | Malicious File | execution | 18 |
| T1090 | Proxy | command-and-control | 14 |
| T1059.005 | Visual Basic | execution | 13 |
| T1498 | Network Denial of Service | impact | 9 |
| T1059.001 | PowerShell | execution | 7 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 5 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://hsbcau[.]jrni[.]com/login`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhsbcau.jrni.com%2Flogin) | url | — | openphish, tweetfeed | 2026-11-26T14:01:23Z | 70 |
| [`hxxps://php-intesasanpaolo-assistenza[.]wasmer[.]app/noaccount`](https://www.virustotal.com/gui/search/https%3A%2F%2Fphp-intesasanpaolo-assistenza.wasmer.app%2Fnoaccount) | url | — | openphish, tweetfeed | 2026-11-26T06:20:04Z | 70 |
| [`hxxps://bgbmail-gov[.]dgfiprotocolbd[.]workers[.]dev/login/?dhsfiourewjdfjgkfdgkldfjiorejfdjgfdgjkdfjgreioo=1`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbgbmail-gov.dgfiprotocolbd.workers.dev%2Flogin%2F%3Fdhsfiourewjdfjgkfdgkldfjiorejfdjgfdgjkdfjgreioo%3D1) | url | — | openphish, tweetfeed | 2026-11-25T17:46:08Z | 70 |
| [`hxxps://f005[.]backblazeb2[.]com/file/0000055/SignintoXfinity[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Ff005.backblazeb2.com%2Ffile%2F0000055%2FSignintoXfinity.html) | url | — | openphish, tweetfeed | 2026-11-23T02:02:14Z | 70 |
| [`hxxp://ns1[.]az/c6/alibaba/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fns1.az%2Fc6%2Falibaba%2F) | url | — | openphish, tweetfeed | 2026-11-22T13:00:57Z | 70 |
| [`hxxp://faq-trezr-git[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Ffaq-trezr-git.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://globaltop[.]org/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fglobaltop.org%2F) | url | — | openphish | — | 70 |
| [`hxxps://robloxapps[.]com/rolks`](https://www.virustotal.com/gui/search/https%3A%2F%2Frobloxapps.com%2Frolks) | url | — | openphish | — | 70 |
| [`hxxps://wvvw--roblox[.]com/users/781611239/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwvvw--roblox.com%2Fusers%2F781611239%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxps://tonicopoderosomagal[.]vercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ftonicopoderosomagal.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://pt-shope299[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fpt-shope299.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://shopee-666[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fshopee-666.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://pemenangshopee121[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fpemenangshopee121.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://qnomos[.]com/cgi-bin/ive24meet`](https://www.virustotal.com/gui/search/http%3A%2F%2Fqnomos.com%2Fcgi-bin%2Five24meet) | url | — | openphish | — | 70 |
| [`hxxps://pemenangshopee35[.]blogspot[.]com/?m=1`](https://www.virustotal.com/gui/search/https%3A%2F%2Fpemenangshopee35.blogspot.com%2F%3Fm%3D1) | url | — | openphish | — | 70 |
| [`hxxps://tonicomaga[.]vercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ftonicomaga.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://project-trezo-io-logn[.]pages[.]dev/robots[.]txt/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fproject-trezo-io-logn.pages.dev%2Frobots.txt%2F) | url | — | openphish | — | 70 |
| [`hxxps://io-starttrezo[.]pages[.]dev/robots[.]txt/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fio-starttrezo.pages.dev%2Frobots.txt%2F) | url | — | openphish | — | 70 |
| [`hxxp://nkvzt95nlo-3p8w2xm-7j4d6g-rq519c-7gu[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fnkvzt95nlo-3p8w2xm-7j4d6g-rq519c-7gu.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://qvtxn731-6m2w8zp-4j7d5g-rk915c-49w[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fqvtxn731-6m2w8zp-4j7d5g-rk915c-49w.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]com[.]et/users/6961506747/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.com.et%2Fusers%2F6961506747%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxps://www[.]instagramfollowers146[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.instagramfollowers146.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://shopeejkt236[.]blogspot[.]com/?m=1`](https://www.virustotal.com/gui/search/https%3A%2F%2Fshopeejkt236.blogspot.com%2F%3Fm%3D1) | url | — | openphish | — | 70 |
| [`hxxps://bbva[.]nuvasafe[.]com/login`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbbva.nuvasafe.com%2Flogin) | url | — | openphish | — | 70 |
| [`hxxps://cinfifidsxceeiddd[.]flazio[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fcinfifidsxceeiddd.flazio.com%2F) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
