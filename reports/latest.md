# Threat Intel Pulse — 2026-11-24

**Window:** last 7 days · **Generated:** 2026-11-24T22:37:54Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 69178 |
| New in window | 14030 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 23 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 314 | ok |
| tor | 10277 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 979 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 575 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 1937 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 43630 | 7931 |
| url | 13218 | 4523 |
| domain | 7652 | 1155 |
| ipv6 | 3818 | 166 |
| sha256 | 701 | 211 |
| md5 | 159 | 44 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 13273 |
| Exit nodes | 2498 |
| Other relays | 10775 |
| New in window | 855 |

Sample (20 of 13273, source: Tor Project Onionoo):
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
| ClickFix | 382 | 98 | — |
| cryptoscam | 111 | 5 | — |
| Kimsuky | 80 | 26 | — |
| Formbook | 42 | 0 | T1566.001, T1056.001, T1555, T1071.001, T1567 |
| Vidar | 21 | 0 | T1555, T1071.001, T1567 |
| Remcos | 19 | 4 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
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
| INCRansom | 2 | 0 | — |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1566 | Phishing | initial-access | 17942 |
| T1566.002 | Spearphishing Link | initial-access | 17942 |
| T1071.001 | Web Protocols | command-and-control | 50356 |
| T1573 | Encrypted Channel | command-and-control | 5627 |
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
| [`hxxps://mapslocatlphone[.]help/isignesp[.]php`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmapslocatlphone.help%2Fisignesp.php) | url | — | openphish | — | 70 |
| [`hxxps://spi86[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fspi86.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://info-resmi325[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Finfo-resmi325.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://infohadiah-shopee74[.]blogspot[.]com/?m=1`](https://www.virustotal.com/gui/search/https%3A%2F%2Finfohadiah-shopee74.blogspot.com%2F%3Fm%3D1) | url | — | openphish | — | 70 |
| [`hxxps://bump-sigverify-masterpda[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbump-sigverify-masterpda.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://us-start[.]framer[.]website/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fus-start.framer.website%2F) | url | — | openphish | — | 70 |
| [`hxxp://claimyourrbux24kkofficial[.]blogspot[.]com/?m=1`](https://www.virustotal.com/gui/search/http%3A%2F%2Fclaimyourrbux24kkofficial.blogspot.com%2F%3Fm%3D1) | url | — | openphish | — | 70 |
| [`hxxp://gebyar-shope20[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fgebyar-shope20.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://pengudiansh0pee[.]blogspot[.]com/?m=1`](https://www.virustotal.com/gui/search/https%3A%2F%2Fpengudiansh0pee.blogspot.com%2F%3Fm%3D1) | url | — | openphish | — | 70 |
| [`hxxp://ptshopee-5777[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fptshopee-5777.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://irs-gov-report[.]netlify[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Firs-gov-report.netlify.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://krishvermaxd-spec[.]github[.]io/netflix-clone`](https://www.virustotal.com/gui/search/https%3A%2F%2Fkrishvermaxd-spec.github.io%2Fnetflix-clone) | url | — | openphish | — | 70 |
| [`hxxps://sevenseven712[.]github[.]io/xn`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsevenseven712.github.io%2Fxn) | url | — | openphish | — | 70 |
| [`hxxps://im[.]nbpublic[.]com/loading_page_cpl/amazon/amazon_cf_2/index[.]html?lptoken=170859fa7232506226c1&cep=N4Igdgpg7g+gFgSwC4wQExALhAMwKwDseOAjASQLQAcaBEFALAEYCGAzBSwGxcEVNUADHlpcmDKmwCcIADQgAbggDOyVBmwAmQdM0txjYQ0ZMR/QWhYU8XKYIDGJXhEIQ5ilWqQIAthGVILD4ADlgg2pp4FCSCFIJcACqCDJiCgpiaXAB0DASaAFruSqpIAPYATuphJFJoUnhSJJRMBPZRDJoEsVIQOJoU9rYsEI5ogySa7vZBwSwIAOZgVdhcVMMsBGg0JBCCJPZpE1wQEC`](https://www.virustotal.com/gui/search/https%3A%2F%2Fim.nbpublic.com%2Floading_page_cpl%2Famazon%2Famazon_cf_2%2Findex.html%3Flptoken%3D170859fa7232506226c1%26cep%3DN4Igdgpg7g%2BgFgSwC4wQExALhAMwKwDseOAjASQLQAcaBEFALAEYCGAzBSwGxcEVNUADHlpcmDKmwCcIADQgAbggDOyVBmwAmQdM0txjYQ0ZMR%2FQWhYU8XKYIDGJXhEIQ5ilWqQIAthGVILD4ADlgg2pp4FCSCFIJcACqCDJiCgpiaXAB0DASaAFruSqpIAPYATuphJFJoUnhSJJRMBPZRDJoEsVIQOJoU9rYsEI5ogySa7vZBwSwIAOZgVdhcVMMsBGg0JBCCJPZpE1wQEC) | url | — | openphish | — | 70 |
| [`hxxps://mtvlj86vzt-qnkxzlpw-4j9k2g-mtv614[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmtvlj86vzt-qnkxzlpw-4j9k2g-mtv614.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://sp25ct11-rulvaku-biz-vemzaro[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsp25ct11-rulvaku-biz-vemzaro.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://sp25ct11-zorkelo-biz-nuvmari[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsp25ct11-zorkelo-biz-nuvmari.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://sp25ct11-nuvzaro-biz-melruni[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsp25ct11-nuvzaro-biz-melruni.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://5n0q7x2-m8v1k9p-3z6d4[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2F5n0q7x2-m8v1k9p-3z6d4.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://sp28ct5-vemlako-biz-rundoro[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsp28ct5-vemlako-biz-rundoro.pages.dev%2F) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
