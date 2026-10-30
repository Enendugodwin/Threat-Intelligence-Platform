# Threat Intel Pulse — 2026-10-30

**Window:** last 7 days · **Generated:** 2026-10-30T22:30:22Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 86781 |
| New in window | 30207 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 614 | ok |
| tor | 8666 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 820 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 542 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 1373 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 31094 | 19113 |
| url | 28186 | 5405 |
| domain | 13739 | 5246 |
| sha256 | 9001 | 177 |
| ipv6 | 3400 | 200 |
| md5 | 715 | 66 |
| sha1 | 646 | 0 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 11781 |
| Exit nodes | 2266 |
| Other relays | 9515 |
| New in window | 914 |

Sample (20 of 11781, source: Tor Project Onionoo):
- `1[.]201[.]176[.]176`
- `1[.]235[.]159[.]83`
- `1[.]248[.]96[.]163`
- `1[.]34[.]44[.]234`
- `100[.]2[.]63[.]41`
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
- `102[.]205[.]44[.]5`
- `102[.]211[.]56[.]20`
- `102[.]211[.]56[.]25`

Full list: `dist/tor/tor_nodes.txt` (in the `threat-intel-output` workflow artifact).
## Top malware families

| Family | Indicators | New | ATT&CK (heuristic) |
| --- | --- | --- | --- |
| Vidar | 5941 | 4 | T1555, T1071.001, T1567 |
| Mirai | 2031 | 0 | T1498, T1071.001 |
| IClickFix | 1976 | 0 | — |
| Unknown Loader | 1829 | 0 | — |
| Unknown malware | 1593 | 0 | — |
| Cobalt Strike | 1332 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| AMOS | 979 | 0 | — |
| ClearFake | 957 | 0 | — |
| VShell | 876 | 0 | — |
| php.shin_webshell | 515 | 0 | — |
| PureRAT | 416 | 0 | — |
| Sliver | 375 | 0 | T1071.001, T1573, T1090, T1055 |
| Remcos | 321 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| Remus | 321 | 0 | — |
| AsyncRAT | 306 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| AdaptixC2 | 286 | 0 | — |
| MacSync | 256 | 0 | — |
| Unknown Stealer | 240 | 0 | — |
| DanaBot | 191 | 0 | T1566.001, T1071.001, T1555, T1041 |
| Formbook | 166 | 11 | T1566.001, T1056.001, T1555, T1071.001, T1567 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1071.001 | Web Protocols | command-and-control | 56623 |
| T1566 | Phishing | initial-access | 16644 |
| T1566.002 | Spearphishing Link | initial-access | 16644 |
| T1105 | Ingress Tool Transfer | command-and-control | 14139 |
| T1555 | Credentials from Password Stores | credential-access | 9396 |
| T1567 | Exfiltration Over Web Service | exfiltration | 9201 |
| T1573 | Encrypted Channel | command-and-control | 8604 |
| T1498 | Network Denial of Service | impact | 5614 |
| T1552.001 | Credentials In Files | credential-access | 5336 |
| T1204.002 | Malicious File | execution | 4365 |
| T1027 | Obfuscated Files or Information | defense-evasion | 4213 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1835 |
| T1090 | Proxy | command-and-control | 1742 |
| T1056.001 | Keylogging | collection, credential-access | 1733 |
| T1566.001 | Spearphishing Attachment | initial-access | 1428 |
| T1059.001 | PowerShell | execution | 1342 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 941 |
| T1113 | Screen Capture | collection | 900 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 295 |
| T1189 | Drive-by Compromise | initial-access | 162 |
| T1218 | System Binary Proxy Execution | defense-evasion | 162 |
| T1059.005 | Visual Basic | execution | 38 |
| T1486 | Data Encrypted for Impact | impact | 36 |
| T1490 | Inhibit System Recovery | impact | 36 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 36 |
| T1190 | Exploit Public-Facing Application | initial-access | 21 |
| T1021.001 | Remote Desktop Protocol | lateral-movement | 6 |
| T1003 | OS Credential Dumping | credential-access | 4 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://zoffry[.]qpon/Adb/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fzoffry.qpon%2FAdb%2F) | url | — | openphish, tweetfeed | 2026-10-29T13:22:48Z | 70 |
| [`hxxps://allegrolokalnie[.]aukcja865637302[.]cfd/oferta/1984-mz-etz-250/80344`](https://www.virustotal.com/gui/search/https%3A%2F%2Fallegrolokalnie.aukcja865637302.cfd%2Foferta%2F1984-mz-etz-250%2F80344) | url | — | openphish, tweetfeed | 2026-10-27T05:18:21Z | 70 |
| [`hxxp://app[.]forward-box[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fapp.forward-box.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://account[.]forward-box[.]com/error[.]aspx?e=404`](https://www.virustotal.com/gui/search/https%3A%2F%2Faccount.forward-box.com%2Ferror.aspx%3Fe%3D404) | url | — | openphish | — | 70 |
| [`hxxps://account[.]forward-box[.]com/login`](https://www.virustotal.com/gui/search/https%3A%2F%2Faccount.forward-box.com%2Flogin) | url | — | openphish | — | 70 |
| [`hxxp://03[.]trendndailyinsider[.]com/?cid=cs60m-2134&t1=9719156&t3=b79b66b3-d579-43b0-9bc9-373268802bcb&t5=68b658c805debd001271bcfe&t6=%7Baff_sub6%7D&t7=%7Baff_sub7%7D&t8=TnDUpTo1000paypal&transaction_id=1024ff9cd082248f2585d8d6bcc983&email=%7Bemail%7D&userFname=%7Bfirst_name%7D&last=%7Blast_name%7D&userAddress=%7Baddress%7D&cityName=%7BcityName%7D&stateName=%7Bstate%7D&stateCode=%7Bstate_code%7D&zipcode=%7Bzip%7D&countryName=%7Bcountry%7D&mobile=%7Bphone%7D&dobdate=%7Bdobdate%7D&dobmonth=%7Bdobmonth%7D&dobyear=%7Bdobyear%7D&gender=%7Bgender%7D&isr=true&sessionid=dc8104bf-e4e4-4c47-8135-1ffd02e48a64&uck=d035839e-ec3d-4b1c-8fdb-fd267fbe1cd1&idr=true&prod=1&domain=03[.]trendndailyinsider[.]com&gls=1`](https://www.virustotal.com/gui/search/http%3A%2F%2F03.trendndailyinsider.com%2F%3Fcid%3Dcs60m-2134%26t1%3D9719156%26t3%3Db79b66b3-d579-43b0-9bc9-373268802bcb%26t5%3D68b658c805debd001271bcfe%26t6%3D%257Baff_sub6%257D%26t7%3D%257Baff_sub7%257D%26t8%3DTnDUpTo1000paypal%26transaction_id%3D1024ff9cd082248f2585d8d6bcc983%26email%3D%257Bemail%257D%26userFname%3D%257Bfirst_name%257D%26last%3D%257Blast_name%257D%26userAddress%3D%257Baddress%257D%26cityName%3D%257BcityName%257D%26stateName%3D%257Bstate%257D%26stateCode%3D%257Bstate_code%257D%26zipcode%3D%257Bzip%257D%26countryName%3D%257Bcountry%257D%26mobile%3D%257Bphone%257D%26dobdate%3D%257Bdobdate%257D%26dobmonth%3D%257Bdobmonth%257D%26dobyear%3D%257Bdobyear%257D%26gender%3D%257Bgender%257D%26isr%3Dtrue%26sessionid%3Ddc8104bf-e4e4-4c47-8135-1ffd02e48a64%26uck%3Dd035839e-ec3d-4b1c-8fdb-fd267fbe1cd1%26idr%3Dtrue%26prod%3D1%26domain%3D03.trendndailyinsider.com%26gls%3D1) | url | — | openphish | — | 70 |
| [`hxxps://vitrineidealmagazine[.]shop/produto/8835998`](https://www.virustotal.com/gui/search/https%3A%2F%2Fvitrineidealmagazine.shop%2Fproduto%2F8835998) | url | — | openphish | — | 70 |
| [`hxxp://roblox[.]com[.]et/communities/904439903/JeohanXmisty`](https://www.virustotal.com/gui/search/http%3A%2F%2Froblox.com.et%2Fcommunities%2F904439903%2FJeohanXmisty) | url | — | openphish | — | 70 |
| [`hxxp://zelpar-vornix-a84de5-nyhh-n2406aco[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fzelpar-vornix-a84de5-nyhh-n2406aco.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://sp30ct10-melvuni-biz-zalero[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsp30ct10-melvuni-biz-zalero.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://nolvik-quaren-60f8d3-njybn-rg2406xma[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fnolvik-quaren-60f8d3-njybn-rg2406xma.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://8kmy-2z5ex-lde8x-213rrj-kevm1[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2F8kmy-2z5ex-lde8x-213rrj-kevm1.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://sp26ct-mavko-biz-zemra-kelti[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsp26ct-mavko-biz-zemra-kelti.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://aup-gq3s-nf9rr-ebcuh-nx9[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Faup-gq3s-nf9rr-ebcuh-nx9.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://sp30ct10-nalreko-biz-murelo[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsp30ct10-nalreko-biz-murelo.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://g72e-kwifta-r5k0-4x8ujc-fs0d[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fg72e-kwifta-r5k0-4x8ujc-fs0d.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://sp30ct10-korvemi-biz-zunako[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsp30ct10-korvemi-biz-zunako.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://46tef6-322u-szg67p-97guse[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2F46tef6-322u-szg67p-97guse.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://fc4p-mob46-hr4y-8u0-9fk59t[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ffc4p-mob46-hr4y-8u0-9fk59t.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://sp30ct10-norlevo-biz-zumari[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsp30ct10-norlevo-biz-zumari.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://sp30ct10-kavlevo-biz-zunemi[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsp30ct10-kavlevo-biz-zunemi.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://sp30ct10-kelreko-biz-zunati[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsp30ct10-kelreko-biz-zunati.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://sp30ct10-dorleko-biz-zuneri[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsp30ct10-dorleko-biz-zuneri.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://ojf3-vosra-tgoya-v10zs-63gw[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fojf3-vosra-tgoya-v10zs-63gw.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://ss0-75e-33e4t-4ha-sro8-vvzs60[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fss0-75e-33e4t-4ha-sro8-vvzs60.pages.dev%2F) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
