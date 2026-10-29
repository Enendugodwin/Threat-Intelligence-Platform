# Threat Intel Pulse — 2026-10-29

**Window:** last 7 days · **Generated:** 2026-10-29T13:22:28Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 87692 |
| New in window | 28091 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8679 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 430 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 524 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 1368 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 29553 | 17408 |
| url | 29219 | 5315 |
| domain | 14046 | 4921 |
| sha256 | 9873 | 159 |
| ipv6 | 3398 | 228 |
| md5 | 833 | 60 |
| sha1 | 770 | 0 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 11816 |
| Exit nodes | 2268 |
| Other relays | 9548 |
| New in window | 952 |

Sample (20 of 11816, source: Tor Project Onionoo):
- `1[.]201[.]176[.]176`
- `1[.]235[.]159[.]83`
- `1[.]248[.]96[.]163`
- `1[.]34[.]44[.]234`
- `100[.]1[.]157[.]56`
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

Full list: `dist/tor/tor_nodes.txt` (in the `threat-intel-output` workflow artifact).
## Top malware families

| Family | Indicators | New | ATT&CK (heuristic) |
| --- | --- | --- | --- |
| Vidar | 6033 | 4 | T1555, T1071.001, T1567 |
| Mirai | 2196 | 0 | T1498, T1071.001 |
| IClickFix | 2065 | 0 | — |
| Unknown Loader | 1982 | 0 | — |
| Unknown malware | 1646 | 0 | — |
| Cobalt Strike | 1338 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| ClearFake | 1080 | 0 | — |
| AMOS | 999 | 0 | — |
| VShell | 886 | 0 | — |
| php.shin_webshell | 609 | 0 | — |
| Unknown Stealer | 492 | 0 | — |
| PureRAT | 425 | 0 | — |
| Sliver | 375 | 0 | T1071.001, T1573, T1090, T1055 |
| Remus | 354 | 0 | — |
| Remcos | 342 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| AsyncRAT | 312 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| AdaptixC2 | 291 | 0 | — |
| MacSync | 256 | 0 | — |
| DanaBot | 192 | 0 | T1566.001, T1071.001, T1555, T1041 |
| Formbook | 184 | 11 | T1566.001, T1056.001, T1555, T1071.001, T1567 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1071.001 | Web Protocols | command-and-control | 56462 |
| T1566 | Phishing | initial-access | 16344 |
| T1566.002 | Spearphishing Link | initial-access | 16344 |
| T1105 | Ingress Tool Transfer | command-and-control | 15021 |
| T1555 | Credentials from Password Stores | credential-access | 9762 |
| T1567 | Exfiltration Over Web Service | exfiltration | 9566 |
| T1573 | Encrypted Channel | command-and-control | 8355 |
| T1498 | Network Denial of Service | impact | 6261 |
| T1552.001 | Credentials In Files | credential-access | 5580 |
| T1204.002 | Malicious File | execution | 4525 |
| T1027 | Obfuscated Files or Information | defense-evasion | 4373 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1844 |
| T1056.001 | Keylogging | collection, credential-access | 1813 |
| T1090 | Proxy | command-and-control | 1750 |
| T1566.001 | Spearphishing Attachment | initial-access | 1491 |
| T1059.001 | PowerShell | execution | 1350 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 981 |
| T1113 | Screen Capture | collection | 933 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 302 |
| T1189 | Drive-by Compromise | initial-access | 165 |
| T1218 | System Binary Proxy Execution | defense-evasion | 165 |
| T1059.005 | Visual Basic | execution | 38 |
| T1486 | Data Encrypted for Impact | impact | 33 |
| T1490 | Inhibit System Recovery | impact | 33 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 33 |
| T1190 | Exploit Public-Facing Application | initial-access | 21 |
| T1021.001 | Remote Desktop Protocol | lateral-movement | 9 |
| T1003 | OS Credential Dumping | credential-access | 4 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://allegrolokalnie[.]aukcja865637302[.]cfd/oferta/1984-mz-etz-250/80344`](https://www.virustotal.com/gui/search/https%3A%2F%2Fallegrolokalnie.aukcja865637302.cfd%2Foferta%2F1984-mz-etz-250%2F80344) | url | — | openphish, tweetfeed | 2026-10-27T05:18:21Z | 70 |
| [`hxxp://echallan[.]party/install`](https://www.virustotal.com/gui/search/http%3A%2F%2Fechallan.party%2Finstall) | url | — | openphish, tweetfeed | 2026-10-21T19:01:12Z | 70 |
| [`hxxps://system-update-account-ilpro[.]vercel[.]app/account-center-support`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsystem-update-account-ilpro.vercel.app%2Faccount-center-support) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]com[.]et/users/1654175985/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.com.et%2Fusers%2F1654175985%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxp://bc23[.]primus[.]rcassocies[.]com/W_PRIMUS_WINE_PROD/SignIn?ReturnUrl=%2FW_PRIMUS_WINE_PROD%2F`](https://www.virustotal.com/gui/search/http%3A%2F%2Fbc23.primus.rcassocies.com%2FW_PRIMUS_WINE_PROD%2FSignIn%3FReturnUrl%3D%252FW_PRIMUS_WINE_PROD%252F) | url | — | openphish | — | 70 |
| [`hxxp://accueilboitear24seconnecte77[.]jimdofree[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Faccueilboitear24seconnecte77.jimdofree.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://accueilsurlespacear24-8744[.]jimdofree[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Faccueilsurlespacear24-8744.jimdofree.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://webnailar24[.]jimdofree[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwebnailar24.jimdofree.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://accueil-servicear24boite7080[.]jimdofree[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Faccueil-servicear24boite7080.jimdofree.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://accueilservicear24boite9704[.]jimdofree[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Faccueilservicear24boite9704.jimdofree.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://accueilservicear24boite97044[.]jimdofree[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Faccueilservicear24boite97044.jimdofree.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://claud[.]vazbi[.]autos/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fclaud.vazbi.autos%2F) | url | — | openphish | — | 70 |
| [`hxxps://ipana[.]fwh[.]is/?page_id=15`](https://www.virustotal.com/gui/search/https%3A%2F%2Fipana.fwh.is%2F%3Fpage_id%3D15) | url | — | openphish | — | 70 |
| [`hxxp://simple-armadillo-6051f0[.]instawp[.]site/wp-content/plugins/indexDSAR24[.]html`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsimple-armadillo-6051f0.instawp.site%2Fwp-content%2Fplugins%2FindexDSAR24.html) | url | — | openphish | — | 70 |
| [`hxxp://luiz-doc-ref[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fluiz-doc-ref.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://auth-ar24espc-web[.]vercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fauth-ar24espc-web.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://allergro[.]shop/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fallergro.shop%2F) | url | — | openphish | — | 70 |
| [`hxxps://ec2-3-11-243-50[.]eu-west-2[.]compute[.]amazonaws[.]com/wp-content/plugins/filester/assets/css/wells/signon[.]php?activity=&client_id=3%2A%24%29%23gNGZsn%2AqPVKtFh%29_MaM%5E5jbz7mr_gQL%21JNE%5EeSqsF2WiS&cmd=signon_submit&crumb=%28jE2Or2uXgruQnLxCeh%21p8Zi7bdAy%2B&done=&email=&id=efc1a9d099203246bf2c87b2caf22b78efc1a9d099203246bf2c87b2caf22b78&intl=&redirect_uri=&session=efc1a9d099203246bf2c87b2caf22b78efc1a9d099203246bf2c87b2caf22b78%3Fsrc%3Dq%2Bm7%5E7bEhz%24ykR_H1XGq`](https://www.virustotal.com/gui/search/https%3A%2F%2Fec2-3-11-243-50.eu-west-2.compute.amazonaws.com%2Fwp-content%2Fplugins%2Ffilester%2Fassets%2Fcss%2Fwells%2Fsignon.php%3Factivity%3D%26client_id%3D3%252A%2524%2529%2523gNGZsn%252AqPVKtFh%2529_MaM%255E5jbz7mr_gQL%2521JNE%255EeSqsF2WiS%26cmd%3Dsignon_submit%26crumb%3D%2528jE2Or2uXgruQnLxCeh%2521p8Zi7bdAy%252B%26done%3D%26email%3D%26id%3Defc1a9d099203246bf2c87b2caf22b78efc1a9d099203246bf2c87b2caf22b78%26intl%3D%26redirect_uri%3D%26session%3Defc1a9d099203246bf2c87b2caf22b78efc1a9d099203246bf2c87b2caf22b78%253Fsrc%253Dq%252Bm7%255E7bEhz%2524ykR_H1XGq) | url | — | openphish | — | 70 |
| [`hxxps://mvrn80dqtwil-zktp2nnx-5o4m1e-zk477a[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmvrn80dqtwil-zktp2nnx-5o4m1e-zk477a.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://ywsd780gpx-qbxj528zkt-5r0p3c-qbx91k[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fywsd780gpx-qbxj528zkt-5r0p3c-qbx91k.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://ywsd71b20pz-qbxj5lsi-7r4p8b-ywsq57c[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fywsd71b20pz-qbxj5lsi-7r4p8b-ywsq57c.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://sp30ct10-korlevo-biz-zanumi[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsp30ct10-korlevo-biz-zanumi.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://sp29ct-vemru-biz-lonak-trefu[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsp29ct-vemru-biz-lonak-trefu.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://wlzgb4avstr-fscdhmja-1o0m2g-wlq03c[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwlzgb4avstr-fscdhmja-1o0m2g-wlq03c.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://sp30ct10-kavzako-biz-lunemi[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsp30ct10-kavzako-biz-lunemi.pages.dev%2F) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
