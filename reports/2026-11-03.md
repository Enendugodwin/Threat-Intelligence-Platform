# Threat Intel Pulse — 2026-11-03

**Window:** last 7 days · **Generated:** 2026-11-03T19:39:37Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 85838 |
| New in window | 16266 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 614 | ok |
| tor | 10199 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 344 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 518 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 1057 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 35399 | 10110 |
| url | 26135 | 4237 |
| domain | 12315 | 1314 |
| sha256 | 7168 | 125 |
| ipv6 | 3692 | 451 |
| md5 | 602 | 29 |
| sha1 | 527 | 0 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 12892 |
| Exit nodes | 2413 |
| Other relays | 10479 |
| New in window | 1966 |

Sample (20 of 12892, source: Tor Project Onionoo):
- `1[.]161[.]130[.]49`
- `1[.]201[.]176[.]169`
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

Full list: `dist/tor/tor_nodes.txt` (in the `threat-intel-output` workflow artifact).
## Top malware families

| Family | Indicators | New | ATT&CK (heuristic) |
| --- | --- | --- | --- |
| Vidar | 5376 | 0 | T1555, T1071.001, T1567 |
| Mirai | 1544 | 0 | T1498, T1071.001 |
| IClickFix | 1524 | 0 | — |
| Unknown Loader | 1405 | 0 | — |
| Unknown malware | 1272 | 0 | — |
| Cobalt Strike | 1264 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| AMOS | 871 | 0 | — |
| VShell | 753 | 0 | — |
| ClearFake | 439 | 0 | — |
| PureRAT | 382 | 0 | — |
| php.shin_webshell | 340 | 0 | — |
| Remus | 296 | 0 | — |
| Remcos | 286 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| AsyncRAT | 271 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| AdaptixC2 | 266 | 0 | — |
| MacSync | 255 | 0 | — |
| DanaBot | 186 | 0 | T1566.001, T1071.001, T1555, T1041 |
| SalatStealer | 140 | 0 | — |
| Formbook | 139 | 1 | T1566.001, T1056.001, T1555, T1071.001, T1567 |
| Coruna | 132 | 0 | — |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1566 | Phishing | initial-access | 17541 |
| T1566.002 | Spearphishing Link | initial-access | 17541 |
| T1071.001 | Web Protocols | command-and-control | 57909 |
| T1105 | Ingress Tool Transfer | command-and-control | 11863 |
| T1573 | Encrypted Channel | command-and-control | 8631 |
| T1555 | Credentials from Password Stores | credential-access | 8005 |
| T1567 | Exfiltration Over Web Service | exfiltration | 7815 |
| T1498 | Network Denial of Service | impact | 4674 |
| T1552.001 | Credentials In Files | credential-access | 4360 |
| T1204.002 | Malicious File | execution | 4018 |
| T1027 | Obfuscated Files or Information | defense-evasion | 3866 |
| T1056.001 | Keylogging | collection, credential-access | 1540 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1490 |
| T1090 | Proxy | command-and-control | 1422 |
| T1059.001 | PowerShell | execution | 1274 |
| T1566.001 | Spearphishing Attachment | initial-access | 1262 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 837 |
| T1113 | Screen Capture | collection | 797 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 259 |
| T1189 | Drive-by Compromise | initial-access | 160 |
| T1218 | System Binary Proxy Execution | defense-evasion | 160 |
| T1486 | Data Encrypted for Impact | impact | 46 |
| T1490 | Inhibit System Recovery | impact | 46 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 46 |
| T1059.005 | Visual Basic | execution | 33 |
| T1190 | Exploit Public-Facing Application | initial-access | 21 |
| T1021.001 | Remote Desktop Protocol | lateral-movement | 6 |
| T1003 | OS Credential Dumping | credential-access | 4 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://vemtasbobinaj[.]com/login[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fvemtasbobinaj.com%2Flogin.html) | url | — | openphish, tweetfeed | 2026-11-02T19:27:35Z | 70 |
| [`hxxps://auditormadrid[.]es/wp-content/mu-plugins/iklqzct/iuo/alibaba/?naps`](https://www.virustotal.com/gui/search/https%3A%2F%2Fauditormadrid.es%2Fwp-content%2Fmu-plugins%2Fiklqzct%2Fiuo%2Falibaba%2F%3Fnaps) | url | — | openphish, tweetfeed | 2026-11-01T13:14:43Z | 70 |
| [`hxxps://zoffry[.]qpon/Adb/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fzoffry.qpon%2FAdb%2F) | url | — | openphish, tweetfeed | 2026-10-29T13:22:48Z | 70 |
| [`hxxps://2017-facebook[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2F2017-facebook.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]2017-facebook[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.2017-facebook.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://microfis-password-recovery[.]wasmer[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fmicrofis-password-recovery.wasmer.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://account-security-notification[.]at-us[.]therelayservice[.]com/matpwp/#/main?type=LiveEmail&locale=en&token=GcRCorP2TGBfKv2HKw6ye5hKk-AeOhN5hv1a5vOAVJAltw8RwAu1LH_C8hfzhdDAr7PNqAb3gq1ZelCsdwLW_K65BmXwJZqKm3rnThroG684Z1Y0lSA2su8EQuoknGhQMRctAGRpTLi3jGt7aHzwv9fI84P7twmWwX_9g0k1ZkQUqLp-wmQX4DWHiUwK-2eu9NxCMnZAr08qeaTgvkGLGL09prt_sWL_OWh414PkKaYoEIVqWprPCXGCJfhkWF_x3mDRhqCvtcovxqrR0qj87M9D5ccJNFia0Pf7dnRpPDPD0zdB1x7U_3I9ZOZ9_CpF6WpGT8c_DWHAyRJf1mWT56C0kV_xsC8Bdvz7XWPuJI18z_CErG_mrqt4lUsssys8uBh5r8Zz4O_qL62uYTFmorsuJLb1Fph5Q3p0rIxGDvWJppoEg97pJpqk0_slipkNERwtjljswqECcl68-jYP2DFVj8iiubIwQA_ncOvj5OW2IJCWPQ76HHVeGBDMo41e0BbPdrAf6a7Zyh-bBGjJgWsx3s3KS-NKLcVkk8jCmprFgfC4OQHQYWxPyDWObV3xWXd03TKwX2LuCFWBL95ATvX6FXOHYvvLAfSDAhuwI-QZIVZvAyn3qq_gnKkvLJuEeSuiV-JLo67YjCx_g7OTVi4RHBLC_sentRtQulZ7CjCLennMi8g6svaWrSaxnO9t2fdjs3zolqUDYoJ_5-Wauwdfzuapy_xM5fqKYd86YeWO8F5wzaR_Wjpu4ScwX9xLiYnNSp3SCKGskGX3ZHRHkLaakd7rb2WlN4-3-noeUCs`](https://www.virustotal.com/gui/search/https%3A%2F%2Faccount-security-notification.at-us.therelayservice.com%2Fmatpwp%2F%23%2Fmain%3Ftype%3DLiveEmail%26locale%3Den%26token%3DGcRCorP2TGBfKv2HKw6ye5hKk-AeOhN5hv1a5vOAVJAltw8RwAu1LH_C8hfzhdDAr7PNqAb3gq1ZelCsdwLW_K65BmXwJZqKm3rnThroG684Z1Y0lSA2su8EQuoknGhQMRctAGRpTLi3jGt7aHzwv9fI84P7twmWwX_9g0k1ZkQUqLp-wmQX4DWHiUwK-2eu9NxCMnZAr08qeaTgvkGLGL09prt_sWL_OWh414PkKaYoEIVqWprPCXGCJfhkWF_x3mDRhqCvtcovxqrR0qj87M9D5ccJNFia0Pf7dnRpPDPD0zdB1x7U_3I9ZOZ9_CpF6WpGT8c_DWHAyRJf1mWT56C0kV_xsC8Bdvz7XWPuJI18z_CErG_mrqt4lUsssys8uBh5r8Zz4O_qL62uYTFmorsuJLb1Fph5Q3p0rIxGDvWJppoEg97pJpqk0_slipkNERwtjljswqECcl68-jYP2DFVj8iiubIwQA_ncOvj5OW2IJCWPQ76HHVeGBDMo41e0BbPdrAf6a7Zyh-bBGjJgWsx3s3KS-NKLcVkk8jCmprFgfC4OQHQYWxPyDWObV3xWXd03TKwX2LuCFWBL95ATvX6FXOHYvvLAfSDAhuwI-QZIVZvAyn3qq_gnKkvLJuEeSuiV-JLo67YjCx_g7OTVi4RHBLC_sentRtQulZ7CjCLennMi8g6svaWrSaxnO9t2fdjs3zolqUDYoJ_5-Wauwdfzuapy_xM5fqKYd86YeWO8F5wzaR_Wjpu4ScwX9xLiYnNSp3SCKGskGX3ZHRHkLaakd7rb2WlN4-3-noeUCs) | url | — | openphish | — | 70 |
| [`hxxp://g4gx8[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fg4gx8.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]flhealthlicense[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.flhealthlicense.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://vortex-auth-proxy[.]pages[.]dev/category/safety`](https://www.virustotal.com/gui/search/https%3A%2F%2Fvortex-auth-proxy.pages.dev%2Fcategory%2Fsafety) | url | — | openphish | — | 70 |
| [`hxxps://vortex-auth-proxy[.]pages[.]dev/category/community`](https://www.virustotal.com/gui/search/https%3A%2F%2Fvortex-auth-proxy.pages.dev%2Fcategory%2Fcommunity) | url | — | openphish | — | 70 |
| [`hxxp://www[.]robiox[.]com[.]tw/login?returnUrl=2076255335`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.robiox.com.tw%2Flogin%3FreturnUrl%3D2076255335) | url | — | openphish | — | 70 |
| [`hxxps://bitmartbit[.]com/m/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbitmartbit.com%2Fm%2F) | url | — | openphish | — | 70 |
| [`hxxps://instagrams[.]com[.]vn/b00dxs6bnu5?uc`](https://www.virustotal.com/gui/search/https%3A%2F%2Finstagrams.com.vn%2Fb00dxs6bnu5%3Fuc) | url | — | openphish | — | 70 |
| [`hxxps://dgfcourier[.]de/Account/LogOn?ReturnUrl=%2f`](https://www.virustotal.com/gui/search/https%3A%2F%2Fdgfcourier.de%2FAccount%2FLogOn%3FReturnUrl%3D%252f) | url | — | openphish | — | 70 |
| [`hxxp://jasapickuptiktok[.]gratisongkir[.]web[.]id/k`](https://www.virustotal.com/gui/search/http%3A%2F%2Fjasapickuptiktok.gratisongkir.web.id%2Fk) | url | — | openphish | — | 70 |
| [`hxxps://mining-itself-theaters-hewlett[.]trycloudflare[.]com/link/usaa2026/usaa2026D/usaa2026D/web/captcha[.]php`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmining-itself-theaters-hewlett.trycloudflare.com%2Flink%2Fusaa2026%2Fusaa2026D%2Fusaa2026D%2Fweb%2Fcaptcha.php) | url | — | openphish | — | 70 |
| [`hxxps://u[.]to/nUnhIg?ssxnxx[.]com`](https://www.virustotal.com/gui/search/https%3A%2F%2Fu.to%2FnUnhIg%3Fssxnxx.com) | url | — | openphish | — | 70 |
| [`hxxp://www[.]edytryyde[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.edytryyde.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://facebook-login-redirect[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ffacebook-login-redirect.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]xfinityy111[.]weebly[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.xfinityy111.weebly.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]loginn-orangnews[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.loginn-orangnews.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://loginn-orangnews[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Floginn-orangnews.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://lezgercomstrt[.]gitbook[.]io/us`](https://www.virustotal.com/gui/search/https%3A%2F%2Flezgercomstrt.gitbook.io%2Fus) | url | — | openphish | — | 70 |
| [`hxxps://lezgercomstrt[.]gitbook[.]io/`](https://www.virustotal.com/gui/search/https%3A%2F%2Flezgercomstrt.gitbook.io%2F) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
