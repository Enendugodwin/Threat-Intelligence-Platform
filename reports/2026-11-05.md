# Threat Intel Pulse — 2026-11-05

**Window:** last 7 days · **Generated:** 2026-11-05T20:08:27Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 82813 |
| New in window | 15671 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 27 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 614 | ok |
| tor | 10216 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 622 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 514 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 1291 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 37548 | 9781 |
| url | 23167 | 4074 |
| domain | 11577 | 1135 |
| sha256 | 5962 | 189 |
| ipv6 | 3724 | 461 |
| md5 | 464 | 31 |
| sha1 | 371 | 0 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 12984 |
| Exit nodes | 2420 |
| Other relays | 10564 |
| New in window | 1996 |

Sample (20 of 12984, source: Tor Project Onionoo):
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
| Vidar | 3353 | 0 | T1555, T1071.001, T1567 |
| IClickFix | 1494 | 0 | — |
| Mirai | 1323 | 0 | T1498, T1071.001 |
| Cobalt Strike | 1244 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| Unknown malware | 1192 | 0 | — |
| Unknown Loader | 843 | 0 | — |
| AMOS | 815 | 0 | — |
| VShell | 660 | 0 | — |
| PureRAT | 369 | 0 | — |
| ClearFake | 297 | 0 | — |
| Remus | 279 | 0 | — |
| AdaptixC2 | 257 | 0 | — |
| MacSync | 255 | 0 | — |
| php.shin_webshell | 251 | 0 | — |
| AsyncRAT | 236 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| Remcos | 235 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| DanaBot | 184 | 0 | T1566.001, T1071.001, T1555, T1041 |
| ClickFix | 166 | 72 | — |
| Sliver | 112 | 2 | T1071.001, T1573, T1090, T1055 |
| Formbook | 109 | 1 | T1566.001, T1056.001, T1555, T1071.001, T1567 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1566 | Phishing | initial-access | 17699 |
| T1566.002 | Spearphishing Link | initial-access | 17699 |
| T1071.001 | Web Protocols | command-and-control | 56623 |
| T1105 | Ingress Tool Transfer | command-and-control | 9525 |
| T1573 | Encrypted Channel | command-and-control | 7621 |
| T1555 | Credentials from Password Stores | credential-access | 5776 |
| T1567 | Exfiltration Over Web Service | exfiltration | 5588 |
| T1498 | Network Denial of Service | impact | 4234 |
| T1552.001 | Credentials In Files | credential-access | 2821 |
| T1204.002 | Malicious File | execution | 2581 |
| T1027 | Obfuscated Files or Information | defense-evasion | 2430 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1448 |
| T1090 | Proxy | command-and-control | 1387 |
| T1056.001 | Keylogging | collection, credential-access | 1339 |
| T1059.001 | PowerShell | execution | 1254 |
| T1566.001 | Spearphishing Attachment | initial-access | 1097 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 712 |
| T1113 | Screen Capture | collection | 672 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 253 |
| T1189 | Drive-by Compromise | initial-access | 159 |
| T1218 | System Binary Proxy Execution | defense-evasion | 159 |
| T1486 | Data Encrypted for Impact | impact | 43 |
| T1490 | Inhibit System Recovery | impact | 43 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 43 |
| T1059.005 | Visual Basic | execution | 30 |
| T1190 | Exploit Public-Facing Application | initial-access | 21 |
| T1003 | OS Credential Dumping | credential-access | 1 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://529motors[.]com/homepersonas/`](https://www.virustotal.com/gui/search/https%3A%2F%2F529motors.com%2Fhomepersonas%2F) | url | — | openphish, tweetfeed | 2026-11-05T11:05:08Z | 70 |
| [`hxxps://vemtasbobinaj[.]com/login[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fvemtasbobinaj.com%2Flogin.html) | url | — | openphish, tweetfeed | 2026-11-02T19:27:35Z | 70 |
| [`hxxps://auditormadrid[.]es/wp-content/mu-plugins/iklqzct/iuo/alibaba/?naps`](https://www.virustotal.com/gui/search/https%3A%2F%2Fauditormadrid.es%2Fwp-content%2Fmu-plugins%2Fiklqzct%2Fiuo%2Falibaba%2F%3Fnaps) | url | — | openphish, tweetfeed | 2026-11-01T13:14:43Z | 70 |
| [`hxxps://mu[.]qmmafe[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmu.qmmafe.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]viewdetail2910tbnaplnw[.]usnicvrfauthenservices[.]com/public/index?ref=business-support-center-DASDFDSYUYEE43FJDSHFSDFsetting%25popup%3fclient_id=889943718806-ual26tplnot2ea8b7n5t4p77keo8eb`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.viewdetail2910tbnaplnw.usnicvrfauthenservices.com%2Fpublic%2Findex%3Fref%3Dbusiness-support-center-DASDFDSYUYEE43FJDSHFSDFsetting%2525popup%253fclient_id%3D889943718806-ual26tplnot2ea8b7n5t4p77keo8eb) | url | — | openphish | — | 70 |
| [`hxxp://www[.]viewdetail2910tbnaplnw[.]usnicvrfauthenservices[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.viewdetail2910tbnaplnw.usnicvrfauthenservices.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]ukinvoibebubu[.]vercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.ukinvoibebubu.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://viewdetail2910tbnaplnw[.]usnicvrfauthenservices[.]com/public/index?ref=business-support-center-DASDFDSYUYEE43FJDSHFSDFsetting%25popup%3fclient_id=889943718806-ual26tplnot2ea8b7n5t4p77keo8eb`](https://www.virustotal.com/gui/search/https%3A%2F%2Fviewdetail2910tbnaplnw.usnicvrfauthenservices.com%2Fpublic%2Findex%3Fref%3Dbusiness-support-center-DASDFDSYUYEE43FJDSHFSDFsetting%2525popup%253fclient_id%3D889943718806-ual26tplnot2ea8b7n5t4p77keo8eb) | url | — | openphish | — | 70 |
| [`hxxps://viewdetail2910tbnaplnw[.]usnicvrfauthenservices[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fviewdetail2910tbnaplnw.usnicvrfauthenservices.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://sharivorcanas[.]netlify[.]app/a`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsharivorcanas.netlify.app%2Fa) | url | — | openphish | — | 70 |
| [`hxxps://sharivorcanas[.]netlify[.]app/a[.]html/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsharivorcanas.netlify.app%2Fa.html%2F) | url | — | openphish | — | 70 |
| [`hxxps://tabstool[.]net/?os=win10`](https://www.virustotal.com/gui/search/https%3A%2F%2Ftabstool.net%2F%3Fos%3Dwin10) | url | — | openphish | — | 70 |
| [`hxxps://https--www--roblox[.]com/users/1596649554/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhttps--www--roblox.com%2Fusers%2F1596649554%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxps://88888[.]ec[.]cc/`](https://www.virustotal.com/gui/search/https%3A%2F%2F88888.ec.cc%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]ipkobznzs[.]sviluppo[.]host/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.ipkobznzs.sviluppo.host%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]robiox[.]com[.]gr/users/4890711579/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.robiox.com.gr%2Fusers%2F4890711579%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxps://couriersplease[.]addliu[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fcouriersplease.addliu.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://couriersplease[.]addlir[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fcouriersplease.addlir.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://couriersplease[.]addlia[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fcouriersplease.addlia.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]buyerhub[.]pk/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.buyerhub.pk%2F) | url | — | openphish | — | 70 |
| [`hxxp://www[.]index2027[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.index2027.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://index2027[.]vercel[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Findex2027.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://pwlri[.]cn/verification/index`](https://www.virustotal.com/gui/search/https%3A%2F%2Fpwlri.cn%2Fverification%2Findex) | url | — | openphish | — | 70 |
| [`hxxps://pwlri[.]cn/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fpwlri.cn%2F) | url | — | openphish | — | 70 |
| [`hxxps://weneals[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fweneals.com%2F) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
