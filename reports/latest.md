# Threat Intel Pulse — 2026-11-02

**Window:** last 7 days · **Generated:** 2026-11-02T06:29:10Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 85993 |
| New in window | 34200 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 614 | ok |
| tor | 10158 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 1052 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 542 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 899 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 34055 | 22323 |
| url | 26743 | 5615 |
| domain | 12437 | 5556 |
| sha256 | 7913 | 194 |
| ipv6 | 3681 | 444 |
| md5 | 617 | 68 |
| sha1 | 547 | 0 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 12838 |
| Exit nodes | 2405 |
| Other relays | 10433 |
| New in window | 1936 |

Sample (20 of 12838, source: Tor Project Onionoo):
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
| Vidar | 5756 | 4 | T1555, T1071.001, T1567 |
| Mirai | 1718 | 0 | T1498, T1071.001 |
| IClickFix | 1550 | 0 | — |
| Unknown Loader | 1423 | 0 | — |
| Unknown malware | 1381 | 0 | — |
| Cobalt Strike | 1302 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| AMOS | 927 | 0 | — |
| VShell | 823 | 0 | — |
| ClearFake | 476 | 0 | — |
| php.shin_webshell | 400 | 0 | — |
| PureRAT | 393 | 0 | — |
| Sliver | 362 | 0 | T1071.001, T1573, T1090, T1055 |
| Remcos | 309 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| Remus | 300 | 0 | — |
| AsyncRAT | 283 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| AdaptixC2 | 273 | 0 | — |
| MacSync | 256 | 0 | — |
| DanaBot | 190 | 0 | T1566.001, T1071.001, T1555, T1041 |
| SalatStealer | 140 | 0 | — |
| Formbook | 139 | 12 | T1566.001, T1056.001, T1555, T1071.001, T1567 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1071.001 | Web Protocols | command-and-control | 57402 |
| T1566 | Phishing | initial-access | 17261 |
| T1566.002 | Spearphishing Link | initial-access | 17261 |
| T1105 | Ingress Tool Transfer | command-and-control | 12546 |
| T1573 | Encrypted Channel | command-and-control | 9056 |
| T1555 | Credentials from Password Stores | credential-access | 8564 |
| T1567 | Exfiltration Over Web Service | exfiltration | 8370 |
| T1498 | Network Denial of Service | impact | 5075 |
| T1552.001 | Credentials In Files | credential-access | 4656 |
| T1204.002 | Malicious File | execution | 4186 |
| T1027 | Obfuscated Files or Information | defense-evasion | 4034 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1777 |
| T1090 | Proxy | command-and-control | 1699 |
| T1056.001 | Keylogging | collection, credential-access | 1603 |
| T1566.001 | Spearphishing Attachment | initial-access | 1325 |
| T1059.001 | PowerShell | execution | 1312 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 882 |
| T1113 | Screen Capture | collection | 842 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 277 |
| T1189 | Drive-by Compromise | initial-access | 161 |
| T1218 | System Binary Proxy Execution | defense-evasion | 161 |
| T1486 | Data Encrypted for Impact | impact | 40 |
| T1490 | Inhibit System Recovery | impact | 40 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 40 |
| T1059.005 | Visual Basic | execution | 33 |
| T1190 | Exploit Public-Facing Application | initial-access | 21 |
| T1021.001 | Remote Desktop Protocol | lateral-movement | 6 |
| T1003 | OS Credential Dumping | credential-access | 4 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://auditormadrid[.]es/wp-content/mu-plugins/iklqzct/iuo/alibaba/?naps`](https://www.virustotal.com/gui/search/https%3A%2F%2Fauditormadrid.es%2Fwp-content%2Fmu-plugins%2Fiklqzct%2Fiuo%2Falibaba%2F%3Fnaps) | url | — | openphish, tweetfeed | 2026-11-01T13:14:43Z | 70 |
| [`hxxps://zoffry[.]qpon/Adb/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fzoffry.qpon%2FAdb%2F) | url | — | openphish, tweetfeed | 2026-10-29T13:22:48Z | 70 |
| [`hxxps://allegrolokalnie[.]aukcja865637302[.]cfd/oferta/1984-mz-etz-250/80344`](https://www.virustotal.com/gui/search/https%3A%2F%2Fallegrolokalnie.aukcja865637302.cfd%2Foferta%2F1984-mz-etz-250%2F80344) | url | — | openphish, tweetfeed | 2026-10-27T05:18:21Z | 70 |
| [`hxxps://mmdancr[.]sbs/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmmdancr.sbs%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]ss/users/884221804/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.ss%2Fusers%2F884221804%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxps://s4w[.]in/EExFO`](https://www.virustotal.com/gui/search/https%3A%2F%2Fs4w.in%2FEExFO) | url | — | openphish | — | 70 |
| [`hxxps://kleinanzelgen[.]ge/m-passwort-erneuern[.]html?id=11451103`](https://www.virustotal.com/gui/search/https%3A%2F%2Fkleinanzelgen.ge%2Fm-passwort-erneuern.html%3Fid%3D11451103) | url | — | openphish | — | 70 |
| [`hxxps://9000-firebase-anf-1781589572311[.]cluster-r7kbxfo3fnev2vskbkhhphetq6[.]cloudworkstations[.]dev/?monospaceUid=378407`](https://www.virustotal.com/gui/search/https%3A%2F%2F9000-firebase-anf-1781589572311.cluster-r7kbxfo3fnev2vskbkhhphetq6.cloudworkstations.dev%2F%3FmonospaceUid%3D378407) | url | — | openphish | — | 70 |
| [`hxxp://signin-xfinlty[.]weebly[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsignin-xfinlty.weebly.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://roblox[.]com[.]et/users/2377452159/profile`](https://www.virustotal.com/gui/search/http%3A%2F%2Froblox.com.et%2Fusers%2F2377452159%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxps://mydpd[.]nnaqo[.]help/track-ch`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmydpd.nnaqo.help%2Ftrack-ch) | url | — | openphish | — | 70 |
| [`hxxps://mydpd[.]oweyy[.]cc/track-ch/#/index`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmydpd.oweyy.cc%2Ftrack-ch%2F%23%2Findex) | url | — | openphish | — | 70 |
| [`hxxps://1url[.]at/www/robloxusers-95109909581-profile`](https://www.virustotal.com/gui/search/https%3A%2F%2F1url.at%2Fwww%2Frobloxusers-95109909581-profile) | url | — | openphish | — | 70 |
| [`hxxps://vmi3646823[.]contaboserver[.]net/we/paw/na/details[.]php/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fvmi3646823.contaboserver.net%2Fwe%2Fpaw%2Fna%2Fdetails.php%2F) | url | — | openphish | — | 70 |
| [`hxxps://135461223[.]site/no/2312/51578074-1a57-4459-b24c-a6c50613dc41/763670/x`](https://www.virustotal.com/gui/search/https%3A%2F%2F135461223.site%2Fno%2F2312%2F51578074-1a57-4459-b24c-a6c50613dc41%2F763670%2Fx) | url | — | openphish | — | 70 |
| [`hxxps://135461223[.]site/2312/51578074-1a57-4459-b24c-a6c50613dc41/763670`](https://www.virustotal.com/gui/search/https%3A%2F%2F135461223.site%2F2312%2F51578074-1a57-4459-b24c-a6c50613dc41%2F763670) | url | — | openphish | — | 70 |
| [`hxxps://135461223[.]site/no/2312/51578074-1a57-4459-b24c-a6c50613dc41/763670`](https://www.virustotal.com/gui/search/https%3A%2F%2F135461223.site%2Fno%2F2312%2F51578074-1a57-4459-b24c-a6c50613dc41%2F763670) | url | — | openphish | — | 70 |
| [`hxxp://www[.]xfinityhelplogin[.]weebly[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.xfinityhelplogin.weebly.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://vmi3696769[.]contaboserver[.]net/qo/xal/rt/msg[.]php`](https://www.virustotal.com/gui/search/https%3A%2F%2Fvmi3696769.contaboserver.net%2Fqo%2Fxal%2Frt%2Fmsg.php) | url | — | openphish | — | 70 |
| [`hxxps://tr[.]ee/1KclXG`](https://www.virustotal.com/gui/search/https%3A%2F%2Ftr.ee%2F1KclXG) | url | — | openphish | — | 70 |
| [`hxxps://www[.]community-policy-info[.]vercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.community-policy-info.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://mydpd[.]ixrii[.]help/track-ch/#%252Findex`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmydpd.ixrii.help%2Ftrack-ch%2F%23%25252Findex) | url | — | openphish | — | 70 |
| [`hxxp://gdfhwd[.]weebly[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fgdfhwd.weebly.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://hellpdesk[.]net/?r=618f8994-268d-46aa-9e7a-8821bc0eb5ce&rg=eu`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhellpdesk.net%2F%3Fr%3D618f8994-268d-46aa-9e7a-8821bc0eb5ce%26rg%3Deu) | url | — | openphish | — | 70 |
| [`hxxps://mydpd[.]qgaan[.]top/track-ch`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmydpd.qgaan.top%2Ftrack-ch) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
