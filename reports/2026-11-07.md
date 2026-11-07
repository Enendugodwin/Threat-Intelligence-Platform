# Threat Intel Pulse — 2026-11-07

**Window:** last 7 days · **Generated:** 2026-11-07T22:04:09Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 79676 |
| New in window | 15694 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 27 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 614 | ok |
| tor | 8744 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 1332 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 511 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 1851 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 39749 | 9484 |
| url | 20299 | 4163 |
| domain | 11313 | 1347 |
| sha256 | 4109 | 201 |
| ipv6 | 3748 | 474 |
| md5 | 277 | 25 |
| sha1 | 181 | 0 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 13083 |
| Exit nodes | 2427 |
| Other relays | 10656 |
| New in window | 1999 |

Sample (20 of 13083, source: Tor Project Onionoo):
- `1[.]161[.]130[.]49`
- `1[.]201[.]176[.]169`
- `1[.]201[.]176[.]176`
- `1[.]235[.]159[.]83`
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

Full list: `dist/tor/tor_nodes.txt` (in the `threat-intel-output` workflow artifact).
## Top malware families

| Family | Indicators | New | ATT&CK (heuristic) |
| --- | --- | --- | --- |
| Vidar | 1547 | 0 | T1555, T1071.001, T1567 |
| IClickFix | 1267 | 0 | — |
| Cobalt Strike | 1208 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| Unknown malware | 942 | 0 | — |
| Unknown Loader | 695 | 0 | — |
| Mirai | 670 | 0 | T1498, T1071.001 |
| AMOS | 663 | 0 | — |
| PureRAT | 355 | 0 | — |
| MacSync | 253 | 0 | — |
| AdaptixC2 | 242 | 0 | — |
| Remus | 217 | 0 | — |
| ClearFake | 209 | 0 | — |
| AsyncRAT | 186 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| Remcos | 182 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| DanaBot | 180 | 0 | T1566.001, T1071.001, T1555, T1041 |
| ClickFix | 166 | 70 | — |
| php.shin_webshell | 151 | 0 | — |
| VShell | 132 | 0 | — |
| Evilginx | 94 | 2 | — |
| Sliver | 91 | 2 | T1071.001, T1573, T1090, T1055 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1566 | Phishing | initial-access | 18327 |
| T1566.002 | Spearphishing Link | initial-access | 18327 |
| T1071.001 | Web Protocols | command-and-control | 55110 |
| T1105 | Ingress Tool Transfer | command-and-control | 7061 |
| T1573 | Encrypted Channel | command-and-control | 6517 |
| T1555 | Credentials from Password Stores | credential-access | 3620 |
| T1567 | Exfiltration Over Web Service | exfiltration | 3436 |
| T1498 | Network Denial of Service | impact | 3283 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1372 |
| T1090 | Proxy | command-and-control | 1329 |
| T1552.001 | Credentials In Files | credential-access | 1313 |
| T1059.001 | PowerShell | execution | 1218 |
| T1204.002 | Malicious File | execution | 1078 |
| T1027 | Obfuscated Files or Information | defense-evasion | 1077 |
| T1056.001 | Keylogging | collection, credential-access | 1073 |
| T1566.001 | Spearphishing Attachment | initial-access | 811 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 531 |
| T1113 | Screen Capture | collection | 500 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 211 |
| T1486 | Data Encrypted for Impact | impact | 43 |
| T1490 | Inhibit System Recovery | impact | 43 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 43 |
| T1059.005 | Visual Basic | execution | 28 |
| T1190 | Exploit Public-Facing Application | initial-access | 20 |
| T1189 | Drive-by Compromise | initial-access | 5 |
| T1218 | System Binary Proxy Execution | defense-evasion | 5 |
| T1003 | OS Credential Dumping | credential-access | 1 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://529motors[.]com/homepersonas/`](https://www.virustotal.com/gui/search/https%3A%2F%2F529motors.com%2Fhomepersonas%2F) | url | — | openphish, tweetfeed | 2026-11-05T11:05:08Z | 70 |
| [`hxxps://vemtasbobinaj[.]com/login[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fvemtasbobinaj.com%2Flogin.html) | url | — | openphish, tweetfeed | 2026-11-02T19:27:35Z | 70 |
| [`hxxps://auditormadrid[.]es/wp-content/mu-plugins/iklqzct/iuo/alibaba/?naps`](https://www.virustotal.com/gui/search/https%3A%2F%2Fauditormadrid.es%2Fwp-content%2Fmu-plugins%2Fiklqzct%2Fiuo%2Falibaba%2F%3Fnaps) | url | — | openphish, tweetfeed | 2026-11-01T13:14:43Z | 70 |
| [`hxxp://ta[.]gdffuy[.]xyz/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fta.gdffuy.xyz%2F) | url | — | openphish | — | 70 |
| [`hxxps://sharemyhtml[.]com/p/M1yBCNzLRG`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsharemyhtml.com%2Fp%2FM1yBCNzLRG) | url | — | openphish | — | 70 |
| [`hxxps://cl[.]realizarconsultaco[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fcl.realizarconsultaco.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://jisooooo0201[.]github[.]io/Instagram[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fjisooooo0201.github.io%2FInstagram.html) | url | — | openphish | — | 70 |
| [`hxxps://start-re-trresezer[.]gitbook[.]io/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fstart-re-trresezer.gitbook.io%2F) | url | — | openphish | — | 70 |
| [`hxxps://knkddkmlmeaedd[.]weebly[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fknkddkmlmeaedd.weebly.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://elaf[.]com[.]eg/adobe-document[.]co/`](https://www.virustotal.com/gui/search/https%3A%2F%2Felaf.com.eg%2Fadobe-document.co%2F) | url | — | openphish | — | 70 |
| [`hxxp://gopayy-indonesiaz[.]resmi-wsl2[.]my[.]id/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fgopayy-indonesiaz.resmi-wsl2.my.id%2F) | url | — | openphish | — | 70 |
| [`hxxps://s[.]team-yr[.]com/admin`](https://www.virustotal.com/gui/search/https%3A%2F%2Fs.team-yr.com%2Fadmin) | url | — | openphish | — | 70 |
| [`hxxps://s[.]team-yr[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fs.team-yr.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://oosoftlms[.]weebly[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Foosoftlms.weebly.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]com[.]ss/users/8795648614/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.com.ss%2Fusers%2F8795648614%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxps://apenasate-hoje2026[.]lol/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fapenasate-hoje2026.lol%2F) | url | — | openphish | — | 70 |
| [`hxxps://mydpd[.]cyobn[.]help/track-ch`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmydpd.cyobn.help%2Ftrack-ch) | url | — | openphish | — | 70 |
| [`hxxps://fighterzone[.]github[.]io/Fb/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ffighterzone.github.io%2FFb%2F) | url | — | openphish | — | 70 |
| [`hxxps://8s1q2g-qw999agreg-mbtz1m8p9z2-fsgc12[.]pages[.]dev/welcome_aboard?welcome=10009568686956300&token248=10009568686956300&name_token136=Espumas%20Chaideappeals%2Fsubmit-appeal-form%2Freturn%2F`](https://www.virustotal.com/gui/search/https%3A%2F%2F8s1q2g-qw999agreg-mbtz1m8p9z2-fsgc12.pages.dev%2Fwelcome_aboard%3Fwelcome%3D10009568686956300%26token248%3D10009568686956300%26name_token136%3DEspumas%2520Chaideappeals%252Fsubmit-appeal-form%252Freturn%252F) | url | — | openphish | — | 70 |
| [`hxxps://account-verify-system[.]netlify[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Faccount-verify-system.netlify.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://store[.]communityartsection[.]com/workshop/AWP-AncientHeritage/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fstore.communityartsection.com%2Fworkshop%2FAWP-AncientHeritage%2F) | url | — | openphish | — | 70 |
| [`hxxps://uv-bitli-compo[.]pages[.]dev/help/contact/477657948684314`](https://www.virustotal.com/gui/search/https%3A%2F%2Fuv-bitli-compo.pages.dev%2Fhelp%2Fcontact%2F477657948684314) | url | — | openphish | — | 70 |
| [`hxxps://uv-bitli-compo[.]pages[.]dev/help/contact/201235025373238appeals/submit-appeal-form/return/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fuv-bitli-compo.pages.dev%2Fhelp%2Fcontact%2F201235025373238appeals%2Fsubmit-appeal-form%2Freturn%2F) | url | — | openphish | — | 70 |
| [`hxxps://uv-bitli-compo[.]pages[.]dev/help/contact/763948189283472appeals/submit-appeal-form/return/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fuv-bitli-compo.pages.dev%2Fhelp%2Fcontact%2F763948189283472appeals%2Fsubmit-appeal-form%2Freturn%2F) | url | — | openphish | — | 70 |
| [`hxxps://uv-bitli-compo[.]pages[.]dev/help/contact/283527628237064appeals/submit-appeal-form/return/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fuv-bitli-compo.pages.dev%2Fhelp%2Fcontact%2F283527628237064appeals%2Fsubmit-appeal-form%2Freturn%2F) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
