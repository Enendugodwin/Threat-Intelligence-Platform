# Threat Intel Pulse — 2026-11-09

**Window:** last 7 days · **Generated:** 2026-11-09T06:55:08Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 78737 |
| New in window | 15154 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 27 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 614 | ok |
| tor | 10181 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 1921 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 511 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 1740 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 41231 | 9066 |
| url | 19345 | 4131 |
| domain | 10839 | 1502 |
| ipv6 | 3767 | 221 |
| sha256 | 3237 | 207 |
| md5 | 208 | 27 |
| sha1 | 110 | 0 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 13180 |
| Exit nodes | 2440 |
| Other relays | 10740 |
| New in window | 1144 |

Sample (20 of 13180, source: Tor Project Onionoo):
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
| Cobalt Strike | 1194 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| Vidar | 1124 | 0 | T1555, T1071.001, T1567 |
| IClickFix | 878 | 0 | — |
| Unknown malware | 705 | 0 | — |
| Unknown Loader | 559 | 0 | — |
| Mirai | 554 | 0 | T1498, T1071.001 |
| AMOS | 499 | 0 | — |
| PureRAT | 335 | 0 | — |
| MacSync | 253 | 0 | — |
| AdaptixC2 | 238 | 0 | — |
| Remus | 209 | 0 | — |
| ClickFix | 200 | 102 | — |
| DanaBot | 178 | 0 | T1566.001, T1071.001, T1555, T1041 |
| AsyncRAT | 174 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| Remcos | 173 | 0 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| ClearFake | 150 | 0 | — |
| VShell | 121 | 0 | — |
| php.shin_webshell | 103 | 0 | — |
| cryptoscam | 95 | 87 | — |
| Evilginx | 93 | 2 | — |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1566 | Phishing | initial-access | 18812 |
| T1566.002 | Spearphishing Link | initial-access | 18812 |
| T1071.001 | Web Protocols | command-and-control | 54581 |
| T1573 | Encrypted Channel | command-and-control | 6927 |
| T1105 | Ingress Tool Transfer | command-and-control | 6360 |
| T1498 | Network Denial of Service | impact | 3075 |
| T1555 | Credentials from Password Stores | credential-access | 2419 |
| T1567 | Exfiltration Over Web Service | exfiltration | 2237 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1347 |
| T1090 | Proxy | command-and-control | 1309 |
| T1059.001 | PowerShell | execution | 1204 |
| T1552.001 | Credentials In Files | credential-access | 1117 |
| T1056.001 | Keylogging | collection, credential-access | 1019 |
| T1566.001 | Spearphishing Attachment | initial-access | 765 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 494 |
| T1113 | Screen Capture | collection | 466 |
| T1204.002 | Malicious File | execution | 463 |
| T1027 | Obfuscated Files or Information | defense-evasion | 462 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 202 |
| T1486 | Data Encrypted for Impact | impact | 43 |
| T1490 | Inhibit System Recovery | impact | 43 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 43 |
| T1059.005 | Visual Basic | execution | 28 |
| T1190 | Exploit Public-Facing Application | initial-access | 20 |
| T1189 | Drive-by Compromise | initial-access | 4 |
| T1218 | System Binary Proxy Execution | defense-evasion | 4 |
| T1003 | OS Credential Dumping | credential-access | 1 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://529motors[.]com/homepersonas/`](https://www.virustotal.com/gui/search/https%3A%2F%2F529motors.com%2Fhomepersonas%2F) | url | — | openphish, tweetfeed | 2026-11-05T11:05:08Z | 70 |
| [`hxxps://vemtasbobinaj[.]com/login[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fvemtasbobinaj.com%2Flogin.html) | url | — | openphish, tweetfeed | 2026-11-02T19:27:35Z | 70 |
| [`hxxps://www[.]webzxkfa[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.webzxkfa.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://vemtasbobinaj[.]com/otp[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fvemtasbobinaj.com%2Fotp.html) | url | — | openphish | — | 70 |
| [`hxxps://www[.]weqweqw[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.weqweqw.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://mobilelegendsindonesia[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmobilelegendsindonesia.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]weqwxkl[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.weqwxkl.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]webgvt[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.webgvt.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://cp552296[.]tw1[.]ru/core/client/desjardins/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fcp552296.tw1.ru%2Fcore%2Fclient%2Fdesjardins%2F) | url | — | openphish | — | 70 |
| [`hxxps://jasejournals[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fjasejournals.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://cp552296[.]tw1[.]ru/core/client/td/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fcp552296.tw1.ru%2Fcore%2Fclient%2Ftd%2F) | url | — | openphish | — | 70 |
| [`hxxps://cp552296[.]tw1[.]ru/core/client/rbcroyal/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fcp552296.tw1.ru%2Fcore%2Fclient%2Frbcroyal%2F) | url | — | openphish | — | 70 |
| [`hxxps://cp552296[.]tw1[.]ru/core/client/scotia/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fcp552296.tw1.ru%2Fcore%2Fclient%2Fscotia%2F) | url | — | openphish | — | 70 |
| [`hxxps://mydpd[.]yfuma[.]xyz/track-ch`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmydpd.yfuma.xyz%2Ftrack-ch) | url | — | openphish | — | 70 |
| [`hxxp://146a2[.]casmex[.]at/kraken/`](https://www.virustotal.com/gui/search/http%3A%2F%2F146a2.casmex.at%2Fkraken%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]etransfer-accept[.]duckdns[.]org/scotia/index[.]php?ref=CAHsqZoFj`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.etransfer-accept.duckdns.org%2Fscotia%2Findex.php%3Fref%3DCAHsqZoFj) | url | — | openphish | — | 70 |
| [`hxxps://qorfani-mpt-vexloro-k7d4pe92[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fqorfani-mpt-vexloro-k7d4pe92.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]etransfer-accept[.]duckdns[.]org/rbc/index[.]php?ref=CAHsqZoFj`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.etransfer-accept.duckdns.org%2Frbc%2Findex.php%3Fref%3DCAHsqZoFj) | url | — | openphish | — | 70 |
| [`hxxps://www[.]securetransfer-x9hs6dlg4jzk[.]duckdns[.]org/scotia/index[.]php?ref=CAHsqZoFj`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.securetransfer-x9hs6dlg4jzk.duckdns.org%2Fscotia%2Findex.php%3Fref%3DCAHsqZoFj) | url | — | openphish | — | 70 |
| [`hxxp://foretaksregist[.]vercel[.]app/page1[.]5[.]html`](https://www.virustotal.com/gui/search/http%3A%2F%2Fforetaksregist.vercel.app%2Fpage1.5.html) | url | — | openphish | — | 70 |
| [`hxxps://www[.]securetransfer-x9hs6dlg4jzk[.]duckdns[.]org/rbc/index[.]php?ref=CAHsqZoFj`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.securetransfer-x9hs6dlg4jzk.duckdns.org%2Frbc%2Findex.php%3Fref%3DCAHsqZoFj) | url | — | openphish | — | 70 |
| [`hxxp://my-upheldcdn[.]teleporthq[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fmy-upheldcdn.teleporthq.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]ly/communities/910424662/DolllieRBLX`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.ly%2Fcommunities%2F910424662%2FDolllieRBLX) | url | — | openphish | — | 70 |
| [`hxxp://support-micrsoft[.]com/concluded[.]php?k=be0fd799b7276164843b3aa7219d1f80e35c6792`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsupport-micrsoft.com%2Fconcluded.php%3Fk%3Dbe0fd799b7276164843b3aa7219d1f80e35c6792) | url | — | openphish | — | 70 |
| [`hxxps://tr[.]ee/ptOQ4P`](https://www.virustotal.com/gui/search/https%3A%2F%2Ftr.ee%2FptOQ4P) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
