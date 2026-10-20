# Threat Intel Pulse — 2026-10-20

**Window:** last 7 days · **Generated:** 2026-10-20T11:52:37Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 82328 |
| New in window | 24424 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 28 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5000 | ok |
| feodo | 5 | ok |
| threatfox | 6696 | ok |
| malwarebazaar | 1269 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8737 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| url | 33862 | 12731 |
| sha256 | 16699 | 5404 |
| domain | 13725 | 3156 |
| ipv4 | 12811 | 2006 |
| ipv6 | 3299 | 314 |
| md5 | 979 | 407 |
| sha1 | 953 | 406 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 11428 |
| Exit nodes | 2423 |
| Other relays | 9005 |
| New in window | 1256 |

Sample (20 of 11428, source: Tor Project Onionoo):
- `1[.]201[.]176[.]176`
- `1[.]235[.]159[.]83`
- `1[.]248[.]96[.]163`
- `1[.]34[.]44[.]234`
- `100[.]1[.]157[.]56`
- `100[.]2[.]63[.]41`
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
| Vidar | 5765 | 4757 | T1555, T1071.001, T1567 |
| Unknown Loader | 5455 | 866 | — |
| Mirai | 5197 | 1099 | T1498, T1071.001 |
| AsyncRAT | 2332 | 86 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| IClickFix | 2106 | 794 | — |
| ClearFake | 2054 | 344 | — |
| Unknown malware | 1695 | 731 | — |
| Cobalt Strike | 1366 | 59 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| VShell | 921 | 641 | — |
| AMOS | 902 | 626 | — |
| php.shin_webshell | 704 | 301 | — |
| Unknown Stealer | 645 | 78 | — |
| PureRAT | 456 | 59 | — |
| Sliver | 378 | 97 | T1071.001, T1573, T1090, T1055 |
| Remcos | 366 | 164 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| AdaptixC2 | 304 | 28 | — |
| Remus | 272 | 107 | — |
| Unknown RAT | 229 | 41 | — |
| Formbook | 224 | 100 | T1566.001, T1056.001, T1555, T1071.001, T1567 |
| DanaBot | 195 | 2 | T1566.001, T1071.001, T1555, T1041 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1071.001 | Web Protocols | command-and-control | 51523 |
| T1105 | Ingress Tool Transfer | command-and-control | 25091 |
| T1498 | Network Denial of Service | impact | 12671 |
| T1555 | Credentials from Password Stores | credential-access | 9652 |
| T1204.002 | Malicious File | execution | 9615 |
| T1567 | Exfiltration Over Web Service | exfiltration | 9456 |
| T1027 | Obfuscated Files or Information | defense-evasion | 9453 |
| T1573 | Encrypted Channel | command-and-control | 9076 |
| T1566 | Phishing | initial-access | 7580 |
| T1566.002 | Spearphishing Link | initial-access | 7580 |
| T1552.001 | Credentials In Files | credential-access | 5633 |
| T1056.001 | Keylogging | collection, credential-access | 4117 |
| T1566.001 | Spearphishing Attachment | initial-access | 3745 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 3093 |
| T1113 | Screen Capture | collection | 3029 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 2011 |
| T1090 | Proxy | command-and-control | 1782 |
| T1059.001 | PowerShell | execution | 1380 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 393 |
| T1189 | Drive-by Compromise | initial-access | 179 |
| T1218 | System Binary Proxy Execution | defense-evasion | 179 |
| T1059.005 | Visual Basic | execution | 95 |
| T1021.001 | Remote Desktop Protocol | lateral-movement | 14 |
| T1486 | Data Encrypted for Impact | impact | 14 |
| T1490 | Inhibit System Recovery | impact | 14 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 14 |
| T1190 | Exploit Public-Facing Application | initial-access | 10 |
| T1003 | OS Credential Dumping | credential-access | 4 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`795e521d428cad906ee11d19a2be00e80f51febf7e4d0a296ac2f5ae5a3c72e2`](https://www.virustotal.com/gui/file/795e521d428cad906ee11d19a2be00e80f51febf7e4d0a296ac2f5ae5a3c72e2) | sha256 | AMOS | threatfox | 2026-10-20T11:49:15Z | 100 |
| [`hxxp://darcy19[.]my:8312/products`](https://www.virustotal.com/gui/search/http%3A%2F%2Fdarcy19.my%3A8312%2Fproducts) | url | Remus | threatfox | 2026-10-20T11:48:19Z | 100 |
| [`hxxp://tool01[.]art:7713/payments`](https://www.virustotal.com/gui/search/http%3A%2F%2Ftool01.art%3A7713%2Fpayments) | url | Remus | threatfox | 2026-10-20T11:45:52Z | 100 |
| [`hxxps://uv[.]abangempayer[.]org/e4/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fuv.abangempayer.org%2Fe4%2F) | url | Vidar | threatfox | 2026-10-20T11:45:48Z | 100 |
| [`hxxp://netulse[.]sbs:5621/tasks`](https://www.virustotal.com/gui/search/http%3A%2F%2Fnetulse.sbs%3A5621%2Ftasks) | url | Remus | threatfox | 2026-10-20T11:45:26Z | 100 |
| [`ca5fe22a25ba07d8d233e9fd45cd537630e76227654e8db3a9f631b45fa8efdd`](https://www.virustotal.com/gui/file/ca5fe22a25ba07d8d233e9fd45cd537630e76227654e8db3a9f631b45fa8efdd) | sha256 | AMOS | threatfox | 2026-10-20T11:44:29Z | 100 |
| [`hxxp://tool01[.]art:7713/reviews`](https://www.virustotal.com/gui/search/http%3A%2F%2Ftool01.art%3A7713%2Freviews) | url | Remus | threatfox | 2026-10-20T11:43:39Z | 100 |
| [`hxxp://popeak[.]biz:8312/events`](https://www.virustotal.com/gui/search/http%3A%2F%2Fpopeak.biz%3A8312%2Fevents) | url | Remus | threatfox | 2026-10-20T11:43:01Z | 100 |
| [`d7b5aff4b659de7ae4079db09f0cb0de93bdb81ac65ee8ba515e60ed34ceabc7`](https://www.virustotal.com/gui/file/d7b5aff4b659de7ae4079db09f0cb0de93bdb81ac65ee8ba515e60ed34ceabc7) | sha256 | AMOS | threatfox | 2026-10-20T11:42:06Z | 100 |
| [`hxxps://uv[.]abangempayer[.]org/rh/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fuv.abangempayer.org%2Frh%2F) | url | Vidar | threatfox | 2026-10-20T11:40:48Z | 100 |
| [`hxxp://tmooreenterprises[.]com:6738/settings`](https://www.virustotal.com/gui/search/http%3A%2F%2Ftmooreenterprises.com%3A6738%2Fsettings) | url | Remus | threatfox | 2026-10-20T11:40:36Z | 100 |
| [`hxxp://tool01[.]art:7713/settings`](https://www.virustotal.com/gui/search/http%3A%2F%2Ftool01.art%3A7713%2Fsettings) | url | Remus | threatfox | 2026-10-20T11:40:28Z | 100 |
| [`hxxp://finter28[.]help:5621/documents`](https://www.virustotal.com/gui/search/http%3A%2F%2Ffinter28.help%3A5621%2Fdocuments) | url | Remus | threatfox | 2026-10-20T11:40:17Z | 100 |
| [`f3f882062273d08c9b3406a724b3e9292bd7b7c8978fd121e169f2a145bd598c`](https://www.virustotal.com/gui/file/f3f882062273d08c9b3406a724b3e9292bd7b7c8978fd121e169f2a145bd598c) | sha256 | AMOS | threatfox | 2026-10-20T11:38:26Z | 100 |
| [`hxxps://uv[.]abangempayer[.]org/do/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fuv.abangempayer.org%2Fdo%2F) | url | Vidar | threatfox | 2026-10-20T11:35:48Z | 100 |
| [`9e2cdcfb651459a46ab5d74b3766fbd671374b05c7a5fcd48e297ee926f5c6d7`](https://www.virustotal.com/gui/file/9e2cdcfb651459a46ab5d74b3766fbd671374b05c7a5fcd48e297ee926f5c6d7) | sha256 | AMOS | threatfox | 2026-10-20T11:34:37Z | 100 |
| [`hxxp://finter28[.]help:5621/images`](https://www.virustotal.com/gui/search/http%3A%2F%2Ffinter28.help%3A5621%2Fimages) | url | Remus | threatfox | 2026-10-20T11:34:36Z | 100 |
| [`09b6a0e73c5233c8475a14cd33def6a85799d82228bf127ff1c9dcde941e5707`](https://www.virustotal.com/gui/file/09b6a0e73c5233c8475a14cd33def6a85799d82228bf127ff1c9dcde941e5707) | sha256 | AMOS | threatfox | 2026-10-20T11:32:04Z | 100 |
| [`hxxps://uv[.]abangempayer[.]org/ij/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fuv.abangempayer.org%2Fij%2F) | url | Vidar | threatfox | 2026-10-20T11:30:48Z | 100 |
| [`hxxps://uv[.]abangempayer[.]org/qz/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fuv.abangempayer.org%2Fqz%2F) | url | Vidar | threatfox | 2026-10-20T11:25:48Z | 100 |
| [`hxxps://uv[.]abangempayer[.]org/gm/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fuv.abangempayer.org%2Fgm%2F) | url | Vidar | threatfox | 2026-10-20T11:20:48Z | 100 |
| [`hxxps://uv[.]abangempayer[.]org/gr/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fuv.abangempayer.org%2Fgr%2F) | url | Vidar | threatfox | 2026-10-20T11:15:48Z | 100 |
| [`hxxps://uv[.]abangempayer[.]org/op/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fuv.abangempayer.org%2Fop%2F) | url | Vidar | threatfox | 2026-10-20T11:10:48Z | 100 |
| [`hxxps://uv[.]abangempayer[.]org/s/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fuv.abangempayer.org%2Fs%2F) | url | Vidar | threatfox | 2026-10-20T11:05:48Z | 100 |
| [`hxxps://hf[.]abangempayer[.]org/a/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhf.abangempayer.org%2Fa%2F) | url | Vidar | threatfox | 2026-10-20T11:00:49Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
