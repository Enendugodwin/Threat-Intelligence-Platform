# Threat Intel Pulse — 2026-10-04

**Window:** last 7 days · **Generated:** 2026-10-04T18:56:31Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 25925 |
| New in window | 25925 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 27 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5000 | ok |
| feodo | 5 | ok |
| threatfox | 11205 | ok |
| malwarebazaar | 1085 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8538 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 8348 | 8348 |
| domain | 5304 | 5304 |
| url | 5091 | 5091 |
| sha256 | 4400 | 4400 |
| ipv6 | 2668 | 2668 |
| md5 | 57 | 57 |
| sha1 | 57 | 57 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 8606 |
| Exit nodes | 2048 |
| Other relays | 6558 |
| New in window | 8606 |

Sample (20 of 8606, source: Tor Project Onionoo):
- `1[.]201[.]176[.]176`
- `100[.]2[.]63[.]41`
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
- `102[.]216[.]253[.]63`
- `102[.]68[.]99[.]63`
- `103[.]105[.]21[.]2`
- `103[.]109[.]100[.]207`
- `103[.]109[.]101[.]105`

Full list: `dist/tor/tor_nodes.txt` (in the `threat-intel-output` workflow artifact).
## Top malware families

| Family | Indicators | New | ATT&CK (heuristic) |
| --- | --- | --- | --- |
| Unknown Loader | 2644 | 2644 | — |
| Mirai | 2018 | 2018 | T1498, T1071.001 |
| Cobalt Strike | 1226 | 1226 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| AsyncRAT | 1190 | 1190 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| Unknown malware | 433 | 433 | — |
| IClickFix | 329 | 329 | — |
| PureRAT | 326 | 326 | — |
| ClearFake | 262 | 262 | — |
| AdaptixC2 | 238 | 238 | — |
| Unknown Stealer | 166 | 166 | — |
| Vidar | 153 | 153 | T1555, T1071.001, T1567 |
| Unknown RAT | 132 | 132 | — |
| DCRat | 96 | 96 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| Evilginx | 91 | 91 | — |
| Remcos | 90 | 90 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| AMOS | 83 | 83 | — |
| Havoc | 83 | 83 | — |
| VShell | 83 | 83 | — |
| Remus | 78 | 78 | — |
| DanaBot | 62 | 62 | T1566.001, T1071.001, T1555, T1041 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1071.001 | Web Protocols | command-and-control | 22643 |
| T1105 | Ingress Tool Transfer | command-and-control | 5994 |
| T1498 | Network Denial of Service | impact | 5098 |
| T1573 | Encrypted Channel | command-and-control | 3469 |
| T1056.001 | Keylogging | collection, credential-access | 1863 |
| T1566.001 | Spearphishing Attachment | initial-access | 1562 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 1423 |
| T1113 | Screen Capture | collection | 1404 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1341 |
| T1090 | Proxy | command-and-control | 1253 |
| T1059.001 | PowerShell | execution | 1238 |
| T1555 | Credentials from Password Stores | credential-access | 493 |
| T1567 | Exfiltration Over Web Service | exfiltration | 431 |
| T1552.001 | Credentials In Files | credential-access | 309 |
| T1566 | Phishing | initial-access | 307 |
| T1566.002 | Spearphishing Link | initial-access | 307 |
| T1027 | Obfuscated Files or Information | defense-evasion | 271 |
| T1204.002 | Malicious File | execution | 271 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 116 |
| T1059.005 | Visual Basic | execution | 41 |
| T1189 | Drive-by Compromise | initial-access | 5 |
| T1218 | System Binary Proxy Execution | defense-evasion | 5 |
| T1021.001 | Remote Desktop Protocol | lateral-movement | 2 |
| T1486 | Data Encrypted for Impact | impact | 2 |
| T1490 | Inhibit System Recovery | impact | 2 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 2 |
| T1003 | OS Credential Dumping | credential-access | 1 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`bb39866f5148a58eb55efc7a54d87a859900f85fb5cc42213fa5a94fd4c76a1e`](https://www.virustotal.com/gui/file/bb39866f5148a58eb55efc7a54d87a859900f85fb5cc42213fa5a94fd4c76a1e) | sha256 | Mirai | threatfox | 2026-10-04T18:47:11Z | 100 |
| [`295ccac6f1eb2f3dac004467539cd7d0b9554890f6ee1d9b01d6b85873683710`](https://www.virustotal.com/gui/file/295ccac6f1eb2f3dac004467539cd7d0b9554890f6ee1d9b01d6b85873683710) | sha256 | Mirai | malwarebazaar, threatfox | 2026-10-04T18:47:10Z | 100 |
| [`2f877ed3668559199e8571be72392d9fffe75d2a4788ae56b9f9b74bfa4bf7f7`](https://www.virustotal.com/gui/file/2f877ed3668559199e8571be72392d9fffe75d2a4788ae56b9f9b74bfa4bf7f7) | sha256 | Mirai | malwarebazaar, threatfox | 2026-10-04T18:47:09Z | 100 |
| [`675e38b86871fcde9f0b75e1a0df9e973e6928ffec3e017c643369650e6eab2c`](https://www.virustotal.com/gui/file/675e38b86871fcde9f0b75e1a0df9e973e6928ffec3e017c643369650e6eab2c) | sha256 | Mirai | threatfox | 2026-10-04T18:47:06Z | 100 |
| [`210edf2fb2b4cc1f9cc73b05858cd5524d402a00e4700e583aa1a746fae3b717`](https://www.virustotal.com/gui/file/210edf2fb2b4cc1f9cc73b05858cd5524d402a00e4700e583aa1a746fae3b717) | sha256 | Mirai | threatfox | 2026-10-04T18:47:05Z | 100 |
| [`32ead15908ca61088701ec6ee4c692658585746bafb52cce23c047d035fc91a5`](https://www.virustotal.com/gui/file/32ead15908ca61088701ec6ee4c692658585746bafb52cce23c047d035fc91a5) | sha256 | PureLogs Stealer | threatfox | 2026-10-04T18:47:04Z | 100 |
| [`edfa292a63fa4b57855d2caae989243189435f4ee043ddbc5ee14c0652ed3694`](https://www.virustotal.com/gui/file/edfa292a63fa4b57855d2caae989243189435f4ee043ddbc5ee14c0652ed3694) | sha256 | Mirai | threatfox | 2026-10-04T18:47:03Z | 100 |
| [`05e1003e63865a41fd2955642be8e217ee7b4e8500d673d87fd15ad93b6ec296`](https://www.virustotal.com/gui/file/05e1003e63865a41fd2955642be8e217ee7b4e8500d673d87fd15ad93b6ec296) | sha256 | Mirai | threatfox | 2026-10-04T18:47:02Z | 100 |
| [`28c0fd06d5941385aa22510ec520ad04f19a7cfd8c583e676d6113d1e00e5611`](https://www.virustotal.com/gui/file/28c0fd06d5941385aa22510ec520ad04f19a7cfd8c583e676d6113d1e00e5611) | sha256 | Mirai | threatfox | 2026-10-04T18:46:59Z | 100 |
| [`bc94f10c4b7da185b319cf4b6195321d4d456ff877324d905867df810880c22c`](https://www.virustotal.com/gui/file/bc94f10c4b7da185b319cf4b6195321d4d456ff877324d905867df810880c22c) | sha256 | Mirai | threatfox | 2026-10-04T18:46:57Z | 100 |
| [`c9ccc5a26c2226dc4ff595af21db15018d6cb02f663df845ca3a498e6346e1e8`](https://www.virustotal.com/gui/file/c9ccc5a26c2226dc4ff595af21db15018d6cb02f663df845ca3a498e6346e1e8) | sha256 | Mirai | threatfox | 2026-10-04T18:46:56Z | 100 |
| [`5314592786ad4bfb70a5b35cc9a1b68a92f790badabf4a4755d1ca77eb35d27e`](https://www.virustotal.com/gui/file/5314592786ad4bfb70a5b35cc9a1b68a92f790badabf4a4755d1ca77eb35d27e) | sha256 | Mirai | threatfox | 2026-10-04T18:46:55Z | 100 |
| [`18433cf591844ace03783e15903e84b6e97812824c50f4b2f5aafc33cb0b0f25`](https://www.virustotal.com/gui/file/18433cf591844ace03783e15903e84b6e97812824c50f4b2f5aafc33cb0b0f25) | sha256 | Mirai | threatfox | 2026-10-04T18:46:54Z | 100 |
| [`ef0d94d552e13da04d16d0a78c170fc443c06e4534a555c2f594b1bcf55f96c8`](https://www.virustotal.com/gui/file/ef0d94d552e13da04d16d0a78c170fc443c06e4534a555c2f594b1bcf55f96c8) | sha256 | Mirai | threatfox | 2026-10-04T18:46:52Z | 100 |
| [`51d2fe42168aea37cbf45483b27c87bd82bff31ec092be890990f10fbdd69fbf`](https://www.virustotal.com/gui/file/51d2fe42168aea37cbf45483b27c87bd82bff31ec092be890990f10fbdd69fbf) | sha256 | Mirai | threatfox | 2026-10-04T18:46:51Z | 100 |
| [`56b5dad237eac47f1ccc062e740ec9e7c38ed9001fda0ef61b254637f7a10d8d`](https://www.virustotal.com/gui/file/56b5dad237eac47f1ccc062e740ec9e7c38ed9001fda0ef61b254637f7a10d8d) | sha256 | Mirai | threatfox | 2026-10-04T18:46:45Z | 100 |
| [`f367633134cf14d9bfa393bdbf246833d90268dc1ffade89051fb3023fa2e6c0`](https://www.virustotal.com/gui/file/f367633134cf14d9bfa393bdbf246833d90268dc1ffade89051fb3023fa2e6c0) | sha256 | Mirai | threatfox | 2026-10-04T18:46:44Z | 100 |
| [`1cf79a8a0d11841719fd64486731338bee22e34f0d40e0cf21fb90d503c8c50b`](https://www.virustotal.com/gui/file/1cf79a8a0d11841719fd64486731338bee22e34f0d40e0cf21fb90d503c8c50b) | sha256 | Mirai | malwarebazaar, threatfox | 2026-10-04T18:46:42Z | 100 |
| [`178f533ef8e1a2515dc4bb1f3ba6a8ee13ca02184475fbfce38137025afe4dc1`](https://www.virustotal.com/gui/file/178f533ef8e1a2515dc4bb1f3ba6a8ee13ca02184475fbfce38137025afe4dc1) | sha256 | Mirai | threatfox | 2026-10-04T18:46:41Z | 100 |
| [`c10abe0caa9c62fb247b0641beaa5577b63e5c08eae6a23989c1c7a0586300c3`](https://www.virustotal.com/gui/file/c10abe0caa9c62fb247b0641beaa5577b63e5c08eae6a23989c1c7a0586300c3) | sha256 | Mirai | threatfox | 2026-10-04T18:46:40Z | 100 |
| [`19e1a79e5b5992999d75deee9c22ae3ecb5142a6714e76a284a9ae829737da3a`](https://www.virustotal.com/gui/file/19e1a79e5b5992999d75deee9c22ae3ecb5142a6714e76a284a9ae829737da3a) | sha256 | Mirai | threatfox | 2026-10-04T18:46:39Z | 100 |
| [`e9d578b368dc85285e4a02fd773fce75b5a8b63364dfeb0405324f9c878b3ce0`](https://www.virustotal.com/gui/file/e9d578b368dc85285e4a02fd773fce75b5a8b63364dfeb0405324f9c878b3ce0) | sha256 | Mirai | threatfox | 2026-10-04T18:46:38Z | 100 |
| [`1511fb0fd9e2e3cd0366f9a2a871bea1ee926bc93ae9bd90d4c7f328138c36c8`](https://www.virustotal.com/gui/file/1511fb0fd9e2e3cd0366f9a2a871bea1ee926bc93ae9bd90d4c7f328138c36c8) | sha256 | Mirai | threatfox | 2026-10-04T18:46:37Z | 100 |
| [`405965c18196ba4aec2803c6390e9663e3884e580680be62c09c8b6b9ec162cd`](https://www.virustotal.com/gui/file/405965c18196ba4aec2803c6390e9663e3884e580680be62c09c8b6b9ec162cd) | sha256 | Mirai | threatfox | 2026-10-04T18:46:35Z | 100 |
| [`60cd4b2b51c75baf6cf8756a894e98d1fa199ceeda0a40cbeab267667ab6c0fc`](https://www.virustotal.com/gui/file/60cd4b2b51c75baf6cf8756a894e98d1fa199ceeda0a40cbeab267667ab6c0fc) | sha256 | Mirai | threatfox | 2026-10-04T18:46:34Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
