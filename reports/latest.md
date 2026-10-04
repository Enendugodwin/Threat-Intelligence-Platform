# Threat Intel Pulse — 2026-10-04

**Window:** last 7 days · **Generated:** 2026-10-04T17:54:15Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 23488 |
| New in window | 23488 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 27 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5000 | ok |
| feodo | 5 | ok |
| threatfox | 11211 | ok |
| tor | 8536 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 8271 | 8271 |
| url | 4775 | 4775 |
| domain | 4385 | 4385 |
| sha256 | 3297 | 3297 |
| ipv6 | 2646 | 2646 |
| md5 | 57 | 57 |
| sha1 | 57 | 57 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 8536 |
| Exit nodes | 2033 |
| Other relays | 6503 |
| New in window | 8536 |

Sample (20 of 8536, source: Tor Project Onionoo):
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
- `102[.]68[.]99[.]63`
- `103[.]105[.]21[.]2`
- `103[.]109[.]100[.]207`
- `103[.]109[.]101[.]105`
- `103[.]109[.]187[.]71`

Full list: `dist/tor/tor_nodes.txt` (in the `threat-intel-output` workflow artifact).
## Top malware families

| Family | Indicators | New | ATT&CK (heuristic) |
| --- | --- | --- | --- |
| Unknown Loader | 2644 | 2644 | — |
| Mirai | 1979 | 1979 | T1498, T1071.001 |
| Cobalt Strike | 1226 | 1226 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| AsyncRAT | 1190 | 1190 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| Unknown malware | 432 | 432 | — |
| IClickFix | 329 | 329 | — |
| PureRAT | 326 | 326 | — |
| AdaptixC2 | 237 | 237 | — |
| ClearFake | 231 | 231 | — |
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
| T1071.001 | Web Protocols | command-and-control | 21570 |
| T1105 | Ingress Tool Transfer | command-and-control | 5978 |
| T1498 | Network Denial of Service | impact | 5044 |
| T1573 | Encrypted Channel | command-and-control | 3468 |
| T1056.001 | Keylogging | collection, credential-access | 1863 |
| T1566.001 | Spearphishing Attachment | initial-access | 1561 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 1423 |
| T1113 | Screen Capture | collection | 1404 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1341 |
| T1090 | Proxy | command-and-control | 1253 |
| T1059.001 | PowerShell | execution | 1238 |
| T1555 | Credentials from Password Stores | credential-access | 491 |
| T1567 | Exfiltration Over Web Service | exfiltration | 429 |
| T1552.001 | Credentials In Files | credential-access | 307 |
| T1027 | Obfuscated Files or Information | defense-evasion | 271 |
| T1204.002 | Malicious File | execution | 271 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 115 |
| T1059.005 | Visual Basic | execution | 41 |
| T1566 | Phishing | initial-access | 7 |
| T1566.002 | Spearphishing Link | initial-access | 7 |
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
| `ecb767b39fd44b5a1d469ef8dd0f5ae4184b517c9a582ad07ba0e10105d21a33` | sha256 | Mirai | threatfox | 2026-10-04T17:46:55Z | 100 |
| `9709f5f5bd7b670a2a79d309c1110b25ffe81a5b06aaf90dd0a3a3701907a046` | sha256 | Mirai | threatfox | 2026-10-04T17:46:54Z | 100 |
| `54e5d84aee4855a9439ce57f0785d89d640e4d56976d4890feda43883bfee9c4` | sha256 | Mirai | threatfox | 2026-10-04T17:46:53Z | 100 |
| `2d468615ebd35f201bf225e52012cffe42266635b30d6dac9eff9e58d633d3cb` | sha256 | Mirai | threatfox | 2026-10-04T17:46:52Z | 100 |
| `5a8910855f365b70364209bdd4c5071dd3ccc592d6da572d8d326511c0bb123f` | sha256 | Mirai | threatfox | 2026-10-04T17:46:51Z | 100 |
| `3d8e1ed39045bc2d576496c434f073c43148f658af9e9155a5bafaf473ad0706` | sha256 | Mirai | threatfox | 2026-10-04T17:46:50Z | 100 |
| `a28a0bae3819a7cdd9bf924db6db8149cec15ed87fc24d6897f5c04efbaa8a75` | sha256 | Mirai | threatfox | 2026-10-04T17:46:49Z | 100 |
| `eb56b26a4b55e6d0d7405e052861bdbdafa36ada2b73ccbb1f32fe0ff6c8197f` | sha256 | Mirai | threatfox | 2026-10-04T17:46:48Z | 100 |
| `12f663c66387fd2194d7901bf1598065e63feb5c7ca2f477419405c71188e22c` | sha256 | Mirai | threatfox | 2026-10-04T17:46:47Z | 100 |
| `acc1de6c1d39dc050935b4eacdb1abdeb3682c54b168f6577056dcd3f963d74b` | sha256 | Mirai | threatfox | 2026-10-04T17:46:46Z | 100 |
| `3a4cbbddf99f696161b533d410b104f2567b204156b2d61e34218a00ecac5148` | sha256 | Mirai | threatfox | 2026-10-04T17:46:45Z | 100 |
| `e597fbb056bbea26a8f7f9b73ad104cae3c47915f13011232e6c5113b9010cc1` | sha256 | Mirai | threatfox | 2026-10-04T17:46:38Z | 100 |
| `2b065c4fb737cb073e50ad11426ee821d2089d63b8b32e13e59192a9a6e18503` | sha256 | Mirai | threatfox | 2026-10-04T17:46:37Z | 100 |
| `bdaf3c99c0dc9f4a9b75b30f228dd64f168de46da83546f8c3b7d93bc7298bae` | sha256 | Mirai | threatfox | 2026-10-04T17:46:35Z | 100 |
| `e65e691c50ac86bab852ab28cc0d0fe86df4032e998ceacbbb5e615d45a7f97d` | sha256 | Mirai | threatfox | 2026-10-04T17:46:34Z | 100 |
| `97a6efe082d0bb8814cbef7516fabf585db0a93fbae7d1ef89ec7cd55f0d794e` | sha256 | Mirai | threatfox | 2026-10-04T17:46:33Z | 100 |
| `507a91f9c3e06ea1e0c8bdfa2891d2eb433524ca0ff5021988000bbb44639998` | sha256 | Mirai | threatfox | 2026-10-04T17:46:32Z | 100 |
| `a7879fa112b4b5cf2a19b226e37b60df5e65ddf29ad2597b50164d0e292d7753` | sha256 | Coinminer | threatfox | 2026-10-04T17:46:31Z | 100 |
| `50d60faa09f5c031e288d26ab6290eee301831f2dd59bb376a43dd74d07e3ad7` | sha256 | Mirai | threatfox | 2026-10-04T17:46:30Z | 100 |
| `e53bad2278d773789d94a6a199f6ddaac0c99af05b08ce2224d1d52a15f6aa0c` | sha256 | Mirai | threatfox | 2026-10-04T17:46:28Z | 100 |
| `18547a337812ec93e0a6ae6101811590ecf634e21076436eaea376b65d2c016e` | sha256 | Mirai | threatfox | 2026-10-04T17:46:27Z | 100 |
| `98d76ee355dc352072c04cdf868e483c9390b01431946c1bab1d25b387ca9caa` | sha256 | Mirai | threatfox | 2026-10-04T17:46:26Z | 100 |
| `918841b8b06eafc79cbb0dfa8586ad2da02f3e373ba1a86e0a473b518e7e8b99` | sha256 | Mirai | threatfox | 2026-10-04T17:46:25Z | 100 |
| `c431790e6da4e89eaf62a8a70d73dc953598d787109d8c6c365038c61bcdd586` | sha256 | Mirai | threatfox | 2026-10-04T17:46:24Z | 100 |
| `99890bb10d0cb653b009770c5fe1aeb24cd394ede9623a1463b46dc01e8d8b9f` | sha256 | Mirai | threatfox | 2026-10-04T17:46:23Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
