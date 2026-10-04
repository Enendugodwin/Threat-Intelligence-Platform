# Threat Intel Pulse — 2026-10-04

**Window:** last 7 days · **Generated:** 2026-10-04T21:40:48Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 26331 |
| New in window | 26331 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 27 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| urlhaus | 5000 | ok |
| feodo | 5 | ok |
| threatfox | 11040 | ok |
| malwarebazaar | 999 | ok |
| openphish | 300 | ok |
| circl | 914 | ok |
| tor | 8604 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 8514 | 8514 |
| domain | 5359 | 5359 |
| url | 5132 | 5132 |
| sha256 | 4494 | 4494 |
| ipv6 | 2718 | 2718 |
| md5 | 57 | 57 |
| sha1 | 57 | 57 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 8806 |
| Exit nodes | 2073 |
| Other relays | 6733 |
| New in window | 8806 |

Sample (20 of 8806, source: Tor Project Onionoo):
- `1[.]201[.]176[.]176`
- `100[.]1[.]157[.]56`
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

Full list: `dist/tor/tor_nodes.txt` (in the `threat-intel-output` workflow artifact).
## Top malware families

| Family | Indicators | New | ATT&CK (heuristic) |
| --- | --- | --- | --- |
| Unknown Loader | 2663 | 2663 | — |
| Mirai | 2100 | 2100 | T1498, T1071.001 |
| Cobalt Strike | 1226 | 1226 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| AsyncRAT | 1193 | 1193 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| Unknown malware | 435 | 435 | — |
| IClickFix | 333 | 333 | — |
| PureRAT | 329 | 329 | — |
| ClearFake | 291 | 291 | — |
| AdaptixC2 | 240 | 240 | — |
| Unknown Stealer | 166 | 166 | — |
| Vidar | 154 | 154 | T1555, T1071.001, T1567 |
| Unknown RAT | 132 | 132 | — |
| DCRat | 97 | 97 | T1566.001, T1547.001, T1056.001, T1113, T1071.001 |
| Evilginx | 92 | 92 | — |
| Remcos | 91 | 91 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| VShell | 86 | 86 | — |
| Havoc | 84 | 84 | — |
| AMOS | 83 | 83 | — |
| Remus | 78 | 78 | — |
| DanaBot | 63 | 63 | T1566.001, T1071.001, T1555, T1041 |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1071.001 | Web Protocols | command-and-control | 23018 |
| T1105 | Ingress Tool Transfer | command-and-control | 6034 |
| T1498 | Network Denial of Service | impact | 5200 |
| T1573 | Encrypted Channel | command-and-control | 3479 |
| T1056.001 | Keylogging | collection, credential-access | 1871 |
| T1566.001 | Spearphishing Attachment | initial-access | 1568 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 1428 |
| T1113 | Screen Capture | collection | 1409 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 1341 |
| T1090 | Proxy | command-and-control | 1253 |
| T1059.001 | PowerShell | execution | 1238 |
| T1555 | Credentials from Password Stores | credential-access | 496 |
| T1567 | Exfiltration Over Web Service | exfiltration | 433 |
| T1552.001 | Credentials In Files | credential-access | 309 |
| T1566 | Phishing | initial-access | 307 |
| T1566.002 | Spearphishing Link | initial-access | 307 |
| T1027 | Obfuscated Files or Information | defense-evasion | 271 |
| T1204.002 | Malicious File | execution | 271 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 117 |
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
| [`95b4e74af25fbe652b36c394e69c5c6c29d9f803f8a81b5ca37021a569910d96`](https://www.virustotal.com/gui/file/95b4e74af25fbe652b36c394e69c5c6c29d9f803f8a81b5ca37021a569910d96) | sha256 | Mirai | malwarebazaar, threatfox | 2026-10-04T20:47:03Z | 100 |
| [`50eba3c916db0f1a0892ed2651cbaab89965b628a618c095de4473fd5d15e536`](https://www.virustotal.com/gui/file/50eba3c916db0f1a0892ed2651cbaab89965b628a618c095de4473fd5d15e536) | sha256 | Mirai | threatfox | 2026-10-04T20:47:02Z | 100 |
| [`22d787cc8ee9319b6e1147f55f7204d846efda4a3a0b1b40fc92d2bfd7345ff5`](https://www.virustotal.com/gui/file/22d787cc8ee9319b6e1147f55f7204d846efda4a3a0b1b40fc92d2bfd7345ff5) | sha256 | Mirai | threatfox | 2026-10-04T20:47:00Z | 100 |
| [`28fa4489e716e5c7928271d86ce8d20593f90c44d6ceac01b16f1edbcaf89a36`](https://www.virustotal.com/gui/file/28fa4489e716e5c7928271d86ce8d20593f90c44d6ceac01b16f1edbcaf89a36) | sha256 | Mirai | threatfox | 2026-10-04T20:46:59Z | 100 |
| [`6e454eff70e386c82120434900dc8c4d9b38ed6ad347580496a71633e5d93896`](https://www.virustotal.com/gui/file/6e454eff70e386c82120434900dc8c4d9b38ed6ad347580496a71633e5d93896) | sha256 | Mirai | threatfox | 2026-10-04T20:46:58Z | 100 |
| [`4d520c344f984fbf9fa08032c13a34ceedcf0293ac6ccb2884845e53b04038d6`](https://www.virustotal.com/gui/file/4d520c344f984fbf9fa08032c13a34ceedcf0293ac6ccb2884845e53b04038d6) | sha256 | Mirai | threatfox | 2026-10-04T20:46:56Z | 100 |
| [`73e128c6ebfa6f0b7f117dc8eae4dd31fc587905f67ce97fac991c4e413008a8`](https://www.virustotal.com/gui/file/73e128c6ebfa6f0b7f117dc8eae4dd31fc587905f67ce97fac991c4e413008a8) | sha256 | Mirai | threatfox | 2026-10-04T20:46:56Z | 100 |
| [`b2a4e3f3c4ee656fed9f7a245c7142e851a4a969287582004616c2ed8f5f299d`](https://www.virustotal.com/gui/file/b2a4e3f3c4ee656fed9f7a245c7142e851a4a969287582004616c2ed8f5f299d) | sha256 | Mirai | threatfox | 2026-10-04T20:46:48Z | 100 |
| [`b3dbae44369975b6711b4a73be8b3995c19b4c7d5f228e641c0bac883ab10721`](https://www.virustotal.com/gui/file/b3dbae44369975b6711b4a73be8b3995c19b4c7d5f228e641c0bac883ab10721) | sha256 | Mirai | threatfox | 2026-10-04T20:46:47Z | 100 |
| [`0b210aa601f12bc1f75ce3fec740c5c1e60d2598733b54d74f1d3efd38d04c19`](https://www.virustotal.com/gui/file/0b210aa601f12bc1f75ce3fec740c5c1e60d2598733b54d74f1d3efd38d04c19) | sha256 | Mirai | threatfox | 2026-10-04T20:46:45Z | 100 |
| [`fccafdc4d3ef4c49dd52b7a1194eb7d132b01da1e4c74bad5920198f968d004c`](https://www.virustotal.com/gui/file/fccafdc4d3ef4c49dd52b7a1194eb7d132b01da1e4c74bad5920198f968d004c) | sha256 | Mirai | threatfox | 2026-10-04T20:46:44Z | 100 |
| [`c82a61264f2bbb1006ff150747b860411cbfac1809b021819622835b431532f4`](https://www.virustotal.com/gui/file/c82a61264f2bbb1006ff150747b860411cbfac1809b021819622835b431532f4) | sha256 | Mirai | malwarebazaar, threatfox | 2026-10-04T20:46:42Z | 100 |
| [`ccc23682bd4ebb03464e44619a735ed0a8cf36c5d4f60134785f8f198223318c`](https://www.virustotal.com/gui/file/ccc23682bd4ebb03464e44619a735ed0a8cf36c5d4f60134785f8f198223318c) | sha256 | Mirai | threatfox | 2026-10-04T20:46:41Z | 100 |
| [`93c4256f51574692dc96f47cac3a3587707dd7edc023c3704f781a25afbe609f`](https://www.virustotal.com/gui/file/93c4256f51574692dc96f47cac3a3587707dd7edc023c3704f781a25afbe609f) | sha256 | Mirai | threatfox | 2026-10-04T20:46:40Z | 100 |
| [`769bd770366308fa1f6edbb235da42b5a6296ab0d3c5d672f291ae1cc566106d`](https://www.virustotal.com/gui/file/769bd770366308fa1f6edbb235da42b5a6296ab0d3c5d672f291ae1cc566106d) | sha256 | Mirai | threatfox | 2026-10-04T20:46:39Z | 100 |
| [`d03ef8fdb39302e0bff56f9ed088e6aa1775b6979ba540ff801bbc7047d97c09`](https://www.virustotal.com/gui/file/d03ef8fdb39302e0bff56f9ed088e6aa1775b6979ba540ff801bbc7047d97c09) | sha256 | Mirai | threatfox | 2026-10-04T20:46:38Z | 100 |
| [`c49ef0b295c49f964a1dbd5f7ac74edae1445398ee1ed619e497b77eded82680`](https://www.virustotal.com/gui/file/c49ef0b295c49f964a1dbd5f7ac74edae1445398ee1ed619e497b77eded82680) | sha256 | Mirai | threatfox | 2026-10-04T20:46:37Z | 100 |
| [`d6b0e46b0d957aac65e1989bd97e1a36f4e0b17ac1fe579272df0deff0c2cd2f`](https://www.virustotal.com/gui/file/d6b0e46b0d957aac65e1989bd97e1a36f4e0b17ac1fe579272df0deff0c2cd2f) | sha256 | Mirai | threatfox | 2026-10-04T20:46:35Z | 100 |
| [`98fd9a8f28856d66e5d45e26749edec79ce1841c0f73b0d2244e1628527fec44`](https://www.virustotal.com/gui/file/98fd9a8f28856d66e5d45e26749edec79ce1841c0f73b0d2244e1628527fec44) | sha256 | Mirai | threatfox | 2026-10-04T20:46:34Z | 100 |
| [`6272cc2ee363eff4577eebc7473a91e178dd97ecc733ff2dbdc21945dca8e6fa`](https://www.virustotal.com/gui/file/6272cc2ee363eff4577eebc7473a91e178dd97ecc733ff2dbdc21945dca8e6fa) | sha256 | Mirai | threatfox | 2026-10-04T20:46:30Z | 100 |
| [`08347e4debb51bc5933356d8288afed66568c3ccf8303955418e9ebc3011d25b`](https://www.virustotal.com/gui/file/08347e4debb51bc5933356d8288afed66568c3ccf8303955418e9ebc3011d25b) | sha256 | Mirai | threatfox | 2026-10-04T20:46:27Z | 100 |
| [`2debeb696ed96e13d480eaa7519175d43c9582eef567ad9b61a32d8acf21d560`](https://www.virustotal.com/gui/file/2debeb696ed96e13d480eaa7519175d43c9582eef567ad9b61a32d8acf21d560) | sha256 | Mirai | threatfox | 2026-10-04T20:46:26Z | 100 |
| [`a4a24d9f15a9998be9ee3515e800090bef248d830c4bbbd97eb5ecf1cd41629c`](https://www.virustotal.com/gui/file/a4a24d9f15a9998be9ee3515e800090bef248d830c4bbbd97eb5ecf1cd41629c) | sha256 | Mirai | threatfox | 2026-10-04T20:46:24Z | 100 |
| [`208b8c2b2ee2e299351427acf7e7c85598efc805ec26f21335535b70d6059c6b`](https://www.virustotal.com/gui/file/208b8c2b2ee2e299351427acf7e7c85598efc805ec26f21335535b70d6059c6b) | sha256 | Mirai | threatfox | 2026-10-04T20:46:23Z | 100 |
| [`d4305895d867b0906826b7ce89957f5b95d019093e2794786c8c07a24c9694d0`](https://www.virustotal.com/gui/file/d4305895d867b0906826b7ce89957f5b95d019093e2794786c8c07a24c9694d0) | sha256 | Mirai | threatfox | 2026-10-04T20:46:22Z | 100 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
