# Threat Intel Pulse — 2026-11-27

**Window:** last 7 days · **Generated:** 2026-11-27T21:29:20Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 70856 |
| New in window | 13329 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 23 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 314 | ok |
| tor | 10236 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 954 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 578 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 1806 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 44843 | 7673 |
| url | 13542 | 4115 |
| domain | 7658 | 1129 |
| ipv6 | 3820 | 143 |
| sha256 | 818 | 228 |
| md5 | 175 | 41 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 13291 |
| Exit nodes | 2485 |
| Other relays | 10806 |
| New in window | 836 |

Sample (20 of 13291, source: Tor Project Onionoo):
- `1[.]161[.]130[.]49`
- `1[.]161[.]139[.]48`
- `1[.]201[.]176[.]169`
- `1[.]201[.]176[.]176`
- `1[.]248[.]96[.]163`
- `1[.]34[.]44[.]234`
- `100[.]12[.]167[.]245`
- `100[.]2[.]63[.]41`
- `100[.]35[.]77[.]114`
- `100[.]8[.]164[.]103`
- `101[.]186[.]157[.]91`
- `101[.]186[.]183[.]53`
- `101[.]55[.]125[.]10`
- `102[.]130[.]113[.]29`
- `102[.]130[.]113[.]30`
- `102[.]130[.]113[.]42`
- `102[.]130[.]113[.]9`
- `102[.]130[.]115[.]59`
- `102[.]130[.]117[.]167`
- `102[.]130[.]119[.]48`

Full list: `dist/tor/tor_nodes.txt` (in the `threat-intel-output` workflow artifact).
## Top malware families

| Family | Indicators | New | ATT&CK (heuristic) |
| --- | --- | --- | --- |
| ClickFix | 409 | 76 | — |
| cryptoscam | 108 | 5 | — |
| Kimsuky | 84 | 18 | — |
| Formbook | 57 | 16 | T1566.001, T1056.001, T1555, T1071.001, T1567 |
| AiTM | 29 | 13 | — |
| Vidar | 21 | 0 | T1555, T1071.001, T1567 |
| Remcos | 19 | 1 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| GuLoader | 12 | 4 | T1027, T1059.005, T1055, T1105 |
| ValleyRAT | 12 | 10 | — |
| infostealer | 10 | 5 | — |
| Cobalt Strike | 8 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| Mirai | 7 | 0 | T1498, T1071.001 |
| Sliver | 7 | 3 | T1071.001, T1573, T1090, T1055 |
| Unknown malware | 5 | 0 | — |
| Evilginx | 4 | 0 | — |
| MustangPanda | 4 | 0 | — |
| QakBot | 4 | 0 | T1566.001, T1204.002, T1055, T1071.001, T1105, T1027, T1041 |
| Mispadu | 3 | 3 | — |
| PHP2Shell | 3 | 0 | — |
| Xworm | 3 | 2 | — |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1566 | Phishing | initial-access | 18103 |
| T1566.002 | Spearphishing Link | initial-access | 18103 |
| T1071.001 | Web Protocols | command-and-control | 51748 |
| T1573 | Encrypted Channel | command-and-control | 6129 |
| T1555 | Credentials from Password Stores | credential-access | 177 |
| T1567 | Exfiltration Over Web Service | exfiltration | 177 |
| T1552.001 | Credentials In Files | credential-access | 120 |
| T1056.001 | Keylogging | collection, credential-access | 111 |
| T1486 | Data Encrypted for Impact | impact | 91 |
| T1490 | Inhibit System Recovery | impact | 91 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 91 |
| T1566.001 | Spearphishing Attachment | initial-access | 82 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 32 |
| T1105 | Ingress Tool Transfer | command-and-control | 29 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 20 |
| T1113 | Screen Capture | collection | 19 |
| T1027 | Obfuscated Files or Information | defense-evasion | 18 |
| T1204.002 | Malicious File | execution | 18 |
| T1090 | Proxy | command-and-control | 15 |
| T1059.005 | Visual Basic | execution | 13 |
| T1498 | Network Denial of Service | impact | 9 |
| T1059.001 | PowerShell | execution | 8 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 5 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://hsbcau[.]jrni[.]com/login`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhsbcau.jrni.com%2Flogin) | url | — | openphish, tweetfeed | 2026-11-26T14:01:23Z | 70 |
| [`hxxps://php-intesasanpaolo-assistenza[.]wasmer[.]app/noaccount`](https://www.virustotal.com/gui/search/https%3A%2F%2Fphp-intesasanpaolo-assistenza.wasmer.app%2Fnoaccount) | url | — | openphish, tweetfeed | 2026-11-26T06:20:04Z | 70 |
| [`hxxps://bgbmail-gov[.]dgfiprotocolbd[.]workers[.]dev/login/?dhsfiourewjdfjgkfdgkldfjiorejfdjgfdgjkdfjgreioo=1`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbgbmail-gov.dgfiprotocolbd.workers.dev%2Flogin%2F%3Fdhsfiourewjdfjgkfdgkldfjiorejfdjgfdgjkdfjgreioo%3D1) | url | — | openphish, tweetfeed | 2026-11-25T17:46:08Z | 70 |
| [`hxxps://f005[.]backblazeb2[.]com/file/0000055/SignintoXfinity[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Ff005.backblazeb2.com%2Ffile%2F0000055%2FSignintoXfinity.html) | url | — | openphish, tweetfeed | 2026-11-23T02:02:14Z | 70 |
| [`hxxp://ns1[.]az/c6/alibaba/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fns1.az%2Fc6%2Falibaba%2F) | url | — | openphish, tweetfeed | 2026-11-22T13:00:57Z | 70 |
| [`hxxps://att-10page42[.]weeblysite[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fatt-10page42.weeblysite.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://metamzkloge[.]gitbook[.]io/us`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmetamzkloge.gitbook.io%2Fus) | url | — | openphish | — | 70 |
| [`hxxp://metamzkloge[.]gitbook[.]io/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fmetamzkloge.gitbook.io%2F) | url | — | openphish | — | 70 |
| [`hxxp://k5q9x2m-16073842-vn4p1z-87[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fk5q9x2m-16073842-vn4p1z-87.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://sp25ct11-zavmilo-biz-nerzaku[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsp25ct11-zavmilo-biz-nerzaku.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://sk-facebook[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsk-facebook.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]sk-facebook[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.sk-facebook.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]facebook-official-page[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.facebook-official-page.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]fake-facebook[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.fake-facebook.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://kcnlgn10[.]gitbook[.]io/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fkcnlgn10.gitbook.io%2F) | url | — | openphish | — | 70 |
| [`hxxps://att-currently-2-8-2025[.]weeblysite[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fatt-currently-2-8-2025.weeblysite.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://shopeejkt-78[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fshopeejkt-78.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://facebook-official-page[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ffacebook-official-page.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://facebookmail-facebook[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ffacebookmail-facebook.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://hadiah-resmi1577[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhadiah-resmi1577.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]facebookmail-facebook[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.facebookmail-facebook.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://facebook-www[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ffacebook-www.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://facebook-carol[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ffacebook-carol.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://statroblox[.]com/roblox-game-stats`](https://www.virustotal.com/gui/search/https%3A%2F%2Fstatroblox.com%2Froblox-game-stats) | url | — | openphish | — | 70 |
| [`hxxps://instagramsupportverify[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Finstagramsupportverify.blogspot.com%2F) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
