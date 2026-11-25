# Threat Intel Pulse — 2026-11-25

**Window:** last 7 days · **Generated:** 2026-11-25T21:54:03Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 69395 |
| New in window | 13135 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 23 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 314 | ok |
| tor | 10198 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 462 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 568 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 2088 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 43937 | 7363 |
| url | 13082 | 4213 |
| domain | 7669 | 1132 |
| ipv6 | 3826 | 169 |
| sha256 | 715 | 205 |
| md5 | 166 | 53 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 13278 |
| Exit nodes | 2498 |
| Other relays | 10780 |
| New in window | 836 |

Sample (20 of 13278, source: Tor Project Onionoo):
- `1[.]161[.]130[.]49`
- `1[.]201[.]176[.]169`
- `1[.]201[.]176[.]176`
- `1[.]248[.]96[.]163`
- `1[.]34[.]44[.]234`
- `100[.]12[.]167[.]245`
- `100[.]2[.]63[.]41`
- `100[.]35[.]77[.]114`
- `100[.]8[.]164[.]103`
- `100[.]8[.]53[.]153`
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
| ClickFix | 411 | 127 | — |
| cryptoscam | 108 | 10 | — |
| Kimsuky | 82 | 26 | — |
| Formbook | 42 | 0 | T1566.001, T1056.001, T1555, T1071.001, T1567 |
| AiTM | 29 | 13 | — |
| Vidar | 21 | 0 | T1555, T1071.001, T1567 |
| Remcos | 19 | 4 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| infostealer | 12 | 5 | — |
| Cobalt Strike | 8 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| GuLoader | 8 | 0 | T1027, T1059.005, T1055, T1105 |
| Mirai | 7 | 0 | T1498, T1071.001 |
| Unknown malware | 6 | 0 | — |
| ValleyRAT | 5 | 5 | — |
| Evilginx | 4 | 0 | — |
| MustangPanda | 4 | 4 | — |
| QakBot | 4 | 0 | T1566.001, T1204.002, T1055, T1071.001, T1105, T1027, T1041 |
| Sliver | 4 | 0 | T1071.001, T1573, T1090, T1055 |
| Mispadu | 3 | 3 | — |
| PHP2Shell | 3 | 0 | — |
| Hookbot | 2 | 2 | — |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1566 | Phishing | initial-access | 17759 |
| T1566.002 | Spearphishing Link | initial-access | 17759 |
| T1071.001 | Web Protocols | command-and-control | 50734 |
| T1573 | Encrypted Channel | command-and-control | 5741 |
| T1555 | Credentials from Password Stores | credential-access | 164 |
| T1567 | Exfiltration Over Web Service | exfiltration | 164 |
| T1552.001 | Credentials In Files | credential-access | 122 |
| T1056.001 | Keylogging | collection, credential-access | 95 |
| T1486 | Data Encrypted for Impact | impact | 90 |
| T1490 | Inhibit System Recovery | impact | 90 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 90 |
| T1566.001 | Spearphishing Attachment | initial-access | 67 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 25 |
| T1105 | Ingress Tool Transfer | command-and-control | 25 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 20 |
| T1113 | Screen Capture | collection | 19 |
| T1027 | Obfuscated Files or Information | defense-evasion | 14 |
| T1204.002 | Malicious File | execution | 14 |
| T1090 | Proxy | command-and-control | 12 |
| T1059.005 | Visual Basic | execution | 9 |
| T1498 | Network Denial of Service | impact | 9 |
| T1059.001 | PowerShell | execution | 8 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 5 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://f005[.]backblazeb2[.]com/file/0000055/SignintoXfinity[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Ff005.backblazeb2.com%2Ffile%2F0000055%2FSignintoXfinity.html) | url | — | openphish, tweetfeed | 2026-11-23T02:02:14Z | 70 |
| [`hxxp://ns1[.]az/c6/alibaba/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fns1.az%2Fc6%2Falibaba%2F) | url | — | openphish, tweetfeed | 2026-11-22T13:00:57Z | 70 |
| [`hxxps://saratio[.]de/gustafsonltd/download[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsaratio.de%2Fgustafsonltd%2Fdownload.html) | url | — | openphish, tweetfeed | 2026-11-19T18:25:18Z | 70 |
| [`hxxp://www[.]talktalkinfo1[.]weebly[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.talktalkinfo1.weebly.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://jodals[.]github[.]io/SPOTIFY-Clone`](https://www.virustotal.com/gui/search/http%3A%2F%2Fjodals.github.io%2FSPOTIFY-Clone) | url | — | openphish | — | 70 |
| [`hxxps://www[.]undian-hadiahshopee33[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.undian-hadiahshopee33.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://opensea[.]28372982[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fopensea.28372982.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://small-base-c44c[.]roberto-kupfer[.]workers[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsmall-base-c44c.roberto-kupfer.workers.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://vmi3744912[.]contaboserver[.]net//amm/rena/msg[.]php/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fvmi3744912.contaboserver.net%2F%2Famm%2Frena%2Fmsg.php%2F) | url | — | openphish | — | 70 |
| [`hxxp://armanbin007[.]github[.]io/Spotify-Replica-Project`](https://www.virustotal.com/gui/search/http%3A%2F%2Farmanbin007.github.io%2FSpotify-Replica-Project) | url | — | openphish | — | 70 |
| [`hxxps://bradescoempresa[.]urlx[.]online/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbradescoempresa.urlx.online%2F) | url | — | openphish | — | 70 |
| [`hxxp://splendorous-sunburst-84749c[.]netlify[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsplendorous-sunburst-84749c.netlify.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://ledger[.]hk[.]cn/downloads`](https://www.virustotal.com/gui/search/https%3A%2F%2Fledger.hk.cn%2Fdownloads) | url | — | openphish | — | 70 |
| [`hxxp://kanishkaverma1405[.]github[.]io/Netflix-clone`](https://www.virustotal.com/gui/search/http%3A%2F%2Fkanishkaverma1405.github.io%2FNetflix-clone) | url | — | openphish | — | 70 |
| [`hxxp://sanganinandini[.]github[.]io/Netflix-dashboard`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsanganinandini.github.io%2FNetflix-dashboard) | url | — | openphish | — | 70 |
| [`hxxps://constitute-ontario-jewish-carefully[.]trycloudflare[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fconstitute-ontario-jewish-carefully.trycloudflare.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://upholexdlogin[.]gitbook[.]io/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fupholexdlogin.gitbook.io%2F) | url | — | openphish | — | 70 |
| [`hxxps://romani[.]ind[.]br/sho/upgrade[.]html#[email%C2%A0protected]`](https://www.virustotal.com/gui/search/https%3A%2F%2Fromani.ind.br%2Fsho%2Fupgrade.html%23%5Bemail%25C2%25A0protected%5D) | url | — | openphish | — | 70 |
| [`hxxp://imtooenne[.]com/en[.]html`](https://www.virustotal.com/gui/search/http%3A%2F%2Fimtooenne.com%2Fen.html) | url | — | openphish | — | 70 |
| [`hxxp://casadosbordados[.]net/_`](https://www.virustotal.com/gui/search/http%3A%2F%2Fcasadosbordados.net%2F_) | url | — | openphish | — | 70 |
| [`hxxp://splendorous-squirrel-a00c04[.]netlify[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsplendorous-squirrel-a00c04.netlify.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://auth[.]re/E[.]0zwzVx5eU3tZvXEbyw?/=userid&messageid=YWZhNDM0c2RqZjk4MjNmb2lkc2pmKC9DODk4RnNhOShGLyhBU0ZzdWlhaGRma2FzZDIoLw==`](https://www.virustotal.com/gui/search/https%3A%2F%2Fauth.re%2FE.0zwzVx5eU3tZvXEbyw%3F%2F%3Duserid%26messageid%3DYWZhNDM0c2RqZjk4MjNmb2lkc2pmKC9DODk4RnNhOShGLyhBU0ZzdWlhaGRma2FzZDIoLw%3D%3D) | url | — | openphish | — | 70 |
| [`hxxps://rbx[.]tg/vYJ-XAmY`](https://www.virustotal.com/gui/search/https%3A%2F%2Frbx.tg%2FvYJ-XAmY) | url | — | openphish | — | 70 |
| [`hxxps://adobe[.]subscribenet[.]com/control/adbe/login?nextURL=%2Fcontrol%2Fadbe%2F`](https://www.virustotal.com/gui/search/https%3A%2F%2Fadobe.subscribenet.com%2Fcontrol%2Fadbe%2Flogin%3FnextURL%3D%252Fcontrol%252Fadbe%252F) | url | — | openphish | — | 70 |
| [`hxxps://adobe[.]subscribenet[.]com/control/adbe/index/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fadobe.subscribenet.com%2Fcontrol%2Fadbe%2Findex%2F) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
