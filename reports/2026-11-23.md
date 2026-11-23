# Threat Intel Pulse — 2026-11-23

**Window:** last 7 days · **Generated:** 2026-11-23T07:57:12Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 69441 |
| New in window | 15021 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 23 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 314 | ok |
| tor | 10352 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 613 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 596 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 1931 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 43861 | 8397 |
| url | 13342 | 4920 |
| domain | 7556 | 1139 |
| ipv6 | 3818 | 209 |
| sha256 | 703 | 297 |
| md5 | 161 | 59 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 13325 |
| Exit nodes | 2490 |
| Other relays | 10835 |
| New in window | 974 |

Sample (20 of 13325, source: Tor Project Onionoo):
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
| ClickFix | 382 | 154 | — |
| cryptoscam | 111 | 7 | — |
| Kimsuky | 76 | 56 | — |
| Formbook | 42 | 0 | T1566.001, T1056.001, T1555, T1071.001, T1567 |
| Vidar | 21 | 0 | T1555, T1071.001, T1567 |
| Remcos | 19 | 5 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| DPRK | 18 | 0 | — |
| AiTM | 16 | 8 | — |
| Cobalt Strike | 9 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| GuLoader | 8 | 0 | T1027, T1059.005, T1055, T1105 |
| Mirai | 7 | 0 | T1498, T1071.001 |
| infostealer | 7 | 0 | — |
| Unknown malware | 6 | 0 | — |
| Evilginx | 4 | 0 | — |
| MustangPanda | 4 | 4 | — |
| PHP2Shell | 4 | 1 | — |
| QakBot | 4 | 0 | T1566.001, T1204.002, T1055, T1071.001, T1105, T1027, T1041 |
| Sliver | 4 | 0 | T1071.001, T1573, T1090, T1055 |
| Mispadu | 3 | 3 | — |
| AdaptixC2 | 2 | 0 | — |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1566 | Phishing | initial-access | 18040 |
| T1566.002 | Spearphishing Link | initial-access | 18040 |
| T1071.001 | Web Protocols | command-and-control | 50519 |
| T1573 | Encrypted Channel | command-and-control | 5629 |
| T1555 | Credentials from Password Stores | credential-access | 154 |
| T1567 | Exfiltration Over Web Service | exfiltration | 154 |
| T1552.001 | Credentials In Files | credential-access | 112 |
| T1486 | Data Encrypted for Impact | impact | 98 |
| T1490 | Inhibit System Recovery | impact | 98 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 98 |
| T1056.001 | Keylogging | collection, credential-access | 94 |
| T1566.001 | Spearphishing Attachment | initial-access | 67 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 26 |
| T1105 | Ingress Tool Transfer | command-and-control | 26 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 20 |
| T1113 | Screen Capture | collection | 19 |
| T1027 | Obfuscated Files or Information | defense-evasion | 14 |
| T1204.002 | Malicious File | execution | 14 |
| T1090 | Proxy | command-and-control | 13 |
| T1059.001 | PowerShell | execution | 9 |
| T1059.005 | Visual Basic | execution | 9 |
| T1498 | Network Denial of Service | impact | 9 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 5 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxps://f005[.]backblazeb2[.]com/file/0000055/SignintoXfinity[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Ff005.backblazeb2.com%2Ffile%2F0000055%2FSignintoXfinity.html) | url | — | openphish, tweetfeed | 2026-11-23T02:02:14Z | 70 |
| [`hxxp://ns1[.]az/c6/alibaba/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fns1.az%2Fc6%2Falibaba%2F) | url | — | openphish, tweetfeed | 2026-11-22T13:00:57Z | 70 |
| [`hxxps://saratio[.]de/gustafsonltd/download[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsaratio.de%2Fgustafsonltd%2Fdownload.html) | url | — | openphish, tweetfeed | 2026-11-19T18:25:18Z | 70 |
| [`hxxps://auth0-google[.]com/2step[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fauth0-google.com%2F2step.html) | url | AiTM | openphish, tweetfeed | 2026-11-18T17:18:56Z | 70 |
| [`hxxps://icloudvsmapalocaliza[.]click/isignesp[.]php?correo=-&id=172974`](https://www.virustotal.com/gui/search/https%3A%2F%2Ficloudvsmapalocaliza.click%2Fisignesp.php%3Fcorreo%3D-%26id%3D172974) | url | — | openphish, tweetfeed | 2026-11-18T16:27:54Z | 70 |
| [`hxxp://conatem[.]com/adobeStudio[.]html`](https://www.virustotal.com/gui/search/http%3A%2F%2Fconatem.com%2FadobeStudio.html) | url | — | openphish, tweetfeed | 2026-11-18T03:56:46Z | 70 |
| [`hxxps://135461223[.]site/pl/1145/e7efb433-a0e3-426d-aacd-d8b957dfc55d/766593/x`](https://www.virustotal.com/gui/search/https%3A%2F%2F135461223.site%2Fpl%2F1145%2Fe7efb433-a0e3-426d-aacd-d8b957dfc55d%2F766593%2Fx) | url | — | openphish | — | 70 |
| [`hxxp://itrustcapitl-en-us[.]apper[.]so/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fitrustcapitl-en-us.apper.so%2F) | url | — | openphish | — | 70 |
| [`hxxps://gwrfdz4nmd[.]wpdns[.]site/wp-content/plugins/rocket/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fgwrfdz4nmd.wpdns.site%2Fwp-content%2Fplugins%2Frocket%2F) | url | — | openphish | — | 70 |
| [`hxxps://escovamagal[.]vercel[.]app/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fescovamagal.vercel.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://sharemyhtml[.]com/p/P4qEOGvSAe`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsharemyhtml.com%2Fp%2FP4qEOGvSAe) | url | — | openphish | — | 70 |
| [`hxxps://olx[.]payu-poland-run[.]bond/viewer/bWlsbGVubml1bQ/Ml8w/PtXS4VsKw5`](https://www.virustotal.com/gui/search/https%3A%2F%2Folx.payu-poland-run.bond%2Fviewer%2FbWlsbGVubml1bQ%2FMl8w%2FPtXS4VsKw5) | url | — | openphish | — | 70 |
| [`hxxp://vzmpt731-4k8w2xn-6j3d9g-rq517c[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fvzmpt731-4k8w2xn-6j3d9g-rq517c.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://rodcm-hdv-a2mo-78web-11-10-2026-aa[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Frodcm-hdv-a2mo-78web-11-10-2026-aa.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://raqmero-mpt-qunzeli-p8d4me57[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fraqmero-mpt-qunzeli-p8d4me57.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://xqvmt82nlo-k7p4w91-zm6j3d-rp825k[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fxqvmt82nlo-k7p4w91-zm6j3d-rp825k.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://15aip-xj9-argi-3d4r3-17-09-2026-hh[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2F15aip-xj9-argi-3d4r3-17-09-2026-hh.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://xkmtq731-9p2w5zt-6j4d8g-rv217c[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fxkmtq731-9p2w5zt-6j4d8g-rv217c.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://zrxmq95pla-7w2k8nt-3j6d4g-vq521c[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fzrxmq95pla-7w2k8nt-3j6d4g-vq521c.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://marvani-mpt-qelzuro-k5x7pe82[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fmarvani-mpt-qelzuro-k5x7pe82.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://meta-ronuno-biz-zavaro-pelaki[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fmeta-ronuno-biz-zavaro-pelaki.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://davquri-mpt-fenzelo-r8x3ka67[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fdavquri-mpt-fenzelo-r8x3ka67.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://x5y2d-75b-99kc-gxhsk-18-09-2026-aa[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fx5y2d-75b-99kc-gxhsk-18-09-2026-aa.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxps://burfavo-mpt-zumqeri-k7x5pe64[.]pages[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fburfavo-mpt-zumqeri-k7x5pe64.pages.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://nqptx619-3m8w5zk-7j2d4g-rv921c[.]pages[.]dev/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fnqptx619-3m8w5zk-7j2d4g-rv921c.pages.dev%2F) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
