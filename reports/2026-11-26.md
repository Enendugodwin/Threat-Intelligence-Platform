# Threat Intel Pulse — 2026-11-26

**Window:** last 7 days · **Generated:** 2026-11-26T21:47:32Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 69956 |
| New in window | 13220 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 23 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 314 | ok |
| tor | 10174 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 475 | ok |
| greensnow | 2000 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 578 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 1929 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 44288 | 7452 |
| url | 13173 | 4197 |
| domain | 7733 | 1139 |
| ipv6 | 3823 | 155 |
| sha256 | 766 | 219 |
| md5 | 173 | 58 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 13275 |
| Exit nodes | 2485 |
| Other relays | 10790 |
| New in window | 834 |

Sample (20 of 13275, source: Tor Project Onionoo):
- `1[.]161[.]130[.]49`
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
- `102[.]130[.]127[.]117`

Full list: `dist/tor/tor_nodes.txt` (in the `threat-intel-output` workflow artifact).
## Top malware families

| Family | Indicators | New | ATT&CK (heuristic) |
| --- | --- | --- | --- |
| ClickFix | 409 | 124 | — |
| cryptoscam | 108 | 5 | — |
| Kimsuky | 84 | 20 | — |
| Formbook | 57 | 16 | T1566.001, T1056.001, T1555, T1071.001, T1567 |
| AiTM | 29 | 13 | — |
| Vidar | 21 | 0 | T1555, T1071.001, T1567 |
| Remcos | 19 | 1 | T1566.001, T1547.001, T1056.001, T1113, T1071.001, T1573 |
| ValleyRAT | 12 | 12 | — |
| infostealer | 10 | 5 | — |
| Cobalt Strike | 8 | 0 | T1071.001, T1573, T1055, T1059.001, T1105, T1090 |
| GuLoader | 8 | 0 | T1027, T1059.005, T1055, T1105 |
| Mirai | 7 | 0 | T1498, T1071.001 |
| Unknown malware | 5 | 0 | — |
| Evilginx | 4 | 0 | — |
| MustangPanda | 4 | 0 | — |
| QakBot | 4 | 0 | T1566.001, T1204.002, T1055, T1071.001, T1105, T1027, T1041 |
| Sliver | 4 | 0 | T1071.001, T1573, T1090, T1055 |
| Mispadu | 3 | 3 | — |
| PHP2Shell | 3 | 0 | — |
| Xworm | 3 | 2 | — |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1566 | Phishing | initial-access | 17842 |
| T1566.002 | Spearphishing Link | initial-access | 17842 |
| T1071.001 | Web Protocols | command-and-control | 51161 |
| T1573 | Encrypted Channel | command-and-control | 5863 |
| T1555 | Credentials from Password Stores | credential-access | 177 |
| T1567 | Exfiltration Over Web Service | exfiltration | 177 |
| T1552.001 | Credentials In Files | credential-access | 120 |
| T1056.001 | Keylogging | collection, credential-access | 110 |
| T1486 | Data Encrypted for Impact | impact | 91 |
| T1490 | Inhibit System Recovery | impact | 91 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 91 |
| T1566.001 | Spearphishing Attachment | initial-access | 82 |
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
| [`hxxps://hsbcau[.]jrni[.]com/login`](https://www.virustotal.com/gui/search/https%3A%2F%2Fhsbcau.jrni.com%2Flogin) | url | — | openphish, tweetfeed | 2026-11-26T14:01:23Z | 70 |
| [`hxxps://php-intesasanpaolo-assistenza[.]wasmer[.]app/noaccount`](https://www.virustotal.com/gui/search/https%3A%2F%2Fphp-intesasanpaolo-assistenza.wasmer.app%2Fnoaccount) | url | — | openphish, tweetfeed | 2026-11-26T06:20:04Z | 70 |
| [`hxxps://bgbmail-gov[.]dgfiprotocolbd[.]workers[.]dev/login/?dhsfiourewjdfjgkfdgkldfjiorejfdjgfdgjkdfjgreioo=1`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbgbmail-gov.dgfiprotocolbd.workers.dev%2Flogin%2F%3Fdhsfiourewjdfjgkfdgkldfjiorejfdjgfdgjkdfjgreioo%3D1) | url | — | openphish, tweetfeed | 2026-11-25T17:46:08Z | 70 |
| [`hxxps://f005[.]backblazeb2[.]com/file/0000055/SignintoXfinity[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Ff005.backblazeb2.com%2Ffile%2F0000055%2FSignintoXfinity.html) | url | — | openphish, tweetfeed | 2026-11-23T02:02:14Z | 70 |
| [`hxxp://ns1[.]az/c6/alibaba/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fns1.az%2Fc6%2Falibaba%2F) | url | — | openphish, tweetfeed | 2026-11-22T13:00:57Z | 70 |
| [`hxxps://argocts[.]com/wwa/pplch/index[.]php`](https://www.virustotal.com/gui/search/https%3A%2F%2Fargocts.com%2Fwwa%2Fpplch%2Findex.php) | url | — | openphish | — | 70 |
| [`hxxps://ozanguner[.]com/BinasaIndustial/Access/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fozanguner.com%2FBinasaIndustial%2FAccess%2F) | url | — | openphish | — | 70 |
| [`hxxps://mydpd[.]pmsml[.]cc/track-ch`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmydpd.pmsml.cc%2Ftrack-ch) | url | — | openphish | — | 70 |
| [`hxxps://mydpd[.]mzqdp[.]xyz/track-ch`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmydpd.mzqdp.xyz%2Ftrack-ch) | url | — | openphish | — | 70 |
| [`hxxps://mydpd[.]hwtrd[.]top/track-ch`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmydpd.hwtrd.top%2Ftrack-ch) | url | — | openphish | — | 70 |
| [`hxxps://info-recap-2[.]kimi[.]page/`](https://www.virustotal.com/gui/search/https%3A%2F%2Finfo-recap-2.kimi.page%2F) | url | — | openphish | — | 70 |
| [`hxxps://mydpd[.]kiaxf[.]xyz/track-ch`](https://www.virustotal.com/gui/search/https%3A%2F%2Fmydpd.kiaxf.xyz%2Ftrack-ch) | url | — | openphish | — | 70 |
| [`hxxps://jardinsdubandiat-onmicrosoft[.]click/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fjardinsdubandiat-onmicrosoft.click%2F) | url | — | openphish | — | 70 |
| [`hxxps://dhyehdhje[.]jimdofree[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fdhyehdhje.jimdofree.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://hiremedicals[.]com/contact/login[.]php`](https://www.virustotal.com/gui/search/http%3A%2F%2Fhiremedicals.com%2Fcontact%2Flogin.php) | url | — | openphish | — | 70 |
| [`hxxps://upgov[.]net/images/z1dpeth/-/louwhan1/pages/login[.]php`](https://www.virustotal.com/gui/search/https%3A%2F%2Fupgov.net%2Fimages%2Fz1dpeth%2F-%2Flouwhan1%2Fpages%2Flogin.php) | url | — | openphish | — | 70 |
| [`hxxp://chipper-profiterole-06b105[.]netlify[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fchipper-profiterole-06b105.netlify.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://bas[.]api[.]usps[.]zda[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fbas.api.usps.zda.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://f005[.]backblazeb2[.]com/file/olaxxx/bellwebmailcadch4se[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Ff005.backblazeb2.com%2Ffile%2Folaxxx%2Fbellwebmailcadch4se.html) | url | — | openphish | — | 70 |
| [`hxxp://akarshagrahari143[.]github[.]io/web-clg-Amazon`](https://www.virustotal.com/gui/search/http%3A%2F%2Fakarshagrahari143.github.io%2Fweb-clg-Amazon) | url | — | openphish | — | 70 |
| [`hxxps://vinted[.]id653655[.]shop/219249488`](https://www.virustotal.com/gui/search/https%3A%2F%2Fvinted.id653655.shop%2F219249488) | url | — | openphish | — | 70 |
| [`hxxps://drumhilldentalcom[.]qusteto-document-qpr-39948589[.]workers[.]dev/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fdrumhilldentalcom.qusteto-document-qpr-39948589.workers.dev%2F) | url | — | openphish | — | 70 |
| [`hxxp://login-att-verification-page[.]weeblysite[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Flogin-att-verification-page.weeblysite.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://cn[.]81mbetx[.]com/home/register/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fcn.81mbetx.com%2Fhome%2Fregister%2F) | url | — | openphish | — | 70 |
| [`hxxps://aaa-105662[.]square[.]site/`](https://www.virustotal.com/gui/search/https%3A%2F%2Faaa-105662.square.site%2F) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
