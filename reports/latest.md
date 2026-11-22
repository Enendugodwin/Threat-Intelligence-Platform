# Threat Intel Pulse — 2026-11-22

**Window:** last 7 days · **Generated:** 2026-11-22T19:52:08Z UTC

| Metric | Value |
| --- | --- |
| Indicators tracked | 70290 |
| New in window | 15182 |
| Malware families (annotated) | 20 |
| ATT&CK techniques (heuristic) | 23 |

## Feed health

| Feed | Indicators this run | Status |
| --- | --- | --- |
| feodo | 5 | ok |
| openphish | 300 | ok |
| circl | 314 | ok |
| tor | 10300 | ok |
| blocklist_de | 3000 | ok |
| binarydefense | 888 | ok |
| greensnow | 1820 | ok |
| phishing_army | 3000 | ok |
| et_compromised | 596 | ok |
| urlhaus_filter | 5000 | ok |
| tweetfeed | 2446 | ok |

## Indicators by type

| Type | Total | New |
| --- | --- | --- |
| ipv4 | 44408 | 8407 |
| url | 13586 | 4990 |
| domain | 7583 | 1201 |
| ipv6 | 3825 | 207 |
| sha256 | 716 | 290 |
| md5 | 172 | 87 |

## Tor relay / exit nodes

| Metric | Value |
| --- | --- |
| Nodes tracked | 13376 |
| Exit nodes | 2493 |
| Other relays | 10883 |
| New in window | 972 |

Sample (20 of 13376, source: Tor Project Onionoo):
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
| ClickFix | 382 | 164 | — |
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
| PHP2Shell | 6 | 1 | — |
| Unknown malware | 6 | 0 | — |
| Evilginx | 4 | 0 | — |
| MustangPanda | 4 | 4 | — |
| QakBot | 4 | 0 | T1566.001, T1204.002, T1055, T1071.001, T1105, T1027, T1041 |
| Sliver | 4 | 0 | T1071.001, T1573, T1090, T1055 |
| Mispadu | 3 | 3 | — |
| AdaptixC2 | 2 | 0 | — |

## ATT&CK coverage (heuristic)

| Technique | Name | Tactics | Indicators |
| --- | --- | --- | --- |
| T1566 | Phishing | initial-access | 18295 |
| T1566.002 | Spearphishing Link | initial-access | 18295 |
| T1071.001 | Web Protocols | command-and-control | 51087 |
| T1573 | Encrypted Channel | command-and-control | 5850 |
| T1555 | Credentials from Password Stores | credential-access | 154 |
| T1567 | Exfiltration Over Web Service | exfiltration | 154 |
| T1552.001 | Credentials In Files | credential-access | 112 |
| T1486 | Data Encrypted for Impact | impact | 104 |
| T1490 | Inhibit System Recovery | impact | 104 |
| T1562.001 | Disable or Modify Tools | defense-evasion | 104 |
| T1056.001 | Keylogging | collection, credential-access | 95 |
| T1566.001 | Spearphishing Attachment | initial-access | 67 |
| T1105 | Ingress Tool Transfer | command-and-control | 28 |
| T1055 | Process Injection | defense-evasion, privilege-escalation | 26 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence, privilege-escalation | 20 |
| T1113 | Screen Capture | collection | 19 |
| T1027 | Obfuscated Files or Information | defense-evasion | 15 |
| T1204.002 | Malicious File | execution | 15 |
| T1090 | Proxy | command-and-control | 13 |
| T1059.001 | PowerShell | execution | 9 |
| T1059.005 | Visual Basic | execution | 9 |
| T1498 | Network Denial of Service | impact | 9 |
| T1041 | Exfiltration Over C2 Channel | exfiltration | 5 |

## Notable new indicators

| Indicator (defanged) | Type | Family | Sources | First seen | Confidence |
| --- | --- | --- | --- | --- | --- |
| [`hxxp://ns1[.]az/c6/alibaba/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fns1.az%2Fc6%2Falibaba%2F) | url | — | openphish, tweetfeed | 2026-11-22T13:00:57Z | 70 |
| [`hxxps://saratio[.]de/gustafsonltd/download[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fsaratio.de%2Fgustafsonltd%2Fdownload.html) | url | — | openphish, tweetfeed | 2026-11-19T18:25:18Z | 70 |
| [`hxxps://auth0-google[.]com/2step[.]html`](https://www.virustotal.com/gui/search/https%3A%2F%2Fauth0-google.com%2F2step.html) | url | AiTM | openphish, tweetfeed | 2026-11-18T17:18:56Z | 70 |
| [`hxxps://icloudvsmapalocaliza[.]click/isignesp[.]php?correo=-&id=172974`](https://www.virustotal.com/gui/search/https%3A%2F%2Ficloudvsmapalocaliza.click%2Fisignesp.php%3Fcorreo%3D-%26id%3D172974) | url | — | openphish, tweetfeed | 2026-11-18T16:27:54Z | 70 |
| [`hxxp://conatem[.]com/adobeStudio[.]html`](https://www.virustotal.com/gui/search/http%3A%2F%2Fconatem.com%2FadobeStudio.html) | url | — | openphish, tweetfeed | 2026-11-18T03:56:46Z | 70 |
| [`hxxp://secure-trezr-login-io[.]typedream[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsecure-trezr-login-io.typedream.app%2F) | url | — | openphish | — | 70 |
| [`hxxp://tech[.]lmtokens[.]top/`](https://www.virustotal.com/gui/search/http%3A%2F%2Ftech.lmtokens.top%2F) | url | — | openphish | — | 70 |
| [`hxxps://facebook-verification-system5[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Ffacebook-verification-system5.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]facebook-verification-system5[.]blogspot[.]com/`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.facebook-verification-system5.blogspot.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://vivekashar[.]github[.]io/NetflixNChill`](https://www.virustotal.com/gui/search/http%3A%2F%2Fvivekashar.github.io%2FNetflixNChill) | url | — | openphish | — | 70 |
| [`hxxp://naveenv-27[.]github[.]io/Spotify-clone`](https://www.virustotal.com/gui/search/http%3A%2F%2Fnaveenv-27.github.io%2FSpotify-clone) | url | — | openphish | — | 70 |
| [`hxxp://vishakhasharma948[.]github[.]io/spotify-mini-project`](https://www.virustotal.com/gui/search/http%3A%2F%2Fvishakhasharma948.github.io%2Fspotify-mini-project) | url | — | openphish | — | 70 |
| [`hxxps://cn[.]manmvp961[.]com/home`](https://www.virustotal.com/gui/search/https%3A%2F%2Fcn.manmvp961.com%2Fhome) | url | — | openphish | — | 70 |
| [`hxxp://availablevoicenote[.]weebly[.]com/`](https://www.virustotal.com/gui/search/http%3A%2F%2Favailablevoicenote.weebly.com%2F) | url | — | openphish | — | 70 |
| [`hxxp://saumya-mehta[.]github[.]io/spotify-clone`](https://www.virustotal.com/gui/search/http%3A%2F%2Fsaumya-mehta.github.io%2Fspotify-clone) | url | — | openphish | — | 70 |
| [`hxxp://bookings-clone-responsive[.]netlify[.]app/`](https://www.virustotal.com/gui/search/http%3A%2F%2Fbookings-clone-responsive.netlify.app%2F) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]com[.]et/users/1109246452/profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.com.et%2Fusers%2F1109246452%2Fprofile) | url | — | openphish | — | 70 |
| [`hxxp://meshack07[.]github[.]io/Netflix-assignment-1`](https://www.virustotal.com/gui/search/http%3A%2F%2Fmeshack07.github.io%2FNetflix-assignment-1) | url | — | openphish | — | 70 |
| [`hxxps://im[.]dailybenefitspro[.]com/loading_page/walmart/walmart_cf_39/index[.]html?lptoken=171a942876cb60e4877f&cep=N4Igdgpg7g%2BgFgSwC4wQExALhAVgOwBsAZgMZqEC0ALERDtQIYFoUMBGAnGxQEwAcHAMyCADAT45BPPCAA0IAG4IAzslQZsEEkRE80EHhTxEqHagT0UJfCBRIEOPSYL4iqJKnMUq1SBAFsIZSQGfwAHLBAeXQIKAEY4%2BJwAFTi8TBdMETwAOgkCAC0vCAAPJAgAJzAGABt1SOASGoQSAGt1AF8vJVUkAHsK%2Bux3KjQcCCo%2BCjQeCeocPkMGCHY7HgZ8KiccAjw2LxJQsIYEAHMwIZAHexxRiA4iHg4REhEROOkGIhwGES8wPr6S4iGA8f6AiAwJAATzCEEiABkGGA0AgwKdwUCSHATmAsABtEAgsEAXXkYQqQQgNS05TQMAB%2BiwoBhcMRyNR6K8IQqpwgKHQkQcrnebG0EFIBF%2B71mRDQVDiGHkjMhguwxP%2BpSQzJArPh2AA8kRaBVuQxefzLrsiHw2ERmGgONp%2BG8Pg8yCQSJjVRoiTAQSIAD4guL%2B4Og%2F2aspYMAAVxqNQ6HXk2NxMDCfV6CD6eMwoBIsYqlLASAAchCAJIo0pYETyNgVZHYquokhBAkk5MgFQwSmoykkbWYJAVWMQeQAR2UETzICaLXaapAjWabU6B0pDD8Ch9DRIm%2B3Pq68gYaAUMEO4RO50uwFP58vxzOF3Qx7nB4QO4ZoX1y%2F3K0Pb9AjfWNYyXYBQNfLx7xgPpjUqW8YLgk113kZCEOqQIGnQwZMIgN8viIBBmi3XdsDvY1iIQUjUO7NAiAYBp0AYt9mIYGB%2FDGJj6PYzicDfU4Tl9YBBKg%2BRRPpPiGgkjixlYwIECYhT5IgBBZJwJTVPUgiUQqPp0EQ3T9PpMSQA5PSDIMqTyPM4z1G0rx%2FAYL1yKckg3zc9SGk8vi3z6ITsKEvyhK88j%2FKsuSvFjRjyOiroux7SAoCwBiamUfCgA%3D%3D%3D&cpid=69c654de9f290c00127af5a0`](https://www.virustotal.com/gui/search/https%3A%2F%2Fim.dailybenefitspro.com%2Floading_page%2Fwalmart%2Fwalmart_cf_39%2Findex.html%3Flptoken%3D171a942876cb60e4877f%26cep%3DN4Igdgpg7g%252BgFgSwC4wQExALhAVgOwBsAZgMZqEC0ALERDtQIYFoUMBGAnGxQEwAcHAMyCADAT45BPPCAA0IAG4IAzslQZsEEkRE80EHhTxEqHagT0UJfCBRIEOPSYL4iqJKnMUq1SBAFsIZSQGfwAHLBAeXQIKAEY4%252BJwAFTi8TBdMETwAOgkCAC0vCAAPJAgAJzAGABt1SOASGoQSAGt1AF8vJVUkAHsK%252Bux3KjQcCCo%252BCjQeCeocPkMGCHY7HgZ8KiccAjw2LxJQsIYEAHMwIZAHexxRiA4iHg4REhEROOkGIhwGES8wPr6S4iGA8f6AiAwJAATzCEEiABkGGA0AgwKdwUCSHATmAsABtEAgsEAXXkYQqQQgNS05TQMAB%252BiwoBhcMRyNR6K8IQqpwgKHQkQcrnebG0EFIBF%252B71mRDQVDiGHkjMhguwxP%252BpSQzJArPh2AA8kRaBVuQxefzLrsiHw2ERmGgONp%252BG8Pg8yCQSJjVRoiTAQSIAD4guL%252B4Og%252F2aspYMAAVxqNQ6HXk2NxMDCfV6CD6eMwoBIsYqlLASAAchCAJIo0pYETyNgVZHYquokhBAkk5MgFQwSmoykkbWYJAVWMQeQAR2UETzICaLXaapAjWabU6B0pDD8Ch9DRIm%252B3Pq68gYaAUMEO4RO50uwFP58vxzOF3Qx7nB4QO4ZoX1y%252F3K0Pb9AjfWNYyXYBQNfLx7xgPpjUqW8YLgk113kZCEOqQIGnQwZMIgN8viIBBmi3XdsDvY1iIQUjUO7NAiAYBp0AYt9mIYGB%252FDGJj6PYzicDfU4Tl9YBBKg%252BRRPpPiGgkjixlYwIECYhT5IgBBZJwJTVPUgiUQqPp0EQ3T9PpMSQA5PSDIMqTyPM4z1G0rx%252FAYL1yKckg3zc9SGk8vi3z6ITsKEvyhK88j%252FKsuSvFjRjyOiroux7SAoCwBiamUfCgA%253D%253D%253D%26cpid%3D69c654de9f290c00127af5a0) | url | — | openphish | — | 70 |
| [`hxxps://www[.]roblox[.]com[.]et/games/2609668898/WITCH-CASE-Custom-Duels?privateServerLinkCode=39838176748643508465383046982462`](https://www.virustotal.com/gui/search/https%3A%2F%2Fwww.roblox.com.et%2Fgames%2F2609668898%2FWITCH-CASE-Custom-Duels%3FprivateServerLinkCode%3D39838176748643508465383046982462) | url | — | openphish | — | 70 |
| [`hxxp://u[.]to/tejZIg`](https://www.virustotal.com/gui/search/http%3A%2F%2Fu.to%2FtejZIg) | url | — | openphish | — | 70 |
| [`hxxps://im[.]nbpublic[.]com/loading_page/walmart/walmart_cf_10/index[.]html?lptoken=177c94c2763e608a1325&cep=N4Igdgpg7g%2BgFgSwC4wQExALhAdggZgAYBWAM2IgFoAjANggEZKAWZtZygDkIE5PK81OgGNOdZtxAAaEADcEAZ2SoM2QgCYe64Vv4RhhWi2o58lAIad81SvWJpSpfKWrnmPaXMXKkCALYQCkjmfgAOWCDqGkYMTAzEACoMOJj4tJjE%2BAB0zIQ4AFqeEAAeSBAATmDmADYqEcDC1QjCANYqAL6e8kpIAPblddjmaObC6uoQaJSkOLQczPh4NJwQ6pTq5oSEaMLUwtaktJ7CIaHmCADmYIMgtDzCtMRsEDykmoQGhAzqOObkm54wL00BAboQYIRAcDQUgAJ6hCARAAy5jAaAQYAuUJBMGEcHOYCwAG0QODIQBdGShcqBCDVfRlNAwIEgrCgOEI5Go9GYzzBcoXCAodARWg4UjCEbEYh7Tibahbb5EPj4YjY0EitQQwElJBskAcxHYADyjgqfPMAqFNzFpDEhzQaHub24X00Ep2wnVYIhEIAPuCGP7weptTJIKUsGAAK7VartdoyPEEmChXo9BC9QmYUDCaPlGlgJAAOWhAEk0SUsIQZNRyqi8RX0cJAsTyYmQIoYDT0TThHrMEhytGIDIAI4KcI5kCNZptTUgBpNVodY408y%2BWQa1SL4TrzfbzoyYayXGnc5XG7AE9nsIX67oI8z%2FcILfMkJG3cvt9VAJP6PRguwAAY%2Bng3r0ZoDEB4GQauMgQaQFTvgE9QIUhv4QE%2BfykAgTQbtu9TYbhCD4XBnYOOY9ToKQ5hPtR5gwH4aBqtgwD0YxzFPhc5w7sA3GgTI%2FFMkxLGLkJHHEHRAQIFR0lSRACASbJCkSVhaLlL06BXtyGlaQJIA6ZpTJaSJhHqUZKiqZ4fijPUNnCE%2B9lKaxTkiU%2BvQ8ahPHuTxzmLh5JmcZ40aUaxIXtAA9CAHZdpAUBYDR1QKJhQA%3D%3D&cpid=69c654de9f290c00127af5a0`](https://www.virustotal.com/gui/search/https%3A%2F%2Fim.nbpublic.com%2Floading_page%2Fwalmart%2Fwalmart_cf_10%2Findex.html%3Flptoken%3D177c94c2763e608a1325%26cep%3DN4Igdgpg7g%252BgFgSwC4wQExALhAdggZgAYBWAM2IgFoAjANggEZKAWZtZygDkIE5PK81OgGNOdZtxAAaEADcEAZ2SoM2QgCYe64Vv4RhhWi2o58lAIad81SvWJpSpfKWrnmPaXMXKkCALYQCkjmfgAOWCDqGkYMTAzEACoMOJj4tJjE%252BAB0zIQ4AFqeEAAeSBAATmDmADYqEcDC1QjCANYqAL6e8kpIAPblddjmaObC6uoQaJSkOLQczPh4NJwQ6pTq5oSEaMLUwtaktJ7CIaHmCADmYIMgtDzCtMRsEDykmoQGhAzqOObkm54wL00BAboQYIRAcDQUgAJ6hCARAAy5jAaAQYAuUJBMGEcHOYCwAG0QODIQBdGShcqBCDVfRlNAwIEgrCgOEI5Go9GYzzBcoXCAodARWg4UjCEbEYh7Tibahbb5EPj4YjY0EitQQwElJBskAcxHYADyjgqfPMAqFNzFpDEhzQaHub24X00Ep2wnVYIhEIAPuCGP7weptTJIKUsGAAK7VartdoyPEEmChXo9BC9QmYUDCaPlGlgJAAOWhAEk0SUsIQZNRyqi8RX0cJAsTyYmQIoYDT0TThHrMEhytGIDIAI4KcI5kCNZptTUgBpNVodY408y%252BWQa1SL4TrzfbzoyYayXGnc5XG7AE9nsIX67oI8z%252FcILfMkJG3cvt9VAJP6PRguwAAY%252Bng3r0ZoDEB4GQauMgQaQFTvgE9QIUhv4QE%252BfykAgTQbtu9TYbhCD4XBnYOOY9ToKQ5hPtR5gwH4aBqtgwD0YxzFPhc5w7sA3GgTI%252FFMkxLGLkJHHEHRAQIFR0lSRACASbJCkSVhaLlL06BXtyGlaQJIA6ZpTJaSJhHqUZKiqZ4fijPUNnCE%252B9lKaxTkiU%252BvQ8ahPHuTxzmLh5JmcZ40aUaxIXtAA9CAHZdpAUBYDR1QKJhQA%253D%253D%26cpid%3D69c654de9f290c00127af5a0) | url | — | openphish | — | 70 |
| [`hxxp://rayshawn8[.]github[.]io/uniswap-fork-mumbai`](https://www.virustotal.com/gui/search/http%3A%2F%2Frayshawn8.github.io%2Funiswap-fork-mumbai) | url | — | openphish | — | 70 |
| [`hxxp://attractive-brown-b1zuhydo[.]edgeone[.]dev/home`](https://www.virustotal.com/gui/search/http%3A%2F%2Fattractive-brown-b1zuhydo.edgeone.dev%2Fhome) | url | — | openphish | — | 70 |
| [`hxxps://s4w[.]in/https-www-roblox-com-users-2757380680-profile`](https://www.virustotal.com/gui/search/https%3A%2F%2Fs4w.in%2Fhttps-www-roblox-com-users-2757380680-profile) | url | — | openphish | — | 70 |
---

<sub>Generated by [threat-intel-pipeline](https://github.com/Enendugodwin/Threat-Intelligence-Platform) · Sources: URLhaus, Feodo Tracker, ThreatFox, Tor Project, AlienVault OTX · Indicators are defanged for safe display · Outputs: `dist/stix/bundle.json`, `dist/sigma/`, `dist/suricata/ti.rules`, `dist/iocs.csv`, `dist/tor/tor_nodes.txt` (published as the workflow artifact `threat-intel-output`).</sub>
