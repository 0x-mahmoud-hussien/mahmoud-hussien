---
title: "TryHackMe: The Finance Trail - Splunk Incident Investigation"
description: "A comprehensive digital forensics and incident response write-up reconstructing an acquisition-review spear-phishing attack, payload delivery, execution, persistence, C2 failover, and data exfiltration using Splunk."
date: 2026-11-09
platform: "TryHackMe"
difficulty: "Medium"
category: "Digital Forensics / Incident Response"
tags: ["splunk", "dfir", "incident-response", "threat-hunting", "suricata", "sysmon"]
featured: true
draft: false
tools: ["Splunk", "Sysmon", "Suricata", "Windows Filtering Platform"]
room_url: "https://tryhackme.com/room/thefinancetrail"
---

## Scenario Overview

Vantara's SOC escalated suspicious activity around an acquisition-review workflow. A finance employee received a legal-review themed email, and shortly afterwards the environment recorded unusual web, endpoint and outbound network activity tied to the same process. Vantara contained the account and workstation but couldn't yet explain how the compromise unfolded, which infrastructure was involved, or whether review material was staged for transfer.

The case chain is: **lure email → ZIP download → loader execution → sync client with persistence → C2 callbacks with failover → staging → transfer to a file server.**

> **Analyst note from the briefing:** the case also contains normal business activity, so an unusual event is not treated as malicious until the surrounding timeline supports it. Two benign examples appear below: the `FinanceTemplateRefresh` scheduled task and Chrome's own `elevation_service.exe`.

Five Splunk indexes were correlated:

| Index | Content |
|---|---|
| `finance_mail` | Mail logs (RFC822 messages) |
| `finance_web` | Web proxy / Nginx logs |
| `finance_endpoint` | Sysmon + Windows Security events |
| `finance_network` | Suricata telemetry (HTTP, DNS, SMB) |

**Affected host:** `VAN-FIN-WS-014` (`10.81.70.254`) — user `VAN-FIN-WS-014\maya.chen`

---

## Attack Chain Overview

```
[1] Delivery
    └─ Email from amelia.hart@lawson-rowe-review.com
    └─ Subject: "Updated acquisition disclosure schedule for review"

[2] User Interaction (02:33:13)
    └─ chrome.exe opens http://lawson-rowe-review.com/review/disclosure-schedule
    └─ Parent: VantaraFinancePortal.exe

[3] Payload Download (02:33:16 → 02:33:20)
    └─ /downloads/Disclosure_Schedule_Update.zip
    └─ Saved to C:\Users\maya.chen\Downloads\

[4] Execution (02:33:25)
    └─ ledgerdrop.exe runs from inside the ZIP
    └─ Same binary becomes VantaraSync.exe

[5] Persistence (02:33:25)
    └─ Scheduled task: VantaraUpdateCheck (daily, 03:15)

[6] C2 (02:34:13 onwards)
    └─ cdn-lawsonreview.net (203.0.113.45), UA VantaraSync/4.1
    └─ Failover to api-lawsoncdn.net (192.0.2.77) after an HTTP 503

[7] Staging & Transfer (02:53)
    └─ PowerShell Compress-Archive → review_notes_2026.zip
    └─ SMB2 WRITE to the file server
```

---

## Question 1 — Find the delivered email whose sender domain also hosted the ZIP. What is its Message-ID (without angle brackets)?

### Splunk Queries

**Step 1 — Find the program that ran from inside a ZIP:**

```spl
index="finance_endpoint" EventCode=1 Image=*.zip*
| table _time User Event.System.Computer Image ParentImage
```

**Step 2 — Find who hosted that ZIP:**

```spl
index="finance_web" uri=*Disclosure_Schedule_Update.zip*
| table _time client_ip http_host uri
```

**Step 3 — Match the sender domain in the mail logs:**

```spl
index="finance_mail" sourcetype="finance:mail:rfc822" sender_address=*lawson-rowe-review.com*
| table _time mail_from mail_to mail_subject sender_address recipient_address message_id
```

### Investigation

**Step 1** shows an executable running from inside an extracted ZIP on `VAN-FIN-WS-014` under `maya.chen`:

```
Disclosure_Schedule_Update.zip\ledgerdrop.exe      2026-10-09 02:33:25.526
```
![Answer](../imgs/TheFinanceTrail-1.png)

**Step 2** shows where the ZIP came from. The proxy log has the download of `/downloads/Disclosure_Schedule_Update.zip` by `10.81.70.254` at `02:33:16`, hosted on:

```
lawson-rowe-review.com
```
![Answer](../imgs/TheFinanceTrail-2.png)

**Step 3** looks in the mail index for mail sent from that same domain. The matching message:

| Field | Value |
|---|---|
| Sender | `Amelia Hart <amelia.hart@lawson-rowe-review.com>` |
| Recipient | `maya.chen@vantara.local` |
| Subject | `Updated acquisition disclosure schedule for review` |
| Delivered | `2026-10-09 02:29:02` |
| Message-ID | `20261009022902.06.1a247614eaf9@lawson-rowe-review.com` |

The delivery time matches the timestamp embedded at the start of the Message-ID (`20261009022902`). The lure came from the very domain that served the ZIP, which ties the email to the payload.

**MITRE ATT&CK:** T1566 — Phishing

**Answer:**

```
20261009022902.06.1a247614eaf9@lawson-rowe-review.com
```
![Answer](../imgs/TheFinanceTrail-3.png)

---

## Question 2 — Which parent executable launched the browser that opened the external review site?

### Splunk Query

```spl
index="finance_endpoint" EventCode=1 Image=*chrome* CommandLine=*lawson-rowe-review.com*
| table _time Image ParentImage CommandLine ProcessId
```

### Investigation

Searching process creation for a Chrome instance whose command line contains the attacker's domain:

| Field | Value |
|---|---|
| Time | `2026-10-09 02:33:13.741` |
| Image | `C:\Program Files\Google\Chrome\Application\chrome.exe` |
| Command line | `"C:\Program Files\Google\Chrome\Application\chrome.exe" http://lawson-rowe-review.com/review/disclosure-schedule` |
| PID | `664` |
| Parent | `C:\Program Files\Vantara\Finance Client\VantaraFinancePortal.exe` |

This is the user-interaction step: about four minutes after the email arrived (02:29:02), the review URL was opened in Chrome, launched by the finance client application. The logs don't show how the link reached that application, so that part is not asserted here.

**MITRE ATT&CK:** T1204.001 — User Execution: Malicious Link

**Answer:**

```
VantaraFinancePortal.exe
```
![Answer](../imgs/TheFinanceTrail-4.png)

---

## Question 3 — What SHA-256 did Sysmon's file-stream hash event record when Chrome saved the ZIP?

### Splunk Query

```spl
index="finance_endpoint" EventCode=15 Image=*chrome*
| table _time TargetFilename Hash
```

### Investigation

Sysmon **EventCode 15** is `FileCreateStreamHash`. Filtering it to Chrome as the writing process returns the event for the download:

| Field | Value |
|---|---|
| Time | `2026-10-09 02:33:20.207` |
| Process | `C:\Program Files\Google\Chrome\Application\chrome.exe` |
| TargetFilename | `C:\Users\maya.chen\Downloads\Disclosure_Schedule_Update.zip` |
| SHA-256 | `98D66005B3F2CFD556EEF503EC1ADA73DE34C24D3800D41D8E30C43AF32DEDEF` |

The save happened 4 seconds after the proxy logged the download request (02:33:16) and 5 seconds before the loader ran (02:33:25).

> **Reading this hash correctly:** EventCode 15 records a hash of the file *stream* that was created. On a typical Windows download, that stream is the mark-of-the-web (`Zone.Identifier`) alternate data stream rather than the main file content. The question asks for the SHA-256 that the stream-hash event recorded, which is what is given here. If the full-file hash of the ZIP is needed for blocking or threat-intel lookups, calculate it from the file itself.

**Answer:**

```
98D66005B3F2CFD556EEF503EC1ADA73DE34C24D3800D41D8E30C43AF32DEDEF
```
![Answer](../imgs/TheFinanceTrail-5.png)

---

## Question 4 — What SHA-256 do the extracted loader and the installed sync client share?

### Splunk Query

```spl
index="finance_endpoint" EventCode=1 (Image=*ledgerdrop.exe* OR Image=*VantaraSync.exe*)
| table _time Image CommandLine Hashes
```

### Investigation

Both programs appear in process-creation events:

| | Loader | Sync client |
|---|---|---|
| Image | `C:\Users\maya.chen\AppData\Local\Temp\Temp1_Disclosure_Schedule_Update.zip\ledgerdrop.exe` | `C:\Users\maya.chen\AppData\Local\VantaraSync\VantaraSync.exe` |
| Command line | `"...\ledgerdrop.exe"` | `"...\VantaraSync.exe" --sync` |
| SHA-256 | `AAD4B231C4AFC7D02A09344545A957086FE36CD6A9CCA8F1F92E1AC3DDFFAC5C` | `AAD4B231C4AFC7D02A09344545A957086FE36CD6A9CCA8F1F92E1AC3DDFFAC5C` |

Identical hashes mean the two files have identical contents: the "sync client" is the loader itself, installed under a new name in a new folder (`...\AppData\Local\VantaraSync\`). The name `VantaraSync.exe` imitates the company's own software so it looks routine in a process list.

The loader executed from the Temp folder where Windows extracted the ZIP (`Temp1_...zip\`), which means the user opened the program directly from the archive.

**MITRE ATT&CK:** T1204.002 — User Execution: Malicious File | T1036.005 — Masquerading: Match Legitimate Name or Location

**Answer:**

```
AAD4B231C4AFC7D02A09344545A957086FE36CD6A9CCA8F1F92E1AC3DDFFAC5C
```
![Answer](../imgs/TheFinanceTrail-6.png)

---

## Question 5 — Which scheduled task belongs to the loader's process lineage, not routine document syncing?

### Splunk Query

```spl
index="finance_endpoint" EventCode=1 Image=*schtasks*
| table _time ParentImage CommandLine
```

### Investigation

Two `schtasks.exe` executions exist, and the **parent image** is what separates them:

| | Benign | Malicious |
|---|---|---|
| Parent | `VantaraDocumentSync.exe` | `...\Temp1_Disclosure_Schedule_Update.zip\ledgerdrop.exe` |
| Task | `FinanceTemplateRefresh` | `VantaraUpdateCheck` |
| Meaning | Routine template refresh | Persistence |

The malicious task was created at `2026-10-09 02:33:25.643`:

```
"schtasks.exe" /Create /TN VantaraUpdateCheck /SC DAILY /ST 03:15 /TR "C:\Users\maya.chen\AppData\Local\VantaraSync\VantaraSync.exe --sync" /F
```

It re-runs the sync client every day at 03:15, so the foothold survives a reboot or a killed process. The task was created 117 ms after the loader started (02:33:25.526 → 02:33:25.643). The name `VantaraUpdateCheck` is chosen to look like routine maintenance.

**MITRE ATT&CK:** T1053.005 — Scheduled Task/Job: Scheduled Task

**Answer:**

```
VantaraUpdateCheck
```
![Answer](../imgs/TheFinanceTrail-7.png)

---

## Question 6 — How many seconds passed between the sync client's process-creation UtcTime and its first C2 callback in the Nginx log?

### Splunk Queries

**Process start time:**

```spl
index="finance_endpoint" EventCode=1 Image=*VantaraSync*
| table _time UtcTime Image ParentImage
```

**First callback in the web log:**

```spl
index="finance_web" http_host=*cdn-lawsonreview.net*
| table _time client_ip http_host status user_agent
| sort _time
```

### Investigation

| Event | Time |
|---|---|
| `VantaraSync.exe` process created (Sysmon `UtcTime`) | `2026-10-09 02:33:25.981` |
| First beacon in the Nginx log | `2026-10-09 02:34:13` |

![Answer](../imgs/TheFinanceTrail-8.png)

The first beacon:

| Field | Value |
|---|---|
| Client | `10.81.70.254` |
| Host | `cdn-lawsonreview.net` |
| Status | `204` |
| User-Agent | `VantaraSync/4.1` |

![Answer](../imgs/TheFinanceTrail-9.png)

```
02:34:13 - 02:33:25.981 = 47.019 s  →  47 seconds
```

The client waits before calling home, a delay that makes the beacon harder to line up with the execution if someone only looks at the minutes right after the click. A `204 No Content` response is a quiet check-in that carries no visible content.

**MITRE ATT&CK:** T1071.001 — Application Layer Protocol: Web Protocols

**Answer:**

```
47
```

---

## Question 7 — Which local TCP source port appears in both Suricata HTTP and the WFP allowed-connection event for the first callback?

### Splunk Queries

**Windows Filtering Platform (allowed connection):**

```spl
index="finance_endpoint" EventCode=5156 Application=*VantaraSync*
| table _time ProcessID SourceAddress SourcePort DestAddress DestPort
| sort _time
```

**Suricata HTTP:**

```spl
index="finance_network" event_type=http "http.hostname"="cdn-lawsonreview.net"
| table _time src_ip src_port dest_ip dest_port
| sort _time
```

### Investigation

The same connection seen by two independent sources:

| Source | Time | Detail |
|---|---|---|
| WFP (EventCode 5156) | `02:34:13.444` | `VantaraSync.exe` (PID `4736`), `10.81.70.254:50611` → `203.0.113.45:80` |
| Suricata HTTP | `02:34:13.481` | `10.81.70.254:50611` → `203.0.113.45:80` |

```
Local source port: 50611
```

The port is the join key: WFP names the *process* making the connection, Suricata names the *traffic* on the wire, and the shared source port proves they are the same flow. The 37 ms gap is the time between the endpoint allowing the connection and the network sensor logging the request.

C2 destination: `203.0.113.45` over plain HTTP (port 80).

**Answer:**

```
50611
```
![Answer](../imgs/TheFinanceTrail-10.png)

![Answer](../imgs/TheFinanceTrail-11.png)

---

## Question 8 — How many milliseconds before the HTTP 503 was the DNS A answer for the backup domain recorded?

### Splunk Queries

**HTTP 503 from the primary C2:**

```spl
index="finance_network" event_type=http NOT "http.hostname"="*vantara.local"
| sort 0 timestamp
| table timestamp dest_ip http.hostname http.status
```

**DNS A answer for the backup domain:**

```spl
index="finance_network" event_type=dns "dns.answers{}.rrtype"=A "dns.queries{}.rrname"="api-lawsoncdn.net"
| table timestamp dest_ip dns.answers{}.rrname
```

### Investigation

| Event | Timestamp |
|---|---|
| DNS A answer for `api-lawsoncdn.net` | `2026-10-09T02:53:21.523656+0000` |
| HTTP 503 from `cdn-lawsonreview.net` (`203.0.113.45`) | `2026-10-09T02:53:21.531963+0000` |

```
531.963 ms - 523.656 ms = 8.307 ms
```

The primary C2 returned `503 Service Unavailable`, and the client moved to a backup domain, `api-lawsoncdn.net` (`192.0.2.77`), which answered `204`. The backup was resolved just before the primary's 503 was logged. That is **C2 failover**: the implant has more than one channel, so blocking only `cdn-lawsonreview.net` would not cut the attacker off.

**MITRE ATT&CK:** T1008 — Fallback Channels

**Answer:**

```
8.307
```
![Answer](../imgs/TheFinanceTrail-12.png)

![Answer](../imgs/TheFinanceTrail-13.png)

---

## Question 9 — Which executable last used the PowerShell process's PID before PowerShell started?

### Splunk Queries

**Find the PowerShell that created the archive:**

```spl
index="finance_endpoint" EventCode=1 Image=*powershell*
| table _time ProcessId ParentImage CommandLine
```

**Check the history of that PID:**

```spl
index="finance_endpoint" EventCode=1 ProcessId=692
| table _time Image ParentImage
```

### Investigation

**Step 1:** the PowerShell process that built the archive:

| Field | Value |
|---|---|
| Time | `2026-10-09 02:53:28.553` |
| PID | `692` |
| Parent | `C:\Users\maya.chen\AppData\Local\VantaraSync\VantaraSync.exe` |
| Command line | `"powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "Compress-Archive -Path 'C:\Users\maya.chen\Documents\BoardReview\*' -DestinationPath 'C:\Users\maya.chen\Documents\review_notes_2026.zip' -Force"` |

The sync client launched PowerShell to archive the `BoardReview` folder. The command line uses `-NoProfile -NonInteractive -ExecutionPolicy Bypass`, so it runs silently and skips the execution policy.
![Answer](../imgs/TheFinanceTrail-14.png)

**Step 2:** the same PID, `692`, was used earlier by another process:

| Time | PID | Image | Parent |
|---|---|---|---|
| `02:33:14.259` | `692` | `C:\Program Files\Google\Chrome\Application\155.0.8059.40\elevation_service.exe` | `services.exe` |
| `02:53:28.553` | `692` | `powershell.exe` | `VantaraSync.exe` |

Windows recycles PIDs, so the number `692` first belonged to Chrome's legitimate `elevation_service.exe` and, about 20 minutes later, to the attacker's PowerShell. Searching by PID alone returns both and could wrongly link them. `elevation_service.exe` is a benign Chrome component and is part of the noise the case warns about; it is not malicious.

**MITRE ATT&CK:** T1059.001 — PowerShell | T1560.001 — Archive Collected Data: Archive via Utility

**Answer:**

```
elevation_service.exe
```
![Answer](../imgs/TheFinanceTrail-15.png)

---

## Question 10 — How many whole seconds passed between the archive's Sysmon file-creation UtcTime and its successful SMB2 WRITE in Suricata?

### Splunk Queries

**Archive created on disk:**

```spl
index="finance_endpoint" EventCode=11 TargetFilename=*review_notes_2026.zip*
| table UtcTime Image TargetFilename
```

**Write to the share:**

```spl
index="finance_network" event_type=smb "smb.command"=SMB2_COMMAND_WRITE
| table timestamp smb.filename smb.command smb.status
```

### Investigation

| Event | Time |
|---|---|
| Sysmon EventCode 11: `powershell.exe` creates `C:\Users\maya.chen\Documents\review_notes_2026.zip` | `2026-10-09 02:53:29.688` |
| Suricata `SMB2_COMMAND_WRITE` of `review_notes_2026.zip`, `STATUS_SUCCESS` | `2026-10-09T02:53:40.986626+0000` |

```
40.986626 - 29.688 = 11.298626 s  →  11 whole seconds
```
![Answer](../imgs/TheFinanceTrail-16.png)

![Answer](../imgs/TheFinanceTrail-17.png)


The archive was created, then written to the file server about 11 seconds later, and the write succeeded. That confirms the staged board-review material did move off the workstation to the file server.

**MITRE ATT&CK:** T1074.002 — Data Staged: Remote Data Staging

**Answer:**

```
11
```

---

## Full Attack Timeline

| Time (2026-10-09 UTC) | Source | Event |
|---|---|---|
| 02:29:02 | Mail | Lure email delivered from `amelia.hart@lawson-rowe-review.com` |
| 02:33:13.741 | Sysmon | `chrome.exe` opens the review URL (parent `VantaraFinancePortal.exe`) |
| 02:33:14.259 | Sysmon | Benign: Chrome `elevation_service.exe` starts with PID 692 |
| 02:33:16 | Proxy | ZIP download request to `lawson-rowe-review.com` |
| 02:33:20.207 | Sysmon (EID 15) | Chrome saves `Disclosure_Schedule_Update.zip` |
| 02:33:25.526 | Sysmon | `ledgerdrop.exe` runs from the ZIP |
| 02:33:25.643 | Sysmon | `schtasks` creates `VantaraUpdateCheck` |
| 02:33:25.981 | Sysmon | `VantaraSync.exe --sync` starts |
| 02:34:13 | Nginx / WFP / Suricata | First C2 callback (source port `50611` → `203.0.113.45:80`) |
| 02:53:21.523656 | Suricata (DNS) | A answer for backup domain `api-lawsoncdn.net` |
| 02:53:21.531963 | Suricata (HTTP) | `503` from `cdn-lawsonreview.net`; client fails over |
| 02:53:28.553 | Sysmon | PowerShell (PID 692) runs `Compress-Archive` on `BoardReview` |
| 02:53:29.688 | Sysmon (EID 11) | `review_notes_2026.zip` created |
| 02:53:40.986626 | Suricata (SMB) | SMB2 WRITE of `review_notes_2026.zip` succeeds |

---

## Indicators of Compromise (IOCs)

| Type | Value | Description |
|---|---|---|
| Email | `amelia.hart@lawson-rowe-review.com` | Lure sender |
| Message-ID | `20261009022902.06.1a247614eaf9@lawson-rowe-review.com` | Lure email |
| Domain | `lawson-rowe-review.com` | Hosts the lure page and ZIP |
| URL | `http://lawson-rowe-review.com/review/disclosure-schedule` | Review page opened by Chrome |
| URL path | `/downloads/Disclosure_Schedule_Update.zip` | ZIP download |
| Domain | `cdn-lawsonreview.net` (`203.0.113.45`) | Primary C2 |
| Domain | `api-lawsoncdn.net` (`192.0.2.77`) | Backup C2 |
| User-Agent | `VantaraSync/4.1` | Sync client beacon |
| File | `Disclosure_Schedule_Update.zip` | Delivery archive |
| File | `ledgerdrop.exe` | Loader |
| File | `C:\Users\maya.chen\AppData\Local\VantaraSync\VantaraSync.exe` | Installed copy of the loader |
| SHA-256 | `AAD4B231C4AFC7D02A09344545A957086FE36CD6A9CCA8F1F92E1AC3DDFFAC5C` | Loader / sync client |
| Hash | `98D66005B3F2CFD556EEF503EC1ADA73DE34C24D3800D41D8E30C43AF32DEDEF` | Sysmon EID 15 hash recorded when Chrome saved the ZIP |
| Scheduled task | `VantaraUpdateCheck` | Persistence (daily 03:15) |
| Port | `50611/TCP` | Local source port of the first C2 callback |
| File | `C:\Users\maya.chen\Documents\review_notes_2026.zip` | Staged archive |
| Folder | `C:\Users\maya.chen\Documents\BoardReview\` | Archived source folder |
| Host | `VAN-FIN-WS-014` (`10.81.70.254`) | Affected workstation |
| Account | `maya.chen@vantara.local` | Targeted user |

**Not indicators (benign noise):** the `FinanceTemplateRefresh` task created by `VantaraDocumentSync.exe`, and Chrome's `elevation_service.exe` (`155.0.8059.40`).

---

## Splunk Queries Reference

```spl
-- Q1: Program run from a ZIP, ZIP host, and matching lure email
index="finance_endpoint" EventCode=1 Image=*.zip*
| table _time User Event.System.Computer Image ParentImage

index="finance_web" uri=*Disclosure_Schedule_Update.zip*
| table _time client_ip http_host uri

index="finance_mail" sourcetype="finance:mail:rfc822" sender_address=*lawson-rowe-review.com*
| table _time mail_from mail_to mail_subject sender_address recipient_address message_id

-- Q2: Browser opening the review site, and its parent
index="finance_endpoint" EventCode=1 Image=*chrome* CommandLine=*lawson-rowe-review.com*
| table _time Image ParentImage CommandLine ProcessId

-- Q3: Sysmon file-stream hash event for the download
index="finance_endpoint" EventCode=15 Image=*chrome*
| table _time TargetFilename Hash

-- Q4: Loader and sync client hashes
index="finance_endpoint" EventCode=1 (Image=*ledgerdrop.exe* OR Image=*VantaraSync.exe*)
| table _time Image CommandLine Hashes

-- Q5: Scheduled tasks and their parents
index="finance_endpoint" EventCode=1 Image=*schtasks*
| table _time ParentImage CommandLine

-- Q6: Sync client start vs first C2 callback
index="finance_endpoint" EventCode=1 Image=*VantaraSync*
| table _time UtcTime Image ParentImage

index="finance_web" http_host=*cdn-lawsonreview.net*
| table _time client_ip http_host status user_agent
| sort _time

-- Q7: WFP vs Suricata, matching source port
index="finance_endpoint" EventCode=5156 Application=*VantaraSync*
| table _time ProcessID SourceAddress SourcePort DestAddress DestPort
| sort _time

index="finance_network" event_type=http "http.hostname"="cdn-lawsonreview.net"
| table _time src_ip src_port dest_ip dest_port
| sort _time

-- Q8: 503 from primary C2 and DNS answer for the backup domain
index="finance_network" event_type=http NOT "http.hostname"="*vantara.local"
| sort 0 timestamp
| table timestamp dest_ip http.hostname http.status

index="finance_network" event_type=dns "dns.answers{}.rrtype"=A "dns.queries{}.rrname"="api-lawsoncdn.net"
| table timestamp dest_ip dns.answers{}.rrname

-- Q9: PowerShell archive command and PID history
index="finance_endpoint" EventCode=1 Image=*powershell*
| table _time ProcessId ParentImage CommandLine

index="finance_endpoint" EventCode=1 ProcessId=692
| table _time Image ParentImage

-- Q10: Archive creation and SMB2 write
index="finance_endpoint" EventCode=11 TargetFilename=*review_notes_2026.zip*
| table UtcTime Image TargetFilename

index="finance_network" event_type=smb "smb.command"=SMB2_COMMAND_WRITE
| table timestamp smb.filename smb.command smb.status
```

---

## MITRE ATT&CK Mapping

| Phase | Technique ID | Technique Name | Evidence |
|---|---|---|---|
| Initial Access | T1566 | Phishing | Lure email from `lawson-rowe-review.com` |
| Execution | T1204.001 | User Execution: Malicious Link | Chrome opens the review URL |
| Execution | T1204.002 | User Execution: Malicious File | `ledgerdrop.exe` run from the ZIP |
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Name or Location | `VantaraSync.exe`, `VantaraUpdateCheck` |
| Persistence | T1053.005 | Scheduled Task/Job: Scheduled Task | `VantaraUpdateCheck`, daily 03:15 |
| Command & Control | T1071.001 | Application Layer Protocol: Web Protocols | HTTP beacons, UA `VantaraSync/4.1` |
| Command & Control | T1008 | Fallback Channels | Failover to `api-lawsoncdn.net` |
| Execution | T1059.001 | PowerShell | `-ExecutionPolicy Bypass` archive command |
| Collection | T1560.001 | Archive Collected Data: Archive via Utility | `Compress-Archive` on `BoardReview` |
| Collection | T1074.002 | Data Staged: Remote Data Staging | SMB2 WRITE of `review_notes_2026.zip` |

---

## Response Scope Supported by the Evidence

**Confirmed:**
- Delivery of a lure email and execution of a loader on `VAN-FIN-WS-014` by `maya.chen`.
- Persistence through `VantaraUpdateCheck`, and C2 over HTTP to two domains with failover.
- Archiving of `BoardReview` into `review_notes_2026.zip` and a successful SMB2 write of that archive to a file server.

**Not shown by this evidence:**
- Whether the archive left the network to the internet. The evidence shows the move to the file server, not external exfiltration.
- How the review link reached `VantaraFinancePortal.exe` before Chrome was launched.

---

## Recommendations

1. **Block both C2 domains and IPs** — `cdn-lawsonreview.net` / `203.0.113.45` and `api-lawsoncdn.net` / `192.0.2.77`, plus the delivery domain `lawson-rowe-review.com`. Blocking only the primary leaves the failover channel open.
2. **Remove the foothold** — delete the `VantaraUpdateCheck` task and `C:\Users\maya.chen\AppData\Local\VantaraSync\`, and re-image the workstation. The identical hash shows the "sync client" is the loader itself.
3. **Reset `maya.chen`'s credentials and review her access** — the attacker ran as her and could reach `BoardReview`.
4. **Inspect the file server** — find where `review_notes_2026.zip` was written, check who can read that location, and check the server for any other transfers from the same workstation.
5. **Treat the board-review material as exposed** — notify legal and compliance owners, since it relates to an acquisition at a financial services firm.
6. **Hunt for the same artifacts elsewhere** — `VantaraSync/4.1` user-agent, the shared SHA-256, task name `VantaraUpdateCheck`, and any mail from `lawson-rowe-review.com`.
7. **Detect programs running from inside ZIPs** — alert on process creation from `...\Temp\Temp1_*.zip\` paths.
8. **Alert on unusual parents for `schtasks.exe`** — a task created by a program that was just extracted from a download should be high severity.
9. **Use `ProcessGuid`, not `ProcessId`, when pivoting in Sysmon** — PIDs are recycled (PID 692 here), so a PID search can join unrelated processes.
10. **Restrict outbound HTTP to uncategorized domains** — beacons to newly seen domains with a custom user-agent should be flagged.

---

*Writeup produced as part of SOC Analyst training — TryHackMe: The Finance Trail*