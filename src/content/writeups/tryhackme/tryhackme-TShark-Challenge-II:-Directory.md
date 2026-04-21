---
title: "Operation Directory Curiosity: Investigating Malicious File Indexing"
description: "A SOC investigation into a True Positive alert where user curiosity led to a Trojan download via an exposed HTTP directory. Analyzing pcap traffic, extracting .NET malware, and validating IOCs with VirusTotal."
date: 2026-04-21
platform: "TryHackMe"
difficulty: "Easy"
category: "Network Forensics / PCAP Analysis / SOC Analysis"
tags: ["TShark", "PCAP-Analysis", "Malware-Extraction", "VirusTotal", "Directory-Listing", "BlueBot-Trojan"]
featured: true
draft: false
tools: ["TShark", "VirusTotal", "CyberChef", "Bash"]
room_url: "https://tryhackme.com/room/tsharkchallengestwo"
---

# TShark Challenge II: Directory — CTF Writeup

---

## Scenario Overview

An alert was triggered based on the rule: *"A user came across a poor file index, and their curiosity led to problems."* The task is to investigate the provided PCAP file (`directory-curiosity.pcap`), identify the malicious domain contacted, analyze the HTTP traffic, and extract and investigate the downloaded malware artifact.

---

## Environment Setup

All analysis was performed using TShark from the terminal:

```bash
cd ~/Desktop/exercise-files
ls
# directory-curiosity.pcap
```

---

## Question 1 — What is the name of the malicious/suspicious domain?

### Investigation

The first step is to extract all DNS queries from the PCAP to identify every domain the victim machine contacted:

```bash
tshark -r directory-curiosity.pcap -T fields -e 'dns.qry.name' | awk NF | sort -r | uniq -c | sort -r
```

The output produced a list of queried domains. Each unique domain was submitted to **VirusTotal** for reputation checks. One domain was flagged by multiple security vendors as malicious/suspicious.

### Answer (Defanged)

```
jx2-bavuong[.]com
```
![Answer](../images/TShark-Challenge-II:Directory-1.png)
![Answer](../images/TShark-Challenge-II:Directory-2.png)

---

## Question 2 — What is the total number of HTTP requests sent to the malicious domain?

### Investigation

Filtering the PCAP for all HTTP requests destined for the malicious domain:

```bash
tshark -r directory-curiosity.pcap \
  -Y "http.request and ip.dst == 141.164.41.174" | wc -l
```

Alternatively, filtering by HTTP host header:

```bash
tshark -r directory-curiosity.pcap \
  -Y 'http.host contains "jx2-bavuong"' | wc -l
```

### Answer

```
14
```
![Answer](../images/TShark-Challenge-II:Directory-3.png)

---

## Question 3 — What is the IP address associated with the malicious domain?

### Investigation

Extracting the DNS A record response for the malicious domain:

```bash
tshark -r directory-curiosity.pcap \
  -Y 'dns.qry.name == "jx2-bavuong.com"' \
  -T fields -e dns.a
```

### Answer (Defanged)

```
141[.]164[.]41[.]174
```
![Answer](../images/TShark-Challenge-II:Directory-4.png)
![Answer](../images/TShark-Challenge-II:Directory-5.png) 

---

## Question 4 — What is the server info of the suspicious domain?

### Investigation

Extracting the HTTP response `Server` header from traffic destined to or coming from the malicious IP:

```bash
tshark -r directory-curiosity.pcap -T fields -e "http.server" | awk NF
```

```bash
tshark -r directory-curiosity.pcap \
  -Y "http.response and ip.src == 141.164.41.174" \
  -T fields -e http.server | sort -u
```

The server banner revealed a severely outdated and vulnerable software stack — a Windows-based Apache server running components that reached end-of-life over a decade ago. This configuration is a major red flag and indicates a deliberately or negligently unpatched server.

### Answer

```
Apache/2.2.11 (Win32) DAV/2 mod_ssl/2.2.11 OpenSSL/0.9.8i PHP/5.2.9
```
![Answer](../images/TShark-Challenge-II:Directory-6.png) 

---

## Question 5 — Follow the first TCP stream. What is the number of listed files?

### Investigation

Following the first TCP stream in ASCII mode to inspect the raw HTTP conversation:

```bash
tshark -r directory-curiosity.pcap \
  -z follow,tcp,ascii,0 -q
```

The output revealed an **Apache Directory Listing** (`Index of /`) — an open file index on the web server. The user browsed this index and was presented with all available files.

Counting the listed entries in the directory index output:

### Answer

```
3
```

*(Files listed: `123.php`, `vlauto.php`, `vlauto.exe`)*
![Answer](../images/TShark-Challenge-II:Directory-7.png) 

---

## Question 6 — What is the filename of the first file?

### Investigation

Reviewing the directory listing output from the TCP stream, the first file entry in the `Index of /` was:

### Answer (Defanged)

```
123[.]php
```

---

## Question 7 — Export all HTTP traffic objects. What is the name of the downloaded executable file?

### Investigation

Exporting all HTTP objects from the PCAP:

```bash
tshark -r directory-curiosity.pcap \
  --export-objects http,./exported_objects
ls ./exported_objects/
```

Among the exported files, one `.exe` file was present — the artifact downloaded by the user after browsing the directory listing. The other files (`123.php`, `vlauto.php`) are server-side scripts and would not produce a downloadable response in the same way.

### Answer (Defanged)

```
vlauto[.]exe
```
![Answer](../images/TShark-Challenge-II:Directory-8.png) 

---

## Question 8 — What is the SHA256 value of the malicious file?

### Investigation

Hashing the exported executable:

```bash
sha256sum ./exported_objects/vlauto.exe
```

The hash was then submitted to **VirusTotal** for full threat intelligence analysis.

### Answer

```
b4851333efaf399889456f78eac0fd532e9d8791b23a86a19402c1164aed20de
```
![Answer](../images/TShark-Challenge-II:Directory-9.png) 

---

## Question 9 — What is the "PEiD packer" value?

### Investigation

On the VirusTotal results page for the hash, navigating to the **Details** tab and locating the **PEiD packer** field under the PE file metadata section.

The PEiD value indicates how the executable was compiled and whether any packing or obfuscation tool was used on the binary.

### Answer

```
.NET executable
```
![Answer](../images/TShark-Challenge-II:Directory-10.png) 

---

## Question 10 — What does the "Lastline Sandbox" flag this as?

### Investigation

On the same VirusTotal page, navigating to the **Behavior** tab and reviewing the **Sandbox Reports** section. Locating the **Lastline** sandbox entry and checking its verdict/classification.

### Answer

```
MALWARE TROJAN BOTNET
```
![Answer](../images/TShark-Challenge-II:Directory-11.png) 

---

## Full Attack Chain Reconstruction

```
[1] Discovery
    └─ User browsed to jx2-bavuong[.]com
    └─ Server exposed Apache Directory Listing (Index of /)
    └─ Server: Apache/2.2.11 (Win32) — severely outdated

[2] File Listing
    └─ 3 files visible in the index:
       ├─ 123[.]php
       ├─ vlauto[.]php
       └─ vlauto[.]exe  ← downloaded by the user

[3] Download & Execution (Assumed)
    └─ vlauto[.]exe downloaded via HTTP GET
    └─ SHA256: b4851333efaf399889456f78eac0fd532e9d8791b23a86a19402c1164aed20de

[4] Malware Behavior (VirusTotal / Sandbox)
    └─ Family: BlueBot (Trojan/Botnet)
    └─ Persistence: Writes to Windows Startup folder
    └─ Evasion: detect-debug-environment, long-sleeps
    └─ Detection: 62/71 vendors flagged as malicious
```

---

## Indicators of Compromise (IOCs)

| Type | Value | Description |
|---|---|---|
| Domain | `jx2-bavuong[.]com` | Malicious hosting server |
| IP Address | `141[.]164[.]41[.]174` | Resolved IP of malicious domain |
| File | `vlauto[.]exe` | Downloaded malware artifact |
| SHA256 | `b4851333efaf399889456f78eac0fd532e9d8791b23a86a19402c1164aed20de` | Hash of `vlauto.exe` |
| Server Banner | `Apache/2.2.11 (Win32) DAV/2 mod_ssl/2.2.11 OpenSSL/0.9.8i PHP/5.2.9` | Attacker-controlled server info |

---

## Threat Intelligence Summary

| Property | Value |
|---|---|
| Malware Family | BlueBot |
| Classification | Trojan / Botnet |
| VirusTotal Detections | 62 / 71 vendors |
| PEiD Packer | .NET executable |
| Lastline Verdict | MALWARE TROJAN BOTNET |
| Persistence Method | Windows Startup folder write |
| Evasion Techniques | Anti-debug, long sleep intervals |

---

## Key TShark Commands Reference

```bash
# Extract all DNS queries
tshark -r directory-curiosity.pcap -T fields -e 'dns.qry.name' | awk NF | sort -r | uniq -c | sort -r 

# Count HTTP requests to malicious IP
tshark -r directory-curiosity.pcap \
  -Y "http.request and ip.dst == 141.164.41.174" | wc -l

# Get DNS resolution for domain
tshark -r directory-curiosity.pcap \
  -Y 'dns.qry.name == "jx2-bavuong.com"' -T fields -e dns.a

# Extract server header
tshark -r directory-curiosity.pcap \
  -Y "http.response and ip.src == 141.164.41.174" \
  -T fields -e http.server | sort -u

# Follow first TCP stream
tshark -r directory-curiosity.pcap -z follow,tcp,ascii,0 -q

# Export HTTP objects
tshark -r directory-curiosity.pcap --export-objects http,./exported_objects

# Hash the exported file
sha256sum ./exported_objects/vlauto.exe
```

---

## Lessons Learned

1. **Disable Apache Directory Listing** — Never expose a directory index (`Options -Indexes` in Apache config). An open index is an open invitation.
2. **Keep server software patched** — Apache 2.2.11 and OpenSSL 0.9.8i are critically outdated with numerous known CVEs.
3. **Block executable downloads at the perimeter** — A web proxy or firewall with content inspection should block `.exe` downloads from uncategorized or suspicious domains.
4. **User awareness training** — Curiosity-driven downloads are a major attack vector. Users need to understand the risk of downloading unknown files.
5. **DNS monitoring** — DNS queries to newly registered or low-reputation domains should trigger alerts in the SIEM.

---

*Writeup produced as part of SOC Analyst training — TryHackMe: TShark Challenge II: Directory*