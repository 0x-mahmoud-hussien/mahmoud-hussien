---
title: "Splunk: Backdoor Persistence & C2 Discovery"
description: "A digital forensics investigation using Splunk to uncover remote backdoor creation via WMIC, registry persistence, and malicious PowerShell C2 communication."
date: 2026-04-24
platform: "TryHackMe"
difficulty: "Medium"
category: "Incident Response / SOC Analysis"
tags: ["splunk", "persistence", "backdoor", "powershell-analysis", "c2-communication", "wmic"]
featured: true
draft: false
tools: ["Splunk", "CyberChef", "Sysmon", "PowerShell"]
room_url: "https://tryhackme.com/room/investigatingwithsplunk"
---

---

# Investigating with Splunk — CTF Writeup

---

## Scenario Overview

SOC Analyst Johny observed anomalous behavior across several Windows machines. Evidence suggested that an adversary had gained access to these hosts and successfully created backdoors. Logs were pulled from the suspected hosts and ingested into Splunk for investigation. The goal is to examine these logs, identify the attacker's actions, and trace the full attack chain.

---

## Attack Summary

The adversary:
1. Gained remote access to a workstation.
2. Used **WMIC** for lateral movement and remote command execution.
3. Created a **backdoor user** (`Alberto`) for persistence.
4. Updated **registry keys** to solidify the new account.
5. Executed an **obfuscated PowerShell script** to establish a C2 connection.

---

## Question 1 — How many events were collected and ingested in the index main?

### Splunk Query

```spl
index=main | stats count
```

### Investigation

This baseline query counts every event ingested into the `main` index — the starting point for any Splunk investigation to understand the data volume available.

### Answer

```
12,256
```
![Answer](../images/Windows-Backdoor-Splunk1.png)

---

## Question 2 — What is the new backdoor username created by the adversary?

### Splunk Query

```spl
index=main EventID="4720"
| table _time SamAccountName TargetUserName SubjectUserName
```

### Investigation

**Windows Event ID 4720** is generated whenever a new user account is created. Filtering for this event ID and reviewing the `TargetUserName` field reveals the newly created account.

The account was created outside of normal IT provisioning processes and was not associated with any approved change request.

### Answer

```
Alberto
```
![Answer](../images/Windows-Backdoor-Splunk2.png)

---

## Question 3 — What is the full path of the registry key updated for the backdoor user?

### Splunk Query

```spl
index=main EventID="13" Alberto
| table _time Image Message
```

### Investigation

**Sysmon Event ID 13** logs registry value set operations. After account creation, Windows automatically writes an entry into the SAM (Security Account Manager) hive. Filtering for registry events mentioning `Alberto` reveals the exact path where the new user was registered in the system.

### Answer

```
HKLM\SAM\SAM\Domains\Account\Users\Names\Alberto
```
![Answer](../images/Windows-Backdoor-Splunk3.png)

---

## Question 4 — What user was the adversary trying to impersonate?

### Splunk Query

```spl
index=main | top limit=20 User
```

### Investigation

Cross-referencing the backdoor account name `Alberto` with legitimate Active Directory accounts, and reviewing the `SubjectUserName` field from Event ID 4720, reveals that the adversary was attempting to blend in with an existing user account to avoid detection.

### Answer

```
Alberto
```
![Answer](../images/Windows-Backdoor-Splunk4.png)

---

## Question 5 — What is the command used to add a backdoor user from a remote computer?

### Splunk Query

```spl
index=main User="Cybertees\\James" (EventID="4688" OR EventID="1")
| table _time HostName CommandLine ParentCommandLine
| sort - _time
```

### Investigation

**Event ID 4688** (Process Creation) and **Sysmon Event ID 1** both capture process launches with full command-line arguments. Filtering by the impersonated user `James` and looking for remote execution commands reveals the exact WMIC command used.

The attacker used **WMIC** (`Windows Management Instrumentation Command-line`) to remotely create a process on `WORKSTATION6` — a living-off-the-land technique that abuses a built-in Windows tool to avoid triggering AV/EDR.

### Answer

```
WMIC.exe /node:WORKSTATION6 process call create "net user /add Alberto paw0rd1"
```
![Answer](../images/Windows-Backdoor-Splunk5.png)

---

## Question 6 — How many times was the login attempt from the backdoor user observed?

### Splunk Query

```spl
index=main Alberto (EventID="4624" OR EventID="4625")
| stats count
```

### Investigation

**Event ID 4624** logs successful logon events, while **Event ID 4625** logs failed logon attempts, which helps identify brute-force or unauthorized access trials. Filtering for the Alberto account shows how many times the attacker actively used the backdoor account to authenticate into systems during the investigation window.

### Answer

```
0
```
![Answer](../images/Windows-Backdoor-Splunk6.png)

---

## Question 7 — What is the name of the infected host on which suspicious PowerShell commands were executed?

### Splunk Query

```spl
index=main EventID="4103"
| table _time Hostname
| dedup Hostname
```

### Investigation

**Event ID 4103** is generated by PowerShell Module Logging and captures the full content of PowerShell pipeline executions. Identifying which host generated these events pinpoints the machine where the attacker ran their malicious script.

The host was running under the PowerShell `ConsoleHost` environment, confirming interactive or script-based execution.

### Answer

```
James.browne
```
![Answer](../images/Windows-Backdoor-Splunk7.png)

---

## Question 8 — How many events were logged for the malicious PowerShell execution?

### Splunk Query

```spl
index=main EventID="4103"
| stats count
```

### Investigation

Counting all PowerShell Module Logging events (Event ID 4103) provides the total number of recorded pipeline executions. This high event count is typical of a complex, multi-step obfuscated PowerShell script that performs many operations.

### Answer

```
79
```
![Answer](../images/Windows-Backdoor-Splunk8.png)

---

## Question 9 — What is the full URL from the encoded PowerShell web request?

### Splunk Query

```spl
index=main EventID="4103"
| search ScriptBlockText="*FromBase64String*" OR ScriptBlockText="*-enc*"
| table _time ScriptBlockText
```
![Answer](../images/Windows-Backdoor-Splunk9.png)

### Investigation

Within the 79 PowerShell events, the script contained Base64-encoded strings. Isolating the encoded payload and decoding it using **CyberChef**:

**Encoded String:**
```
aAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADAALgA1AA==
```
![Answer](../images/Windows-Backdoor-Splunk10.png)

**CyberChef Recipe:**
```
From Base64 → Decode Text (UTF-16LE)
```

**Decoded Output:**
```
http://10.10.10.5/news.php
```

The script additionally employed the following evasion techniques:
- **AMSI Bypass** — Attempted to disable `AmsiScanBuffer` to prevent Windows Defender from scanning the script.
- **ScriptBlockLogging Bypass** — Attempted to suppress PowerShell's own logging to avoid forensic capture.
- **RC4 Encryption** — Used a custom RC4 function to encrypt C2 communication data.

### Answer

```
http://10.10.10.5/news.php
```
![Answer](../images/Windows-Backdoor-Splunk11.png)

---

## Full Attack Chain Reconstruction

```
[1] Initial Access
    └─ Adversary gains remote access to workstation
    └─ Uses compromised credentials of user: James

[2] Lateral Movement
    └─ WMIC remote process creation
    └─ Target: WORKSTATION6
    └─ Command: WMIC.exe /node:WORKSTATION6 process call create
               "net user /add Alberto paw0rd1"

[3] Persistence — Backdoor Account
    └─ New user created: Alberto
    └─ Event ID 4720 triggered
    └─ Registry updated: HKLM\SAM\SAM\Domains\Account\Users\Names\Alberto

[4] Execution — Obfuscated PowerShell
    └─ Host: James.browne
    └─ 79 PowerShell events (Event ID 4103)
    └─ Encoding: Base64 + RC4 encryption
    └─ AMSI & ScriptBlockLogging bypass attempted

[5] Command & Control (C2)
    └─ Web request to: http://10.10.10.5/news.php
    └─ User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0)
```

---

## Indicators of Compromise (IOCs)

| Type | Value | Description |
|---|---|---|
| IP Address | `10.10.10.5` | C2 Server |
| URL | `http://10.10.10.5/news.php` | C2 Callback Endpoint |
| Username | `Alberto` | Backdoor Account |
| Password | `paw0rd1` | Backdoor Account Credential |
| Registry Path | `HKLM\SAM\SAM\Domains\Account\Users\Names\Alberto` | Persistence Key |
| Host | `James.browne` | Infected Workstation |
| User-Agent | `Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko` | C2 Beacon UA |

---

## Key Splunk Queries Reference

```spl
-- Total event count
index=main | stats count

-- Backdoor user creation (Event ID 4720)
index=main EventID="4720"
| table _time SamAccountName TargetUserName SubjectUserName

-- Registry persistence (Sysmon Event ID 13)
index=main EventID="13" Alberto
| table _time Image Message

-- Remote WMIC execution (Event ID 4688 / Sysmon 1)
index=main User="Cybertees\\James" (EventID="4688" OR EventID="1")
| table _time HostName CommandLine ParentCommandLine
| sort - _time

-- Backdoor user logon attempts (Event ID 4624)
index=main Alberto (EventID="4624" OR EventID="4625")
| stats count

-- PowerShell module logging (Event ID 4103)
index=main EventID="4103" | stats count

-- Find Base64 encoded commands
index=main EventID="4103"
| search ScriptBlockText="*FromBase64String*"
| table _time ScriptBlockText
```

---

## MITRE ATT&CK Mapping

| Phase | Technique ID | Technique Name |
|---|---|---|
| Execution | T1047 | Windows Management Instrumentation |
| Execution | T1059.001 | PowerShell |
| Persistence | T1136.001 | Create Account: Local Account |
| Persistence | T1547.001 | Registry Run Keys / Startup Folder |
| Defense Evasion | T1027 | Obfuscated Files or Information |
| Defense Evasion | T1562.001 | Disable or Modify Tools (AMSI Bypass) |
| Lateral Movement | T1021 | Remote Services |
| Command & Control | T1071.001 | Web Protocols |
| Command & Control | T1573 | Encrypted Channel (RC4) |

---

## Lessons Learned

1. **Enable and monitor PowerShell logging** — Event IDs 4103, 4104, and 4688 are essential for catching obfuscated script execution. Without them, this attack would have been invisible.
2. **Alert on Event ID 4720** — Any new user account creation outside of a provisioning workflow should trigger an immediate alert.
3. **Block WMIC remote execution** — Restrict `WMIC.exe` usage to authorized admin accounts only, especially the `/node:` remote execution flag.
4. **Monitor SAM registry modifications** — Unexpected writes to `HKLM\SAM\SAM\Domains\Account\Users\` indicate unauthorized account creation or manipulation.
5. **Baseline PowerShell activity** — 79 events from a single script execution on a standard workstation is highly anomalous and should trigger a SIEM rule.
6. **Hunt for AMSI bypass attempts** — Strings like `AmsiScanBuffer` in PowerShell logs are a strong indicator of malicious intent.

---

*Writeup produced as part of SOC Analyst training — TryHackMe: Investigating with Splunk*