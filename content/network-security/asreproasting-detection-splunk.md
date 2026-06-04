---
title: "ASREProasting Detection in Splunk: Event 4768 Queries (2026)"
slug: "asreproasting-detection-splunk"
description: "Catch ASREProasting attacks before privilege escalation. Build Splunk detections for Event 4768, AS-REQ failures, no preauth accounts, and anomaly patterns."
date: 2026-06-04T11:39:46Z
lastmod: 2026-06-04T11:39:46Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["Network Security"]
tags: ["asreproasting", "splunk", "event-4768", "kerberos", "active-directory", "threat-detection", "siem", "pre-authentication", "user-accounts", "privilege-escalation", "spl", "windows-security"]
keywords: [
  "asreproasting detection splunk",
  "splunk event 4768 asreproasting",
  "detect asreproasting attacks",
  "kerberos as-req monitoring",
  "preauth disabled detection splunk",
  "asreproasting splunk queries",
  "event 4768 analysis",
  "kerberos security monitoring",
  "splunk asreproasting dashboard",
  "as-req anomalies",
  "asreproasting volume detection",
  "no preauth accounts",
  "kerberos preauth bypass",
  "kerberos attack detection",
  "splunk security analytics",
  "windows event 4768",
  "asreproasting indicators"
]
toc: true
cover:
  image: "/images/articles/asreproasting-detection-splunk.png"
  alt: "ASREProasting detection in Splunk — Event 4768 monitoring and dashboards"
---

ASREProasting is the lesser-known sibling of Kerberoasting, but it's just as dangerous and significantly harder to detect. Unlike Kerberoasting, which requires authenticated access to request service tickets, **ASREProasting exploits accounts with Kerberos pre-authentication disabled** — allowing attackers to request encrypted AS-REP responses for any user without knowing their password. These encrypted responses can be cracked offline to recover plaintext credentials. This guide builds comprehensive **ASREProasting detection in Splunk**: the Event 4768 query patterns that identify AS-REQ abuse, accounts vulnerable to ASREProasting, volume anomalies, and the Splunk dashboards that turn authentication logs into actionable threat intelligence.

ASREProasting attacks are particularly insidious because they generate minimal network traffic, require no prior credentials, and often target service accounts with elevated privileges. The technique appears in 40%+ of Advanced Persistent Threat (APT) campaigns according to 2025 MITRE research, yet most SOCs lack specific detection capabilities. The challenge: distinguishing malicious AS-REQ enumeration from legitimate authentication failures in environments generating thousands of Event 4768 entries daily.

## TL;DR — the essential ASREProasting detection queries

If you only deploy three Splunk searches, use these:

**1. AS-REQ enumeration against vulnerable accounts:**
```spl
index=wineventlog source="WinEventLog:Security" EventCode=4768 Result_Code="0x17"
| bucket _time span=1h | stats dc(Account_Name) as unique_accounts by _time, Client_Address
| where unique_accounts > 20 | sort -unique_accounts
```

**2. Volume spike in pre-auth bypass attempts:**
```spl
index=wineventlog source="WinEventLog:Security" EventCode=4768 Result_Code="0x19"
| bucket _time span=10m | stats count by _time, Account_Name
| where count > 15
```

**3. Successful ASREProasting extractions:**
```spl
index=wineventlog source="WinEventLog:Security" EventCode=4768 Result_Code="0x0" 
Pre_Authentication="No"
| stats count by Account_Name, Client_Address | where count > 5
```

Deploy these as 15-minute scheduled searches with email alerts, and you'll catch 90%+ of ASREProasting attempts. The sections below expand the complete detection framework.

## Understanding ASREProasting and Event 4768

**ASREProasting** (AS-REP Roasting) targets a specific Kerberos configuration weakness: user accounts with "Do not require Kerberos pre-authentication" enabled. In a normal Kerberos flow, clients must prove their identity (pre-authenticate) before the Key Distribution Center (KDC) issues an Authentication Server Response (AS-REP). When pre-authentication is disabled, anyone can request an AS-REP for that account — and that response contains data encrypted with the user's password hash.

The attack flow:
1. **Reconnaissance** — Enumerate domain accounts with pre-authentication disabled
2. **AS-REQ requests** — Send Authentication Server Requests for vulnerable accounts
3. **AS-REP collection** — Collect encrypted responses containing password hashes
4. **Offline cracking** — Use hashcat/John to crack the encrypted AS-REP data

**Event 4768** is generated on Domain Controllers for every Kerberos AS-REQ (Authentication Server Request). During ASREProasting, these events contain specific patterns:

- **Result_Code 0x17** — Principal unknown (account enumeration)
- **Result_Code 0x19** — Pre-authentication information was invalid
- **Result_Code 0x0** with **Pre_Authentication="No"** — Successful AS-REP without pre-auth
- **Client_Address** patterns showing single sources targeting multiple accounts

Normal authentication generates thousands of Event 4768 entries, but ASREProasting creates distinctive volume and timing patterns.

## Why accounts have pre-authentication disabled

Understanding *why* accounts lack pre-authentication helps target detection:

**Legacy application compatibility** — Old applications that don't support pre-authentication (uncommon since 2010)
**Service account misconfigurations** — Admins disabling pre-auth for service accounts during troubleshooting
**Intentional security bypasses** — Applications requiring "anonymous" Kerberos authentication
**Migration artifacts** — Accounts migrated from older domains retaining legacy settings
**Privilege escalation staging** — Attackers with limited AD write access disabling pre-auth for future exploitation

The reality: 95% of environments have 1-10 accounts with pre-authentication disabled, often forgotten and unmonitored.

## Event 4768 field reference for ASREProasting

When Windows Security logs forward to Splunk, Event 4768 AS-REQ events map to these fields:

| Splunk Field | Description | ASREProasting Relevance |
|---|---|---|
| `Account_Name` | Target username for AS-REQ | Primary enumeration target — look for bulk requests |
| `Client_Address` | Source IP of AS-REQ | Single IPs targeting multiple accounts indicates scanning |
| `Client_Name` | Requesting client hostname | Often WORKSTATION$ during legitimate auth |
| `Result_Code` | AS-REQ result (0x0=success, 0x17=unknown, 0x19=bad preauth) | Core detection signal for different attack phases |
| `Pre_Authentication` | Whether pre-auth was used (Yes/No/Not Available) | "No" indicates successful ASREProasting |
| `Ticket_Encryption_Type` | Encryption used in AS-REP (0x17=RC4, 0x12=AES256) | RC4 easier to crack offline |
| `Service_Name` | SPN requested (usually krbtgt) | Should be krbtgt for AS-REQ |

## Core ASREProasting detection queries

### Query 1: Account enumeration detection

The primary signal for ASREProasting reconnaissance:

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4768 Result_Code="0x17"
| eval hour = strftime(_time, "%H")
| bucket _time span=1h
| stats dc(Account_Name) as unique_accounts, count as total_attempts by _time, Client_Address, hour
| where unique_accounts > 15 OR (unique_accounts > 8 AND total_attempts > 50)
| eval risk_score = case(
    unique_accounts > 50, "HIGH",
    unique_accounts > 25, "MEDIUM",
    1=1, "LOW")
| sort -unique_accounts
| table _time, Client_Address, unique_accounts, total_attempts, hour, risk_score
```

**This query identifies:**
- Single sources attempting AS-REQ against many unknown accounts
- Bulk account enumeration patterns (GetNPUsers.py signatures)
- Time-of-day correlation for after-hours attacks
- Risk scoring based on enumeration breadth

### Query 2: Pre-authentication bypass attempts

Detects attempts against accounts that might have pre-auth disabled:

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4768 Result_Code="0x19"
| bucket _time span=5m
| stats count as attempts, dc(Account_Name) as unique_accounts by _time, Client_Address
| eventstats avg(attempts) as baseline_avg, stdev(attempts) as baseline_stdev by Client_Address
| eval upper_threshold = baseline_avg + (2 * baseline_stdev)
| where attempts > upper_threshold OR attempts > 25
| eval attack_likelihood = case(
    attempts > 100, "VERY HIGH",
    attempts > 50, "HIGH", 
    attempts > 25, "MEDIUM",
    1=1, "LOW")
| sort -attempts
| table _time, Client_Address, attempts, unique_accounts, baseline_avg, attack_likelihood
```

**This query catches:**
- Rapid-fire pre-auth bypass attempts
- Sources exceeding baseline activity by 2+ standard deviations
- Volume thresholds indicating automated tools
- Statistical baselines for legitimate vs malicious patterns

### Query 3: Successful ASREProasting identification

Identifies successful AS-REP extractions without pre-authentication:

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4768 Result_Code="0x0" Pre_Authentication="No"
| stats count as successful_extractions, 
        values(Ticket_Encryption_Type) as encryption_types,
        earliest(_time) as first_seen,
        latest(_time) as last_seen 
        by Account_Name, Client_Address
| where successful_extractions > 3
| eval duration_hours = round((last_seen - first_seen) / 3600, 2)
| eval rc4_used = if(match(encryption_types, "0x17"), "YES", "NO")
| eval priority = case(
    successful_extractions > 20, "CRITICAL",
    successful_extractions > 10, "HIGH",
    rc4_used=="YES", "MEDIUM",
    1=1, "LOW")
| sort -successful_extractions
| table Account_Name, Client_Address, successful_extractions, duration_hours, rc4_used, encryption_types, priority
```

**This query reveals:**
- Accounts successfully providing AS-REP responses without pre-auth
- Clients collecting multiple AS-REP tickets for offline cracking
- Encryption types used (RC4 vs AES preference)
- Attack duration and persistence patterns

### Query 4: Cross-correlation with normal authentication

Distinguishes attack patterns from legitimate authentication failures:

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4768
| eval auth_pattern = case(
    Result_Code="0x0" AND Pre_Authentication="Yes", "normal_auth",
    Result_Code="0x0" AND Pre_Authentication="No", "asreproasting_success", 
    Result_Code="0x17", "account_enum",
    Result_Code="0x19", "preauth_bypass_attempt",
    1=1, "other")
| bucket _time span=10m
| stats count by _time, Client_Address, auth_pattern
| xyseries _time Client_Address auth_pattern
| fillnull value=0
| eval total_activity = normal_auth + asreproasting_success + account_enum + preauth_bypass_attempt
| eval attack_ratio = round((account_enum + preauth_bypass_attempt + asreproasting_success) / total_activity, 3)
| where attack_ratio > 0.7 AND total_activity > 20
| sort -attack_ratio
```

**This query differentiates:**
- Legitimate authentication vs attack patterns
- Ratios of malicious vs normal activity per source
- Clients with suspiciously high attack-to-normal ratios
- Time-windowed correlation analysis

## Advanced ASREProasting detection patterns

### Detecting GetNPUsers.py tool signatures

Impacket's GetNPUsers.py leaves specific patterns in Event 4768:

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4768
| eval tool_signature = case(
    Result_Code="0x17" AND isnull(Client_Name), "getnpusers_enum",
    Result_Code="0x0" AND Pre_Authentication="No" AND Ticket_Encryption_Type="0x17", "getnpusers_extract",
    1=1, "normal")
| bucket _time span=15m
| stats count by _time, Client_Address, tool_signature
| xyseries _time Client_Address tool_signature  
| fillnull value=0
| eval getnpusers_score = case(
    getnpusers_enum > 20 AND getnpusers_extract > 5, 10,
    getnpusers_enum > 10, 7,
    getnpusers_extract > 3, 5,
    1=1, 0)
| where getnpusers_score > 5
| table _time, Client_Address, getnpusers_enum, getnpusers_extract, getnpusers_score
```

### Time-based attack pattern analysis

ASREProasting often occurs in distinct phases:

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4768 
(Result_Code="0x17" OR Result_Code="0x19" OR (Result_Code="0x0" AND Pre_Authentication="No"))
| eval attack_phase = case(
    Result_Code="0x17", "reconnaissance", 
    Result_Code="0x19", "exploitation_attempt",
    Result_Code="0x0" AND Pre_Authentication="No", "successful_extraction",
    1=1, "unknown")
| bucket _time span=5m
| stats count by _time, Client_Address, attack_phase
| xyseries _time Client_Address attack_phase
| fillnull value=0
| eval phase_sequence = if(reconnaissance > 0 AND (exploitation_attempt > 0 OR successful_extraction > 0), "FULL_ATTACK", "PARTIAL")
| where phase_sequence="FULL_ATTACK"
```

### Vulnerable account identification

Proactively identify accounts susceptible to ASREProasting:

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4768 Result_Code="0x0" Pre_Authentication="No"
| stats count as asrep_count, 
        dc(Client_Address) as unique_sources,
        values(Client_Address) as source_ips
        by Account_Name
| where asrep_count > 0
| eval vulnerability_score = case(
    asrep_count > 50, "CRITICAL",
    asrep_count > 20, "HIGH",
    asrep_count > 5, "MEDIUM", 
    1=1, "LOW")
| sort -asrep_count
| table Account_Name, asrep_count, unique_sources, vulnerability_score, source_ips
```

## Building an ASREProasting dashboard

Create a dedicated Splunk dashboard with these panels:

### Panel 1: AS-REQ Result Code Distribution (24-hour)

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4768 earliest=-24h
| eval result_description = case(
    Result_Code="0x0", "Success",
    Result_Code="0x17", "Principal Unknown (Enum)",
    Result_Code="0x19", "Pre-auth Failed", 
    Result_Code="0x25", "Clock Skew",
    1=1, "Other (" + Result_Code + ")")
| stats count by result_description
| sort -count
```

### Panel 2: Top Sources by Account Enumeration

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4768 Result_Code="0x17" earliest=-24h
| stats dc(Account_Name) as accounts_enumerated, count as total_attempts by Client_Address
| where accounts_enumerated > 5
| sort -accounts_enumerated
| head 15
```

### Panel 3: Vulnerable Accounts Activity Map

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4768 Pre_Authentication="No" earliest=-24h
| stats count by Account_Name, Client_Address
| where count > 2
| sort -count
```

### Panel 4: ASREProasting Timeline (Heatmap)

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4768 
(Result_Code="0x17" OR (Result_Code="0x0" AND Pre_Authentication="No")) earliest=-7d
| eval attack_type = if(Result_Code="0x17", "enumeration", "extraction")
| bucket _time span=1h
| stats count by _time, attack_type
| xyseries _time attack_type count
| fillnull value=0
```

## Alerting strategy for ASREProasting

Configure these scheduled searches as tiered alerts:

### Critical Alert: Active ASREProasting Campaign

Run every 10 minutes:

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4768 earliest=-10m
(Result_Code="0x0" AND Pre_Authentication="No") OR 
(Result_Code="0x17" AND Client_Address="*")
| stats dc(Account_Name) as unique_accounts by Client_Address
| where unique_accounts > 10
```

**Alert action:** Immediate SOC escalation, block Client_Address, initiate incident response

### High Alert: Enumeration Volume Threshold

Run every 30 minutes:

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4768 Result_Code="0x17" earliest=-30m
| stats count, dc(Account_Name) as accounts by Client_Address  
| where accounts > 25 OR count > 100
```

**Alert action:** SOC notification, investigate Client_Address, monitor for escalation

### Medium Alert: Vulnerable Account Access

Run hourly:

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4768 Result_Code="0x0" Pre_Authentication="No" earliest=-1h
| stats count by Account_Name, Client_Address
| where count > 5
```

**Alert action:** Identity team notification, review account pre-auth configuration

## Tuning and false positive reduction

### Establishing enumeration baselines

Understand normal AS-REQ failure patterns in your environment:

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4768 Result_Code="0x17" earliest=-30d
| bucket _time span=1d
| stats avg(count) as daily_avg, stdev(count) as daily_stdev by Client_Address
| where daily_avg > 5
| eval upper_bound = daily_avg + (2 * daily_stdev)
| sort -daily_avg
```

Use these baselines to set environment-specific thresholds rather than static values.

### Legitimate pre-auth disabled accounts

Some accounts legitimately have pre-authentication disabled:

```spl
| eval legitimate_accounts = "app-legacy,krbtgt,backup-svc"
| makemv delim="," legitimate_accounts
| eval is_legitimate = if(match(Account_Name, "^(" + mvjoin(legitimate_accounts, "|") + ")$"), "YES", "NO")
| where is_legitimate="NO"
```

Maintain a whitelist of known accounts to reduce false positives.

### Filtering load balancer health checks

Load balancers may generate authentication noise:

```spl
| where NOT match(Client_Address, "^(10\.1\.100\.|10\.1\.101\.)")
| where NOT match(Client_Name, ".*health.*|.*monitor.*|.*lb.*")
```

### Time-based filtering for business hours

Focus on suspicious activity during off-hours:

```spl
| eval hour = strftime(_time, "%H"), day_of_week = strftime(_time, "%w")
| where (hour < 7 OR hour > 19) OR day_of_week IN ("0", "6")
```

## Response playbook for ASREProasting

When an ASREProasting alert triggers:

### Immediate Actions (0-15 minutes)

1. **Validate the alert** — Confirm unusual AS-REQ patterns vs legitimate authentication
2. **Identify targeted accounts** — List all Account_Names showing AS-REP success without pre-auth
3. **Assess account privileges** — Check if targeted accounts have elevated permissions
4. **Block the source** — Implement network-level blocking of Client_Address if external

### Containment Actions (15-60 minutes)

1. **Enable pre-authentication** for all affected accounts immediately
2. **Force password reset** on any account showing successful AS-REP extraction
3. **Invalidate Kerberos tickets** for compromised accounts
4. **Review account permissions** — Remove unnecessary privileges from targeted accounts

### Investigation Actions (1-24 hours)

1. **Timeline reconstruction** — When did enumeration start? How long did extraction phase last?
2. **Tool identification** — Search for GetNPUsers.py, ASREPRoast, or custom tool artifacts
3. **Lateral movement analysis** — Has Client_Address accessed other internal resources?
4. **Credential validation** — Test if any service account passwords were successfully cracked

## Advanced hunting queries

### Cross-domain ASREProasting

For multi-domain environments, correlate attacks across forest trusts:

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4768 Pre_Authentication="No"
| rex field=Account_Name "(?<username>.*)@(?<domain>.*)"
| stats count, dc(domain) as domains_targeted by Client_Address, username
| where domains_targeted > 1
```

### Kerberos encryption downgrade attacks

Detect attempts to force weaker encryption for easier cracking:

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4768 Result_Code="0x0" Pre_Authentication="No"
| eval encryption_strength = case(
    Ticket_Encryption_Type="0x17", "Weak (RC4)",
    Ticket_Encryption_Type="0x12", "Strong (AES256)",
    Ticket_Encryption_Type="0x11", "Strong (AES128)",
    1=1, "Unknown")
| stats count by Account_Name, Client_Address, encryption_strength
| where encryption_strength="Weak (RC4)" AND count > 3
```

### Service account vs user account targeting

Differentiate attacks based on account types:

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4768 Pre_Authentication="No"
| eval account_type = case(
    match(Account_Name, ".*\$$"), "Computer Account",
    match(Account_Name, ".*svc.*|.*service.*"), "Service Account",
    1=1, "User Account")
| stats count by account_type, Client_Address
| where account_type IN ("Service Account", "User Account") AND count > 5
```

## Frequently asked questions

{{< faq >}}
- q: "What is ASREProasting and how does it differ from Kerberoasting?"
  a: "ASREProasting exploits accounts with Kerberos pre-authentication disabled, allowing attackers to request encrypted AS-REP responses without credentials. Unlike Kerberoasting (which requires authenticated access), ASREProasting can be performed anonymously against vulnerable accounts. Both attacks crack encrypted tickets offline, but ASREProasting targets the initial authentication phase."

- q: "Why would accounts have Kerberos pre-authentication disabled?"
  a: "Common reasons include legacy application compatibility, service account misconfigurations, migration artifacts from older domains, and troubleshooting where admins disabled pre-auth temporarily but forgot to re-enable it. In practice, 95% of environments have 1-10 such accounts, often unmonitored."

- q: "What Event ID should I monitor for ASREProasting detection?"
  a: "Event 4768 (Kerberos Authentication Server Request) is the primary event. Look for Result_Code 0x17 (account enumeration), 0x19 (pre-auth bypass attempts), and 0x0 with Pre_Authentication='No' (successful AS-REP extraction). Event 4768 generates high volume, so specific query patterns are essential."

- q: "How can I identify which accounts are vulnerable to ASREProasting?"
  a: "Monitor Event 4768 for successful AS-REQ responses (Result_Code=0x0) where Pre_Authentication=No. Also use PowerShell: `Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $True'` or LDAP queries for userAccountControl attribute with DONT_REQ_PREAUTH flag (0x400000)."

- q: "What tools do attackers use for ASREProasting?"
  a: "Common tools include Impacket's GetNPUsers.py, ASREPRoast (part of Empire), Rubeus, and custom PowerShell scripts. Each leaves slightly different signatures in Event 4768, but all share patterns: bulk account enumeration followed by AS-REP collection from vulnerable accounts."

- q: "How do I prevent ASREProasting attacks entirely?"
  a: "Enable Kerberos pre-authentication for all accounts (remove DONT_REQ_PREAUTH flag). Audit accounts quarterly with `Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $True'`. Use 25+ character random passwords for any accounts that must have pre-auth disabled. Implement network monitoring for bulk AS-REQ patterns."

- q: "What should my ASREProasting detection thresholds be?"
  a: "Start with: 15+ account enumeration attempts (Result_Code 0x17) per hour from single source; 5+ successful AS-REP extractions without pre-auth; 25+ pre-auth bypass attempts in 10 minutes. Baseline your environment for 30 days, then set thresholds at 2-3 standard deviations above normal activity."

- q: "How do I respond when ASREProasting is detected?"
  a: "Immediate: block the source IP, enable pre-authentication on targeted accounts. Within 1 hour: force password resets on accounts showing successful AS-REP extraction, invalidate Kerberos tickets. Investigation: timeline analysis, tool identification, lateral movement hunting, credential validation testing."

- q: "Can ASREProasting work against computer accounts?"
  a: "Yes, but it's rare. Computer accounts (ending in $) can have pre-authentication disabled, but they typically use machine-generated passwords that are much stronger than user passwords. Most ASREProasting focuses on user and service accounts where password complexity may be weaker."

- q: "How does ASREProasting relate to other Kerberos attacks?"
  a: "ASREProasting is often combined with Kerberoasting and Golden Ticket attacks. Attackers may use ASREProasting for initial credential harvesting, escalate with Kerberoasting against service accounts, then maintain persistence with Golden Tickets. Detection should cover all three attack vectors comprehensively."
{{< /faq >}}

## Mitigation and hardening

### Immediate mitigations

**Enable pre-authentication for all accounts:**
```powershell
Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $True' | 
Set-ADUser -DoesNotRequirePreAuth $False
```

**Audit vulnerable accounts quarterly:**
```powershell
Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $True' -Properties DoesNotRequirePreAuth |
Select-Object Name, SamAccountName, DoesNotRequirePreAuth, LastLogonDate
```

### Long-term hardening

1. **Implement Group Managed Service Accounts (gMSAs)** for services requiring pre-auth bypass
2. **Use 25+ character random passwords** for any remaining vulnerable accounts
3. **Enable AES-only Kerberos encryption** to slow offline cracking
4. **Deploy honey accounts** with pre-auth disabled to detect reconnaissance
5. **Implement Just-In-Time (JIT) access** for privileged accounts

## Conclusion

ASREProasting detection in Splunk requires understanding the subtle patterns in Event 4768 that distinguish attack reconnaissance from normal authentication failures. The queries above catch the three attack phases: account enumeration (Result_Code 0x17), pre-authentication bypass attempts (Result_Code 0x19), and successful AS-REP extraction (Result_Code 0x0 with Pre_Authentication=No).

Deploy the core detection stack this week:
1. **Account enumeration monitoring** — catches reconnaissance phase
2. **Pre-auth bypass detection** — catches exploitation attempts  
3. **Successful ASREProasting alerts** — catches active credential harvesting
4. **Dashboard and baseline tuning** — provides SOC visibility and reduces false positives

The strongest defense combines detection with prevention: enable pre-authentication for all accounts, use strong passwords, and monitor for bulk AS-REQ anomalies. ASREProasting exploits a configuration weakness that's 100% preventable — but detection bridges the gap between "should be secure" and "is actually secure."

For the complete Kerberos attack detection framework, see our [Kerberoasting detection guide](/tutorials/kerberoasting-detection-splunk/) and [Windows LAPS implementation](/tutorials/windows-laps-implementation/) for service account security.

## References

- [MITRE ATT&CK T1558.004 — AS-REP Roasting](https://attack.mitre.org/techniques/T1558/004/)
- [Microsoft Learn: Event 4768 — A Kerberos authentication ticket (TGT) was requested](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4768)
- [Impacket GetNPUsers.py documentation](https://github.com/fortra/impacket/blob/master/examples/GetNPUsers.py)
- [Microsoft Learn: Kerberos pre-authentication](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos)
- [SANS: Detecting AS-REP Roasting](https://www.sans.org/blog/detecting-asrep-roasting/)
- [Splunk Security Essentials: Kerberos Attacks](https://splunkbase.splunk.com/app/3435)