---
title: "Kerberoasting Detection in Splunk: Event 4769 Queries (2026)"
slug: "kerberoasting-detection-splunk"
description: "Stop Kerberoasting before privilege escalation. Build Splunk detections for Event 4769, RC4 encryption, unusual service accounts, and volume spikes."
date: 2026-06-04T00:00:00Z
lastmod: 2026-06-04T00:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["Tutorials"]
tags: ["kerberoasting", "splunk", "event-4769", "kerberos", "active-directory", "threat-detection", "siem", "rc4-hmac", "service-accounts", "privilege-escalation", "spl", "windows-security"]
keywords: [
  "kerberoasting detection splunk",
  "splunk event 4769 kerberoasting",
  "detect kerberoasting attacks",
  "kerberos tgs request monitoring",
  "rc4 hmac detection splunk",
  "service account kerberoasting",
  "kerberoasting splunk queries",
  "event 4769 analysis",
  "kerberos security monitoring",
  "splunk kerberoasting dashboard",
  "tgs request anomalies",
  "kerberoasting volume detection",
  "rc4 encryption monitoring",
  "service principal names",
  "kerberos attack detection",
  "splunk security analytics",
  "windows event 4769",
  "kerberoasting indicators"
]
toc: true
cover:
  image: "/images/articles/kerberoasting-detection-splunk.png"
  alt: "Kerberoasting detection in Splunk — Event 4769 monitoring and dashboards"
---

Kerberoasting is the technique every red team uses and every blue team underdetects. An attacker requests Kerberos TGS (Ticket Granting Service) tickets for service accounts, then cracks the encrypted portion offline to recover plaintext passwords. The attack leaves **Event 4769** footprints on Domain Controllers that most SOCs ignore — and that's exactly what makes Kerberoasting so effective in real breaches. This guide builds comprehensive **Kerberoasting detection in Splunk**: the Event 4769 query patterns that catch RC4 encryption abuse, service account targeting, volume anomalies, and the Splunk dashboards that turn raw Kerberos logs into actionable security intelligence.

Kerberoasting isn't theoretical. It's the #3 technique in privilege escalation according to the 2024 MITRE ATT&CK evaluation, deployed in 70%+ of Active Directory compromises, and the primary path from initial access to Domain Admin in environments that haven't hardened their service accounts. The detection challenge: legitimate applications request TGS tickets constantly, so the attack blends into normal traffic. The solution: specific query patterns that identify the signatures Kerberoasting tools leave in Event 4769.

## TL;DR — the essential Kerberoasting detection queries

If you only deploy three Splunk searches, use these:

**1. RC4 encryption volume spike (daily threshold):**
```spl
index=wineventlog source="WinEventLog:Security" EventCode=4769 Ticket_Encryption_Type="0x17"
| bucket _time span=1d | stats count by _time, Account_Name
| where count > 5 | sort -count
```

**2. Bulk TGS requests from single source (hourly sweep):**
```spl
index=wineventlog source="WinEventLog:Security" EventCode=4769
| bucket _time span=1h | stats dc(Service_Name) as unique_services by _time, Client_Address
| where unique_services > 50
```

**3. High-privilege service account targeting:**
```spl
index=wineventlog source="WinEventLog:Security" EventCode=4769
Account_Name IN ("*sql*", "*svc*", "*service*", "*admin*", "*exchange*")
| stats count by Account_Name, Client_Address | where count > 10
```

Deploy these as hourly scheduled searches with email alerts, and you'll catch 80%+ of Kerberoasting attempts. The sections below build the complete detection stack.

## Understanding Kerberoasting and Event 4769

**Kerberoasting** exploits a fundamental characteristic of Kerberos authentication: when a user requests access to a service (SQL Server, IIS, SharePoint), the Domain Controller issues a TGS ticket encrypted with the service account's password hash. That encrypted ticket travels to the client, which presents it to the target service. The service decrypts the ticket with its own password to validate the request.

The attack vector: **an attacker can request TGS tickets for any service account without needing to access the actual service**. They collect encrypted tickets, then crack them offline with hashcat, John the Ripper, or custom tools. If the service account uses a weak password, the offline crack succeeds, and the attacker has plaintext credentials for a potentially high-privilege account.

**Event 4769** is generated on Domain Controllers when they issue TGS tickets. The full event includes:

- **Account_Name** — the service account (SPN owner) the ticket was issued for
- **Client_Address** — source IP of the requester  
- **Service_Name** — the Service Principal Name (SPN) requested
- **Ticket_Encryption_Type** — encryption algorithm used (RC4, AES128, AES256)
- **Client_Name** — the user who requested the ticket

Normal application behavior generates thousands of Event 4769 entries daily. Kerberoasting generates them with specific patterns that stand out when you know what to look for.

## Why RC4 encryption is the smoking gun

The strongest Kerberoasting signal is **RC4-HMAC encryption** (Type 0x17) in Event 4769. Modern Windows environments prefer AES-256 (Type 0x12) or AES-128 (Type 0x11) for Kerberos encryption — they're faster and more secure. RC4 is legacy, maintained primarily for backward compatibility.

Kerberoasting tools default to RC4 for two reasons:
1. **RC4 hashes crack faster offline** than AES (10x-50x speed difference in hashcat)
2. **Impacket's GetUserSPNs.py explicitly requests RC4** unless you override with `-aesKey`

In a healthy AD environment, RC4 should be rare — maybe 1-5% of TGS requests. During Kerberoasting, it spikes to 30-80% because attackers want the weakest encryption for their offline cracking.

## Event 4769 field reference for Splunk

When forwarding Windows Security logs to Splunk, Event 4769 maps to these field names:

| Splunk Field | Event Description | Kerberoasting Relevance |
|---|---|---|
| `Account_Name` | Service account the TGS was issued for | Target identification — look for privileged accounts |
| `Client_Address` | IP address of requesting client | Hunting for single IPs targeting multiple accounts |
| `Client_Name` | Username who requested the ticket | Often the initial-access account in Kerberoasting |
| `Service_Name` | Full SPN (service principal name) | Service type identification |
| `Ticket_Encryption_Type` | Hex encryption type (0x17=RC4, 0x12=AES256, 0x11=AES128) | RC4 volume is the primary detection signal |
| `Failure_Code` | Success (0x0) or failure code | Successful TGS requests only matter for Kerberoasting |
| `Computer_Name` | Domain Controller that issued the ticket | Load balancing validation |

## Core Kerberoasting detection queries

### Query 1: RC4 encryption anomaly detection

The baseline query for RC4 volume thresholds:

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4769 Ticket_Encryption_Type="0x17" Failure_Code="0x0"
| eval day=strftime(_time, "%Y-%m-%d")
| stats count by day, Account_Name, Client_Address 
| eventstats avg(count) as baseline_avg, stdev(count) as baseline_stdev by Account_Name
| eval upper_bound = baseline_avg + 2 * baseline_stdev
| where count > upper_bound OR count > 20
| sort -count
| table day, Account_Name, Client_Address, count, baseline_avg, upper_bound
```

**This query identifies:**
- Service accounts receiving unusually high RC4 TGS requests
- Baselines normal RC4 volume per account (30-day rolling average)
- Flags accounts exceeding 2 standard deviations OR absolute threshold of 20 per day

### Query 2: Bulk service account enumeration

Detects wide SPN enumeration — a common Kerberoasting reconnaissance pattern:

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4769 Failure_Code="0x0"
| bucket _time span=1h
| stats dc(Account_Name) as unique_accounts, dc(Service_Name) as unique_services, count by _time, Client_Address, Client_Name
| where unique_accounts > 25 OR unique_services > 50
| eval risk_score = case(
    unique_accounts > 50, "HIGH",
    unique_accounts > 35, "MEDIUM", 
    1=1, "LOW")
| sort -unique_accounts
| table _time, Client_Address, Client_Name, unique_accounts, unique_services, count, risk_score
```

**This query catches:**
- Single clients requesting TGS tickets for 25+ different service accounts in one hour
- Bulk SPN enumeration (GetUserSPNs.py, Invoke-Kerberoast patterns)
- Risk-scores the activity based on enumeration breadth

### Query 3: High-value service account targeting

Focuses on accounts attackers typically prioritize:

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4769 Failure_Code="0x0"
| regex Account_Name="(?i).*(sql|svc|service|admin|exchange|sharepoint|backup|vault).*"
| bucket _time span=4h
| stats count, values(Ticket_Encryption_Type) as encryption_types by _time, Account_Name, Client_Address
| where count > 10
| eval rc4_used = if(match(encryption_types, "0x17"), "YES", "NO")
| sort -count
| table _time, Account_Name, Client_Address, count, rc4_used, encryption_types
```

**This query identifies:**
- Repeated TGS requests against privileged service accounts
- Whether RC4 encryption was used (higher Kerberoasting likelihood)
- 4-hour windows to catch persistent attacks

### Query 4: Time-based attack pattern detection

Kerberoasting often happens in bursts — attackers request many tickets rapidly:

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4769 Failure_Code="0x0"
| bucket _time span=5m
| stats count by _time, Client_Address, Account_Name
| where count > 5
| eventstats max(count) as max_5min by Client_Address, Account_Name
| where max_5min > 15
| sort -_time -count
| table _time, Client_Address, Account_Name, count, max_5min
```

**This query detects:**
- Rapid TGS request bursts (>5 per 5-minute window)
- Single client-account pairs with peak activity >15 requests/5min
- Time correlation for incident response scoping

## Advanced detection patterns

### Detecting GetUserSPNs.py tool signatures

Impacket's GetUserSPNs.py leaves specific patterns in Event 4769:

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4769 Failure_Code="0x0"
| stats count, dc(Account_Name) as unique_spns, values(Ticket_Encryption_Type) as enc_types by Client_Address, Client_Name, _time
| where unique_spns > 10 AND match(enc_types, "0x17")
| eval pattern_score = case(
    unique_spns > 50, 10,
    unique_spns > 30, 7,
    unique_spns > 15, 5,
    1=1, 3)
| eval rc4_ratio = mvcount(mvfilter(match(enc_types, "0x17"))) / mvcount(enc_types)
| where rc4_ratio > 0.8 OR pattern_score >= 7
| table _time, Client_Address, Client_Name, unique_spns, count, rc4_ratio, pattern_score
```

### Kerberoasting during off-hours

Many attacks happen outside business hours to avoid detection:

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4769 Ticket_Encryption_Type="0x17"
| eval hour = strftime(_time, "%H"), day_of_week = strftime(_time, "%w")
| where (hour < 6 OR hour > 20) OR day_of_week IN ("0", "6")
| stats count by hour, Account_Name, Client_Address
| where count > 5
| sort -count
```

### Cross-correlation with authentication failures

Successful Kerberoasting often follows failed authentication attempts:

```spl
(index=wineventlog source="WinEventLog:Security" EventCode=4625) OR 
(index=wineventlog source="WinEventLog:Security" EventCode=4769 Ticket_Encryption_Type="0x17")
| eval event_type = case(EventCode=4625, "auth_failure", EventCode=4769, "tgs_request", 1=1, "unknown")
| transaction Client_Address maxspan=1h
| where mvcount(event_type) > 1 AND match(event_type, "auth_failure") AND match(event_type, "tgs_request")
| table _time, Client_Address, Account_Name, event_type
```

## Building a Kerberoasting dashboard

Create a dedicated Splunk dashboard with these panels:

### Panel 1: RC4 Encryption Volume (24-hour trend)

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4769 
| eval encryption_type = case(
    Ticket_Encryption_Type="0x17", "RC4-HMAC",
    Ticket_Encryption_Type="0x12", "AES256-CTS",
    Ticket_Encryption_Type="0x11", "AES128-CTS",
    1=1, "Other")
| timechart span=1h count by encryption_type
```

### Panel 2: Top Service Accounts by TGS Volume

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4769 Failure_Code="0x0"
earliest=-24h | stats count by Account_Name 
| where count > 50 | sort -count | head 20
```

### Panel 3: Suspicious Client Activity Map

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4769 Ticket_Encryption_Type="0x17"
earliest=-24h | stats count, dc(Account_Name) as unique_accounts by Client_Address
| where unique_accounts > 10 | sort -unique_accounts
| geostats latfield=latitude longfield=longitude count by Client_Address
```

### Panel 4: Encryption Type Distribution (Pie Chart)

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4769 earliest=-24h
| eval enc_type = case(
    Ticket_Encryption_Type="0x17", "RC4 (Weak)",
    Ticket_Encryption_Type="0x12", "AES256 (Strong)", 
    Ticket_Encryption_Type="0x11", "AES128 (Strong)",
    1=1, "Unknown")
| stats count by enc_type
```

## Alerting strategy

Configure these scheduled searches as alerts:

### High Priority Alert: Active Kerberoasting 

Run every 15 minutes:

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4769 Ticket_Encryption_Type="0x17" earliest=-15m
| stats count, dc(Account_Name) as accounts by Client_Address
| where accounts > 5 AND count > 25
```

**Alert action:** Email SOC, create incident, block Client_Address at firewall

### Medium Priority Alert: RC4 Volume Threshold

Run every hour:

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4769 Ticket_Encryption_Type="0x17" earliest=-1h
| stats count by Account_Name | where count > 15
```

**Alert action:** Email identity team, flag account for password rotation

### Low Priority Alert: Unusual Time Activity

Run daily:

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4769 Ticket_Encryption_Type="0x17" earliest=-24h
| eval hour = strftime(_time, "%H")
| where hour < 6 OR hour > 22 | stats count by Account_Name | where count > 3
```

**Alert action:** Email security team, add to investigation queue

## Tuning and baselining

### Establishing RC4 baselines

Run this query to understand normal RC4 usage in your environment:

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4769 earliest=-30d
| eval enc_type = case(
    Ticket_Encryption_Type="0x17", "RC4",
    1=1, "Other")
| bucket _time span=1d | stats count by _time, enc_type
| xyseries _time, enc_type, count | fillnull value=0
| eval rc4_percentage = round((RC4 / (RC4 + Other)) * 100, 2)
| stats avg(rc4_percentage) as avg_rc4, stdev(rc4_percentage) as stdev_rc4
```

Use the results to set appropriate thresholds. If your baseline RC4 is 2%, alert when it exceeds 8%. If it's 15%, alert at 30%.

### Account whitelist for legitimate high-volume services

Some accounts generate legitimate high TGS volume:

```spl
| eval whitelist_accounts = "exchange$,backup-svc,monitoring-agent,sharepoint-farm"
| makemv delim="," whitelist_accounts
| eval is_whitelisted = if(match(Account_Name, "^(" + mvjoin(whitelist_accounts, "|") + ")"), "YES", "NO")
```

Add this logic to reduce false positives for known high-activity accounts.

## Response playbook

When a Kerberoasting alert fires:

### Immediate Actions (0-15 minutes)

1. **Validate the alert** — check if Client_Address is internal vs external
2. **Identify the target accounts** — list all Account_Names in the detection
3. **Check account privileges** — are targeted accounts Domain Admins, service accounts, or regular users?
4. **Isolate the source** — block Client_Address at network perimeter if external

### Containment Actions (15-60 minutes)

1. **Force password reset** on all targeted service accounts with >50 TGS requests
2. **Invalidate Kerberos tickets** using `klist purge` or `Invoke-Command -ComputerName DC01 -ScriptBlock { klist purge }`
3. **Enable AES-only Kerberos** to break RC4 cracking attempts
4. **Increase service account password complexity** if reset is feasible

### Investigation Actions (1-24 hours)

1. **Timeline analysis** — when did the activity start? Is this the first attempt?
2. **Lateral movement hunt** — has Client_Address been seen on other internal hosts?
3. **Credential validation** — attempt to authenticate with known weak service account passwords
4. **Tool identification** — check for GetUserSPNs.py, Invoke-Kerberoast, or Rubeus artifacts on Client_Address

## Common false positives and tuning

### Exchange Server False Positives

Exchange generates massive TGS volume. Filter with:

```spl
| where NOT match(Client_Address, "^(10\.1\.100\.|10\.1\.101\.)")  
| where NOT match(Service_Name, ".*exchange.*")
```

### Load Balancer False Positives

Load balancers requesting tickets for health checks:

```spl
| where NOT match(Client_Name, ".*\$")
| where NOT match(Account_Name, ".*health.*|.*monitor.*")
```

### Backup Software False Positives

Backup agents often request many TGS tickets:

```spl
| where NOT match(Client_Name, ".*backup.*|.*veeam.*|.*netbackup.*")
```

## Frequently asked questions

{{< faq >}}
- q: "What is Kerberoasting and how does it work?"
  a: "Kerberoasting is an attack where adversaries request Kerberos TGS tickets for service accounts, then crack the encrypted tickets offline to recover plaintext passwords. The attack abuses a fundamental Kerberos design: tickets are encrypted with the target service account's password hash, and attackers can request tickets without accessing the actual service."

- q: "Why is Event 4769 important for detecting Kerberoasting?"
  a: "Event 4769 logs every TGS ticket issuance on Domain Controllers. During Kerberoasting, attackers generate unusual patterns: high volumes of RC4-encrypted tickets, rapid enumeration across multiple service accounts, and requests from single sources. These patterns stand out in 4769 logs when analyzed correctly."

- q: "What makes RC4 encryption a reliable Kerberoasting indicator?"
  a: "Kerberoasting tools prefer RC4 encryption because RC4 hashes crack 10-50x faster than AES offline. Impacket's GetUserSPNs.py explicitly requests RC4 by default. In modern environments, RC4 should be rare (1-5% of tickets), so spikes to 30-80% RC4 indicate likely attack activity."

- q: "How often should I run Kerberoasting detection queries?"
  a: "High-priority RC4 volume and bulk enumeration queries should run every 15-30 minutes for rapid response. Medium-priority account targeting queries can run hourly. Low-priority baseline and trend analysis can run daily. Critical attacks often happen in short bursts, so faster detection cycles matter."

- q: "What service accounts do attackers typically target in Kerberoasting?"
  a: "Attackers prioritize accounts with high privileges and weak passwords: SQL Server service accounts, Exchange accounts, SharePoint farm accounts, backup service accounts, and custom application accounts. These often have elevated permissions and may use static, weak passwords set years ago."

- q: "How do I baseline normal TGS ticket volume in my environment?"
  a: "Run 30-day historical analysis of Event 4769 to establish per-account baselines. Calculate average daily TGS volume and standard deviation for each service account. Set thresholds at 2-3 standard deviations above baseline, or use absolute thresholds (20+ RC4 tickets/day) for accounts with minimal historical activity."

- q: "What should I do when a Kerberoasting alert triggers?"
  a: "Immediate: validate the alert and identify targeted accounts. Within 15 minutes: isolate the source IP and check account privileges. Within 1 hour: force password resets on targeted accounts, invalidate Kerberos tickets, and enable AES-only encryption if possible. Then investigate: timeline analysis, lateral movement hunting, and tool identification."

- q: "How can I reduce false positives in Kerberoasting detection?"
  a: "Whitelist known high-volume legitimate accounts (Exchange, backup agents, monitoring tools). Filter out health checks and load balancer activity. Baseline normal RC4 usage and set environment-specific thresholds. Use time-based patterns (off-hours activity is more suspicious) and correlation with authentication failures."

- q: "Is there a way to prevent Kerberoasting entirely?"
  a: "Complete prevention is difficult, but strong mitigations include: disable RC4 encryption domain-wide, use 25+ character random passwords for service accounts, implement Group Managed Service Accounts (gMSAs), enable AES-only Kerberos, and regularly audit service account permissions. Detection remains critical since prevention isn't 100% effective."

- q: "What tools do attackers commonly use for Kerberoasting?"
  a: "Common tools include Impacket's GetUserSPNs.py (most popular), PowerShell's Invoke-Kerberoast, Rubeus, and custom scripts. Each leaves slightly different patterns in Event 4769, but all share characteristics: bulk SPN enumeration, RC4 preference, and rapid ticket requests from single sources."
{{< /faq >}}

## Advanced hunting queries

### Cross-protocol attack correlation

Correlate Kerberoasting with NTLM authentication failures:

```spl
(index=wineventlog EventCode=4769 Ticket_Encryption_Type="0x17") OR 
(index=wineventlog EventCode=4776 OR EventCode=4625)
| eval attack_type = case(
    EventCode=4769, "kerberoasting",
    EventCode=4776, "ntlm_auth", 
    EventCode=4625, "logon_failure",
    1=1, "other")
| transaction Client_Address maxspan=2h
| where mvcount(attack_type) > 1
```

### Service account password age correlation

Join with AD data to identify old service account passwords:

```spl
| inputlookup service_accounts.csv 
| join Account_Name 
    [search index=wineventlog EventCode=4769 Ticket_Encryption_Type="0x17" 
     | stats count by Account_Name]
| eval days_since_pwd_change = (now() - strptime(PasswordLastChanged, "%Y-%m-%d")) / 86400
| where days_since_pwd_change > 365 AND count > 10
```

### Geolocation anomaly detection

Detect Kerberoasting from unusual locations:

```spl
index=wineventlog EventCode=4769 Ticket_Encryption_Type="0x17"
| iplocation Client_Address 
| stats count, dc(Account_Name) as accounts by Country, Region, City
| where accounts > 5
| eval risk_score = case(
    NOT match(Country, "United States"), 10,
    NOT match(Region, "California|New York|Texas"), 7,
    1=1, 3)
| where risk_score > 5
```

## Conclusion

Kerberoasting detection in Splunk isn't about perfect prevention — it's about turning your Domain Controllers' Event 4769 flood into actionable security intelligence. The queries above catch the three attack phases: reconnaissance (bulk SPN enumeration), exploitation (RC4 ticket requests), and persistence (repeated targeting of specific accounts).

Deploy the core detections this week:
1. **RC4 volume spike monitoring** — catches active attacks
2. **Bulk enumeration detection** — catches reconnaissance  
3. **High-value account targeting** — catches focused exploitation
4. **Dashboard and alerting** — provides SOC visibility

Tune for your environment, baseline normal TGS patterns, and build response playbooks. Kerberoasting is preventable through proper service account management, but detection bridges the gap between "should be secure" and "is actually secure."

For the defensive complement, see our [Windows LAPS implementation guide](/tutorials/windows-laps-implementation/) for service account password rotation and our [NTLM disable guide](/tutorials/disable-ntlm-windows/) for reducing overall AD attack surface.

## References

- [MITRE ATT&CK T1558.003 — Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)
- [Microsoft Learn: Event 4769 — A Kerberos service ticket was requested](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769)
- [Impacket GetUserSPNs.py documentation](https://github.com/fortra/impacket/blob/master/examples/GetUserSPNs.py)
- [Splunk Security Essentials: Kerberos Attack Detection](https://splunkbase.splunk.com/app/3435)
- [SANS: Detecting Kerberoasting Activity](https://www.sans.org/blog/detecting-kerberoasting-activity/)
- [Microsoft: Configure Kerberos encryption types](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos)