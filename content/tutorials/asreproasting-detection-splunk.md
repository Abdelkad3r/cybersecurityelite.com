---
title: "ASREProasting Detection in Splunk: Event 4768 Queries (2026)"
slug: "asreproasting-detection-splunk"
description: "Build and validate Splunk searches for AS-REP Roasting indicators in Windows Event 4768 data, including accounts without Kerberos pre-authentication."
date: 2026-06-04T11:39:46Z
lastmod: 2026-06-04T11:39:46Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["Tutorials"]
aliases:
  - /network-security/asreproasting-detection-splunk/
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
  alt: "Dark grid cover card for ASREProasting Detection in Splunk, with large high-contrast title lettering."
---

AS-REP Roasting targets Active Directory accounts configured to **not require Kerberos pre-authentication**. A requester can obtain an AS-REP for such an account without first proving knowledge of its password; the response can then be tested offline. This guide shows how to identify the relevant Event 4768 records in Splunk and how to validate detections against the fields your Windows event collection actually provides.

An Event 4768 with pre-authentication type `0` is a useful signal, but it does not by itself prove that a response was collected or cracked. Treat it as evidence to investigate alongside the account, source address, event status, and your inventory of accounts that intentionally do not require pre-authentication.

## Event 4768: the fields that matter

Event 4768 is generated on a domain controller for a Kerberos TGT request. Windows event versions and Splunk add-ons may expose the XML data under different Splunk field names. The event XML names are the reference point; check a raw event before relying on any saved search.

| Event XML field | Common display or add-on alias | Use |
|---|---|---|
| `TargetUserName` | `Account_Name` | Account for which the TGT was requested |
| `IpAddress` | `Client_Address` | Requesting client address |
| `Status` | `Result_Code` | Result of the TGT request; `0x0` means success |
| `PreAuthType` | Sometimes normalized as `Pre_Authentication` | `0` means no pre-authentication; `2` is the normal encrypted-timestamp type |
| `TicketEncryptionType` | `Ticket_Encryption_Type` | Encryption type of the issued TGT; contextual evidence, not a stand-alone roast verdict |

The 2025-updated Event 4768 schema contains additional encryption and pre-authentication fields. Older domain controllers or older event versions may not have all of them. The examples below normalize common names, but you must adapt the index, sourcetype, and aliases to your Splunk deployment.

Kerberos status values are easy to misread. `0x6` means the client principal is unknown and can contribute to account-enumeration evidence. `0x17` is not “principal unknown” (Microsoft documents it as key expired, and notes it does not occur in Event 4768). `0x19` means pre-authentication is required; it can be a normal KDC response to a client that has not yet sent pre-authentication data. Do not label either `0x17` or `0x19` as a successful roast or bypass.

## Normalize your Splunk fields

The following mapping block supports the event XML names and common aliases used by some Windows inputs. Run it on a small sample first and confirm the resulting values against Event Viewer or the raw XML.

```spl
index=wineventlog EventCode=4768
| eval status_norm=lower(replace(tostring(coalesce(Status, Result_Code)), "^0x", ""))
| eval preauth_raw=coalesce(tostring(PreAuthType), tostring(Pre_Authentication))
| eval preauth_norm=case(
    lower(preauth_raw)="no", "0",
    lower(preauth_raw)="yes", "2",
    true(), preauth_raw
  )
| eval target_user=coalesce(TargetUserName, Account_Name)
| eval client_ip=coalesce(IpAddress, Client_Address)
```

If your events arrive as raw XML without extracted fields, configure field extractions for the `Data Name="…"` elements before using these searches. Do not assume underscore aliases exist just because an example search uses them.

## Core detection searches

### Successful TGT request without pre-authentication

This is the central event pattern to investigate. It indicates a successful request with no pre-authentication recorded; it does not tell you that the response was cracked.

```spl
index=wineventlog EventCode=4768
| eval status_norm=lower(replace(tostring(coalesce(Status, Result_Code)), "^0x", ""))
| eval preauth_raw=coalesce(tostring(PreAuthType), tostring(Pre_Authentication))
| eval preauth_norm=case(lower(preauth_raw)="no", "0", lower(preauth_raw)="yes", "2", true(), preauth_raw)
| eval target_user=coalesce(TargetUserName, Account_Name)
| eval client_ip=coalesce(IpAddress, Client_Address)
| where status_norm="0" AND preauth_norm="0"
| stats count earliest(_time) as first_seen latest(_time) as last_seen by target_user, client_ip
| convert ctime(first_seen) ctime(last_seen)
| sort - count
```

Triage hits against approved exceptions and account-owner context. Repeated requests from an unexpected host, or requests for accounts that should require pre-authentication, merit investigation.

### Potential username enumeration

Status `0x6` is “client principal unknown.” A high count of distinct attempted names from one source may indicate enumeration, but may also reflect a misconfigured client or application. Tune the threshold to local baseline data rather than copying a universal number.

```spl
index=wineventlog EventCode=4768
| eval status_norm=lower(replace(tostring(coalesce(Status, Result_Code)), "^0x", ""))
| eval target_user=coalesce(TargetUserName, Account_Name)
| eval client_ip=coalesce(IpAddress, Client_Address)
| where status_norm="6"
| bin _time span=10m
| stats count dc(target_user) as distinct_names values(target_user) as examples by _time, client_ip
| where distinct_names > 10
| sort - distinct_names
```

`distinct_names > 10` is an example starting point, not a recommended universal threshold. Baseline normal failures, account provisioning, application behavior, and log volume before alerting.

### Review the accounts configured without pre-authentication

This Active Directory query is read-only. It checks the `DONT_REQ_PREAUTH` bit (`0x400000`) in `userAccountControl` using the LDAP bitwise-AND matching rule.

```powershell
$ldapFilter = '(userAccountControl:1.2.840.113556.1.4.803:=4194304)'
Get-ADUser -LDAPFilter $ldapFilter -Properties userAccountControl, servicePrincipalName, enabled |
    Select-Object SamAccountName, Enabled, userAccountControl, servicePrincipalName
```

Compare this inventory with Event 4768 hits. A service account may be enabled intentionally for compatibility, but that exception should have an owner, justification, and strong unique password. Prefer enabling pre-authentication where the application permits it; use a managed service account where appropriate.

## Validation before alerting

1. Confirm that domain controllers audit Kerberos Authentication Service success and failure events and that Splunk receives Event 4768 from every relevant DC.
2. Inspect one success and one failure in the raw event. Confirm how `Status`, `PreAuthType`, `TargetUserName`, and `IpAddress` are extracted. Event 4768 versions vary by Windows update level.
3. Run the searches over a known time range and compare results with the event XML and the account inventory above.
4. Tune thresholds using a representative baseline and validate alerts with a controlled lab account. Do not test against production identities by disabling pre-authentication.

Event 4768 does not identify the tool that made a request, and normal clients can generate failed requests while negotiating pre-authentication. Correlate source, target account, event status, and endpoint/network telemetry instead of treating a single field as an attack verdict.

## Frequently asked questions

{{< faq >}}
- q: "Which Event 4768 pattern is relevant to AS-REP Roasting?"
  a: "A successful request with PreAuthType equal to 0 records a TGT request without pre-authentication. Investigate the account and source; the event alone does not prove the response was cracked."
- q: "Does Status 0x19 mean pre-authentication was bypassed?"
  a: "No. It means additional pre-authentication is required. A client may receive it during normal Kerberos negotiation."
- q: "Does Status 0x17 identify an unknown account?"
  a: "No. It is not the unknown-principal code. Microsoft documents 0x6 as client principal unknown and identifies 0x17 as key expired; do not use 0x17 as an account-enumeration indicator in Event 4768."
- q: "How can I find accounts that do not require Kerberos pre-authentication?"
  a: "Use a read-only LDAP query for the DONT_REQ_PREAUTH userAccountControl bit, then compare the returned accounts with successful Event 4768 records where PreAuthType is 0."
- q: "Do the field names in the Splunk searches work in every deployment?"
  a: "No. Windows event XML names are TargetUserName, IpAddress, Status, PreAuthType, and TicketEncryptionType, but Splunk add-ons and inputs can expose aliases. Verify the extracted fields and adapt the coalesce mapping to your data."
{{< /faq >}}

## References

- [MITRE ATT&CK T1558.004 — AS-REP Roasting](https://attack.mitre.org/techniques/T1558/004/)
- [Microsoft Learn: Event 4768 — A Kerberos authentication ticket (TGT) was requested](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4768)
- [Impacket GetNPUsers.py](https://github.com/fortra/impacket/blob/master/examples/GetNPUsers.py)
- [Microsoft Learn: Configure encryption types allowed for Kerberos](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos)
- [SANS: Detecting AS-REP Roasting](https://www.sans.org/blog/detecting-asrep-roasting/)
- [Splunk Security Essentials: Kerberos Attacks](https://splunkbase.splunk.com/app/3435)

For the complementary service-ticket attack, see the [Kerberoasting detection guide](/tutorials/kerberoasting-detection-splunk/). The [Windows LAPS implementation guide](/tutorials/windows-laps-implementation/) covers service-account password management.
