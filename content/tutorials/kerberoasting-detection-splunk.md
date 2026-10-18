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

Kerberoasting abuses normal Kerberos service-ticket requests: an authenticated domain user can request a ticket for a service principal name (SPN), then test the ticket offline against candidate passwords. Event 4769 records service-ticket requests on domain controllers and provides useful hunting evidence. No single field—including RC4—proves that a request was malicious.

This guide uses Splunk searches to identify unusual request volume and encryption behavior, then validate the activity against account and service context. Treat all counts as starting points for local tuning, not universal thresholds.

## Event 4769 fields and Splunk mapping

The account requesting the ticket and the service being requested are different fields. In particular, the event’s target account name is the **requesting user**, while `ServiceName` identifies the requested service/SPN. Confusing these fields reverses who the search is analyzing.

| Event XML field | Common display or add-on alias | Meaning |
|---|---|---|
| `TargetUserName` | `Account_Name` | User or computer account requesting the ticket |
| `ServiceName` | `Service_Name` | Account or SPN for which the ticket was requested |
| `IpAddress` | `Client_Address` | Client address seen by the domain controller |
| `Status` | `Failure_Code`, `Result_Code` | Request status; `0x0` indicates success |
| `TicketEncryptionType` | `Ticket_Encryption_Type` | Encryption type used for the service ticket |
| `SessionKeyEncryptionType` | Often similarly named alias | Encryption type for the session key; not the service-ticket encryption type |

Event 4769 was updated for Windows Server 2016 and later after the January 2025 security update. Older event versions and Splunk add-ons can expose a different field set or names. Confirm the raw event and normalize those names before running saved searches.

## Normalize fields in Splunk

The examples below assume an index named `wineventlog`. Adjust the index and sourcetype to match your deployment. The aliases cover common add-on naming, but field extractions are not identical across Splunk inputs.

```spl
index=wineventlog EventCode=4769
| eval status_norm=lower(replace(tostring(coalesce(Status, Failure_Code, Result_Code)), "^0x", ""))
| eval requestor=coalesce(TargetUserName, Account_Name)
| eval service=coalesce(ServiceName, Service_Name)
| eval client_ip=coalesce(IpAddress, Client_Address)
| eval ticket_etype=lower(coalesce(TicketEncryptionType, Ticket_Encryption_Type))
```

If the required fields are absent, create or correct the extractions from the `Data Name="…"` fields in the event XML. Do not infer that the requested service is `Account_Name`; use `ServiceName`/`Service_Name` for the SPN or service account.

## Detection searches

### Inventory successful RC4 service tickets

`0x17` is RC4-HMAC for the **service ticket** in Event 4769. This search is an inventory signal for compatibility review and triage, not a standalone Kerberoasting alert. RC4 may be present for legacy service accounts or systems that cannot use AES; conversely, an attacker may request or obtain AES-encrypted tickets.

```spl
index=wineventlog EventCode=4769
| eval status_norm=lower(replace(tostring(coalesce(Status, Failure_Code, Result_Code)), "^0x", ""))
| eval requestor=coalesce(TargetUserName, Account_Name)
| eval service=coalesce(ServiceName, Service_Name)
| eval client_ip=coalesce(IpAddress, Client_Address)
| eval ticket_etype=lower(coalesce(TicketEncryptionType, Ticket_Encryption_Type))
| where status_norm="0" AND ticket_etype="0x17"
| stats count dc(service) as distinct_services values(service) as services by client_ip, requestor
| sort - count
```

Use the output to identify which clients and requestors generate RC4 tickets, then check whether the service key configuration and legacy dependencies explain them. Microsoft’s current Kerberos guidance should be reviewed before changing encryption policy; disabling RC4 without an inventory can break legacy services.

### Find broad service-ticket requests

A client requesting tickets for many distinct services in a short interval can be worth investigating. Legitimate middleware, management platforms, and service hosts can also request tickets at high volume.

```spl
index=wineventlog EventCode=4769
| eval status_norm=lower(replace(tostring(coalesce(Status, Failure_Code, Result_Code)), "^0x", ""))
| eval requestor=coalesce(TargetUserName, Account_Name)
| eval service=coalesce(ServiceName, Service_Name)
| eval client_ip=coalesce(IpAddress, Client_Address)
| where status_norm="0"
| bin _time span=10m
| stats count dc(service) as distinct_services values(service) as services by _time, client_ip, requestor
| where distinct_services > 10
| sort - distinct_services
```

`10` is an example threshold for an initial hunt. Baseline by requestor, host role, and time of day before creating an alert.

### Prioritize sensitive service accounts

Maintain an approved lookup containing sensitive service identifiers rather than guessing from substrings such as `sql`, `svc`, or `admin`. Those names are inconsistent and can match unrelated principals.

```spl
index=wineventlog EventCode=4769
| eval status_norm=lower(replace(tostring(coalesce(Status, Failure_Code, Result_Code)), "^0x", ""))
| eval requestor=coalesce(TargetUserName, Account_Name)
| eval service=coalesce(ServiceName, Service_Name)
| eval client_ip=coalesce(IpAddress, Client_Address)
| eval ticket_etype=lower(coalesce(TicketEncryptionType, Ticket_Encryption_Type))
| where status_norm="0"
| lookup sensitive_kerberos_services service OUTPUT is_sensitive
| where is_sensitive="true"
| stats count values(ticket_etype) as ticket_types by service, requestor, client_ip
| sort - count
```

Populate and maintain `sensitive_kerberos_services` from your SPN/service-account inventory. A successful 4769 event shows that the KDC issued a ticket; it does not show that the requester exported it or cracked it offline.

## How to interpret RC4

RC4-HMAC (`0x17`) is a weaker legacy Kerberos encryption type and can make offline password guessing more practical. However, its presence is not a reliable attack verdict. Legacy compatibility, account key availability, domain-controller policy, and recent Windows updates affect what encryption types are issued. Modern tools can also request AES tickets. Use RC4 as one contextual feature alongside request volume, unusual client-to-service relationships, sensitive account targeting, and endpoint or network evidence.

Do not claim that RC4 is universally rare or that an RC4 percentage establishes an attack. Establish a baseline by service account and client role, and review Microsoft’s current [RC4 detection and remediation guidance](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos) before making policy changes.

## Validation before alerting

1. Confirm Event 4769 auditing and collection on every domain controller in scope.
2. Inspect raw events from both pre- and post-January 2025-updated domain controllers. Verify `TargetUserName`, `ServiceName`, `IpAddress`, `Status`, and `TicketEncryptionType` mappings.
3. Compare Splunk output with the event XML and the organization’s SPN/service-account inventory. A dashboard label should identify the requesting account separately from the requested service.
4. Run broad-request and RC4 searches in report-only mode. Tune around known service hosts, backup systems, monitoring tools, and scheduled workloads before enabling alerts.
5. Validate detections in a controlled test domain. Do not change production encryption policy or request tickets for accounts outside your authorized test scope.

Event 4769 does not identify the client tool, and it cannot distinguish a malicious roast from every legitimate request on its own. Use it as KDC-side telemetry and correlate with endpoint process, identity, and service-account evidence.

## Frequently asked questions

{{< faq >}}
- q: "Does RC4 in Event 4769 prove Kerberoasting?"
  a: "No. RC4-HMAC (0x17) is a useful legacy-encryption signal, but it can be legitimate and attackers can use AES. Correlate it with the requester, service/SPN, volume, host role, and other telemetry."
- q: "Which account requested the ticket?"
  a: "TargetUserName identifies the requesting user or computer. ServiceName identifies the requested service or SPN. Keep those roles separate in field mappings and searches."
- q: "What does Status 0x0 mean?"
  a: "It indicates the KDC successfully issued the service ticket. It does not prove that a client collected or cracked the ticket."
- q: "Do Event 4769 field names differ between Splunk inputs?"
  a: "Yes. Use the Windows event XML names as the reference and verify aliases in your Splunk data. The example coalesce expressions cover common alternatives but may need adjustment."
- q: "What threshold should trigger an alert?"
  a: "There is no universal threshold. Establish a baseline by requestor and host role, then tune on the number of distinct requested services and the sensitivity of the targeted service accounts."
{{< /faq >}}

## Conclusion

Use Event 4769 to investigate unusual service-ticket request patterns, not to label every RC4 event as an attack. Accurate field mapping is essential: distinguish the requesting principal from the requested SPN, and distinguish service-ticket encryption from session-key encryption. Validate every search against raw events before enabling alerts.

For account-password lifecycle controls, see the [Windows LAPS implementation guide](/tutorials/windows-laps-implementation/). The [NTLM disable guide](/tutorials/disable-ntlm-windows/) covers a separate authentication protocol and should not be treated as a substitute for Kerberos monitoring.

## References

- [MITRE ATT&CK T1558.003 — Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)
- [Microsoft Learn: Event 4769 — A Kerberos service ticket was requested](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769)
- [Microsoft Learn: Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [Impacket GetUserSPNs.py](https://github.com/fortra/impacket/blob/master/examples/GetUserSPNs.py)
- [Splunk Security Essentials: Kerberos Attack Detection](https://splunkbase.splunk.com/app/3435)
- [SANS: Detecting Kerberoasting Activity](https://www.sans.org/blog/detecting-kerberoasting-activity/)
- [Microsoft Learn: Configure encryption types allowed for Kerberos](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos)
