---
title: "Disable NTLM in Windows Safely: 2026 Step-by-Step Hardening Guide"
slug: "disable-ntlm-windows"
description: "Step-by-step guide to safely disabling NTLM authentication in Windows 11, Server 2025, and Active Directory: audit usage, stage rollouts, and roll back without breaking production apps."
date: 2026-05-19T12:00:00Z
lastmod: 2026-05-19T12:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["Tutorials"]
tags: ["windows-security", "ntlm", "active-directory", "kerberos", "windows-hardening", "group-policy", "powershell", "ntlm-relay", "lmcompatibilitylevel", "windows-11", "windows-server-2025"]
series: ["Windows Hardening"]
keywords: [
  "how to disable NTLM in Windows",
  "disable NTLM authentication Windows 11",
  "disable NTLM Windows Server 2025",
  "disable NTLMv1",
  "disable NTLMv2",
  "NTLM disable Group Policy",
  "LmCompatibilityLevel registry",
  "audit NTLM usage Windows",
  "Restrict NTLM in this domain",
  "Kerberos only authentication Windows",
  "NTLM relay attack mitigation",
  "Windows NTLM deprecation",
  "disable NTLM without breaking applications",
  "NTLM hardening Active Directory",
  "how to enforce Kerberos only"
]
toc: true
cover:
  image: "/images/articles/disable-ntlm-windows.png"
  alt: "How to disable NTLM safely in Windows — a 2026 hardening guide"
---

NTLM has been on borrowed time for two decades, and Microsoft made it official: as of late 2023 Microsoft formally announced that **NTLM is deprecated**, with Kerberos and the new Negotiate-based authentication taking over. Windows 11 24H2 and Windows Server 2025 ship with NTLMv1 fully removed, and Microsoft strongly recommends auditing and disabling NTLMv2 wherever Kerberos can take over. This guide walks through how to **disable NTLM in Windows safely** — auditing first, staging the rollout, and rolling back cleanly if something breaks.

This is not a "flip the switch" guide. Disabling NTLM domain-wide on day one will break things — schedulers running `\\IP\share` paths, legacy NAS appliances, applications that hard-code IP addresses, and any workgroup machine that doesn't speak Kerberos. The right approach is to **audit, identify, migrate, and only then enforce**. We'll do all four.

## TL;DR — the safe NTLM disable workflow

If you only have ten seconds, this is the order of operations:

1. **Audit** NTLM usage on Domain Controllers and member servers for at least 2 weeks (Event ID 8004 / 8001 / 8003)
2. **Inventory** every client and app showing up in those logs
3. **Migrate** the easy fixes: hostnames instead of IPs, SPN registration, SMB signing
4. **Enforce NTLMv2-only** by setting `LmCompatibilityLevel = 5` everywhere
5. **Block NTLM per-server** on critical assets (file servers, DCs)
6. **Block NTLM domain-wide** with explicit exceptions
7. **Verify** Kerberos is doing the work (`klist`, Event 4624)
8. **Plan rollback** before you start — and document the GPO link order so you can reverse it in one minute

Below, each step is unpacked with the real Group Policy paths, registry keys, PowerShell commands, and the failure modes you'll hit.

## Why disable NTLM in 2026?

Three forces are pushing NTLM into the grave:

**1. NTLM is fundamentally vulnerable to relay attacks.** Tools like `ntlmrelayx.py` (Impacket), `Responder`, and `Inveigh` exploit the fact that NTLM authentication can be passed verbatim from one endpoint to another. Attackers chain a credential coercion (PetitPotam, PrinterBug, DFSCoerce, ShadowCoerce, MS-EFSR, MS-EVEN) with relay to LDAP, SMB, or AD CS, escalating from "I can ping the network" to "I control the domain" in minutes. None of these attacks work against Kerberos.

**2. Microsoft formally deprecated NTLM in 2023.** The announcement on the Windows IT Pro blog declared NTLM "deprecated" and committed to defaults of Kerberos and the new Negotiate flow. Deprecation isn't removal yet, but it signals that future Windows releases will progressively restrict NTLM, default-deny it, and eventually drop support entirely. Windows 11 24H2 already removed NTLMv1 entirely.

**3. Recent CVEs keep underlining the urgency.**

| CVE | Year | Class | Affected |
|---|---|---|---|
| CVE-2022-26925 (PetitPotam) | 2022 | Coerced NTLM auth → AD CS relay | All DCs |
| CVE-2024-21412 (SmartScreen / NTLM) | 2024 | NTLMv2 hash disclosure via internet shortcut | All Windows |
| CVE-2024-43451 | 2024 | NTLMv2 hash disclosure on file preview | All Windows |
| CVE-2025-21204 | 2025 | NTLM hash exposure during Windows Update | Server 2019+ |

Every one of these is a "user opens a file, attacker gets their NTLMv2 hash" pattern. Kerberos environments are immune.

**The compounding risk:** every NTLMv2 hash that leaves your network can be cracked offline (modern GPUs hit 70+ billion NTLM hashes/sec for weak passwords) **or** relayed in real-time to access services you didn't realise were exposed. The only durable mitigation is to stop emitting NTLM in the first place.

## NTLM, NTLMv2, and Kerberos: a quick clarification

Three closely-related terms that mean different things — and matter for what you actually disable:

| Protocol | Year | Status in 2026 | Disable how |
|---|---|---|---|
| **LM** (LAN Manager hash) | 1987 | Removed from defaults since Vista | `LmCompatibilityLevel ≥ 3` |
| **NTLMv1** | 1993 | Removed from Windows 11 24H2 | `LmCompatibilityLevel ≥ 4` |
| **NTLMv2** | 1998 | **Deprecated, still active by default** | `LmCompatibilityLevel = 5` + `Restrict NTLM` GPOs |
| **Kerberos v5** | 1999 (Win2000) | Default in AD; recommended | (already default — verify it's working) |
| **Negotiate / NEGOEX** | wraps Kerberos+NTLM | Default selector — picks Kerberos when possible | (no action needed) |

Crucially, "disabling NTLM" almost always means **disabling NTLMv2**. NTLMv1 should already be off; if it isn't, that's your highest-priority fix.

## Pre-flight checklist

Before you change a single setting:

1. **Make sure you have console access** to at least one Domain Controller. If you remote in over RDP and the change locks you out, you need physical/iLO/iDRAC/console access to recover.
2. **Snapshot or back up** the Default Domain Policy and the Default Domain Controllers Policy. Use `Backup-GPO -All -Path C:\GPOBackups` in PowerShell.
3. **Confirm Kerberos is healthy.** Run `klist tickets` on a workstation, verify you have TGS tickets for the services you use. If Kerberos is already broken, fix that first — disabling NTLM will just expose the breakage.
4. **Identify your "critical exception" apps in advance.** Legacy line-of-business apps, NAS appliances, and old printers are the usual suspects.
5. **Schedule a maintenance window** for the eventual cut-over, even though most of these changes are reversible in seconds.

{{< callout type="warning" title="Don't skip the audit phase" >}}
Every "NTLM rollout disaster" I've personally seen started the same way: someone read a hardening guide, flipped `Restrict NTLM in this domain` to `Deny all`, and watched a quarter of the helpdesk tickets land on their desk by 09:30. The audit phase isn't optional — it's the difference between a 3-week project and a 3-month outage post-mortem.
{{< /callout >}}

## Step-by-step: how to disable NTLM in Windows

The full safe-rollout sequence:

{{< howto title="How to disable NTLM in Windows safely" duration="PT6H" >}}
- name: "Enable NTLM auditing on Domain Controllers"
  text: "Open `gpedit.msc` (or use the Default Domain Controllers Policy via `gpmc.msc`). Navigate to `Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options`. Set **Network security: Restrict NTLM: Audit NTLM authentication in this domain** to `Enable for all accounts`. Then set **Network security: Restrict NTLM: Audit Incoming NTLM Traffic** to `Enable auditing for all accounts`. Run `gpupdate /force`."
- name: "Collect events for at least 14 days"
  text: "NTLM auth events land in `Applications and Services Logs → Microsoft → Windows → NTLM → Operational`. Pull `Event ID 8004` (DC observed NTLM auth) and `Event ID 8001/8003` (member server observed NTLM auth). Two weeks is the minimum — month-end batch jobs and quarterly tasks need to be in scope."
- name: "Build the inventory"
  text: "Parse the event logs into a table of `(client, server, account, service)`. Anything connecting via IP address instead of hostname, anything using local accounts on remote servers, and anything from non-domain-joined hosts is a future breakage candidate."
- name: "Migrate the easy fixes"
  text: "Convert hardcoded IPs to hostnames (Kerberos requires an SPN matching the hostname). Register missing SPNs with `setspn -S HTTP/server01.corp.local CORP\\svc-account`. Move workgroup hosts into AD where feasible. Replace legacy NAS appliances or upgrade their firmware to support Kerberos."
- name: "Enforce NTLMv2-only with LmCompatibilityLevel = 5"
  text: "GPO: `Network security: LAN Manager authentication level` → `Send NTLMv2 response only. Refuse LM & NTLM`. Or registry: `HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa` → `LmCompatibilityLevel = 5` (DWORD). Apply at the DC level first, then to member servers, then to clients."
- name: "Block NTLM on critical servers (per-server hardening)"
  text: "On file servers, database servers, and admin jump hosts: set **Network security: Restrict NTLM: Incoming NTLM traffic** to `Deny all accounts`. Test access from a domain client — Kerberos should transparently take over. Monitor for `Event ID 8002` (blocked auth) and resolve the failures one app at a time."
- name: "Block NTLM domain-wide with explicit exceptions"
  text: "Once per-server blocking is stable, set **Network security: Restrict NTLM: NTLM authentication in this domain** to `Deny all`. Use **Restrict NTLM: Add server exceptions in this domain** to list the remaining legacy targets (FQDN format: `legacynas.corp.local`). Watch event logs closely for the first 48 hours."
- name: "Verify Kerberos and document rollback"
  text: "On clients, run `klist purge` then `klist tickets` after a login — confirm `Authentication Package: Kerberos` in `Event 4624`. Document the exact GPO settings changed, in order, in a runbook. To roll back: reverse the GPO values to `Not Defined`, run `gpupdate /force`, and reboot affected hosts."
{{< /howto >}}

## Step 1: Enable NTLM auditing

The single most important setting in the entire rollout. Without audit data, you're guessing at which apps depend on NTLM.

**Group Policy path (Default Domain Controllers Policy):**

```text
Computer Configuration
  └ Policies
    └ Windows Settings
      └ Security Settings
        └ Local Policies
          └ Security Options
            ├ Network security: Restrict NTLM: Audit Incoming NTLM Traffic
            │    = Enable auditing for all accounts
            └ Network security: Restrict NTLM: Audit NTLM authentication in this domain
                 = Enable for all accounts
```

**Registry equivalents** (apply via `New-ItemProperty` if you're scripting):

{{< terminal title="Administrator: PowerShell — DC" >}}
$lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
New-ItemProperty -Path $lsa -Name 'AuditReceivingNTLMTraffic' -PropertyType DWord -Value 2 -Force
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' `
  -Name 'AuditNTLMInDomain' -PropertyType DWord -Value 7 -Force

gpupdate /force
{{< /terminal >}}

Once the policy applies, NTLM auth events appear in **Event Viewer → Applications and Services Logs → Microsoft → Windows → NTLM → Operational**.

**The events you care about:**

| Event ID | Source | Meaning |
|---|---|---|
| **8001** | NTLM client | Outbound NTLM auth was attempted |
| **8002** | NTLM client | Outbound NTLM was blocked (after enforcement) |
| **8003** | NTLM server | Incoming NTLM auth was received |
| **8004** | DC | NTLM passthrough auth observed (most useful for inventory) |

Pipe Event 8004 to CSV for analysis:

{{< terminal title="Administrator: PowerShell — DC" >}}
Get-WinEvent -LogName 'Microsoft-Windows-NTLM/Operational' -FilterXPath "*[System[EventID=8004]]" |
  Select-Object TimeCreated,
    @{N='User';      E={$_.Properties[1].Value}},
    @{N='ClientPC';  E={$_.Properties[2].Value}},
    @{N='ServerName';E={$_.Properties[3].Value}} |
  Export-Csv -Path C:\NTLMAudit.csv -NoTypeInformation
{{< /terminal >}}

Run this on every DC for 14 days minimum. Aggregate the CSVs.

## Step 2: Build the migration inventory

Open the aggregated CSV in Excel/PowerBI/your tool of choice and group by `(ClientPC, ServerName, User)`. Classify each row:

- **"Easy fix"** — client uses IP address; replace with hostname. Or service account missing SPN; register the SPN.
- **"Workgroup host"** — non-domain machine; join the domain or carve out an exception.
- **"Legacy appliance"** — NAS, printer, IPMI controller; check firmware for Kerberos support or plan replacement.
- **"Local account auth"** — someone is authenticating with a local account on a remote server (often admins). Migrate to a domain account.
- **"Genuine NTLM-only app"** — old line-of-business application that genuinely can't speak Kerberos. Note it for the exception list.

The first three categories are your prep work. The fourth is a process fix. The fifth is the permanent allowlist.

## Step 3: Migrate the easy fixes

**Replace IP-based connections with hostnames.** Kerberos service tickets are issued for SPNs that match a specific hostname. If a scheduled task connects to `\\10.1.1.5\backup`, the client can't request a Kerberos ticket — the SPN lookup happens on hostname, not IP. Update the path to `\\fileserver01.corp.local\backup`.

**Register missing SPNs.** When a service runs under a custom account (e.g., a SQL Server instance using a domain service account), the SPN must exist for Kerberos to work. Check with `setspn -L corp\svc-sqlsvc`. Add missing ones:

{{< terminal title="Administrator: PowerShell" >}}
setspn -S MSSQLSvc/sql01.corp.local:1433 corp\svc-sqlsvc
setspn -S MSSQLSvc/sql01.corp.local       corp\svc-sqlsvc
{{< /terminal >}}

**Re-join workgroup hosts where possible.** Anything outside the domain falls back to NTLM. Domain-join eliminates that.

**SMB hardening pairs naturally with NTLM removal.** Set SMB signing required on both servers and clients via GPO: `Microsoft network server: Digitally sign communications (always)` and `Microsoft network client: Digitally sign communications (always)`. SMB signing makes the most common NTLM relay attack (SMB → SMB) infeasible even where NTLM still flows.

## Step 4: Enforce NTLMv2-only with LmCompatibilityLevel = 5

The single most important hardening change before you block NTLM. **`LmCompatibilityLevel = 5`** means "send and accept NTLMv2 only; refuse LM and NTLMv1." Setting this on every host kills NTLMv1 forever.

**Group Policy path:**

```text
Computer Configuration
  └ Policies
    └ Windows Settings
      └ Security Settings
        └ Local Policies
          └ Security Options
            └ Network security: LAN Manager authentication level
                 = Send NTLMv2 response only. Refuse LM & NTLM.
```

**Registry equivalent:**

{{< terminal title="Administrator: PowerShell" >}}
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
  -Name 'LmCompatibilityLevel' -Value 5 -Type DWord

# Verify
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel
{{< /terminal >}}

**The full value table for reference:**

| Value | Sends | Accepts |
|---|---|---|
| 0 | LM and NTLM | LM, NTLM, NTLMv2 |
| 1 | LM and NTLM; uses NTLMv2 if negotiated | LM, NTLM, NTLMv2 |
| 2 | NTLM only | LM, NTLM, NTLMv2 |
| 3 | NTLMv2 only | LM, NTLM, NTLMv2 |
| 4 | NTLMv2 only | NTLM and NTLMv2 (rejects LM) |
| **5** | **NTLMv2 only** | **NTLMv2 only (rejects LM and NTLM)** |

Apply on DCs first, then member servers, then workstations. Most environments are already at 3 or 4; the jump to 5 rarely breaks anything that audit didn't already flag.

## Step 5: Block NTLM on critical servers (per-server hardening)

Per-server blocking is the low-risk first restriction. You're saying "this specific file server does not accept NTLM" without touching the rest of the domain. If something breaks, the blast radius is one host.

**Group Policy path (applied to the server itself or via a per-server OU):**

```text
Network security: Restrict NTLM: Incoming NTLM traffic
   = Deny all accounts
```

The three available values:

- **Allow all** — default, no restriction
- **Deny all domain accounts** — domain accounts can't NTLM-auth to this server; local accounts still can (useful as a stepping stone)
- **Deny all accounts** — full block

Start with `Deny all domain accounts` for a week. Watch Event 8002 (blocked NTLM). Resolve the failures. Then move to `Deny all accounts`.

**Test from a domain client:**

{{< terminal title="Domain workstation" >}}
# Before: should succeed via Kerberos (check with klist after)
Test-NetConnection fileserver01.corp.local -Port 445
net use Z: \\fileserver01.corp.local\share /persistent:no
klist | findstr cifs

# After enforcement: same commands should still work — Kerberos takes over.
# If they fail, something is forcing NTLM (IP address? local account?).
{{< /terminal >}}

## Step 6: Block NTLM domain-wide

Once 80%+ of your servers are running per-server blocks cleanly, escalate to domain-wide enforcement.

**Group Policy path (Default Domain Controllers Policy):**

```text
Network security: Restrict NTLM: NTLM authentication in this domain
   = Deny all
```

The five available values:

- **Disable** — no restriction (default)
- **Deny for domain accounts to domain servers** — domain users can't NTLM-auth to domain-joined servers
- **Deny for domain accounts** — domain users can't NTLM-auth anywhere
- **Deny for domain servers** — no NTLM auth to any domain-joined server
- **Deny all** — full block, all accounts, all servers

Start at `Deny for domain accounts to domain servers`. Monitor for 1 week. Move to `Deny all` if clean.

**Exception list for the genuinely stuck apps:**

```text
Network security: Restrict NTLM: Add server exceptions in this domain
   = legacynas.corp.local
     oldsoftware.corp.local
     vendor-appliance.corp.local
```

Use **FQDN** format, one per line. Exceptions should be a documented, time-bounded list — not a permanent dumping ground. Every exception is a footnote in your next pentest report.

{{< callout type="tip" title="Test the rollback procedure before you need it" >}}
The cleanest rollback is to reverse the GPO settings to **Not Defined** (not "Allow all" — there's a difference in policy precedence) and run `gpupdate /force` on the DCs. Then force replication with `repadmin /syncall /AdeP`. Reboot affected hosts if Kerberos tickets are cached oddly. Practice this on a test DC *before* you flip the production switch.
{{< /callout >}}

## Step 7: Verify Kerberos is doing the work

After enforcement, you need positive confirmation that Kerberos is filling the gap.

**Check ticket cache on a workstation:**

{{< terminal title="domain workstation — User PowerShell" >}}
klist purge
# Log off and back on, then:
klist tickets

# You should see TGS tickets like:
#   Server: cifs/fileserver01.corp.local @ CORP.LOCAL
#   KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
#   ...
{{< /terminal >}}

**Audit logon events on a target server:**

In Event Viewer → Security log → filter Event ID 4624 (successful logon). For each entry, check the **Authentication Package** field:

- `Kerberos` ✓ — what you want
- `NTLM` — still happening; you have an unfound NTLM dependency
- `Negotiate` — typically wraps Kerberos; verify by checking the LogonProcessName

A useful PowerShell one-liner to count auth methods over the last 24 hours:

{{< terminal title="Server: PowerShell" >}}
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624 and TimeCreated[timediff(@SystemTime) <= 86400000]]]" |
  ForEach-Object { ($_.Message -split "`n" | Where-Object { $_ -match 'Authentication Package' }) -replace '.*:\s*','' } |
  Group-Object | Sort-Object Count -Descending
{{< /terminal >}}

You're looking for Kerberos > 95% and NTLM converging to zero (excluding documented exceptions).

## What typically breaks (and how to fix it)

Twelve years of helpdesk pattern recognition, condensed:

| Symptom | Root cause | Fix |
|---|---|---|
| `\\IP\share` access fails | Kerberos can't resolve SPN from IP | Use FQDN; or add to exception list |
| Scheduled task fails with `Access Denied` | Task uses IP or local credentials | Switch to managed service account (gMSA) with Kerberos SPN |
| Legacy app sees `0xC0000122` (`STATUS_TIME_DIFFERENCE_AT_DC`) | Clock skew > 5 min — Kerberos needs sync | Fix NTP; verify with `w32tm /resync` |
| `klist` shows no TGT after logon | Kerberos failed at logon, fell back to cached creds | Check DNS resolution of DC; check trust health |
| SQL Linked Server fails | SPN not registered for SQL service account | `setspn -S MSSQLSvc/host:port DOMAIN\svcacct` |
| RDP fails with NLA error | Local account on a non-domain target | Use a domain account, or add the target to the exception list |
| Citrix StoreFront issues | NTLM-based passthrough configured | Reconfigure to use Kerberos constrained delegation |
| Old NAS rejects all connections | Firmware predates Kerberos | Add to exceptions; flag for replacement |
| Print server jobs disappear | Printer object using IP instead of hostname | Re-publish printer with FQDN |
| Cross-forest authentication breaks | Forest trust missing or NTLM-only | Audit trust; enable Kerberos forest trust |
| Workgroup Win11 host can't reach domain share | No domain credentials → falls to NTLM → blocked | Domain-join, or exception |
| `Event 5805` on DC (`NETLOGON`: NTLM authentication failed) | Genuinely-disabled-account or NTLM-only authenticator | Investigate the source; if legitimate, exception |

## Rollback procedure

If something goes wrong and you need to back out:

1. On any DC: `gpmc.msc` → edit the Default Domain Controllers Policy → reverse the changed settings to **Not Defined**.
2. PowerShell: `gpupdate /force` on the DC.
3. Force replication: `repadmin /syncall /AdeP /e`.
4. On affected client/server: `gpupdate /force` then `klist purge` and re-logon.
5. If the issue was the LmCompatibilityLevel, restore the registry value: `Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Value 3` (or whatever your baseline was).

Total time to revert: usually < 5 minutes once you know the exact GPO names. Which is why **documenting the rollout in a runbook is non-optional**.

## Frequently asked questions

{{< faq >}}
- q: "Can I just disable NTLM domain-wide immediately?"
  a: "No — you will break Kerberos-incompatible apps without warning. The audit phase exists to surface those apps so you can either migrate them or add them to the exception list before enforcement. Skipping audit is the single most common cause of failed NTLM rollouts."

- q: "What is the difference between NTLMv1 and NTLMv2?"
  a: "NTLMv1 uses DES-based challenge/response and is trivially crackable; NTLMv2 uses HMAC-MD5 with a client and server challenge, making offline cracking harder but still feasible for weak passwords. **NTLMv1 should already be disabled in any modern environment** (`LmCompatibilityLevel >= 4`). NTLMv2 is what most environments still use and what this guide focuses on disabling."

- q: "Will disabling NTLM break my workgroup or non-domain machines?"
  a: "Yes, if those machines authenticate to domain resources. Workgroup hosts can't get Kerberos tickets because they aren't domain-joined — they fall back to NTLM. Either join them to the domain, add them to the server exception list, or accept that they lose access to domain shares."

- q: "Does disabling NTLM affect local logons?"
  a: "Local logons to a workstation (signing in with `.\\localadmin`) don't use NTLM — they go through MSV1_0 directly. Disabling NTLM affects network authentication only. You can still sign in locally even if NTLM is fully blocked domain-wide."

- q: "What about NTLM auth from Linux/macOS clients?"
  a: "Modern Linux (`sssd` + `realm join`) and macOS (`dsconfigad`) speak Kerberos to AD just fine. Older configurations using `smbclient` with `--user=DOMAIN\\user` typically negotiate NTLMv2 — update to use `--krb5-ccache` and a valid TGT. Samba 4.18+ supports Kerberos-only mode."

- q: "How long does an NTLM rollout typically take?"
  a: "For a 500-seat environment with a typical app portfolio: 2 weeks audit, 4 weeks migration, 2 weeks per-server enforcement, 1 week domain-wide. So roughly 9 weeks end-to-end. Larger environments (5,000+ seats) routinely take 6 months because the exception inventory is larger and migrations require app-vendor coordination."

- q: "Is Kerberos vulnerable to similar relay attacks?"
  a: "Kerberos is not vulnerable to the kind of NTLM relay attacks PetitPotam exploits, because Kerberos tickets are bound to a specific target SPN — you can't replay a ticket issued for `cifs/server-a` against `ldap/server-b`. Kerberos has different attack classes (Kerberoasting, Golden Tickets, unconstrained delegation abuse), which require separate hardening but aren't network-relay attacks."

- q: "Will Microsoft fully remove NTLM in Windows 12?"
  a: "Microsoft has only committed to deprecation, not removal. Their public roadmap signals continued NTLM presence for backwards compatibility, but with progressively tighter defaults. The pragmatic stance: assume Microsoft will keep NTLM around for legacy interop, but that defaults will tighten every release. Don't wait — disable it on your own schedule."

- q: "Does disabling NTLM mitigate Kerberoasting too?"
  a: "No. Kerberoasting requires Kerberos to be enabled (which it is by default in AD). The mitigations are different: use long random passwords for service accounts, prefer Group Managed Service Accounts (gMSAs), and avoid RC4-HMAC encryption types in favour of AES."
{{< /faq >}}

## What to do next

If you've made it this far, the immediate next actions:

1. **Enable NTLM auditing today** on your Domain Controllers (Step 1) — zero risk, immediate visibility
2. **Schedule a 2-week audit window** before any enforcement
3. **Build the inventory** in week 3
4. **Start per-server blocking** in week 5 on a single low-traffic file server as a pilot
5. **Domain-wide enforcement** only after the per-server pattern is proven across a representative sample

For related Windows hardening guides on this site, see our [Windows Hardening series](/series/windows-hardening/). If you ran into a specific NTLM rollout issue not covered above, [get in touch](/contact/) — we maintain a running list of "weird NTLM dependencies" from reader reports.

## References

- [Microsoft: The evolution of Windows authentication](https://techcommunity.microsoft.com/blog/windows-itpro-blog/the-evolution-of-windows-authentication/3926097) — the official NTLM deprecation announcement
- [Microsoft Learn: Network security: Restrict NTLM (GPO reference)](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-ntlm-authentication-in-this-domain)
- [Microsoft Learn: Network security: LAN Manager authentication level](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level)
- [MITRE ATT&CK T1187 — Forced Authentication](https://attack.mitre.org/techniques/T1187/)
- [MITRE ATT&CK T1557.001 — LLMNR/NBT-NS Poisoning and SMB Relay](https://attack.mitre.org/techniques/T1557/001/)
- [PetitPotam (CVE-2022-26925) advisory](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-26925)
- [Impacket `ntlmrelayx.py` documentation](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py) — the reference relay tool
