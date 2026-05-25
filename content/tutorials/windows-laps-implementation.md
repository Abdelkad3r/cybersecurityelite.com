---
title: "Windows LAPS Implementation: Step-by-Step Enterprise Guide (2026)"
slug: "windows-laps-implementation"
description: "End local-admin password reuse — the single fix that breaks pass-the-hash propagation. 8-step Windows LAPS rollout: schema, encryption, tiered RBAC, DSRM."
date: 2026-05-20T11:00:00Z
lastmod: 2026-05-20T11:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["Tutorials"]
tags: ["windows-laps", "active-directory", "windows-hardening", "powershell", "group-policy", "identity-and-access", "privileged-access", "windows-server-2025", "windows-11", "intune"]
series: ["Windows Hardening"]
keywords: [
  "Windows LAPS",
  "Windows LAPS tutorial",
  "Windows LAPS implementation",
  "Local Administrator Password Solution",
  "Microsoft LAPS",
  "how to configure Windows LAPS in Active Directory",
  "step-by-step Windows LAPS guide",
  "best practices for Windows LAPS",
  "how to secure local administrator accounts",
  "Microsoft LAPS implementation tutorial",
  "LAPS PowerShell",
  "Windows hardening",
  "privileged account security",
  "AD security best practices",
  "secure local admin passwords",
  "Windows LAPS encryption",
  "Update-LapsADSchema",
  "Add-KdsRootKey",
  "LAPS Group Policy",
  "DSRM password LAPS"
]
toc: true
cover:
  image: "/images/articles/windows-laps-implementation.png"
  alt: "Windows LAPS implementation — step-by-step enterprise deployment guide"
---

If an attacker compromises a single endpoint in your environment and finds a reused local Administrator password, they own every other workstation that shares it. That single misconfiguration is how a phishing click on one helpdesk laptop becomes a 4,000-endpoint ransomware incident — and it's exactly what **Windows LAPS** (Local Administrator Password Solution) was built to prevent. This is the complete step-by-step **Windows LAPS implementation guide** for enterprise environments in 2026: AD schema preparation, KDS root key generation, encrypted password storage, Group Policy reference, PowerShell administration, and the full DSRM password backup workflow for Domain Controllers.

Windows LAPS is no longer the legacy MSI you used to bolt onto member servers. It's a native Windows component shipped with every supported Windows 11 and Windows Server 2022+ release, supports both on-prem Active Directory and Microsoft Entra (Azure AD) backends, encrypts stored passwords at rest, and — critically — manages the Directory Services Restore Mode (DSRM) password on Domain Controllers, something the legacy product never could.

## TL;DR — Windows LAPS deployment in one screen

The 8 actions that get you to a working enterprise deployment:

1. **Schema** — `Update-LapsADSchema` on a Schema Admin account
2. **Encryption key** — `Add-KdsRootKey -EffectiveImmediately` on a DC
3. **Self-update permission** — `Set-LapsADComputerSelfPermission` per OU
4. **Read permission (RBAC tiered)** — `Set-LapsADReadPasswordPermission` to scoped groups only
5. **Group Policy** — Configure backup directory, password settings, post-auth actions, encryption
6. **DC DSRM** — Enable DSRM backup on Domain Controllers (unique to Windows LAPS)
7. **Deploy + verify** — `Invoke-LapsPolicyProcessing` then `Get-LapsDiagnostics`
8. **Retrieve passwords** — `Get-LapsADPassword -Identity HOST -AsPlainText`

Total time for a clean lab deployment: under one hour. Production rollouts with phased enforcement: 2–4 weeks.

## Why Windows LAPS matters in 2026

A few realities that make this a top-tier priority, not a "nice-to-have":

**Lateral movement is almost always credential-driven.** The 2024 Microsoft Digital Defense Report puts >80% of ransomware incidents on a credential-abuse path. Once attackers get a foothold, they harvest cached credentials and password hashes with Mimikatz, Lazagne, or built-in `procdump lsass.exe`. If your local `Administrator` accounts share a password, one compromised hash unlocks the entire fleet — what red teams call **pass-the-hash propagation**.

**Pass-the-hash mitigation is a CIS Controls v8 mandate.** CIS Control 5.4 (Unique Local Admin Passwords) and Control 6 (Access Control Management) both explicitly call out LAPS-style rotation as a baseline requirement. Auditors check for it. Cyber insurance providers ask about it.

**Windows LAPS is now free, native, and cloud-aware.** Microsoft's April 2023 update brought Windows LAPS into the OS itself, retired the legacy MSI installer, added password encryption (the legacy product stored passwords in plaintext within the AD attribute), and introduced Microsoft Entra (Azure AD) as a supported backend. If you're still running Microsoft LAPS legacy in 2026, you're carrying technical debt with active attack surface.

**Companion control to NTLM hardening.** Disabling local admin credential reuse closes the relay/pass-the-hash chain at the credential level; [disabling NTLM](/tutorials/disable-ntlm-windows/) closes it at the protocol level. Deploy both.

## Windows LAPS vs Legacy Microsoft LAPS: what actually changed

This is the comparison most administrators want when planning their migration. Print it.

| Feature | Legacy Microsoft LAPS (2015) | Windows LAPS (2023+) |
|---|---|---|
| **Installation** | Separate MSI per host (`LAPS.x64.msi`) | Built into Windows 10 22H2+, 11, Server 2019 (Apr 2023+), 2022, 2025 |
| **Password storage** | Plaintext in `ms-Mcs-AdmPwd` attribute | Encrypted via KDS root key in `msLAPS-EncryptedPassword` |
| **Backend** | Active Directory only | Active Directory **or** Microsoft Entra ID |
| **DSRM password** | Not supported | Supported on Domain Controllers |
| **Password history** | Not supported | Up to 12 previous passwords (encrypted) |
| **Post-auth actions** | Not supported | Reset after authentication, log off user, reboot |
| **PowerShell module** | Limited cmdlets | Full `LAPS` module: `Get-LapsADPassword`, `Reset-LapsPassword`, `Set-LapsADComputerSelfPermission`, etc. |
| **GPO templates** | Separate ADMX install | Native — `LAPS.admx` ships with Windows |
| **Intune support** | Third-party connectors | Native CSP — first-class |
| **Schema attributes** | `ms-Mcs-AdmPwd`, `ms-Mcs-AdmPwdExpirationTime` | `msLAPS-Password`, `msLAPS-PasswordExpirationTime`, `msLAPS-EncryptedPassword`, `msLAPS-EncryptedDSRMPassword`, `msLAPS-EncryptedPasswordHistory` |

If you're migrating, run both side by side during transition (Windows LAPS will ignore legacy attributes by default) and decommission the legacy MSI and its GPOs after a 30-day verification window.

## Windows LAPS architecture

Three components do the work:

1. **The client extension** is built into the OS. It runs as part of the Group Policy Client service and applies whichever LAPS policy it finds (GPO, Intune MDM channel, or local registry).
2. **The directory backend** (AD or Entra) stores the encrypted password and metadata. In AD, that means five new attributes on every computer object; in Entra, equivalent properties on the device object.
3. **The management surface** is split: Group Policy for AD-joined hosts, Intune CSP (`./Device/Vendor/MSFT/LAPS`) for MDM-managed hosts, or direct registry under `HKLM\Software\Microsoft\Policies\LAPS` for testing.

The encryption flow is what makes this version a meaningful improvement over the legacy product. When **password encryption** is enabled, the client retrieves the **KDS root key** from a DC, derives a key bound to a specific principal (a user or group authorized to decrypt — set via "Configure authorized password decryptors"), encrypts the password with that key, and writes the ciphertext to `msLAPS-EncryptedPassword`. Only members of the authorized decryptor group can read the password in plaintext. **Domain Admins are not implicitly authorized** — that's a feature, not a bug.

## Prerequisites checklist

Before you run a single command, confirm:

- [ ] **Domain functional level** Windows Server 2016 or higher (required for KDS root key infrastructure used in encryption)
- [ ] **At least one DC** at Windows Server 2019 with the April 2023 cumulative update (or 2022 / 2025)
- [ ] **Schema Admin** account available for `Update-LapsADSchema`
- [ ] **Console / out-of-band access** to one DC in case Group Policy misconfiguration locks you out remotely
- [ ] **GPO backup taken** (`Backup-GPO -All -Path C:\GPOBackups`)
- [ ] **Pilot OU defined** — never apply LAPS policy domain-wide on day one
- [ ] **RBAC tier groups created** — e.g., `LAPS-Readers-Tier0`, `LAPS-Readers-Tier1`, `LAPS-Readers-Tier2`
- [ ] **Naming convention for managed account** decided — usually the built-in `Administrator` (RID 500), but can be a custom local admin
- [ ] **Legacy LAPS inventoried** — if installed, plan parallel run then decommission
- [ ] **DSRM password backup policy approved** for DCs — this is sensitive

## How to implement Windows LAPS step by step

{{< howto title="How to implement Windows LAPS in an enterprise Active Directory environment" duration="PT3H" >}}
- name: "Update the Active Directory schema"
  text: "On a Schema Admin account, install the LAPS PowerShell module from a DC: `Install-WindowsFeature -Name RSAT-AD-PowerShell`. Then run `Import-Module LAPS; Update-LapsADSchema` and accept the warning. This adds five new attributes (`msLAPS-Password`, `msLAPS-PasswordExpirationTime`, `msLAPS-EncryptedPassword`, `msLAPS-EncryptedDSRMPassword`, `msLAPS-EncryptedPasswordHistory`) to the directory. Schema additions are forest-wide and irreversible — verify in a non-production forest first if you're cautious."
- name: "Generate a KDS root key for password encryption"
  text: "On any DC: `Add-KdsRootKey -EffectiveImmediately`. The `-EffectiveImmediately` flag is fine in a single-domain lab but in production the key takes ~10 hours to replicate to all DCs; if you can wait, use `Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(10))`. Without a KDS root key, encryption is impossible and the policy silently falls back to plaintext storage."
- name: "Grant computers permission to update their own password"
  text: "Per OU (or per parent OU containing your computers): `Set-LapsADComputerSelfPermission -Identity 'OU=Servers,DC=corp,DC=local'`. Repeat for each OU containing managed computers (`OU=Workstations`, `OU=Domain Controllers`, etc.). Without this, the client can't write the encrypted password back to its computer object and event log fills with permission errors."
- name: "Grant scoped read permissions to RBAC tier groups"
  text: "Tier 0 admins → DC OU only. Tier 1 admins → server OUs. Tier 2 admins → workstation OUs. Example: `Set-LapsADReadPasswordPermission -Identity 'OU=Tier2-Workstations,DC=corp,DC=local' -AllowedPrincipals 'CORP\\LAPS-Readers-Tier2'`. Never grant blanket Domain Admins read — split by tier to limit blast radius if any account is compromised."
- name: "Configure LAPS Group Policy (or Intune CSP)"
  text: "GPO path: `Computer Configuration → Policies → Administrative Templates → System → LAPS`. Set: (1) Configure password backup directory = Active Directory; (2) Enable password encryption = Enabled; (3) Configure authorized password decryptors = your tier-appropriate group; (4) Password Settings = Complexity 4, Length 20+, Age 30 days; (5) Name of administrator account to manage = leave blank to use built-in RID 500, or specify a custom name; (6) Post-authentication actions = Reset password and log off the managed account."
- name: "Enable DSRM password backup on Domain Controllers"
  text: "On DC OU policy only, set `Enable password backup for DSRM account = Enabled`. Windows LAPS will then rotate and back up the Directory Services Restore Mode password to `msLAPS-EncryptedDSRMPassword` on the DC's own computer object. This is a Windows-LAPS-only capability and a huge improvement over manual DSRM management. Restrict read access on this attribute to Tier 0 admins exclusively."
- name: "Deploy, force policy refresh, and verify"
  text: "Run `gpupdate /force` on a target. Force LAPS to evaluate policy immediately: `Invoke-LapsPolicyProcessing`. Run diagnostics: `Get-LapsDiagnostics -OutputFolder C:\\temp` — this dumps a CAB with event logs, registry state, and the resolved policy. Verify success by reading the event log `Microsoft-Windows-LAPS/Operational` — look for Event ID 10004 (password updated) or 10018 (encrypted password updated)."
- name: "Retrieve a password on demand"
  text: "From any host with the LAPS module and read permission: `Get-LapsADPassword -Identity COMPUTER01 -AsPlainText`. To force an immediate rotation (after, say, a privileged-access ticket closes): `Reset-LapsPassword -Identity COMPUTER01`. Both actions are auditable — set up Event ID 4662 (object attribute access) monitoring on the LAPS attributes for full visibility."
{{< /howto >}}

The next sections expand each step with the technical detail you'll need.

## Step 1: Update the AD schema (technical detail)

You only do this once per forest. It's irreversible — there's no `Remove-LapsADSchema`. Test in a lab forest first if your governance requires it.

{{< terminal title="Schema Admin: PowerShell on a DC" >}}
# Confirm forest functional level
Get-ADForest | Select-Object Name, ForestMode

# Confirm schema version BEFORE
(Get-ADObject -Identity (Get-ADRootDSE).schemaNamingContext -Properties objectVersion).objectVersion

# Run the schema extension
Import-Module LAPS
Update-LapsADSchema -Verbose

# Confirm the new attributes exist
Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -Filter 'name -like "msLAPS-*"' |
  Select-Object Name, ObjectClass
{{< /terminal >}}

You should see five `msLAPS-*` attribute objects. If you only see one or two, the schema extension partially failed — re-run as a Schema Admin, ideally on the FSMO Schema Master.

## Step 2: Generate the KDS root key (encryption foundation)

Without a KDS root key, `Enable password encryption = Enabled` is a no-op. Worse, the policy may silently fall back to plaintext storage (legacy attribute path) — exactly what you're trying to avoid.

{{< terminal title="Domain Admin: PowerShell on a DC" >}}
# Check if a KDS root key already exists (e.g., from gMSA setup)
Get-KdsRootKey

# If empty, create one. In a multi-DC environment, omit -EffectiveImmediately
# and use -EffectiveTime ((Get-Date).AddHours(10)) so replication completes.
Add-KdsRootKey -EffectiveImmediately

# Verify
Get-KdsRootKey | Select-Object KeyId, EffectiveTime, CreationTime
{{< /terminal >}}

{{< callout type="warning" title="The 10-hour replication delay is real" >}}
In production with multiple DCs, the KDS root key needs to replicate before encryption operations can succeed reliably. `Add-KdsRootKey -EffectiveImmediately` works in a single-DC lab but in a forest with replication latency you'll see intermittent encryption failures (Event ID 10052) until all DCs have the key. The recommended pattern: `Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(10))` and start LAPS rollout the next day.
{{< /callout >}}

## Step 3: Grant computer self-update permissions

Every computer object needs the ability to write its own LAPS attributes. This is a one-time `Set-LapsADComputerSelfPermission` per OU containing managed computers.

{{< terminal title="Domain Admin: PowerShell" >}}
# Recursively grant on the parent OU
Set-LapsADComputerSelfPermission -Identity 'OU=Servers,DC=corp,DC=local'
Set-LapsADComputerSelfPermission -Identity 'OU=Workstations,DC=corp,DC=local'
Set-LapsADComputerSelfPermission -Identity 'OU=Domain Controllers,DC=corp,DC=local'

# Verify the ACE was added
$ou = Get-ADOrganizationalUnit -Identity 'OU=Servers,DC=corp,DC=local'
(Get-Acl "AD:$($ou.DistinguishedName)").Access |
  Where-Object { $_.IdentityReference -eq 'NT AUTHORITY\SELF' -and $_.ActiveDirectoryRights -match 'WriteProperty' }
{{< /terminal >}}

If the permission isn't there, you'll see Event ID 10039 (insufficient permissions) flooding the client's `Microsoft-Windows-LAPS/Operational` log.

## Step 4: Grant scoped read permissions (RBAC tiering)

**This is the single most-skipped step**, and the one that leaves the most security debt. Most administrators grant `Domain Admins` blanket read — which means a single compromised DA account exposes every managed password in the forest.

The right approach is **tiered delegation** aligned with Microsoft's three-tier admin model:

| Tier | Group | Reads passwords for |
|---|---|---|
| **Tier 0** | `LAPS-Readers-Tier0` | Domain Controllers, ADFS, ADCS, identity infra |
| **Tier 1** | `LAPS-Readers-Tier1` | Member servers, business apps, file servers |
| **Tier 2** | `LAPS-Readers-Tier2` | Workstations, laptops |

{{< terminal title="Domain Admin: PowerShell" >}}
# Create the read-only groups (universal security groups, in their own protected OU)
New-ADGroup -Name 'LAPS-Readers-Tier0' -GroupScope Universal -GroupCategory Security -Path 'OU=Tier0-Groups,DC=corp,DC=local'
New-ADGroup -Name 'LAPS-Readers-Tier1' -GroupScope Universal -GroupCategory Security -Path 'OU=Tier1-Groups,DC=corp,DC=local'
New-ADGroup -Name 'LAPS-Readers-Tier2' -GroupScope Universal -GroupCategory Security -Path 'OU=Tier2-Groups,DC=corp,DC=local'

# Grant scoped read per OU
Set-LapsADReadPasswordPermission -Identity 'OU=Domain Controllers,DC=corp,DC=local' -AllowedPrincipals 'CORP\LAPS-Readers-Tier0'
Set-LapsADReadPasswordPermission -Identity 'OU=Servers,DC=corp,DC=local'             -AllowedPrincipals 'CORP\LAPS-Readers-Tier1'
Set-LapsADReadPasswordPermission -Identity 'OU=Workstations,DC=corp,DC=local'        -AllowedPrincipals 'CORP\LAPS-Readers-Tier2'

# Audit who currently has the extended right
Find-LapsADExtendedRights -Identity 'OU=Workstations,DC=corp,DC=local'
{{< /terminal >}}

`Find-LapsADExtendedRights` is the killer audit cmdlet. Run it quarterly and after any AD permission change — it lists every principal with `ExtendedRight` on the LAPS attributes, making over-privileged-read drift obvious.

## Step 5: Configure LAPS Group Policy

Here's the **complete GPO reference table** for Windows LAPS, with recommended values for an enterprise baseline:

| Setting | Recommended Value | Why |
|---|---|---|
| Configure password backup directory | **Active Directory** (2) | For hybrid-joined or AD-only fleets. Use **Azure Active Directory** (1) for Entra-only. |
| Password Settings | Complexity = **4 (Large + Small + Number + Special)**; Length = **20**; Age = **30 days** | 20 chars beats brute force even for offline-cracked attacks. 30-day age limits exposure window. |
| Name of administrator account to manage | (blank) | Blank = manage built-in `Administrator` (RID 500). Specify a name only if you've created a custom admin and want LAPS to ignore the default. |
| Configure post-authentication actions | **Reset the password and log off the managed account** (3) | Forces password rotation immediately after an admin uses the account — critical for break-glass scenarios. |
| Post-authentication reset delay | **8 hours** | Default is 24h. Lower to 8h for ransomware-resilience; lower further (1h) in high-security tiers. |
| Enable password encryption | **Enabled** | Mandatory. Without this, passwords are stored in plaintext in `msLAPS-Password`. |
| Configure authorized password decryptors | **CORP\LAPS-Readers-Tier{0,1,2}** (one group per tier-scoped GPO) | Encryption key is derived from this group's SID. Only its members can decrypt. |
| Configure size of encrypted password history | **12** | Lets you recover from rotation mishaps; lets forensics see what password was active at incident time. |
| Enable password backup for DSRM account | **Enabled** (DC OU only) | Backs up the DSRM password on each DC. Tier 0 only. |
| Do not allow password expiration time longer than required by policy | **Enabled** | Prevents tampering via attribute write that artificially extends the password lifetime. |

GPO link strategy: one policy linked to each tier OU, configured with that tier's reader group. This makes the encryption key derivation tier-scoped — a Tier 2 LAPS-Reader **cannot** decrypt a Tier 0 password even if the AD ACL were misconfigured.

## Step 6: Enable DSRM password backup on Domain Controllers

This is the capability that makes Windows LAPS materially better than the legacy product. The DSRM (Directory Services Restore Mode) password is the local account password used when a DC boots into safe mode for AD recovery. Historically it was manually set, rarely rotated, and almost never tested.

Windows LAPS rotates it on the same schedule as the regular Administrator password, stores the encrypted value in `msLAPS-EncryptedDSRMPassword`, and lets you retrieve it with the standard `Get-LapsADPassword` cmdlet — just specify the DSRM source:

{{< terminal title="Tier 0 admin: PowerShell" >}}
# Retrieve current DSRM password
Get-LapsADPassword -Identity DC01 -Source EncryptedDSRMPassword -AsPlainText

# Force an immediate DSRM rotation (after restoration drill, for example)
Reset-LapsPassword -Identity DC01

# Audit who has decryptor permission on DSRM attribute specifically
Find-LapsADExtendedRights -Identity 'OU=Domain Controllers,DC=corp,DC=local'
{{< /terminal >}}

Keep the DSRM read permission on **Tier 0 only** — never delegate this to Tier 1/2 reader groups.

## Step 7: Deploy and verify

After GPO is configured and linked:

{{< terminal title="Target endpoint: PowerShell as Admin" >}}
# Force policy refresh
gpupdate /force

# Force LAPS to evaluate the policy immediately
Invoke-LapsPolicyProcessing

# Read the resolved policy
Get-LapsAADPassword -Identity (hostname)   # for Entra-backed
# or
Get-LapsADPassword  -Identity (hostname) -AsPlainText   # for AD-backed

# Generate a full diagnostics bundle
Get-LapsDiagnostics -OutputFolder C:\temp

# Watch the event log
Get-WinEvent -LogName 'Microsoft-Windows-LAPS/Operational' -MaxEvents 20 |
  Format-Table TimeCreated, Id, LevelDisplayName, Message -AutoSize
{{< /terminal >}}

**Event IDs to know:**

| Event ID | Meaning | Action |
|---|---|---|
| 10004 | Password updated successfully (plaintext attribute) | None — but consider migrating to encrypted |
| 10018 | **Encrypted** password updated successfully | None — this is what you want |
| 10009 | Schema not updated | Re-run `Update-LapsADSchema` |
| 10031 | KDS root key not found | Verify `Get-KdsRootKey`; wait for replication |
| 10039 | Insufficient permission to update password | Re-run `Set-LapsADComputerSelfPermission` for the OU |
| 10052 | Encryption failure (key derivation) | Verify authorized decryptor group SID; verify KDS replication |
| 10056 | Backup directory misconfigured | Check GPO `Configure password backup directory` |
| 10059 | DSRM backup failed | DC-specific — check Tier 0 GPO is linked to Domain Controllers OU |

## Step 8: Retrieve, rotate, and audit passwords

Daily-operations workflow for a helpdesk or SOC analyst with read permission:

{{< terminal title="Tier 2 reader: PowerShell" >}}
# Read the current password
Get-LapsADPassword -Identity WKSTN-001 -AsPlainText

# Show the full attribute set (rotation timestamp, account name, source)
Get-LapsADPassword -Identity WKSTN-001 -IncludeHistory | Format-List

# After a privileged session ends, force immediate rotation
Reset-LapsPassword -Identity WKSTN-001

# Show password history (last 12 rotations, if encrypted history is enabled)
Get-LapsADPassword -Identity WKSTN-001 -IncludeHistory -AsPlainText
{{< /terminal >}}

For SOC visibility, enable **Event ID 4662** auditing on the LAPS attributes (configured in Default Domain Controllers Policy → Audit Object Access → Directory Service Access) and forward Domain Controller Security logs to your SIEM. Every password retrieval generates a 4662 with the principal name and the attribute GUID — full read-audit trail.

## Windows LAPS PowerShell command cheat sheet

The full `LAPS` module, the way you'll actually use it. Copy-paste-ready.

```powershell
# === SETUP ===
Import-Module LAPS
Update-LapsADSchema -Verbose
Add-KdsRootKey -EffectiveImmediately   # or -EffectiveTime for multi-DC

# === DELEGATION ===
Set-LapsADComputerSelfPermission   -Identity 'OU=Workstations,DC=corp,DC=local'
Set-LapsADReadPasswordPermission   -Identity 'OU=Workstations,DC=corp,DC=local' -AllowedPrincipals 'CORP\LAPS-Readers-Tier2'
Set-LapsADResetPasswordPermission  -Identity 'OU=Workstations,DC=corp,DC=local' -AllowedPrincipals 'CORP\LAPS-Resetters-Tier2'

# === AUDIT ===
Find-LapsADExtendedRights -Identity 'OU=Workstations,DC=corp,DC=local'

# === OPERATIONS ===
Get-LapsADPassword     -Identity WKSTN-001 -AsPlainText
Get-LapsADPassword     -Identity WKSTN-001 -IncludeHistory -AsPlainText
Reset-LapsPassword     -Identity WKSTN-001
Invoke-LapsPolicyProcessing                         # force immediate evaluation on local host
Get-LapsDiagnostics    -OutputFolder C:\temp
```

Save this as `LAPS-Cheatsheet.ps1` and pin it on your admin jump host.

## Security best practices

Twelve enterprise patterns that separate a real LAPS deployment from a checkbox one:

1. **Always enable encryption.** Plaintext storage in 2026 is indefensible at audit.
2. **Tier your reader groups.** Tier 0 / 1 / 2 — never blanket Domain Admins.
3. **Rotate KDS root keys periodically.** Microsoft doesn't enforce a rotation interval, but every 5 years is a defensible baseline.
4. **Audit read access with Event 4662.** Forward to SIEM with a 90-day retention minimum.
5. **Enable post-authentication actions.** Reset the password after each privileged session, not just on schedule.
6. **Lower password age in high-security tiers.** 30 days for general fleet; 7 days for Tier 0 servers.
7. **Run `Find-LapsADExtendedRights` quarterly.** Detect ACL drift before it becomes an audit finding.
8. **Use Just-In-Time (JIT) access for password retrieval.** Combine LAPS with Privileged Access Management (PIM) — read permission is granted only during an approved access window.
9. **Protect the LAPS-Readers groups themselves.** Place them in a protected OU; restrict membership-modify rights to a small group of identity admins; review membership monthly.
10. **Don't disable the built-in Administrator.** Renaming/disabling it breaks `Name of administrator account to manage = blank`. If you want a renamed account, configure that explicitly in policy.
11. **Test rollback.** Document the GPO unlink procedure; practice it on a non-production OU.
12. **Decommission legacy LAPS deliberately.** Remove the GPO settings, uninstall the MSI, clean up `ms-Mcs-AdmPwd` attribute reads from any tooling that still references it.

## Common mistakes (and how to avoid them)

The recurring failures I see during LAPS engagements:

| Mistake | Why it happens | Fix |
|---|---|---|
| Storing passwords in plaintext (no encryption) | Forgot to enable encryption GPO, or no KDS root key exists | Enable `Enable password encryption` and `Add-KdsRootKey` |
| Granting Domain Admins blanket read | "It's just easier" | Create tiered reader groups; revoke DA read on LAPS attributes |
| Schema update partial failure | Not running as Schema Admin on FSMO Schema Master | Re-run as Schema Admin on Schema Master DC |
| LAPS policy not applying | Linked to wrong OU; client-side LAPS service stopped | Verify with `Invoke-LapsPolicyProcessing`; check `Get-LapsDiagnostics` |
| Encryption failures (Event 10052) | KDS root key hasn't replicated | Wait 10 hours after `Add-KdsRootKey`; verify with `Get-KdsRootKey` on each DC |
| Passwords never rotate | Computer object lacks `SELF write` permission | Re-run `Set-LapsADComputerSelfPermission` for the OU |
| DSRM password not backing up | DC-specific GPO not linked to Domain Controllers OU | Link Tier 0 GPO to `OU=Domain Controllers,DC=...` |
| Renamed local admin breaks LAPS | Disabled or renamed built-in Administrator without updating policy | Set `Name of administrator account to manage` to the custom name |
| Helpdesk sees "Access denied" reading password | Not a member of the authorized decryptor group | Add to the appropriate `LAPS-Readers-TierN` group; re-login |
| Legacy LAPS attributes still populated | Old MSI still installed on some clients | Uninstall `LAPS.x64.msi` via SCCM/Intune; clean up legacy GPO |
| Password retrieval audit gap | No 4662 auditing configured | Enable Audit Directory Service Access at DC level; forward to SIEM |
| Customer audit asks for password complexity proof | No documented baseline | Export GPO with `Backup-GPO`; document settings in the security baseline runbook |

## Troubleshooting guide

When something doesn't work, this is the order of operations:

**1. Confirm the LAPS service is running on the client:**
```powershell
Get-Service -Name LAPS
```
If it's stopped, start it: `Start-Service LAPS`. If it's missing, the OS doesn't have Windows LAPS — confirm the build (`winver`) and patch level.

**2. Generate a diagnostics bundle:**
```powershell
Get-LapsDiagnostics -OutputFolder C:\temp
```
Open the resulting `.cab`. Inside, `LAPS.Diagnostics.log` shows policy resolution; `LAPS.Diagnostics.json` shows the parsed configuration; the event log dump shows recent failures.

**3. Re-evaluate policy on demand:**
```powershell
Invoke-LapsPolicyProcessing -Verbose
```
The verbose output names the exact policy source and reports success/failure for the password rotation.

**4. Verify backend connectivity:**
```powershell
# For AD-backed
nltest /sc_query:corp.local
Get-ADDomainController -Discover -Domain corp.local

# For Entra-backed
dsregcmd /status   # look for "AzureAdJoined : YES" and "TenantId : ..."
```

**5. Validate encryption end-to-end:**
```powershell
# Should return a value, not a long error
Get-KdsRootKey
# Should show the authorized decryptor group SID
Get-LapsDiagnostics ... | look for AuthorizedDecryptors
```

If after all five steps the password still doesn't rotate, escalate by capturing a network trace with Wireshark filtered to LDAP/MS-RPC traffic to your DC — the LAPS write attempt is observable.

## Windows LAPS audit checklist

Use this as a quarterly self-audit. Each item is a yes/no.

- [ ] Domain functional level is 2016 or higher
- [ ] At least one DC at Server 2019+ with April 2023 cumulative update
- [ ] AD schema includes all five `msLAPS-*` attributes
- [ ] KDS root key exists and is older than 24 hours
- [ ] `Set-LapsADComputerSelfPermission` applied to every OU containing managed computers
- [ ] `Set-LapsADReadPasswordPermission` granted only to tiered reader groups (Tier 0/1/2)
- [ ] Domain Admins **do not** have implicit LAPS read
- [ ] GPO sets `Enable password encryption = Enabled`
- [ ] GPO sets `Configure password backup directory = Active Directory` (or Azure AD)
- [ ] GPO sets `Password complexity = 4`, `Length ≥ 20`, `Age ≤ 30 days`
- [ ] GPO sets `Post-authentication actions = Reset password and log off`
- [ ] GPO sets `Configure size of encrypted password history ≥ 6`
- [ ] DC-specific GPO sets `Enable password backup for DSRM account = Enabled`
- [ ] Event ID 4662 auditing enabled on LAPS attributes
- [ ] SIEM ingests `Microsoft-Windows-LAPS/Operational` from all DCs and a representative client sample
- [ ] `Find-LapsADExtendedRights` reviewed in the last 90 days
- [ ] Legacy Microsoft LAPS MSI uninstalled from every host
- [ ] Legacy `ms-Mcs-AdmPwd*` GPO settings removed
- [ ] LAPS recovery runbook exists, documenting GPO unlink steps
- [ ] Tier-0 admins can retrieve DSRM password via `Get-LapsADPassword -Source EncryptedDSRMPassword`

If you're sub-90% on this checklist, your LAPS deployment has visible audit and operational gaps. Fix the no-answers in priority order before chasing additional hardening controls.

## Frequently asked questions

{{< faq >}}
- q: "What is Windows LAPS and how does it differ from Microsoft LAPS?"
  a: "Windows LAPS is the native, built-in Local Administrator Password Solution introduced in the April 2023 Windows update. It replaces the legacy Microsoft LAPS MSI (released 2015), adds password encryption (legacy stored plaintext), supports Microsoft Entra ID as a backend (legacy was AD-only), manages the DSRM password on Domain Controllers (legacy could not), and ships with a full PowerShell module. If you're running legacy LAPS in 2026, migrate."

- q: "Do I need Windows Server 2025 to deploy Windows LAPS?"
  a: "No. Windows LAPS is supported on Windows Server 2019 (with the April 2023 cumulative update), Server 2022, and Server 2025. The schema extension is forest-wide and works in any AD domain at Windows Server 2016 functional level or higher. The April 2023 update is the minimum bar; older patch levels lack the client extension."

- q: "Is the password stored encrypted in Active Directory?"
  a: "Only if you explicitly enable it. With `Enable password encryption = Enabled` (and a valid KDS root key), Windows LAPS writes ciphertext to `msLAPS-EncryptedPassword`. Without the setting, it falls back to plaintext in `msLAPS-Password` — which is what the legacy product always did. Enable encryption from day one."

- q: "How do I configure Windows LAPS with Intune instead of Group Policy?"
  a: "Intune supports Windows LAPS natively via the **Endpoint Security → Account Protection → Local Admin Password Solution (LAPS)** policy. The settings map 1:1 to the GPO settings — backup directory, complexity, length, age, post-auth actions, encryption, authorized decryptors. For Entra-joined devices use `Backup directory = Microsoft Entra ID`; for hybrid-joined, AD or Entra both work. The CSP path is `./Device/Vendor/MSFT/LAPS/Policies`."

- q: "Can Windows LAPS manage the DSRM password on Domain Controllers?"
  a: "Yes — this is one of the biggest reasons to migrate from legacy LAPS. Enable `Enable password backup for DSRM account = Enabled` in a GPO linked to the Domain Controllers OU. The DSRM password is rotated on the same schedule as the regular Administrator account and stored in `msLAPS-EncryptedDSRMPassword`. Retrieve with `Get-LapsADPassword -Identity DC01 -Source EncryptedDSRMPassword -AsPlainText`."

- q: "Who should have permission to read LAPS passwords?"
  a: "Use Microsoft's three-tier admin model. Tier 0 readers can retrieve DC and identity-infra passwords. Tier 1 readers can retrieve member-server passwords. Tier 2 readers can retrieve workstation passwords. Never grant Domain Admins blanket read — one compromised DA account would otherwise expose every managed password in the forest. Use `Find-LapsADExtendedRights` to audit who has access."

- q: "How often should LAPS passwords rotate?"
  a: "30 days for general fleet. 7 days for Tier 0 servers (DCs, ADFS, ADCS). Also enable post-authentication rotation (`Reset the password and log off the managed account`) so the password rotates immediately after any privileged session ends — this is the highest-value setting for ransomware resilience."

- q: "Does Windows LAPS work in a workgroup environment?"
  a: "No. Windows LAPS requires either Active Directory or Microsoft Entra ID as a backend to store the encrypted password. Workgroup hosts have nowhere to write the password attribute to. If you have stand-alone workgroup machines, manage them via Intune (Entra-joined) or accept that LAPS is not applicable and use a different rotation tool like CyberArk EPM."

- q: "What happens if I lose the KDS root key?"
  a: "All previously-encrypted LAPS passwords become unreadable — there is no recovery. The KDS root key is the cryptographic anchor for password derivation. Back up the System State of at least one DC weekly; the KDS root key lives in `CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services` in the Configuration partition and is part of System State backup. Test the restore quarterly."

- q: "Can I migrate from Microsoft LAPS legacy to Windows LAPS without downtime?"
  a: "Yes. Windows LAPS coexists with legacy LAPS by default — it reads from new `msLAPS-*` attributes while legacy writes to `ms-Mcs-AdmPwd*`. Deploy Windows LAPS GPO to a pilot OU, verify password rotation in the new attributes for 7 days, expand OU coverage in waves, and finally uninstall the legacy MSI and remove legacy GPO settings. Plan a 30-day overlap minimum to catch corner cases."
{{< /faq >}}

## Conclusion: ship it this sprint

Windows LAPS is the highest-ROI hardening control in the Windows ecosystem right now: an hour of deployment work eliminates an entire class of lateral-movement attack, satisfies CIS Control 5.4, and gives auditors evidence they actually want to see. The legacy product is technical debt; the modern Windows LAPS is free, native, encrypted by default, and supports both AD and Entra ID backends.

The roadmap from this article:

1. **This week**: lab deployment on a single test OU. Verify encryption, retrieval, and rotation.
2. **Next sprint**: pilot rollout to one production OU (server tier first, workstations second). Tiered RBAC from day one.
3. **Within 30 days**: full enterprise rollout with DSRM backup on DCs and SIEM-forwarded retrieval audit.

Pair this with the [NTLM disable guide](/tutorials/disable-ntlm-windows/) to close both the credential-reuse vector (LAPS) and the credential-relay vector (NTLM) at the same time — combined, they remove the two most-abused Windows attack surfaces in a single quarter's hardening work.

If you ran into a Windows LAPS deployment issue not covered here — especially the weird Entra-hybrid edge cases — [drop a line](/contact/). We maintain a running list of "LAPS deployment gotchas" from reader reports.

## Share this guide

**LinkedIn**:
> Windows LAPS — the native, encrypted, DC-aware replacement for legacy Microsoft LAPS — eliminates an entire class of lateral-movement attacks for one hour of deployment work. Here's the full 8-step enterprise rollout: schema, KDS key, tiered RBAC, GPO, DSRM, deploy, verify, audit. 👇

**X / Twitter** (one-tweet summary):
> Windows LAPS rollout in 8 commands: Update-LapsADSchema · Add-KdsRootKey · Set-LapsADComputerSelfPermission · Set-LapsADReadPasswordPermission · Configure GPO · Enable DSRM backup · Invoke-LapsPolicyProcessing · Get-LapsADPassword. Full step-by-step guide:

## References

- [Microsoft Learn: Windows LAPS overview](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
- [Microsoft Learn: Windows LAPS scenarios using Windows Server Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory)
- [Microsoft Learn: Windows LAPS troubleshooting](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-troubleshooting)
- [Microsoft Learn: Intune CSP for Windows LAPS](https://learn.microsoft.com/en-us/windows/client-management/mdm/laps-csp)
- [CIS Microsoft Windows 11 Enterprise Benchmark (Section: Local Admin Password Solution)](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
- [Microsoft Tier model for AD admin tiering](https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model)
- [MITRE ATT&CK T1078.003 — Local Accounts](https://attack.mitre.org/techniques/T1078/003/)
- [MITRE ATT&CK T1550.002 — Pass the Hash](https://attack.mitre.org/techniques/T1550/002/)
