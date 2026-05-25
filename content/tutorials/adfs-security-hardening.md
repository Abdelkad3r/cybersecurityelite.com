---
title: "ADFS Security Hardening: Token Signing, Claim Rules, Golden SAML Defence (2026)"
slug: "adfs-security-hardening"
description: "ADFS (Active Directory Federation Services) hardening — token-signing rotation, claim-rule audit, Extranet Lockout, MFA enforcement, mimikatz/ADFSDump defence."
date: 2026-05-24T15:30:00Z
lastmod: 2026-05-24T15:30:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["Tutorials"]
tags: ["adfs", "active-directory", "federation", "identity", "saml", "golden-saml", "mimikatz", "windows-hardening", "entra-id"]
keywords: [
  "ADFS security",
  "ADFS hardening",
  "ADFS hardening guide",
  "adfs ad",
  "active directory federation services",
  "active directory federation services security",
  "ADFS token signing certificate",
  "Golden SAML",
  "Golden SAML attack",
  "Golden SAML defence",
  "mimikatz ADFS",
  "ADFSDump",
  "ADFS migration to Entra",
  "Extranet Lockout",
  "ADFS claim rules audit",
  "WS-Trust 1.3 disable",
  "ADFS Event 1200"
]
toc: true
cover:
  image: "/images/articles/adfs-security-hardening.png"
  alt: "ADFS security hardening guide — token signing, claim rules, Golden SAML defence"
---

If your environment still runs **Active Directory Federation Services (ADFS)** — and most large enterprises that adopted federation between 2015 and 2020 still do — you are sitting on the single highest-value target in your identity stack. An attacker who extracts the ADFS **token-signing certificate** can mint SAML tokens for any user, including domain admins, with no further AD interaction and no Kerberos or NTLM tickets to detect. That class of attack is **Golden SAML**, and it's exactly what hit SolarWinds-era victims in 2020. This is the practical **ADFS security hardening guide** for 2026: rotating signing certificates, auditing claim rules, enforcing Extranet Lockout, blocking the mimikatz / ADFSDump extraction path, and the migration path to Microsoft Entra ID for the eventual decommission.

## TL;DR — the ADFS hardening priority list

If you only have time for the five highest-impact controls:

1. **Rotate the token-signing certificate**, then rotate it again 14 days later. Anyone holding an old cert is locked out.
2. **Block local logon to ADFS servers** for everyone except a tiered admin group. ADFS servers are Tier 0 — treat them like Domain Controllers.
3. **Enable Extranet Lockout** with `AdfsSmartLockoutEnforce` mode. Without it, ADFS is a password-spray funnel.
4. **Audit every claim rule** for transformations that bypass MFA or grant excessive scope. Most environments have unused claim rules accumulated over five years.
5. **Forward Event IDs 1200/1201/1202/411/412** to your SIEM. These are the Golden SAML, brute force, and token-replay signals — every ADFS-relevant detection lives in one of those Event IDs.

After those five, the remaining hardening (WS-Trust 1.3 disable, smart account lockout, PowerShell auditing, network segmentation) closes the long tail.

## What is ADFS, and why is it still relevant?

**Active Directory Federation Services (ADFS)** is Microsoft's on-premises identity federation service. It accepts authentication from Active Directory and issues SAML 2.0 / WS-Federation / OAuth 2.0 tokens that downstream relying parties (Office 365, Salesforce, ServiceNow, custom apps) trust. In a federated topology the relying party doesn't see AD credentials — it sees signed tokens minted by ADFS.

ADFS was the default Microsoft identity-federation path from 2009 (Server 2008 R2) through about 2018. After that, **Microsoft Entra ID** (formerly Azure AD) took over as the recommended modern path — but a lot of environments are still running ADFS in 2026 because:

- **Long-tail Office 365 migrations** that started on ADFS and never finished the cut-over to Entra
- **Hybrid identity** where ADFS is the bridge to on-prem RP-STS relying parties
- **Compliance environments** (US Federal, defence contractors) that prefer on-prem identity
- **Legacy SaaS apps** with custom SAML configurations tied to the ADFS issuer URL

If you have ADFS, two things are true: **(a) you should plan to decommission it** (Microsoft has signalled this for years and the Entra ID path is materially safer); and **(b) until you finish that migration**, ADFS must be hardened to the same standard as a Domain Controller.

## Why ADFS hardening matters now

Three reasons to put ADFS at the top of your 2026 hardening backlog:

**1. Golden SAML is a one-shot domain compromise.** An attacker who reads the ADFS token-signing certificate (specifically the private key, stored encrypted on the ADFS server filesystem and in the database) can mint arbitrary SAML tokens. No AD interaction. No Kerberos tickets. No NTLM hashes. They appear at Office 365 (and any other federated RP) as any user they want, including the most privileged. The 2020 SolarWinds incident demonstrated this against multiple US federal agencies and enterprise victims — UNC2452 / APT29 extracted the ADFS signing key and minted tokens for high-value accounts at will.

**2. Mimikatz and ADFSDump trivialise the extraction.**

- `mimikatz.exe "vault::cred /patch" "exit"` reads cached credentials from ADFS service accounts
- `mimikatz "lsadump::backupkeys" / "lsadump::dpapi"` recovers the DPAPI master key used to encrypt the signing cert
- The dedicated `ADFSDump.exe` (Doug Bienstock, Mandiant) and `aadinternals` PowerShell module make the extraction a one-liner for anyone with local SYSTEM on the ADFS server

If your ADFS server is reachable from a Tier 1 admin's workstation, and that workstation is compromised, Golden SAML is one lateral hop away.

**3. ADFS is often the LEAST-hardened machine in the identity stack.** Many environments hardened DCs aggressively, deployed LAPS, enabled Credential Guard — and left the ADFS server with default settings, an old token-signing cert that has never been rotated, the WS-Trust 1.3 endpoint exposed to the internet, and no Extranet Lockout. The blast radius is asymmetric: ADFS compromise = federation compromise = every SaaS app trusts forged tokens.

## ADFS attack surface

The four major paths to ADFS compromise, and what each enables:

| Attack | Where | Outcome | Mitigated by |
|---|---|---|---|
| **Golden SAML (token signing cert theft)** | ADFS server filesystem + DPAPI | Forge arbitrary SAML tokens; impersonate any user | Cert rotation, ADFS-server tiering, signing key in HSM |
| **Password spray via WS-Trust 1.3** | External `/adfs/services/trust/2005/usernamemixed` endpoint | Account credentials at scale; no MFA path on legacy WS-Trust | Disable WS-Trust 1.3; Extranet Lockout; smart lockout |
| **Claim-rule injection / abuse** | ADFS configuration database | Privilege escalation through transformed claims; MFA bypass | Quarterly claim-rule audit; change-control on relying parties |
| **Service-account compromise** | `svc-adfs` AD account; local admin on ADFS host | Direct access to ADFS configuration; signing key extraction | LAPS on ADFS hosts; gMSA for ADFS service; restricted local admins |

The full hardening plan addresses all four paths in priority order.

## How to harden ADFS step-by-step

{{< howto title="How to harden ADFS (Active Directory Federation Services) in 2026" duration="PT8H" >}}
- name: "Rotate the token-signing certificate"
  text: "Open the ADFS Management console (or `Get-AdfsCertificate`). Generate a new token-signing certificate (`Update-AdfsCertificate -CertificateType Token-Signing`). Federation Trust Service publishes the new certificate via the federation metadata; relying parties pick it up automatically if they consume metadata. After 14 days, run `Set-AdfsCertificate -CertificateType Token-Signing -IsPrimary -Thumbprint <new>` and remove the old certificate. Anyone holding a stolen old cert can no longer mint valid tokens."
- name: "Move ADFS servers to Tier 0 with strict tiered admin"
  text: "ADFS servers are identity-tier (Tier 0). Block local logon to ADFS hosts for everyone except a small dedicated `ADFS-Admins` group. Use `secpol.msc → User Rights Assignment` and remove standard admin groups from the `Allow log on locally` policy. Deploy [LAPS](/tutorials/windows-laps-implementation/) on ADFS servers — local admin password must be rotated like DCs."
- name: "Enable Extranet Lockout with smart-lockout mode"
  text: "Run `Set-AdfsProperties -ExtranetLockoutEnabled $true -ExtranetLockoutMode AdfsSmartLockoutEnforce -ExtranetLockoutRequirePDC $false -ExtranetLockoutThreshold 5 -ExtranetObservationWindow (New-TimeSpan -Minutes 15)`. This caps password attempts from the extranet before the request reaches AD — closes the password-spray funnel without locking real AD accounts."
- name: "Disable WS-Trust 1.3 unless something explicitly needs it"
  text: "WS-Trust 1.3 endpoints (`/adfs/services/trust/2005/usernamemixed`, `/adfs/services/trust/13/usernamemixed`) are the legacy auth path that **does not require MFA**. Most modern apps don't need them. Disable: `Set-AdfsEndpoint -TargetAddressPath /adfs/services/trust/2005/usernamemixed -Proxy $false; Disable-AdfsEndpoint -TargetAddressPath /adfs/services/trust/13/usernamemixed`. Inventory anything still authenticating via WS-Trust before disabling — those are usually old Exchange ActiveSync clients or legacy SaaS connectors."
- name: "Enforce MFA on every relying party trust"
  text: "Per relying party (`Get-AdfsRelyingPartyTrust`), set the access control policy to require MFA. The recommended modern policy is `Permit everyone and require MFA`. For relying parties that genuinely don't support MFA (rare in 2026), document the exception and put compensating controls (network restrictions, IP-based access) in place."
- name: "Audit every claim rule for unused transformations and excessive scope"
  text: "`Get-AdfsRelyingPartyTrust | ForEach-Object { $_.Name; $_.IssuanceTransformRules }`. Look for: claim rules that explicitly elevate group membership; claim rules that pass through `tokenGroupsGlobalAndUniversal` (broad group disclosure); claim rules referencing apps that no longer exist. Remove unused rules; tighten broad rules to specific allowlists."
- name: "Configure PowerShell scriptblock logging on ADFS servers"
  text: "GPO: `Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell → Turn on PowerShell Script Block Logging = Enabled`. Forward Event 4104 from ADFS servers to your SIEM. ADFSDump, mimikatz dumps, and certificate exports are all visible in scriptblock logs."
- name: "Enable advanced ADFS auditing and forward to SIEM"
  text: "On ADFS server: `Set-AdfsProperties -AuditLevel Verbose`; on the AD audit policy: enable subcategory 'Application Generated' under Object Access. Forward Event IDs 1200/1201/1202 (token issuance) and 411/412 (token validation failure) to Splunk / Sentinel. These are the Golden SAML detection signals — token-issuance volume from unusual accounts is the canary."
- name: "Network-segment ADFS servers behind a Web Application Proxy"
  text: "Place the internal ADFS farm in a Tier 0 VLAN. Expose only the Web Application Proxy (WAP) tier to the DMZ. Block direct access from corporate workstations to the ADFS farm — only WAPs and ADFS Admins should reach them. Apply Windows Firewall rules and network ACLs."
- name: "Plan and execute migration to Microsoft Entra ID"
  text: "Run `Test-AzureADAuthPolicyMigration` (or the Entra ID Connect health tool) to identify relying parties that can move to Entra ID directly. Apps using SAML 2.0 or WS-Fed migrate cleanly; OAuth/OIDC apps migrate even more cleanly. Document a 6-12 month decommission plan: each relying party moves from ADFS to Entra ID, ADFS retains a smaller scope, eventually only legacy WS-Trust apps remain (which usually means decommissioning the app entirely)."
{{< /howto >}}

Each step is unpacked below with the technical detail you'll need.

## Step 1: Token-signing certificate rotation (the highest-priority control)

The token-signing certificate's private key is what makes Golden SAML possible. If an attacker has read this key (typically via mimikatz extracting the DPAPI master and ADFSDump pulling the cert from the ADFS configuration DB), they can mint arbitrary SAML tokens for any user.

The defence is **frequent rotation**. Microsoft's recommendation: rotate annually. Best practice for security-conscious environments: rotate every 90 days. After any suspected compromise: rotate immediately, twice, with a 14-day gap.

{{< terminal title="ADFS server: PowerShell as admin" >}}
# Show the current signing certificate
Get-AdfsCertificate -CertificateType Token-Signing |
  Format-List Thumbprint, NotBefore, NotAfter, IsPrimary, CertificateType

# Generate a new one (becomes secondary; relying parties get it via federation metadata)
Update-AdfsCertificate -CertificateType Token-Signing

# Wait 7–14 days for relying parties to pick up the new cert via metadata
# Then promote the new cert to primary and remove the old
$new = Get-AdfsCertificate -CertificateType Token-Signing |
  Where-Object { -not $_.IsPrimary }
Set-AdfsCertificate -Thumbprint $new.Thumbprint -CertificateType Token-Signing -IsPrimary

# Remove the old certificate
$old = Get-AdfsCertificate -CertificateType Token-Signing |
  Where-Object { -not $_.IsPrimary }
Remove-AdfsCertificate -Thumbprint $old.Thumbprint -CertificateType Token-Signing
{{< /terminal >}}

**For maximum security:** generate the token-signing certificate in a Hardware Security Module (HSM). The private key never touches the ADFS filesystem — even local SYSTEM on the ADFS host can't extract it. Microsoft documents HSM integration for ADFS using nShield and similar; pair with the [Microsoft Learn ADFS docs](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/operations/how-to-configure-hardware-security-module-hsm).

## Step 2: Tier-0 isolation of ADFS servers

ADFS servers are part of your identity stack — Tier 0 — alongside Domain Controllers. The hardening rule is "no Tier 1/2 admin ever logs on locally to an ADFS server."

**Restrict local logon (GPO at the ADFS OU):**

```text
Computer Configuration
 └ Policies
   └ Windows Settings
     └ Security Settings
       └ Local Policies
         └ User Rights Assignment
           ├ Allow log on locally           = ADFS-Admins, Local Administrators
           ├ Deny log on locally            = Domain Users
           ├ Deny log on through RDS        = Domain Users
           └ Allow log on through RDS       = ADFS-Admins
```

**Deploy LAPS on ADFS servers** so the local admin password rotates daily and the read permission is scoped to Tier 0 admins only. See the [Windows LAPS implementation guide](/tutorials/windows-laps-implementation/) — the same DSRM backup workflow applies to ADFS.

**Use a gMSA (Group Managed Service Account) for the ADFS service.** Replaces the default `NT SERVICE\adfssrv` or domain service account. gMSA passwords rotate automatically and there's no human-knowable password to steal.

```powershell
# On the ADFS server
New-ADServiceAccount -Name svc-adfs -DNSHostName adfs.corp.local `
  -PrincipalsAllowedToRetrieveManagedPassword "ADFS-Servers"
Install-ADServiceAccount svc-adfs
```

Then re-configure ADFS to use `corp\svc-adfs$` as the service account.

## Step 3: Extranet Lockout — closing the password-spray funnel

By default, ADFS's external endpoints will happily accept thousands of password attempts per minute. Without Extranet Lockout, an attacker can password-spray your entire user base via the ADFS WS-Trust endpoint.

{{< terminal title="ADFS server: PowerShell as admin" >}}
Set-AdfsProperties `
  -ExtranetLockoutEnabled $true `
  -ExtranetLockoutMode AdfsSmartLockoutEnforce `
  -ExtranetLockoutThreshold 5 `
  -ExtranetObservationWindow (New-TimeSpan -Minutes 15) `
  -ExtranetLockoutRequirePDC $false

# Verify
Get-AdfsProperties | Select-Object Extranet*
{{< /terminal >}}

The `AdfsSmartLockoutEnforce` mode (vs. `AdfsSmartLockoutLogOnly`) actually blocks at the ADFS layer — accounts can't accumulate failed-logon counts against AD. The `RequirePDC $false` ensures the lockout enforcement works even if the PDC emulator is unreachable.

## Step 4: Disabling WS-Trust 1.3

WS-Trust 1.3 (and 2005) are the legacy authentication endpoints that pre-date modern auth. They accept username/password directly and **do not enforce MFA** — they're the password-spray and credential-theft surface ADFS exposes. Modern apps don't need them.

{{< terminal title="ADFS server: PowerShell as admin" >}}
# Inventory which endpoints are currently enabled and proxy-exposed
Get-AdfsEndpoint | Where-Object { $_.Enabled -and $_.Proxy } |
  Select-Object FullUrl, Enabled, Proxy

# Disable the WS-Trust legacy mixed endpoints from the proxy
Set-AdfsEndpoint -TargetAddressPath '/adfs/services/trust/2005/usernamemixed' -Proxy $false
Set-AdfsEndpoint -TargetAddressPath '/adfs/services/trust/13/usernamemixed' -Proxy $false
Set-AdfsEndpoint -TargetAddressPath '/adfs/services/trust/2005/windowstransport' -Enabled $false
Set-AdfsEndpoint -TargetAddressPath '/adfs/services/trust/13/windowstransport' -Enabled $false

# Restart the ADFS service
Restart-Service adfssrv
{{< /terminal >}}

**Before disabling**, audit which clients are currently authenticating via WS-Trust. Look in your ADFS audit logs for Event 1200 entries with `Activity = TokenIssuanceFromAuthentication` and `AuthenticationProtocol = WSTrust`. Common culprits:

- Older Exchange ActiveSync devices (iOS pre-13, Android pre-9)
- Legacy SaaS integrations (often custom-built or vendor-provided in 2014-2017)
- Internal apps still using `WS2007HttpBinding`

For each, document the migration path: upgrade the client to modern auth (OAuth 2.0), replace the app, or — if the app can't be modernised — keep WS-Trust enabled but lock it down with IP restrictions on the WAP.

## Step 5: Audit claim rules for hidden bypasses

ADFS relying-party trusts have **claim transformation rules** that issue, transform, or filter claims as tokens flow through. Over years, these accumulate, and unused or over-permissive rules are common findings in security audits.

{{< terminal title="ADFS server: PowerShell" >}}
# Dump every claim rule for review
Get-AdfsRelyingPartyTrust | ForEach-Object {
  Write-Host "===== $($_.Name) =====" -ForegroundColor Yellow
  Write-Host "Issuance:" -ForegroundColor Cyan
  Write-Host $_.IssuanceTransformRules
  Write-Host "Authorization:" -ForegroundColor Cyan
  Write-Host $_.IssuanceAuthorizationRules
  Write-Host "AdditionalAuth:" -ForegroundColor Cyan
  Write-Host $_.AdditionalAuthenticationRules
}
{{< /terminal >}}

**Red flags to look for in each relying party's rules:**

- Rules that pass through `tokenGroupsGlobalAndUniversal` — discloses ALL groups, far more than the RP needs
- Rules that issue a literal `role` claim with a hardcoded `Administrator` value
- Rules using `EXISTS([Type == "..."])` patterns that bypass `MultiFactorAuthentication = true` requirements
- Relying parties that have not been touched in 24+ months — often shadow IT or shut-down apps

Tighten or remove. Document changes. Test each relying party in a UAT environment before pushing to production.

## Step 6: Detection — the Event IDs you need in your SIEM

The full ADFS detection cheat sheet for SIEM ingestion. Forward these from the ADFS server's `Security` log and `AD FS/Admin` log:

| Event ID | Source | Meaning | Detection idea |
|---|---|---|---|
| **1200** | AD FS/Admin | Token issuance success | Volume by user — sudden spike from a service account = Golden SAML candidate |
| **1201** | AD FS/Admin | Token issuance failure | Authentication failed |
| **1202** | AD FS/Admin | Token validation success | Sanity counter |
| **1203** | AD FS/Admin | Token validation failure | Replay attempt or expired token |
| **411** | AD FS/Admin | Token request validation failure | Often password-spray |
| **412** | AD FS/Admin | Sign-in authentication failure | Pair with 411 — user behind the password is failing |
| **510** | AD FS/Admin | Configuration database change | Should be rare; any 510 outside change windows = investigate |
| **501** | AD FS/Admin | Federation metadata change | Watch for unauthorised RP additions |
| **4104** | PowerShell/Operational | PowerShell scriptblock | Look for `mimikatz`, `ADFSDump`, `Export-PfxCertificate`, `Get-AdfsCertificate` content from non-admin sessions |

**Splunk rule example** for Golden SAML detection (issuance volume anomaly):

```spl
index=adfs source="*/AD FS/Admin*" EventCode=1200
| bucket _time span=1h
| stats count by _time, src_user
| eventstats avg(count) as baseline_avg, stdev(count) as baseline_stdev by src_user
| where count > (baseline_avg + 3 * baseline_stdev)
| eval severity="high", reason="Anomalous ADFS token issuance volume"
```

## Step 7: Defending against mimikatz / ADFSDump extraction

The Golden SAML kill chain has three phases. Disrupt any one and Golden SAML fails:

1. **Local SYSTEM on the ADFS server** — required for both mimikatz and ADFSDump. Defended by ADFS Tier 0 isolation, LAPS, and modern endpoint hardening (Credential Guard, LSA Protection, ASR rules) per the [Windows 11 enterprise hardening guide](/tutorials/windows-11-enterprise-hardening/).
2. **DPAPI master key extraction** — mimikatz reads the master key from `lsadump::dpapi`. Mitigations: Credential Guard (which protects LSA), HSM-backed signing cert (no DPAPI involvement), and proper service-account permissions (the cert is encrypted with the service account's DPAPI master key — if the SA is gMSA, harder to extract).
3. **Signing key access in the ADFS config DB** — even with the DPAPI master key, the attacker needs read access to the WID/SQL configuration database. The DB lives at `C:\Windows\WID\Data\` (Windows Internal Database) or in SQL Server for ADFS farms. Restrict NTFS / SQL permissions to the ADFS service account only.

**Detection complement:** Any time `lsass.exe` is read by a non-SYSTEM process, OR `mimikatz` or `ADFSDump` keywords appear in PowerShell scriptblock logs from an ADFS server, that's a high-fidelity alarm.

## Migration path to Microsoft Entra ID

ADFS won't last forever. Microsoft's current default identity stack is Entra ID; new tenants don't use ADFS at all. A typical decommission plan:

| Phase | Duration | Activity |
|---|---|---|
| **Discovery** | 2-4 weeks | Inventory every relying party trust. Classify: trivially-migratable (SAML/WS-Fed/OAuth) vs requires-app-change vs decommission-candidate. |
| **Pilot migration** | 4-6 weeks | Move 2-3 low-risk relying parties to Entra ID. Validate sign-in, MFA, conditional access policies. |
| **Bulk migration** | 3-6 months | Migrate relying parties in batches of 5-10. Each batch: backup ADFS config, configure on Entra side, repoint metadata, validate, sunset on ADFS. |
| **Long-tail** | 6-12 months | The remaining apps (legacy WS-Trust, custom SAML quirks) get individual treatment. Many decommission-candidates get retired. |
| **ADFS sunset** | After last RP migrated | Decommission ADFS farm. Retain WAP/AD-FS audit logs in cold storage for compliance retention. |

The Entra ID side has stronger MFA story, native conditional access, continuous access evaluation, and risk-based sign-in — all hard or impossible to build on ADFS. For most environments, the migration pays for itself in reduced operational burden alone.

## Common mistakes (and how to avoid them)

| Mistake | Why it happens | Fix |
|---|---|---|
| Never rotating the token-signing certificate | "Set and forget" | Annual rotation minimum; quarterly recommended; immediate after suspected compromise |
| Tier-1 admins logging on to ADFS servers | Convenience | Restrict local logon via GPO; enforce ADFS-Admins-only |
| Extranet Lockout left disabled | Default off in older ADFS | Enable in smart-enforce mode; review thresholds quarterly |
| WS-Trust 1.3 still proxied to internet | "We might need it for X" | Audit usage first; disable; only re-enable for documented exceptions with IP restrictions |
| Claim rules accumulating over years | No quarterly review | Quarterly Get-AdfsRelyingPartyTrust dump + diff vs baseline |
| ADFS service account is a regular AD user | Legacy install pattern | Migrate to gMSA |
| No SIEM ingestion of ADFS Event IDs | "ADFS is just identity, not interesting" | ADFS is the highest-value target — forward 1200/1201/1202/411/412 with priority |
| Token-signing key on disk (not HSM) | Default install | HSM for the signing cert; the operational lift pays back at the first incident |
| No baseline of token issuance volume per user | Anomaly detection needs baseline | 30-day baseline by user; alert on >3σ deviation |
| ADFS server patched late | "It's working, don't touch it" | Patch within 14 days of release; treat ADFS like a DC for patch cadence |
| WAP and ADFS on same subnet | Network design ignored Tier 0 | WAP in DMZ; ADFS in Tier 0 VLAN; firewall between |
| No Entra ID migration plan | "We'll do it next quarter" | Document a 12-month plan with quarterly milestones |

## Frequently asked questions

{{< faq >}}
- q: "What is ADFS in Active Directory?"
  a: "**Active Directory Federation Services (ADFS)** is Microsoft's on-premises identity federation server. It authenticates users against Active Directory and issues SAML 2.0, WS-Federation, or OAuth 2.0 tokens that downstream applications (Office 365, Salesforce, ServiceNow, custom SaaS) trust. It's how on-prem AD identities sign in to cloud and SaaS apps without exposing AD credentials directly to those apps."

- q: "Is ADFS deprecated in 2026?"
  a: "Microsoft has not formally deprecated ADFS but has clearly signalled Entra ID as the modern path — new Microsoft tenants don't use ADFS at all, and feature development is concentrated in Entra. ADFS remains supported and patched, but if you're starting fresh, choose Entra ID. If you have ADFS, plan a 6-12 month decommission."

- q: "What is the Golden SAML attack?"
  a: "Golden SAML is when an attacker who has extracted the ADFS token-signing private key uses it to mint arbitrary SAML tokens for any user, including the most privileged. Once an attacker has the signing key, they no longer need to authenticate against AD — they generate tokens directly. The 2020 SolarWinds incident was the highest-profile real-world example. Defence: rotate the signing key, protect it with HSM if possible, harden the ADFS host to Tier 0 standards."

- q: "How do I detect a Golden SAML attack?"
  a: "There's no perfect signature for Golden SAML because the forged tokens are cryptographically valid. But three detection patterns help: (1) **volume anomaly on Event 1200** — sudden spike in token issuance for an account that doesn't normally request that many; (2) **issuance from impossible source IPs** — forged tokens sometimes don't include accurate `IPAddress` claims; (3) **token claims that don't match AD state** — a forged token claiming Domain Admin membership when AD doesn't have that user in DA right now. Add all three as Splunk/Sentinel rules."

- q: "Does mimikatz work against ADFS?"
  a: "Yes — specifically mimikatz's `lsadump::dpapi` and `vault::cred` modules can extract the DPAPI master key used to encrypt the ADFS token-signing certificate. The certificate itself is then extracted from the ADFS configuration database. Dedicated tools like ADFSDump (Mandiant) and aadinternals automate the extraction. Mitigations: Credential Guard, LSA Protection (RunAsPPL), HSM for signing keys, and strict Tier 0 isolation of ADFS servers."

- q: "Should I disable WS-Trust 1.3 on my ADFS?"
  a: "Yes, in most modern environments. WS-Trust 1.3 (and 2005) endpoints accept username/password directly and **do not enforce MFA** — they're the password-spray surface ADFS exposes. Audit first: query your ADFS logs for any clients still authenticating via WS-Trust. Common holdouts are old ActiveSync clients and legacy SaaS connectors. Plan migrations for those, then disable."

- q: "How often should I rotate the ADFS token-signing certificate?"
  a: "Annually at minimum; quarterly for security-conscious environments; immediately (with a second rotation 14 days later) after any suspected compromise. The rotation cycle is straightforward: generate the new cert, wait 7-14 days for relying parties to pick it up via federation metadata, promote the new cert to primary, then remove the old. Microsoft documents this in `Update-AdfsCertificate`."

- q: "What's the difference between ADFS and Entra ID (Azure AD)?"
  a: "**ADFS** is on-premises federation — runs on your Windows servers, federates your on-prem AD to relying parties. **Entra ID** (formerly Azure AD) is cloud-native identity — Microsoft runs it, you configure it, sign-ins terminate at Entra. Entra has materially stronger MFA, conditional access, continuous evaluation, and risk-based sign-in features. If you're starting in 2026, choose Entra. If you have ADFS, plan a migration."

- q: "Can I run ADFS and Entra ID at the same time?"
  a: "Yes — hybrid federation with ADFS handling some relying parties and Entra ID handling others is supported and common during migrations. Configure each relying party independently. The typical migration arc: 100% ADFS → 80% ADFS / 20% Entra → 30% / 70% → 0% / 100% (ADFS decommissioned)."

- q: "What Event IDs should I monitor on ADFS for security?"
  a: "**1200** (token issuance success — watch for volume anomalies per user), **1201** (issuance failure — paired with 411 for auth failures), **1202** (validation success), **1203** (validation failure — possible replay), **411 / 412** (request validation / sign-in failure — password spray indicators), **510** (configuration database change — should be rare and during change windows only), **501** (federation metadata change — watch for unauthorised RP additions), plus **PowerShell Event 4104** for scriptblock logs (look for mimikatz, ADFSDump, certificate export commands). Forward all to your SIEM."
{{< /faq >}}

## Conclusion: rotate the cert this sprint

The single highest-value action you can take this week: **rotate the ADFS token-signing certificate.** Even if you do nothing else from this guide, that one action invalidates any stolen signing key an attacker might already hold. The full rotation cycle (generate new → wait for relying parties to pick up metadata → promote to primary → remove old) takes 2-3 weeks calendar time but maybe 30 minutes of admin work.

Then layer in:
1. **Tier 0 lockdown** of ADFS servers (restricted local logon, LAPS, gMSA)
2. **Extranet Lockout** in smart-enforce mode
3. **WS-Trust 1.3 disable** after auditing legacy client dependencies
4. **SIEM ingestion** of Events 1200/1201/1202/411/412 from every ADFS server
5. **Quarterly claim-rule audit** with documented changes

That's a complete ADFS hardening posture inside a quarter. Pair with the [Windows 11 enterprise hardening guide](/tutorials/windows-11-enterprise-hardening/) for the underlying OS controls (Credential Guard, LSA Protection, ASR rules) that make mimikatz extraction substantially harder, and the [Windows LAPS implementation guide](/tutorials/windows-laps-implementation/) for the local-admin rotation that keeps the ADFS service account uncompromisable.

Eventual end-state: ADFS decommissioned in favour of Entra ID. Until then, treat ADFS as Tier 0.

## Share this guide

**LinkedIn**:
> ADFS is the single highest-value target in any federated identity stack — and most enterprises haven't rotated their token-signing cert in years. The Golden SAML defence playbook: cert rotation, Tier 0 isolation, Extranet Lockout, WS-Trust 1.3 disable, and the Event IDs your SIEM must ingest. 👇

**X / Twitter**:
> ADFS hardening priority list: (1) rotate the token-signing cert (2) Tier-0 lockdown the server (3) Extranet Lockout in enforce mode (4) disable WS-Trust 1.3 (5) ingest Events 1200/1201/411/412. Anything else after that is incremental. Full guide:

## References

- [Microsoft Learn: AD FS overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/ad-fs-overview)
- [Microsoft Learn: Best practices for securing AD FS](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/deployment/best-practices-securing-ad-fs)
- [Microsoft: Configure AD FS Extranet Smart Lockout](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/operations/configure-ad-fs-extranet-smart-lockout-protection)
- [Mandiant: Detecting Microsoft 365 and ADFS Attack Tools (Golden SAML)](https://www.mandiant.com/resources/blog/detecting-microsoft-365-azure-active-directory-backdoors) — the foundational Golden SAML detection paper
- [ADFSDump (Doug Bienstock, Mandiant)](https://github.com/mandiant/ADFSDump)
- [MITRE ATT&CK T1606.002 — Forge Web Credentials: SAML Tokens](https://attack.mitre.org/techniques/T1606/002/)
- [Microsoft: Migrate from AD FS to Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/migrate-from-federation-to-cloud-authentication)
- [CISA Alert AA21-008A — SolarWinds supply chain compromise](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-008a) — real-world Golden SAML in practice
