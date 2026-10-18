---
title: "Windows 11 Enterprise Hardening Guide for 2026: Practical Checklist"
slug: "windows-11-enterprise-hardening"
description: "A practical Windows 11 enterprise hardening guide covering Microsoft security baselines, Defender ASR, BitLocker, Windows LAPS, Intune, Group Policy, and safe validation checks."
date: 2026-05-20T10:30:00Z
lastmod: 2026-10-18T00:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["Tutorials"]
tags: ["windows-11", "windows-hardening", "endpoint-security", "microsoft-defender", "attack-surface-reduction", "intune", "group-policy", "cis-benchmark", "credential-guard", "bitlocker", "windows-security", "zero-trust", "ransomware-protection"]
series: ["Windows Hardening"]
keywords: [
  "Windows 11 hardening",
  "Windows 11 security",
  "Windows 11 hardening guide",
  "Windows 11 enterprise security",
  "Windows 11 security best practices",
  "how to harden Windows 11 for enterprise",
  "Windows 11 security checklist 2026",
  "best Windows 11 security settings",
  "enterprise Windows hardening guide",
  "how to secure Windows 11 endpoints",
  "Attack Surface Reduction rules",
  "Windows Defender hardening",
  "Microsoft Defender security",
  "Windows security checklist",
  "endpoint security",
  "Intune security policies",
  "ASR rules PowerShell",
  "Credential Guard Windows 11",
  "BitLocker TPM PIN",
  "Smart App Control",
  "Windows 11 Zero Trust",
  "CIS Windows 11 Benchmark",
  "Windows 11 ransomware protection"
]
toc: true
cover:
  image: "/images/articles/windows-11-enterprise-hardening.png"
  alt: "Dark grid cover card for Windows 11 Enterprise Hardening for 2026, with large high-contrast title lettering."
---

Windows 11 includes security features such as Microsoft Defender Antivirus, SmartScreen, Secure Boot, virtualization-based protections on supported hardware, and automatic security updates. Enterprise protection still depends on edition, hardware, configuration, licensing, management authority, and the applications an organization must support. This guide provides a staged way to assess and improve those controls with Microsoft Intune, Group Policy, or both.

Treat the recommendations as a starting point for a pilot, not a universal baseline. Confirm each setting against your Windows release, Microsoft Security Baseline, threat model, and business requirements. Test changes with representative devices, document exceptions, and maintain a recovery path. Commands labeled **Validation (read-only)** query local state and do not change settings. Commands labeled **Configuration** make changes and should be deployed through your normal change process.

## TL;DR — the 90-day Windows 11 hardening rollout

The phased plan you can copy into a project tracker today:

- **Days 1–7 (Phase 0):** Review the Microsoft Security Baseline for the Windows release you deploy; compare it with current policy and select a pilot group
- **Days 8–14 (Phase 1):** Identity hardening — review Credential Guard and LSA protection eligibility, Windows Hello for Business, [Windows LAPS](/tutorials/windows-laps-implementation/)
- **Days 15–21 (Phase 2):** Network hardening — review SMB signing, SMBv1, name-resolution protocols, DNS design, and firewall policy
- **Days 22–35 (Phase 3):** Attack Surface Reduction (ASR) — pilot selected rules, review events and application impact, then deploy in stages
- **Days 36–42 (Phase 4):** Microsoft Defender hardening — cloud protection, tamper protection, Controlled Folder Access, Network Protection
- **Days 43–49 (Phase 5):** Application Control — evaluate Smart App Control and App Control for Business (formerly WDAC), SmartScreen, and Office macro policy
- **Days 50–56 (Phase 6):** BitLocker policy, recovery-key escrow, and removable-media requirements
- **Days 57–63 (Phase 7):** Privilege management — reduce standing local admin, use supported elevation workflows, assess [NTLM reduction](/tutorials/disable-ntlm-windows/)
- **Days 64–77 (Phase 8):** Logging & detection — PowerShell logging, Windows event policy, optional Sysmon, and forwarding to a monitored destination
- **Days 78–84 (Phase 9):** OS surface reduction — review AutoPlay, optional components, diagnostics policy, and update rings
- **Days 85–90 (Phase 10):** Access controls — evaluate Conditional Access, device compliance, and supported continuous-access scenarios

This is an example schedule, not a guaranteed completion time. Adjust the phases to fleet size, policy ownership, application testing, licensing, and change windows; do not compress testing to meet an arbitrary date.

## Why Windows 11 hardening matters in 2026

The right priorities depend on the data, threat model, endpoint roles, and regulatory obligations in your environment. Start with Microsoft's current Windows security baseline, identify gaps against your own requirements, and pilot high-impact controls before broad deployment. Neither a checklist nor a benchmark score establishes compliance by itself; map controls to the specific framework and scope you must meet.

## The hardening framework (10 phases at a glance)

| # | Phase | Primary controls | Tooling |
|---|---|---|---|
| 1 | **Identity & Auth** | Credential Guard, LSA protection, Windows Hello for Business, Windows LAPS | GPO + Intune |
| 2 | **Network** | SMB signing, SMBv1 inventory, name-resolution policy, firewall rules | GPO + Intune |
| 3 | **ASR Rules** | 19 ASR rules in Defender for Endpoint | Intune + PS |
| 4 | **Defender Hardening** | Cloud protection, CFA, Network Protection, Tamper Protection | Intune + PS |
| 5 | **Application Control** | App Control for Business, SmartScreen, Office macro policy | Intune + GPO |
| 6 | **Encryption** | BitLocker, recovery, removable-media policy | GPO + Intune |
| 7 | **Privilege Mgmt** | Least privilege, approved elevation, NTLM transition | GPO + Intune |
| 8 | **Logging** | PS scriptblock, module, transcript, Sysmon, WEF | GPO + Intune |
| 9 | **Surface Reduction** | AutoPlay policy, optional-feature review, diagnostics policy | GPO + Intune |
| 10 | **Zero Trust** | Conditional Access, device compliance, continuous eval | Entra ID |

Use the phases as an assessment and rollout sequence. The management path and available settings can vary by Windows version, edition, ADMX templates, Intune policy type, and co-management configuration, so validate the applicable [Microsoft Security Baseline](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines) and policy documentation before deployment.

## How to harden Windows 11 for enterprise (10-phase rollout)

{{< howto title="How to plan a Windows 11 enterprise hardening rollout" duration="PT90D" >}}
- name: "Import the security baseline"
  text: "Use the Microsoft Security Compliance Toolkit to review the baseline for the Windows release you deploy. Compare it with existing GPOs, pilot approved settings in a test OU or device group, and record intentional deviations before expanding deployment."
- name: "Enable identity hardening: Credential Guard + LSA Protection + WHfB + LAPS"
  text: "Check Microsoft’s hardware and join-state requirements for Credential Guard and LSA protection; both are enabled by default on some eligible Windows 11 22H2+ installations. Pilot Windows Hello for Business and configure [Windows LAPS](/tutorials/windows-laps-implementation/) to rotate and back up local administrator passwords. These controls reduce credential exposure but do not eliminate credential theft."
- name: "Review legacy network protocols, SMB signing, and DNS policy"
  text: "Inventory dependencies before disabling legacy protocols. Disable SMBv1 where present, review LLMNR and NetBIOS name-resolution policy, and use Microsoft’s SMB signing defaults for supported releases. Avoid blanket mDNS, WPAD, or DNS-over-HTTPS changes until you have tested discovery, proxy, and domain DNS requirements. Keep inbound firewall rules limited to documented business needs."
- name: "Pilot Attack Surface Reduction rules and expand in stages"
  text: "Choose rules based on Microsoft’s current ASR reference and your security baseline. Deploy with Intune’s Endpoint security → Attack surface reduction policy, start with a representative pilot, and use Defender reporting plus local events to evaluate impact. Microsoft recommends Block mode for standard-protection rules, with documented compatibility exceptions such as Configuration Manager’s use of WMI; test other rules with your applications instead of relying on a fixed 14-day window."
- name: "Harden Microsoft Defender: cloud protection, CFA, Network Protection, Tamper Protection"
  text: "Use a single authoritative management channel for Defender settings where possible. Configure cloud-delivered protection, sample submission, Controlled Folder Access, and Network Protection through the appropriate Defender or Intune policy, after testing privacy and application impact. Manage Tamper Protection through supported Defender/Intune policy and verify the policy state centrally; local preference commands do not replace that management path."
- name: "Lock down application execution: Smart App Control, WDAC, SmartScreen, macros"
  text: "Evaluate Smart App Control on eligible clean installations and understand its limited manageability before enabling it. For enterprise policy control, consider App Control for Business (formerly WDAC): build and test a policy in audit mode before enforcement. Configure Windows and Edge SmartScreen separately, and retain Office’s internet-macro blocking policy unless a documented exception is required."
- name: "Configure BitLocker and plan recovery"
  text: "Enable BitLocker on supported devices and confirm that recovery information is escrowed and accessible to authorized responders. Choose TPM-only or preboot PIN based on physical-access risk, device usability, and Microsoft’s hardware guidance; do not describe TPM-only as universally insecure. XTS-AES 128-bit is the Windows default; use 256-bit when required by policy or regulation. Set removable-media rules to match data-handling requirements."
- name: "Reduce standing privilege and stage NTLM reduction"
  text: "Review local Administrators membership and remove standing access where application and support workflows allow. Use a managed elevation solution such as Intune Endpoint Privilege Management or an approved privileged-access workflow. Entra PIM governs supported Entra roles and groups; it is not by itself a local endpoint elevation policy. Audit NTLM usage before following the staged [NTLM reduction guide](/tutorials/disable-ntlm-windows/)."
- name: "Implement selected logging and central monitoring"
  text: "Select PowerShell and Windows audit events that support your detection and retention needs. Protect logs because script-block and transcription records can contain sensitive data. If you deploy Sysmon, use a reviewed, version-controlled configuration and test event volume. Forward selected logs to a monitored destination through WEF, Azure Monitor Agent, or your supported SIEM connector."
- name: "Integrate with Zero Trust: Conditional Access, device compliance, continuous evaluation"
  text: "Design Conditional Access policies for your identity and application environment. Use report-only mode and emergency-access exclusions while testing policies that require MFA or a compliant device. Define a supported Intune compliance baseline and verify that device enrollment, licensing, and user sign-in flows work before enforcing access. Continuous Access Evaluation and risk-based controls apply only to supported services and licensed scenarios."
{{< /howto >}}

The remaining sections expand each phase with the implementation detail you need.

## Phase 1: Identity & Authentication

Four controls. Deploy in this order.

### Credential Guard

[Credential Guard](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/configure) uses virtualization-based security to isolate selected LSA secrets. It can reduce credential-theft risk, but it does not make credential theft or pass-the-hash impossible. Since Windows 11 22H2, it is enabled by default on eligible devices that meet Microsoft’s requirements; support depends on hardware, configuration, and device state. Check the current Microsoft deployment and known-issues guidance before forcing a UEFI lock or rolling it out to a mixed fleet.

**Validation (read-only):**

{{< terminal title="PowerShell — read-only" >}}
# Query VBS and security-service state; this does not change configuration
$dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard'
[pscustomobject]@{
  VBSStatus = $dg.VirtualizationBasedSecurityStatus # 2 = running
  CredentialGuardRunning = 1 -in $dg.SecurityServicesRunning
  MemoryIntegrityRunning = 2 -in $dg.SecurityServicesRunning
}
{{< /terminal >}}

**Configure centrally:** In Group Policy, use `Computer Configuration → Administrative Templates → System → Device Guard → Turn On Virtualization Based Security`. Select the Credential Guard option appropriate to the device lifecycle. Microsoft recommends enabling it before domain join or the first domain sign-in when possible. Intune Settings Catalog and the DeviceGuard CSP are also supported. An enabled UEFI lock requires physical or firmware-assisted recovery steps to disable; use it only when your recovery process accounts for that constraint.

**Compatibility:** Credential Guard can affect software that depends on older authentication methods or incompatible drivers. Test VPN, credential, and management workflows in a representative pilot and consult Microsoft’s current known-issues list. `msinfo32.exe` and the System log provide supported ways to confirm runtime state; do not treat a single registry value as proof that the hypervisor-based service is running.

### LSA Protection (RunAsPPL)

LSA protection runs LSASS as a protected process and restricts loading of untrusted code into it. It raises the bar for credential theft but is not a guarantee against every technique or a substitute for Defender, patching, and least privilege. Added LSA protection is enabled by default on eligible enterprise-joined Windows 11 22H2+ installations that meet Microsoft’s HVCI capability requirements; verify the actual runtime state.

**Configure centrally:** Use `Computer Configuration → Administrative Templates → System → Local Security Authority → Configure LSASS to run as a protected process`, or a supported Intune policy. On Windows 11 22H2 and later, Microsoft documents `RunAsPPL` value `1` (with UEFI variable) and `2` (without UEFI variable); policy is preferable for managed fleets. Apply changes through change control and restart as required.

**Validation (read-only):** Confirm policy result in Group Policy/Intune, then review the System log for Wininit LSA-protection events and `Microsoft-Windows-CodeIntegrity/Operational` for compatibility blocks. A configured policy or `RunAsPPL` registry value alone does not prove protection is active.

**Compatibility:** Test security, credential, and authentication software before enforcement. Review Code Integrity events and Microsoft’s LSA-protection troubleshooting guidance for blocked plug-ins or drivers; remediate with supported vendor versions rather than suppressing the control without an exception record.

### Windows Hello for Business

Windows Hello for Business uses a device-bound key or certificate to authenticate users, with a PIN or supported biometric gesture as the local unlock method. Configure through the current Intune account-protection/Settings Catalog or supported Group Policy settings for your deployment model. Select cloud Kerberos trust, key trust, or certificate trust based on Microsoft’s current identity requirements; certificate trust is not a universal requirement for hybrid environments. Set PIN and biometric options according to risk and user needs, and test registration, recovery, and sign-in before broad deployment.

### Windows LAPS

Windows LAPS manages and backs up a local account password to Microsoft Entra ID or Windows Server Active Directory, depending on the device and policy. See the [Windows LAPS implementation guide](/tutorials/windows-laps-implementation/), and cross-check its steps against Microsoft’s current Windows LAPS documentation: cloud and AD deployments have different prerequisites, and DSRM backup is a domain-controller scenario, not a Windows client hardening step.

## Phase 2: Network Security

Review these controls against required file-sharing, name-resolution, and proxy workflows. Avoid disabling protocols indiscriminately; record dependencies and test the resulting policy on a pilot ring.

### Disable SMBv1

**Validation (read-only):**

{{< terminal title="PowerShell — read-only" >}}
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol |
  Select-Object FeatureName, State
{{< /terminal >}}

To remove SMBv1 where it is installed and no dependency remains, use the Windows optional-feature management tooling through your approved deployment process. This change can require a restart. Verify client and server components separately where they are present; don't run a removal command before checking application and device dependencies.

SMBv1 is an obsolete protocol associated with serious vulnerabilities. Microsoft recommends removing or disabling it where it is not required. Identify affected systems and upgrade or isolate devices that still depend on it rather than silently breaking business workflows.

### Enforce SMB signing required

Windows 11 24H2 requires inbound and outbound SMB signing by default on Pro, Enterprise, and Education editions. Other Windows versions and Windows Server have different defaults. For systems where a policy is needed, the legacy GPO settings are in `Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options`:

- `Microsoft network server: Digitally sign communications (always)` = **Enabled**
- `Microsoft network client: Digitally sign communications (always)` = **Enabled**

SMB signing protects SMB message integrity and helps prevent relay attacks. Third-party NAS and guest-share configurations can be incompatible with required signing; inventory and test these connections before changing policy. **Validation (read-only):** use `Get-SmbClientConfiguration` and `Get-SmbServerConfiguration` to inspect the client and server signing requirements.

### Review name resolution and proxy discovery

| Setting | Recommended review |
|---|---|
| **LLMNR** | If not needed, enable `Turn off multicast name resolution` in `Computer Configuration → Administrative Templates → Network → DNS Client`. Validate local-name discovery and fallback behavior. |
| **NetBIOS over TCP/IP** | Inventory legacy applications and networks. Microsoft provides the `Configure NetBIOS settings` policy under `Computer Configuration → Administrative Templates → Network → DNS Client`; choose a setting appropriate for each network profile. |
| **mDNS** | Do not disable it with `Set-NetTCPSetting` (that parameter does not exist). mDNS supports local service discovery; if you need to restrict it, test app dependencies and apply a supported network/firewall policy. |
| **WPAD / automatic proxy discovery** | Do not disable `WinHttpAutoProxySvc` fleet-wide as a generic hardening step. Review your proxy design and disable automatic discovery only where the organization uses an explicitly configured proxy and has tested WinHTTP clients. |

LLMNR and NetBIOS can disclose or enable spoofing of local name-resolution traffic. Treat them as network-specific controls, not a reason to disable every discovery feature on every device. Microsoft exposes [supported DNS Client policies](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-dnsclient) for LLMNR and NetBIOS; use those rather than undocumented adapter properties.

### DNS over HTTPS (DoH)

Windows 11 can use DoH with compatible DNS resolvers. DoH encrypts DNS transport between the client and resolver; it does not replace DNS security, endpoint protection, or network controls. For enterprise devices, confirm that resolver discovery, certificates, domain-joined name resolution, VPN behavior, and split DNS are supported before requiring encrypted-only DNS. Microsoft documents [DNS-over-HTTPS configuration](https://learn.microsoft.com/en-us/windows-server/networking/dns/doh-client-support), `Add-DnsClientDohServerAddress` to add a resolver, and `Set-DnsClientDohServerAddress` to modify one already configured.

**Configuration example (changes local resolver configuration):** Prefer a centrally managed policy. For a controlled test device, replace the placeholders and use the documented `Add-DnsClientDohServerAddress` parameters only after confirming the resolver endpoint and certificate:

{{< terminal title="Administrator: PowerShell — configuration" >}}
Add-DnsClientDohServerAddress -ServerAddress '<resolver IP>' `
  -DohTemplate 'https://<resolver-host>/dns-query' `
  -AllowFallbackToUdp $false -AutoUpgrade $true
{{< /terminal >}}

**Validation (read-only):** `Get-DnsClientDohServerAddress` displays configured DoH resolvers. This reports resolver configuration, not proof that every DNS query used HTTPS.

### Firewall lockdown

Windows Defender Firewall normally blocks unsolicited inbound traffic by default. Confirm that all profiles are enabled and that organization-managed rules permit only required traffic. Configure through `Computer Configuration → Windows Settings → Security Settings → Windows Defender Firewall with Advanced Security`. Avoid disabling the firewall during troubleshooting as a workaround.

**Validation (read-only):**

{{< terminal title="PowerShell — read-only" >}}
Get-NetFirewallProfile -Profile Domain,Private,Public |
  Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
{{< /terminal >}}

## Phase 3: Attack Surface Reduction rules (the 19-rule reference)

ASR rules in Microsoft Defender Antivirus target behavior commonly used by malware, such as Office child processes, obfuscated scripts, and credential theft. Available rules and their prerequisites can change. Microsoft classifies a subset as standard-protection rules; the remaining rules should be selected, piloted, and tuned against the organization’s app inventory. Use Microsoft’s [ASR overview](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction) and [current rule reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference) for supported management methods, rule actions, exclusions, and event IDs.

**Rule GUID reference:** The names and GUIDs below reflect Microsoft’s ASR reference at review time. Check the linked source before deployment; Microsoft can add or revise rules and applicability.

| Rule | GUID |
|---|---|
| Block abuse of exploited vulnerable signed drivers | `56a863a9-875e-4185-98a7-b882c64b5ce5` |
| Block Adobe Reader from creating child processes | `7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c` |
| Block all Office applications from creating child processes | `d4f940ab-401b-4efc-aadc-ad5f3c50688a` |
| Block credential stealing from the Windows local security authority subsystem | `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2` |
| Block executable content from email client and webmail | `be9ba2d9-53ea-4cdc-84e5-9b1eeee46550` |
| Block executable files from running unless they meet a prevalence, age, or trusted list criterion | `01443614-cd74-433a-b99e-2ecdc07bfc25` |
| Block execution of potentially obfuscated scripts | `5beb7efe-fd9a-4556-801d-275e5ffc04cc` |
| Block JavaScript or VBScript from launching downloaded executable content | `d3e037e1-3eb8-44c8-a917-57927947596d` |
| Block Office applications from creating executable content | `3b576869-a4ec-4529-8536-b80a7769e899` |
| Block Office applications from injecting code into other processes | `75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84` |
| Block Office communication application from creating child processes | `26190899-1602-49e8-8b27-eb1d0a1ce869` |
| Block persistence through WMI event subscription | `e6db77e5-3df2-4cf1-b95a-636979351e5b` |
| Block process creations originating from PSExec and WMI commands | `d1e49aac-8f56-4280-b9ba-993a6d77406c` |
| Block rebooting machine in Safe Mode | `33ddedf1-c6e0-47cb-833e-de6133960387` |
| Block untrusted and unsigned processes that run from USB | `b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4` |
| Block use of copied or impersonated system tools | `c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb` |
| Block Webshell creation for Servers | `a8f5898e-1dc8-49a9-9878-85004b8a61e6` |
| Block Win32 API calls from Office macros | `92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b` |
| Use advanced protection against ransomware | `c1db55ab-c21a-4637-bb3f-a12568109d35` |

**Validation (read-only):**

{{< terminal title="PowerShell — read-only" >}}
$pref = Get-MpPreference
for ($i = 0; $i -lt $pref.AttackSurfaceReductionRules_Ids.Count; $i++) {
  [pscustomobject]@{
    RuleId = $pref.AttackSurfaceReductionRules_Ids[$i]
    Action = $pref.AttackSurfaceReductionRules_Actions[$i]
  }
}

Get-WinEvent -FilterHashtable @{
  LogName = 'Microsoft-Windows-Windows Defender/Operational'
  Id = 1121, 1122
} -MaxEvents 25 -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, Id, Message
{{< /terminal >}}

The query displays locally reported ASR state and recent block/audit events; it does not change policy. Centrally managed settings can override local preferences, so use Intune or Defender reporting as the source of truth for managed devices. Event availability and retention depend on policy and the device.

**Event IDs:**
- `1121` — ASR rule blocked an action
- `1122` — ASR rule audited an action (would have blocked)
- `5007` — Defender preference change

## Phase 4: Microsoft Defender hardening

Defender Antivirus behavior depends on whether it is active, passive, or managed by another endpoint-protection product. Use the current Microsoft Defender security baseline and select one authoritative management channel—such as Intune endpoint security or Defender for Endpoint security settings management—to reduce policy conflicts. Avoid applying a long list of local `Set-MpPreference` values without checking the supported policy, platform, privacy, and false-positive implications.

Review cloud-delivered protection, sample-submission consent, potentially unwanted application protection, Network Protection, and Controlled Folder Access against Microsoft guidance and your incident-response needs. Higher cloud-block levels can increase false positives; test before broad deployment. For Controlled Folder Access, use audit mode and review events before enforcing; grant only reviewed applications the access they need.

**Tamper Protection** is managed through supported Defender/Intune policy. In Intune, use an Antivirus policy with the Windows Security experience profile; Microsoft Defender for Endpoint onboarding and licensing prerequisites apply. Do not claim local `Set-MpPreference` can enable Tamper Protection, and do not assume the setting is available in every tenant or management configuration.
See Microsoft’s [Tamper Protection configuration and status guidance](https://learn.microsoft.com/en-us/defender-endpoint/tamper-protection-windows-configure) for current management prerequisites.

**Validation (read-only):**

{{< terminal title="PowerShell — read-only" >}}
Get-MpComputerStatus |
  Select-Object AMRunningMode, AMServiceEnabled, AntivirusEnabled,
    RealTimeProtectionEnabled, IsTamperProtected

Get-MpPreference |
  Select-Object MAPSReporting, SubmitSamplesConsent, CloudBlockLevel,
    EnableControlledFolderAccess, EnableNetworkProtection, PUAProtection
{{< /terminal >}}

These commands query local Defender state. A passive-mode device or centrally managed endpoint may show different local values; verify assignment, conflicts, and policy status in your management console as well.

## Phase 5: Application Control

Application control complements antivirus and SmartScreen by enforcing policy about which applications can run. Select and test controls according to device role and software inventory.

### Smart App Control

Smart App Control uses Microsoft’s app-intelligence service and code-signing information to assess apps. It is available only on eligible clean installations of Windows 11. Evaluation mode determines whether the feature is suitable for that installation; it is not an administrator-managed audit policy. Turning it off can require a reset or clean installation before it can be re-enabled, so assess compatibility and recovery implications first. Its settings are in `Windows Security → App & browser control → Smart App Control settings`. For managed enterprise allow/deny policy, evaluate [App Control for Business](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/) instead.

### App Control for Business (formerly WDAC)

App Control for Business lets administrators author and deploy application-control policies. A generic policy built by scanning `C:\` on a live endpoint can include temporary files, miss software installed elsewhere, or produce a policy that does not suit another device role; do not copy a one-line `New-CIPolicy` command into production. Start from Microsoft’s recommended policy design, define trusted signers and update/rollback ownership, then collect audit data across representative devices before enforcement. Microsoft’s App Control Policy Wizard and current deployment guidance document supported authoring options.

**Validation (read-only):** Review `Applications and Services Logs → Microsoft → Windows → CodeIntegrity → Operational` for policy load and audit/enforcement events. On supported Windows releases, `CiTool.exe -lp -json` lists active App Control policies. Confirm deployed policy IDs and modes in the management system; audit-mode events alone do not mean a policy is enforcing.

### SmartScreen

Configure Windows shell SmartScreen and Edge SmartScreen separately. Microsoft recommends enabling the Windows Explorer SmartScreen policy with **Warn and prevent bypass**, enabling SmartScreen in Edge, and enabling Edge policies that prevent bypass of warnings for sites and downloads. `Configure App Install Control` restricts downloaded apps from outside Microsoft Store; it is a separate policy and does not replace SmartScreen. Use the current Microsoft policy documentation to select the matching GPO, Intune, or CSP settings.

### Block Office macros from the internet

For Microsoft 365 Apps for enterprise, enable the per-application **Block macros from running in Office files from the Internet** policy where appropriate. Recent Office versions also block internet-origin macros by default in many cases, but trusted locations, trusted documents, and Mark-of-the-Web behavior affect the outcome. Check current Office documentation and your Office version before relying on a default.

Use separate macro policies only where they address an explicit requirement; disabling macros broadly can disrupt signed business workflows and is not the same as blocking macros tagged as internet-origin. Avoid adding broad trusted locations to bypass the internet-macro control.

## Phase 6: BitLocker and recovery

Enable BitLocker on supported endpoints and manage recovery-key escrow before deployment. TPM-only startup is a supported configuration and can be appropriate on modern devices with Secure Boot and DMA protections. A preboot PIN can add protection in higher-risk situations, but introduces user friction and may affect sleep, preboot input, Autopilot, or recovery workflows. Select the protector based on the threat model, device capabilities, and Microsoft’s [current BitLocker guidance](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/configure) rather than treating one option as universal.

**GPO path:** `Computer Config → Admin Templates → Windows Components → BitLocker Drive Encryption → Operating System Drives`:

- For devices that require a preboot PIN, configure `Require additional authentication at startup` and `Configure TPM startup PIN` to match the approved policy.
- If enhanced PINs are allowed, verify that the preboot environment supports the chosen characters.
- Set a minimum PIN length only when using PIN protectors; Microsoft documents supported ranges and platform considerations.
- Set `Choose drive encryption method and cipher strength` to XTS-AES. Windows uses XTS-AES 128-bit by default; choose 256-bit when policy, regulation, or risk assessment calls for it.

**Removable media:** `Removable Data Drives → Deny write access to removable drives not protected by BitLocker = Enabled`.

**Recovery-key escrow:** Use Intune policy for Entra-joined or Intune-managed endpoints, or the supported BitLocker Group Policy for AD DS backup. Restrict recovery-key access, monitor escrow failures, and test the recovery process. A local status check does not prove that the recovery key has reached Entra ID or AD DS.

**Validation (read-only):**

{{< terminal title="PowerShell — read-only" >}}
Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus, EncryptionMethod,
  ProtectionStatus, @{Name='ProtectorTypes';Expression={$_.KeyProtector.KeyProtectorType -join ', '}}
{{< /terminal >}}

Interpret results against your chosen policy: confirm the OS volume is protected and encrypted with the expected method, and that its protectors match the design. Check escrow separately in Entra ID or AD DS.

## Phase 7: Privilege management

Review local Administrators membership and remove standing access where application and support workflows allow. Use a tested Group Policy or Intune local-group policy. The Group Policy **Restricted Groups** setting can enforce an exact membership list; members not included in that list may be removed, so test the resulting group membership before applying it broadly. Intune’s Local users and groups policy or another approved management method may be more appropriate for your fleet.

```text
Computer Configuration → Policies → Windows Settings → Security Settings → Restricted Groups
  → Administrators → Members of this group: <explicit approved membership>
```

Use an explicit inventory and change plan. Do not put high-privilege domain accounts on workstations unless the administrative-tier model requires it.

**UAC at maximum:**

Use the applicable UAC policies under `Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options`. Configure the administrator elevation prompt, Admin Approval Mode, and secure desktop behavior to match your workstation/server tier and usability needs. Validate the impact on software deployment and support tooling before enforcing a stricter prompt.

**Elevation workflows:** Entra Privileged Identity Management governs supported Entra roles and groups; it does not automatically broker local Windows elevation. For endpoints, consider Intune Endpoint Privilege Management or a vetted privileged-access product. Avoid ad hoc group-add scripts unless they have strong authentication, narrow scope, expiry, audit, and rollback controls.

Reduce NTLM only after auditing usage and addressing compatibility. Disabling it can break legacy applications and trust paths, and it does not remove every credential-relay risk. Follow the staged [NTLM reduction guide](/tutorials/disable-ntlm-windows/) and document exceptions.

**Validation (read-only):** On a local endpoint, `Get-LocalGroupMember -Group 'Administrators'` lists current members. Review the result against the approved per-device role; this command does not change group membership.

## Phase 8: Logging & detection

The goal is to collect useful security events, protect them from unauthorized access, retain them for a defined period, and assign someone to review detections.

### PowerShell logging trio

GPO: `Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell`:

- `Turn on Module Logging = Enabled`, with modules selected for your investigation needs. Logging `*` increases volume and may record sensitive arguments.
- `Turn on PowerShell Script Block Logging = Enabled` (Event 4104)
- `Turn on PowerShell Transcription = Enabled` only with a protected destination, access controls, retention, and a plan for sensitive content.

Script Block Logging records script blocks processed by PowerShell in Event 4104. It can help investigation, but it is not a complete record of every command or a guarantee that all obfuscation is decoded. Logs may include credentials, tokens, or personal data; Microsoft’s [PowerShell logging guidance](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1) recommends Protected Event Logging when enabling this outside diagnostics. Define access, encryption, retention, and forwarding before broad rollout.

### Sysmon

Sysmon is an optional system-monitoring service that can add process, network, file, and registry telemetry. It is not a replacement for endpoint protection, and there is no universally correct third-party configuration. If your detection program needs Sysmon, review the Microsoft Sysinternals documentation, pin the version and configuration you deploy, test event volume, and maintain updates through change control.

{{< terminal title="PowerShell — read-only" >}}
Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue |
  Select-Object Name, Status, StartType

Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 5 `
  -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, ProviderName
{{< /terminal >}}

### Audit policy

Choose audit subcategories based on your threat model, Microsoft baseline, and event-volume capacity. Common starting points include:

- **Account Logon → Credential Validation:** Success and Failure
- **Account Management → User Account Management, Computer Account Management:** Success and Failure
- **Detailed Tracking → Process Creation:** Success (with command-line auditing GPO enabled)
- **Logon/Logoff → Logon, Logoff, Special Logon:** Success and Failure
- **Object Access → File Share, File System (selectively):** Success and Failure
- **Policy Change → Audit Policy Change:** Success and Failure
- **Privilege Use → Sensitive Privilege Use:** evaluate Success and Failure for noise and storage impact

For Event 4688 command-line capture, enable `Computer Configuration → Administrative Templates → System → Audit Process Creation → Include command line in process creation events`. Command lines can contain secrets or personal data; restrict access and set retention accordingly. Use `auditpol /get /category:*` to inspect the current audit policy (read-only).

### Forward to SIEM

Use Windows Event Forwarding, Azure Monitor Agent, or your supported SIEM connector where central monitoring is required. Select channels according to detections and retention requirements; forwarding every channel can increase ingestion cost and expose sensitive data. Test that alerts are actionable and that an owner responds to them.

## Phase 9: OS surface reduction

Review these settings against current Windows 11 policy documentation and your fleet inventory:

| Setting | GPO / Action | Why |
|---|---|---|
| **AutoPlay** | Review `Computer Configuration → Administrative Templates → Windows Components → AutoPlay Policies` and disable where removable-media workflows do not require it. | Reduces automatic actions when media is attached. |
| **Diagnostic data** | Use the current Windows 11 `Allow Diagnostic Data` policy and Microsoft privacy documentation. “Security” was the former name for the Enterprise/Education “Diagnostic data off” setting; it is not a general network-exposure control. | Aligns collection with organizational privacy requirements. |
| **Optional components** | Inventory installed features and remove only components not required by the device role. Do not run a comma-separated blanket removal command across IIS, WCF, or other features without checking dependencies. | Reduces unused functionality without breaking applications. |
| **Update rings** | Use Intune update rings, feature-update policies, and deadlines to meet the organization’s patch SLA; pilot servicing changes and track failed installs. | Keeps devices supported and security-patched. |
| **PowerShell 2.0** | Windows 11 24H2 no longer includes Windows PowerShell 2.0. Check OS build instead of running a removal command intended for older releases. | Retire any legacy script dependency; Windows PowerShell 5.1 and PowerShell 7 are separate versions. |

## Phase 10: Zero Trust integration

Endpoint configuration can provide signals used by identity and access policies. Conditional Access is a separate Entra control plane and needs careful testing, emergency access, and applicable licensing.

### Conditional Access policies

Plan policies by user, target resource, device state, and authentication method. Common scenarios include requiring multifactor authentication, requiring a compliant or hybrid-joined device for selected resources, and blocking legacy authentication clients that cannot satisfy modern controls. Use Microsoft’s current licensing and application-support documentation. Policies for session controls, unmanaged-device downloads, and user or sign-in risk depend on the target service and licensing.

Start new policies in **report-only** mode, review sign-in impact, and maintain documented emergency-access accounts and monitoring. Avoid broad policy combinations that can lock out administrators or interrupt service principals and other noninteractive workloads.

### Device compliance (Intune)

Select compliance signals that are available for your Windows edition, enrollment type, and Intune policy. Typical checks include:

- BitLocker = enabled
- Secure Boot = enabled
- TPM = present and ready
- OS version meets the current servicing and security-update policy
- Antivirus = active
- Antispyware = active
- Firewall = active
- OS minimum version and threat-protection state appropriate to the update policy

Intune compliance is a policy result, not a universal Windows endpoint health verdict. Confirm the policy is assigned and devices have checked in. Conditional Access blocks access only when a matching policy is enabled and the target app supports the selected controls.

### Continuous Access Evaluation

Continuous Access Evaluation (CAE) supports selected Microsoft services and events, allowing supported services to respond to certain critical events without waiting for the normal token lifetime. It is not a universal “real-time revocation” switch for every app. Confirm application support and policy behavior in Microsoft’s current CAE documentation before relying on it in an incident-response procedure.

## Ransomware resilience and recovery

Endpoint controls can reduce the chance or impact of ransomware, but no single setting prevents every attack. Combine tested Defender configuration, least privilege, reliable patching, and backups that an attacker cannot easily alter. Use Controlled Folder Access and applicable ASR rules only after checking application compatibility; Microsoft documents their prerequisites and management modes.

For backup resilience, keep protected copies separated from ordinary endpoint and domain credentials, restrict administrative access, and test restoration of representative files and systems. Define recovery objectives and record when the last restore test succeeded. An immutable copy can help, but immutability alone does not prove that backups are complete or recoverable.

## CIS Microsoft Windows 11 Enterprise Benchmark alignment

CIS publishes Windows desktop benchmarks with profiles intended for different levels of security and operational impact. Download the current benchmark from CIS and map its recommendations to the exact Windows release, edition, and device roles in scope. A benchmark checklist or score does not by itself establish compliance with a regulation, prove that controls are effective, or mean that this article is formally CIS-validated. Test benchmark settings before deploying them and document approved deviations.

## Choosing the management method: GPO, Intune, and local tools

| Method | Suitable use | Considerations |
|---|---|---|
| **Group Policy** | Domain-joined Windows devices and existing AD policy workflows | Review GPO precedence, ADMX template version, scope, and conflicts with MDM or security products. |
| **Microsoft Intune** | Enrolled Windows devices managed through MDM and endpoint-security policy | Confirm tenant, enrollment, platform, licensing, and policy prerequisites. Prefer security policy profiles for their intended settings. |
| **PowerShell** | Read-only inventory, supported one-off administration, and testing | Local preferences can be overridden by policy and do not provide assignment, compliance reporting, or drift management. The validation commands in this guide are read-only. |
| **Microsoft Security Compliance Toolkit** | Reviewing and comparing Microsoft security baselines and GPO configurations | Compare recommended settings with existing policy; import only after review and pilot testing. |
| **App Control for Business** | Centrally managed application-control policy | Requires policy design, audit analysis, deployment ownership, and rollback planning. |

Avoid configuring the same setting through competing channels without understanding precedence. Record the authoritative policy source and verify the resulting state on representative devices.

## Example 90-day implementation roadmap

Use this schedule as a planning template, not a promised duration. Larger or more regulated fleets may need longer pilots, staged exception handling, or separate schedules for workstations, servers, developers, and privileged-access workstations.

| Window | Milestone | Evidence to keep |
|---|---|---|
| Days 1–14 | Inventory OS builds, hardware capability, policy sources, critical apps, and recovery access; compare the current Microsoft baseline | Device inventory, baseline comparison, risk register, approved pilot group |
| Days 15–28 | Pilot identity controls, LAPS, local-admin reduction, and BitLocker recovery workflow | Policy assignment results, test-device evidence, recovery test record |
| Days 29–42 | Review SMB, name-resolution, firewall, and Defender ASR policy | Compatibility findings, audit events, exceptions with owners and expiry |
| Days 43–56 | Test Defender, SmartScreen, Office macro, and App Control policies | False-positive review, rollback steps, sign-off by app owners |
| Days 57–70 | Deploy selected logging and forward useful events to a monitored destination | Event-volume estimate, access/retention settings, alert owner |
| Days 71–90 | Enforce approved controls by ring, review compliance and exceptions, test recovery | Deployment report, open risks, restore-test result, next review date |

Move a control to the next ring only when owners understand the user impact, support process, and rollback. Use measured rollout data rather than a target percentage to decide whether the deployment is ready to expand.

## Common hardening mistakes and safer alternatives

| Mistake | Better approach |
|---|---|
| Enabling every ASR rule in Block mode on day one | Follow Microsoft’s standard-protection recommendations, pilot other rules, and review the current ASR report and exceptions. |
| Requiring TPM+PIN and XTS-AES 256 on every device without a risk reason | Match startup protectors and cipher strength to physical-access risk, hardware, regulation, and usability requirements. |
| Applying Restricted Groups without checking current membership | Test the exact resulting local Administrators membership and retain an access-recovery path. |
| Setting firewall defaults without testing services | Keep firewall profiles enabled and allow only documented traffic; validate management and business connectivity. |
| Disabling LLMNR, mDNS, WPAD, or NetBIOS with ad hoc commands | Use supported policy only after identifying dependencies and the network scope. |
| Treating local Defender preferences as the source of truth | Confirm the assigned Intune/Defender/GPO policy and check for conflicts between management channels. |
| Enabling Script Block Logging without protecting logs | Limit access, use protected logging where appropriate, and set retention based on privacy and incident-response needs. |
| Enforcing Conditional Access without report-only testing | Review sign-in impact and maintain monitored emergency-access accounts before enforcement. |
| Removing optional Windows components by bulk command | Inventory each feature and validate its dependencies before targeted removal. |

## Windows 11 enterprise hardening audit checklist

Use the downloadable [Windows 11 Hardening Checklist](</downloads/windows-11-enterprise-hardening-checklist.csv>) to assign an owner, record status, attach evidence, document exceptions, and schedule review dates. The spreadsheet-friendly CSV is designed for an internal control tracker; it contains no macros or scripts.

A useful review record should answer:

- Is the control applicable to this device role and Windows release?
- Which policy source configures it, and which team owns that policy?
- What evidence shows the control is configured and operating as intended?
- What application, user, or recovery impact was tested?
- If there is an exception, who approved it and when does it expire?
- When will the team revalidate the policy, assignment, and recovery process?

### Read-only PowerShell validation examples

These commands query local configuration or event state; they do not change policy. Run them from an appropriately authorized PowerShell session. A local result is not proof of tenant-wide deployment: compare it with Intune, Group Policy, or Defender reporting.

**Windows release, Defender, encryption, and firewall:**

{{< terminal title="PowerShell — read-only" >}}
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsBuildNumber
Get-MpComputerStatus | Select-Object AMRunningMode, AntivirusEnabled, RealTimeProtectionEnabled, IsTamperProtected
Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus, EncryptionMethod, ProtectionStatus
Get-NetFirewallProfile -Profile Domain,Private,Public |
  Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
{{< /terminal >}}

**Credential protection and local administrator membership:**

{{< terminal title="PowerShell — read-only" >}}
$dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard'
[pscustomobject]@{
  VBSStatus = $dg.VirtualizationBasedSecurityStatus
  CredentialGuardRunning = 1 -in $dg.SecurityServicesRunning
  MemoryIntegrityRunning = 2 -in $dg.SecurityServicesRunning
}
Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue |
  Select-Object Name, ObjectClass, PrincipalSource
{{< /terminal >}}

**SMB signing, DoH configuration, audit policy, and recent PowerShell events:**

{{< terminal title="PowerShell — read-only" >}}
Get-SmbClientConfiguration | Select-Object RequireSecuritySignature, EnableSecuritySignature
Get-SmbServerConfiguration | Select-Object RequireSecuritySignature, EnableSecuritySignature
Get-DnsClientDohServerAddress | Select-Object ServerAddress, DohTemplate, AutoUpgrade, AllowFallbackToUdp
auditpol /get /category:*
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} `
  -MaxEvents 10 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id
{{< /terminal >}}

A successful query only confirms what that local API reports. Validate policy assignment and effective configuration separately, and avoid copying commands that modify state into a “check” script.

## Frequently asked questions

{{< faq >}}
- q: "How do I harden Windows 11 for enterprise use?"
  a: "Start with the Microsoft Security Baseline for the Windows release you deploy. Inventory management sources and application dependencies, then pilot identity controls, Defender and ASR, firewall/network policy, BitLocker, least privilege, logging, and application control in staged rings. Use the read-only checks in this guide to inspect local state, and confirm fleet-wide assignment in Intune, Group Policy, or Defender reporting. Keep an exception and recovery process."

- q: "Can I harden Windows 11 Pro the same way as Enterprise?"
  a: "Many core controls are available across Windows editions, but exact policy support varies by feature, edition, hardware, management enrollment, and licensing. Check the applicability tables for each Microsoft policy or CSP; do not assume a setting described for Enterprise is available on Pro. Use the current Microsoft Security Baseline and your Intune/Group Policy management documentation to build an edition-specific plan."

- q: "What is the most important Windows 11 security setting?"
  a: "There is no single setting that protects every endpoint. A strong starting point is to keep supported devices patched, use Defender and firewall protections, reduce standing local administrator access, enable BitLocker with recoverable escrow, and configure Microsoft’s recommended baseline. Prioritize based on exposure and test each change against business workflows."

- q: "How long does it take to harden a Windows 11 enterprise environment?"
  a: "Timing depends on fleet size, application diversity, policy ownership, change windows, and recovery requirements. This article offers a 90-day planning example, not a guaranteed deadline. Keep enough time for a representative pilot, compatibility review, staged enforcement, and recovery testing."

- q: "Do I need Intune to harden Windows 11, or can Group Policy do everything?"
  a: "It depends on which controls and device types you manage. Group Policy is commonly used for AD-joined devices; Intune provides MDM and endpoint-security policies for enrolled devices. Some features have different prerequisites or management paths. Verify each policy’s current Microsoft documentation and avoid configuring the same setting through conflicting management channels."

- q: "What are Attack Surface Reduction rules and which should I enable?"
  a: "ASR rules in Microsoft Defender Antivirus restrict behaviors commonly abused by malware. Microsoft’s reference lists rule IDs, prerequisites, management support, and recommended modes, and can change over time. Use the standard-protection recommendations where applicable; pilot and review other rules against your applications. Check the current ASR documentation rather than treating this article’s GUID list as a permanent configuration baseline."

- q: "Should I require a BitLocker PIN or is TPM-only enough?"
  a: "TPM-only is a supported BitLocker configuration and can be appropriate on modern devices with Secure Boot and DMA protections. A preboot PIN may be justified by physical-access risk or policy, but affects usability and may introduce hardware and recovery constraints. Choose the startup protector based on Microsoft guidance, device capabilities, and your threat model; escrow and test recovery information either way."

- q: "How does Windows 11 hardening map to Zero Trust?"
  a: "Intune compliance can provide a device state that Conditional Access evaluates for supported apps. Define compliance signals that fit your enrollment, Windows edition, and update policy, test assignments in report-only or pilot mode, and keep emergency-access procedures. Endpoint hardening and Conditional Access are related controls but neither automatically configures the other."

- q: "How do I align Windows 11 hardening with the CIS Benchmark?"
  a: "Download the current Windows desktop benchmark from CIS, choose a profile appropriate to your system roles, and map each applicable recommendation to the correct Windows release and policy source. Pilot changes, document exceptions, and use an approved assessment method. A benchmark score is evidence for review, not proof of regulatory compliance or effective protection."

- q: "Does enabling Credential Guard break anything?"
  a: "Credential Guard can affect software that depends on older authentication methods or incompatible drivers. Review Microsoft’s current known-issues documentation, test VPN and management workflows on representative hardware, and verify Credential Guard is actually running after deployment. Keep a tested recovery path before enabling a UEFI lock."

- q: "What's the difference between Smart App Control and WDAC?"
  a: "Smart App Control is designed for eligible clean Windows 11 installations and uses Microsoft's app intelligence and signing information; its evaluation and on/off lifecycle limit central enterprise customization. App Control for Business (formerly Windows Defender Application Control or WDAC) supports organization-authored policies with audit and enforcement modes. Choose based on the required manageability, device role, compatibility, and deployment capacity."
{{< /faq >}}

## Conclusion: hardening is a rollout, not a checkbox

Use this guide as a planning aid alongside the current Microsoft Security Baseline and the policy documentation for your Windows release. Start with an inventory, select controls that address your risks, verify them on pilot devices, and keep evidence of policy assignment, exceptions, and recovery tests. The downloadable checklist helps teams assign owners and review the result over time.

For controls that need separate implementation guides, continue with [Windows LAPS](/tutorials/windows-laps-implementation/) and the staged [NTLM reduction guide](/tutorials/disable-ntlm-windows/). Before enforcing application control or Conditional Access, confirm compatibility and recovery access with the teams responsible for the affected devices and users. For help planning a rollout, [contact our team](/contact/).

## Share this guide

**LinkedIn**:
> Planning Windows 11 enterprise hardening? This practical guide covers Microsoft security baselines, Defender ASR, BitLocker, Windows LAPS, application control, logging, Intune, Group Policy, and safe read-only validation commands. It also includes a downloadable checklist for tracking owners, evidence, exceptions, and review dates. 👇

**X / Twitter**:
> Windows 11 hardening works best as a tested rollout: review Microsoft’s baseline, pilot identity and Defender controls, validate encryption and recovery, reduce standing admin access, then enforce policy in stages. This guide includes read-only PowerShell checks and a downloadable audit checklist:

## References

- [Microsoft Security Baselines for Windows](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines)
- [Microsoft Security Compliance Toolkit guide](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10)
- [Credential Guard configuration and verification](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/configure)
- [LSA protection configuration](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
- [Windows LAPS overview](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
- [ASR rules overview](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction)
- [ASR rule names, GUIDs, prerequisites, and deployment support](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)
- [Defender cloud protection configuration](https://learn.microsoft.com/en-us/defender-endpoint/cloud-protection-configure)
- [Configure and verify Tamper Protection](https://learn.microsoft.com/en-us/defender-endpoint/tamper-protection-windows-configure)
- [BitLocker configuration](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/configure)
- [SMB security hardening](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security-hardening)
- [Detect and disable SMBv1](https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3)
- [Windows SmartScreen policy settings](https://learn.microsoft.com/en-us/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen/available-settings)
- [Office macros from the internet](https://learn.microsoft.com/en-us/deployoffice/security/internet-macros-blocked)
- [Smart App Control overview](https://learn.microsoft.com/en-us/windows/apps/develop/smart-app-control/overview)
- [App Control for Business overview and deployment guidance](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/)
- [Configure Windows diagnostic data](https://learn.microsoft.com/en-us/windows/privacy/configure-windows-diagnostic-data-in-your-organization)
- [Windows features removed from client releases](https://learn.microsoft.com/en-us/windows/whats-new/removed-features)
- [PowerShell logging and Protected Event Logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1)
- [Microsoft Entra Conditional Access planning](https://learn.microsoft.com/en-us/entra/identity/conditional-access/plan-conditional-access)
- [Microsoft Intune compliance settings for Windows](https://learn.microsoft.com/en-us/Intune/device-security/compliance/ref-windows-settings)
- [CIS Microsoft Windows desktop benchmarks](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)

Recommendations and links reviewed on October 18, 2026. Microsoft and CIS documentation can change; confirm applicability and settings in the linked current documentation before implementation.
