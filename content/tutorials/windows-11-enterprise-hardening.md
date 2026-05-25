---
title: "Windows 11 Enterprise Hardening Guide for 2026 (Complete Checklist)"
slug: "windows-11-enterprise-hardening"
description: "Complete Windows 11 enterprise hardening for 2026: ASR rules, Defender config, LAPS, BitLocker + PIN, Credential Guard, Intune & GPO, aligned with CIS Benchmark v3."
date: 2026-05-20T10:30:00Z
lastmod: 2026-05-20T10:30:00Z
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
  alt: "Complete Windows 11 enterprise hardening guide for 2026"
---

A default-installed Windows 11 endpoint in 2026 has eight major attack surfaces enabled out of the box that should not be: NTLM authentication, LM/NTLMv1 fallback in many cases, unsigned-driver execution, LSASS access from non-protected processes, BitLocker without PIN, Office macros from internet sources, SmartScreen passable via mark-of-the-web bypass, and PowerShell without script-block logging. This **Windows 11 enterprise hardening guide for 2026** is the consolidated 10-phase rollout that closes every one of those gaps — aligned with the CIS Microsoft Windows 11 Enterprise Benchmark, Microsoft's Security Baselines, and the operational realities of running a multi-thousand-endpoint fleet under Intune, Group Policy, or both.

If you operate a Windows 11 enterprise environment and you've been waiting for a guide that goes deeper than "turn on Defender," this is it. Every phase has concrete PowerShell, the exact GPO and Intune CSP path, real ASR rule GUIDs, a "what breaks" warning, and a roll-back recipe.

## TL;DR — the 90-day Windows 11 hardening rollout

The phased plan you can copy into a project tracker today:

- **Days 1–7 (Phase 0):** Baseline import — Microsoft Security Baseline + CIS Benchmark Level 1 GPO into a staging OU
- **Days 8–14 (Phase 1):** Identity hardening — Credential Guard, LSA Protection, Windows Hello for Business, [Windows LAPS](/tutorials/windows-laps-implementation/)
- **Days 15–21 (Phase 2):** Network hardening — SMB signing, disable SMBv1/LLMNR/NetBIOS/mDNS/WPAD, DoH, firewall lockdown
- **Days 22–35 (Phase 3):** Attack Surface Reduction (ASR) — all 19 rules in **audit** mode for 14 days before any switch to block
- **Days 36–42 (Phase 4):** Microsoft Defender hardening — cloud protection, tamper protection, Controlled Folder Access, Network Protection
- **Days 43–49 (Phase 5):** Application Control — Smart App Control, WDAC base policy, SmartScreen at maximum, block macros from internet
- **Days 50–56 (Phase 6):** BitLocker + PIN, removable media policy, encrypted Recovery Partition
- **Days 57–63 (Phase 7):** Privilege management — remove standard users from local Administrators, JIT admin, UAC at maximum, [NTLM disable](/tutorials/disable-ntlm-windows/)
- **Days 64–77 (Phase 8):** Logging & detection — PowerShell scriptblock + module logging, Sysmon (Olaf Hartong config), WEF/AMA to SIEM, audit policy at CIS Level 1
- **Days 78–84 (Phase 9):** OS surface reduction — disable autoplay, Cortana web search, telemetry to Security level, optional features review
- **Days 85–90 (Phase 10):** Zero Trust integration — Conditional Access policies, device compliance, risk-based sign-in, continuous evaluation

Total: 90 days for a measured, audit-friendly rollout. Aggressive teams can compress to 45.

## Why Windows 11 hardening matters in 2026

Four numbers that frame the priority:

- **80%+ of ransomware incidents** in Microsoft's 2024 Digital Defense Report involved credential-abuse paths that ASR rules + Credential Guard + LAPS would have blocked.
- **94% of malware** observed in IBM's 2024 X-Force Threat Index was delivered through email or web — exactly what Smart App Control, MOTW enforcement, and the email-execution ASR rule are designed to stop.
- **The median dwell time** before detection of a Windows endpoint compromise in 2024 was **10 days** (Mandiant M-Trends). PowerShell scriptblock logging + Sysmon forwarded to a SIEM compresses that to hours.
- **CIS Microsoft Windows 11 Enterprise Benchmark v3** has 365 settings. The 80/20 hit comes from ~60 of them — the ones in this guide.

Hardening Windows 11 isn't optional for any organization processing regulated data (HIPAA, PCI DSS, NIST 800-171, ISO 27001). It's also a hard requirement for cyber insurance — the 2025 application questionnaires from major carriers (Beazley, AIG, Chubb) explicitly ask about MFA, LAPS, EDR, ASR rules, BitLocker, and PowerShell logging. "No" to any of these is now a coverage-affecting answer.

## The hardening framework (10 phases at a glance)

| # | Phase | Primary controls | Tooling |
|---|---|---|---|
| 1 | **Identity & Auth** | Credential Guard, LSA Protection, WHfB, LAPS | GPO + Intune |
| 2 | **Network** | SMB signing, disable SMBv1/LLMNR/NetBIOS/WPAD, DoH | GPO + PS |
| 3 | **ASR Rules** | 19 ASR rules in Defender for Endpoint | Intune + PS |
| 4 | **Defender Hardening** | Cloud protection, CFA, Network Protection, Tamper Protection | Intune + PS |
| 5 | **Application Control** | Smart App Control, WDAC, SmartScreen, macro blocking | Intune + GPO |
| 6 | **Encryption** | BitLocker + TPM 2.0 + PIN, removable media | GPO + Intune |
| 7 | **Privilege Mgmt** | Remove from local admin, UAC max, JIT, NTLM disable | GPO + PIM |
| 8 | **Logging** | PS scriptblock, module, transcript, Sysmon, WEF | GPO + Intune |
| 9 | **Surface Reduction** | Disable autoplay, Cortana, optional features, telemetry | GPO + Intune |
| 10 | **Zero Trust** | Conditional Access, device compliance, continuous eval | Entra ID |

Each phase below is self-contained: prerequisites, what to set, the exact path, the verification command, and the failure modes.

## How to harden Windows 11 for enterprise (10-phase rollout)

{{< howto title="How to harden Windows 11 for enterprise in 90 days" duration="PT90D" >}}
- name: "Import the security baseline"
  text: "Download the **Microsoft Security Baseline for Windows 11 24H2** from the Microsoft Security Compliance Toolkit. Import the GPO objects into a staging OU. Also reference **CIS Microsoft Windows 11 Enterprise Benchmark v3** Level 1 settings (Level 2 for high-security tier). Baseline first, then layer organisation-specific deltas — never start from scratch."
- name: "Enable identity hardening: Credential Guard + LSA Protection + WHfB + LAPS"
  text: "Enable **Credential Guard** (UEFI virtualisation-based security) and **LSA Protection** (RunAsPPL = 1) — both block credential theft from `lsass.exe`. Deploy **Windows Hello for Business** for passwordless. Deploy [Windows LAPS](/tutorials/windows-laps-implementation/) for local admin rotation. These four controls together eliminate the most-abused credential attack paths."
- name: "Harden the network: disable legacy protocols, enforce SMB signing, switch to DoH"
  text: "Disable **SMBv1** (`Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol`), **LLMNR** (GPO: Turn off multicast name resolution), **NetBIOS over TCP/IP**, **mDNS**, **WPAD**. Enforce **SMB signing required** on both client and server. Configure **DNS over HTTPS** (`Set-DnsClientDohServerAddress`). Lock the Windows Firewall to default-deny inbound."
- name: "Enable Attack Surface Reduction rules in audit mode for 14 days, then block"
  text: "Deploy all 19 ASR rules in **Audit** mode first via Intune (`Endpoint security → Attack surface reduction`) or PowerShell (`Set-MpPreference -AttackSurfaceReductionRules_Ids ... -AttackSurfaceReductionRules_Actions AuditMode`). Watch Event ID 1122 in `Microsoft-Windows-Windows Defender/Operational` for hits. After 14 days, flip the production-safe rules to **Block** (Action = Enabled), keep the noisy ones in Audit."
- name: "Harden Microsoft Defender: cloud protection, CFA, Network Protection, Tamper Protection"
  text: "`Set-MpPreference -MAPSReporting Advanced -SubmitSamplesConsent SendSafeSamples -DisableBlockAtFirstSeen $false -CloudBlockLevel High -EnableControlledFolderAccess Enabled -EnableNetworkProtection Enabled`. Enable **Tamper Protection** via Intune (cannot be set locally). Tamper Protection is the single most important Defender setting — it stops attackers from disabling AV via registry/PS."
- name: "Lock down application execution: Smart App Control, WDAC, SmartScreen, macros"
  text: "**Smart App Control** on (Win 11 22H2+ clean installs only). **WDAC** base policy in audit mode → enforce within 30 days. **SmartScreen** for Apps and Edge at Block. Block all **Office macros from the internet** via GPO (`Block macros from running in Office files from the Internet`). Block **VBA macros in trusted documents** for high-risk users (finance, legal)."
- name: "Encrypt with BitLocker + TPM 2.0 + PIN"
  text: "BitLocker with TPM-only is **insecure** against an attacker with physical access (DMA attacks, cold-boot residuals). Require **TPM + PIN** for all enterprise endpoints. Use **XTS-AES 256** encryption. Configure removable media policy: BitLocker To Go required, or block writes to unencrypted removable media. Store recovery keys in Entra ID (Intune) or AD."
- name: "Eliminate standing privilege: remove from local admin, UAC max, JIT access, disable NTLM"
  text: "Remove standard users from the local **Administrators** group. Set **UAC = Always notify** (Consent Prompt = 2). Adopt **Just-in-Time (JIT)** admin via Entra PIM or third-party PAM — no permanent admins. Disable NTLM via [the NTLM removal guide](/tutorials/disable-ntlm-windows/). The combination is what red teams hate most."
- name: "Enable comprehensive logging: PowerShell + Sysmon + audit policy + SIEM forwarding"
  text: "Turn on PowerShell **ScriptBlock logging** (Event 4104), **Module logging** (Event 4103), and **Transcription**. Deploy **Sysmon** with Olaf Hartong's modular config (or SwiftOnSecurity baseline). Enable **CIS Level 1 audit policy** (Account Logon, Logon/Logoff, Object Access, Privilege Use). Forward via **Windows Event Forwarding (WEF)** or **Azure Monitor Agent (AMA)** to your SIEM. Without forwarding, you have logs nobody reads."
- name: "Integrate with Zero Trust: Conditional Access, device compliance, continuous evaluation"
  text: "Enforce **Conditional Access** policies on every cloud app: require compliant device + MFA. Configure **device compliance** in Intune: BitLocker on, secure boot, OS version >= 24H2, AV active. Enable **Continuous Access Evaluation** so token revocation is real-time. Add **risk-based sign-in policies** in Entra ID Premium P2. This is the final layer: identity-aware access on top of an already-hardened endpoint."
{{< /howto >}}

The remaining sections expand each phase with the implementation detail you need.

## Phase 1: Identity & Authentication

Four controls. Deploy in this order.

### Credential Guard

Virtualisation-based security (VBS) that runs LSASS secrets in an isolated VTL1 enclave. Mimikatz, lsadump-style attacks, and pass-the-hash become **impossible against domain credentials**. Available on Win 10 1607+, default-on for Win 11 22H2+ on clean installs of Enterprise/Education SKUs.

**Verification:**

{{< terminal title="Administrator: PowerShell" >}}
# Check VBS + Credential Guard status
$dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard'
$dg.VirtualizationBasedSecurityStatus      # 2 = running
$dg.SecurityServicesRunning                # contains 1 = CredGuard, 2 = HVCI
$dg.AvailableSecurityProperties            # 1 BaseVirtualizationSupport, 2 SecureBoot, 3 DMA Protection
{{< /terminal >}}

**Enable via GPO (if not default-on):**
`Computer Config → Admin Templates → System → Device Guard → Turn On Virtualization Based Security` → `Enabled`, with `Credential Guard Configuration = Enabled with UEFI lock`.

**What breaks:** Some old VPN clients (Cisco AnyConnect pre-4.10), some Citrix Receiver versions, legacy biometric drivers. Audit list of known-incompatible drivers with `mdmdiagnosticstool.exe -Area DeviceGuard`.

### LSA Protection (RunAsPPL)

Stops non-PPL (Protected Process Light) code from injecting into `lsass.exe`. Blocks `procdump lsass.exe` and most reflective DLL injection.

{{< terminal title="Administrator: PowerShell" >}}
# Enable PPL on LSASS
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -Type DWord -Value 1
# Verify after reboot
(Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -MaxEvents 50 |
  Where-Object { $_.Message -match 'LSASS' }) | Format-List
{{< /terminal >}}

**What breaks:** Custom AV drivers that aren't PPL-signed. Audit for 7 days, identify any failure events (Event ID 3033 in CodeIntegrity log), get signed drivers from your vendor.

### Windows Hello for Business

Passwordless logon backed by TPM-bound asymmetric keys. Configure via Intune (`Endpoint security → Account protection → Windows Hello for Business`) or GPO (`Computer Config → Admin Templates → Windows Components → Windows Hello for Business`). Require PIN complexity (min 8 digits), biometric off for high-security tiers, certificate-trust model for hybrid AD.

### Windows LAPS

Native local Administrator password rotation. See the [full Windows LAPS implementation guide](/tutorials/windows-laps-implementation/) for the 8-step rollout: schema, KDS root key, tiered RBAC, encrypted storage, and DSRM password backup on DCs.

## Phase 2: Network Security

Five settings that together kill the most common lateral-movement techniques.

### Disable SMBv1

{{< terminal title="Administrator: PowerShell" >}}
# Check current state
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

# Remove (requires reboot)
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
{{< /terminal >}}

**Why:** SMBv1 is the protocol EternalBlue (MS17-010) exploited. Removal is a no-brainer. Any device that still requires SMBv1 (some old NAS, some MFP scan-to-share) needs an upgrade or replacement, full stop.

### Enforce SMB signing required

GPO: `Computer Config → Policies → Windows Settings → Security Settings → Local Policies → Security Options`:

- `Microsoft network server: Digitally sign communications (always)` = **Enabled**
- `Microsoft network client: Digitally sign communications (always)` = **Enabled**

SMB signing prevents the SMB→SMB relay attack that's the second most common ntlmrelayx target. Required by default since Win 11 24H2 / Server 2025; verify older builds explicitly.

### Disable LLMNR, NetBIOS, mDNS, WPAD

| Protocol | What it leaks | Disable how |
|---|---|---|
| **LLMNR** | Hashes (Responder bait) | GPO: Computer Config → Admin Templates → Network → DNS Client → `Turn off multicast name resolution = Enabled` |
| **NetBIOS over TCP/IP** | Hashes + hostnames | Per NIC: `Set-NetAdapterAdvancedProperty -Name 'Ethernet' -DisplayName 'NetBIOS over TCP/IP' -DisplayValue 'Disabled'`; or GPO via DHCP option |
| **mDNS** | Hostnames | `Set-NetTCPSetting -SettingName Internet -MDnsEnabled $false` |
| **WPAD** | Proxy hijack vector | GPO: `Disable Internet Explorer's automatic detection of proxy settings`; also `Set-Service -Name WinHttpAutoProxySvc -StartupType Disabled` |

These four are universal Responder/Inveigh bait. Disable on every workstation and server.

### DNS over HTTPS (DoH)

{{< terminal title="Administrator: PowerShell" >}}
# Configure DoH against your corporate resolver (or 1.1.1.1 as example)
Set-DnsClientDohServerAddress -ServerAddress '10.1.1.53' -DohTemplate 'https://corp-dns.local/dns-query' -AllowFallbackToUdp $false -AutoUpgrade $true
{{< /terminal >}}

Prevents passive DNS sniffing by attackers on the same broadcast domain. Pair with split-horizon DNS so internal queries still resolve through your DC.

### Firewall lockdown

Default-deny inbound on every profile. Allow only what's explicitly required (RDP from jump hosts, SMB from servers to file shares, etc.). GPO at: `Computer Config → Windows Settings → Security Settings → Windows Defender Firewall with Advanced Security` → set Inbound to Block by default for Domain, Private, **and** Public profiles.

## Phase 3: Attack Surface Reduction rules (the 19-rule reference)

The single highest-ROI Defender feature. ASR rules are heuristic blocks for common malware behaviour. Roll out **in Audit mode for 14 days** before flipping to Block — the noise rate varies wildly by environment.

**The full 19-rule table with recommended action and GUID:**

| Rule | GUID | Audit first? | Production action |
|---|---|---|---|
| Block abuse of exploited vulnerable signed drivers | `56a863a9-875e-4185-98a7-b882c64b5ce5` | Yes | **Block** |
| Block Adobe Reader from creating child processes | `7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c` | No | **Block** |
| Block all Office applications from creating child processes | `d4f940ab-401b-4efc-aadc-ad5f3c50688a` | Yes | **Block** |
| Block credential stealing from `lsass.exe` | `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2` | Yes | **Block** |
| Block executable content from email/webmail | `be9ba2d9-53ea-4cdc-84e5-9b1eeee46550` | No | **Block** |
| Block executable files unless prevalence/age/trusted | `01443614-cd74-433a-b99e-2ecdc07bfc25` | **Yes** (high noise) | Audit → Block in tier 2 only |
| Block execution of obfuscated scripts | `5beb7efe-fd9a-4556-801d-275e5ffc04cc` | Yes | **Block** |
| Block JS/VBS from launching downloaded executable | `d3e037e1-3eb8-44c8-a917-57927947596d` | No | **Block** |
| Block Office apps from creating executable content | `3b576869-a4ec-4529-8536-b80a7769e899` | No | **Block** |
| Block Office apps from injecting code into other processes | `75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84` | Yes | **Block** |
| Block Office communication app (Outlook) from child procs | `26190899-1602-49e8-8b27-eb1d0a1ce869` | No | **Block** |
| Block persistence through WMI event subscription | `e6db77e5-3df2-4cf1-b95a-636979351e5b` | No | **Block** |
| Block process creations from PSExec and WMI | `d1e49aac-8f56-4280-b9ba-993a6d77406c` | **Yes** | Block in tier 2; Audit-only for admin tier (PSExec is a legit admin tool) |
| Block reboot to Safe Mode (preview) | `33ddedf1-c6e0-47cb-833e-de6133960387` | Yes | **Block** |
| Block untrusted/unsigned processes from USB | `b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4` | No | **Block** |
| Block use of copied/impersonated system tools | `c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb` | Yes | **Block** |
| Block Webshell creation for Servers | `a8f5898e-1dc8-49a9-9878-85004b8a61e6` | Yes | **Block** (server SKUs) |
| Block Win32 API calls from Office macros | `92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b` | No | **Block** |
| Use advanced protection against ransomware | `c1db55ab-c21a-4637-bb3f-a12568109d35` | **Yes** | Audit only initially; review FPs |

**Bulk-enable in audit mode:**

{{< terminal title="Administrator: PowerShell" >}}
$rules = @(
  '56a863a9-875e-4185-98a7-b882c64b5ce5',
  '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c',
  'd4f940ab-401b-4efc-aadc-ad5f3c50688a',
  '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2',
  'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550',
  '5beb7efe-fd9a-4556-801d-275e5ffc04cc',
  'd3e037e1-3eb8-44c8-a917-57927947596d',
  '3b576869-a4ec-4529-8536-b80a7769e899',
  '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84',
  '26190899-1602-49e8-8b27-eb1d0a1ce869',
  'e6db77e5-3df2-4cf1-b95a-636979351e5b',
  'd1e49aac-8f56-4280-b9ba-993a6d77406c',
  'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4',
  '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b',
  'c1db55ab-c21a-4637-bb3f-a12568109d35'
)
foreach ($r in $rules) {
  Add-MpPreference -AttackSurfaceReductionRules_Ids $r -AttackSurfaceReductionRules_Actions AuditMode
}

# After 14 days, switch to Enabled (Block)
foreach ($r in $rules) {
  Set-MpPreference -AttackSurfaceReductionRules_Ids $r -AttackSurfaceReductionRules_Actions Enabled
}

# Monitor hits
Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' -FilterXPath "*[System[EventID=1121 or EventID=1122]]" -MaxEvents 50 |
  Format-Table TimeCreated, Id, Message -AutoSize
{{< /terminal >}}

**Event IDs:**
- `1121` — ASR rule blocked an action
- `1122` — ASR rule audited an action (would have blocked)
- `5007` — Defender preference change

## Phase 4: Microsoft Defender hardening

Default Defender is "on." Enterprise-grade Defender is configured. The full baseline:

{{< terminal title="Administrator: PowerShell" >}}
Set-MpPreference -MAPSReporting Advanced `
  -SubmitSamplesConsent SendSafeSamples `
  -CloudBlockLevel High `
  -CloudExtendedTimeout 50 `
  -DisableBlockAtFirstSeen $false `
  -DisableArchiveScanning $false `
  -DisableEmailScanning $false `
  -DisableRemovableDriveScanning $false `
  -DisableScriptScanning $false `
  -EnableControlledFolderAccess Enabled `
  -EnableNetworkProtection Enabled `
  -PUAProtection Enabled `
  -SignatureUpdateInterval 4 `
  -ScanScheduleDay Everyday `
  -ScanScheduleTime 02:00:00 `
  -RemediationScheduleDay Everyday
{{< /terminal >}}

**Tamper Protection** can only be enabled centrally via **Intune** (`Endpoint security → Antivirus → Windows Security experience → Tamper Protection`) or **Microsoft Defender for Endpoint** portal — not via Set-MpPreference. Without Tamper Protection, an attacker with local admin can simply turn off everything you just configured.

**Controlled Folder Access (CFA)** is Defender's ransomware-folder protection. After enabling, audit for 14 days (`Set-MpPreference -EnableControlledFolderAccess AuditMode`); add legitimate apps to the allow list with `Add-MpPreference -ControlledFolderAccessAllowedApplications C:\Path\To\App.exe`; then enforce.

**Network Protection** blocks outbound connections to known-bad URLs/IPs based on Microsoft's threat intelligence. Pair with Defender for Endpoint's web content filtering for category blocking.

## Phase 5: Application Control

Layered defense — each tool catches what the others miss.

### Smart App Control

A Microsoft cloud-driven application reputation engine. Only available on **clean installs of Windows 11 22H2+**. If you upgraded from Win 10, you can't enable it post-install — you need a clean re-image. The configuration is at `Windows Security → App & browser control → Smart App Control settings`. Set to **On** for general users; **Evaluation** for power users you don't want to block by default.

### WDAC (Windows Defender Application Control)

Real, kernel-enforced app whitelisting. Build a base policy from a clean reference image:

{{< terminal title="Administrator: PowerShell" >}}
# Build a base WDAC policy from a clean reference image
New-CIPolicy -FilePath C:\WDAC\BasePolicy.xml -Level Publisher -UserPEs -Fallback Hash -ScanPath C:\

# Convert to binary and copy
ConvertFrom-CIPolicy -XmlFilePath C:\WDAC\BasePolicy.xml -BinaryFilePath C:\WDAC\BasePolicy.cip

# Deploy in audit mode first (Set-RuleOption -FilePath BasePolicy.xml -Option 3)
# After 14 days of audit, remove option 3 (audit mode) and re-deploy
{{< /terminal >}}

WDAC is the highest-effort, highest-reward control on this list. Plan 4–8 weeks for a proper rollout per user persona (admin, dev, finance, etc.). Use [Microsoft's WDAC Wizard](https://webapp-wdac-wizard.azurewebsites.net/) for non-PowerShell policy authoring.

### SmartScreen

Block at every level:

GPO: `Computer Config → Admin Templates → Windows Components → Microsoft Defender SmartScreen → Configure App Install Control = Block apps from outside the Store` + `Configure Windows Defender SmartScreen = Warn and prevent bypass`.

For Edge: `Configure Windows Defender SmartScreen = Warn and prevent bypass`.

### Block Office macros from the internet

GPO: `User Config → Admin Templates → Microsoft Office 2016 → Security Settings → Block macros from running in Office files from the Internet = Enabled`.

For each app (Word, Excel, PowerPoint, Outlook, Access, PowerPoint): `<App> 2016 → Security Settings → VBA Macro Notification Settings = Disable all without notification` for high-risk users; **Disable with notification** for general fleet.

## Phase 6: BitLocker + TPM 2.0 + PIN

BitLocker with TPM-only protection is insecure against an attacker with physical access — cold-boot attacks, DMA attacks via Thunderbolt/USB-C, and PCIleech can extract keys. **Require TPM + PIN** for every enterprise endpoint.

**GPO path:** `Computer Config → Admin Templates → Windows Components → BitLocker Drive Encryption → Operating System Drives`:

- `Require additional authentication at startup` = **Enabled** with `Configure TPM startup PIN = Require startup PIN with TPM`
- `Allow enhanced PINs for startup` = **Enabled** (allows alphanumeric PIN)
- `Configure minimum PIN length for startup` = **8** characters
- `Disallow standard users from changing the PIN or password` = **Enabled** (prevents PIN downgrade)
- `Choose drive encryption method and cipher strength (Windows 10 [Version 1511] and later)` = **XTS-AES 256-bit**

**Removable media:** `Removable Data Drives → Deny write access to removable drives not protected by BitLocker = Enabled`.

**Recovery key escrow:** Intune → `Endpoint security → Disk encryption → BitLocker → Save BitLocker recovery information to Microsoft Entra ID = Yes`. For AD-joined hosts, the equivalent GPO writes recovery info to the computer object.

**Verify deployment:**

{{< terminal title="Administrator: PowerShell" >}}
Get-BitLockerVolume | Format-Table MountPoint, VolumeStatus, EncryptionMethod, ProtectionStatus, KeyProtector
{{< /terminal >}}

You want `VolumeStatus = FullyEncrypted`, `EncryptionMethod = XtsAes256`, and the `KeyProtector` list to include both `Tpm` and `TpmPin`.

## Phase 7: Privilege management

**Remove standard users from local Administrators.** This is the single highest-value control on this list. Use Restricted Groups in GPO:

```text
Computer Config → Policies → Windows Settings → Security Settings → Restricted Groups
  → Administrators → Members: DOMAIN\Domain Admins, DOMAIN\Workstation Admins
```

That declaratively sets the local Administrators group membership on every linked endpoint, removing whatever drift has accumulated.

**UAC at maximum:**

GPO: `Computer Config → Admin Templates → Windows Components → User Account Control` (and parallel Security Options) → `Behavior of the elevation prompt for administrators in Admin Approval Mode = Prompt for credentials on the secure desktop`, `Run all administrators in Admin Approval Mode = Enabled`, `Switch to the secure desktop when prompting for elevation = Enabled`.

**Just-in-Time admin access:** Use **Entra Privileged Identity Management (PIM)** for cloud roles. For on-prem admin elevation, use a third-party PAM tool (BeyondTrust, CyberArk, Delinea) or build a JIT workflow with `Just-In-Time` group-add scripts gated by ticket approval.

**Disable NTLM** to remove the credential-relay path entirely — see the full [NTLM disable guide](/tutorials/disable-ntlm-windows/).

## Phase 8: Logging & detection

The goal: **make every privileged action observable, then forward to a SIEM that someone actually reads.**

### PowerShell logging trio

GPO: `Computer Config → Admin Templates → Windows Components → Windows PowerShell`:

- `Turn on Module Logging = Enabled`, with **all** modules: `*`
- `Turn on PowerShell Script Block Logging = Enabled` (Event 4104)
- `Turn on PowerShell Transcription = Enabled`, with output to a write-only network share

PowerShell ScriptBlock logging (4104) is the single highest-value Windows event for detecting modern attacks — it captures every PowerShell script body, including decoded base64, before execution.

### Sysmon

Sysmon's process/network/file/registry events are the standard EDR baseline. Deploy with **Olaf Hartong's modular config** (community-maintained, MITRE-aligned) or **SwiftOnSecurity's baseline** if you want simpler tuning:

{{< terminal title="Administrator: PowerShell" >}}
# Download Sysmon + Hartong config
Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile $env:TEMP\Sysmon.zip
Expand-Archive -Path $env:TEMP\Sysmon.zip -DestinationPath C:\Tools\Sysmon
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml' -OutFile C:\Tools\Sysmon\config.xml

# Install
C:\Tools\Sysmon\Sysmon64.exe -accepteula -i C:\Tools\Sysmon\config.xml

# Verify
sc query Sysmon64
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 5
{{< /terminal >}}

### Audit policy

Configure to CIS Level 1 minimums. The killer subcategories:

- **Account Logon → Credential Validation:** Success and Failure
- **Account Management → User Account Management, Computer Account Management:** Success and Failure
- **Detailed Tracking → Process Creation:** Success (with command-line auditing GPO enabled)
- **Logon/Logoff → Logon, Logoff, Special Logon:** Success and Failure
- **Object Access → File Share, File System (selectively):** Success and Failure
- **Policy Change → Audit Policy Change:** Success and Failure
- **Privilege Use → Sensitive Privilege Use:** Success and Failure

Enable **command-line auditing** for Event 4688 to include the full process command line: `Computer Config → Admin Templates → System → Audit Process Creation → Include command line in process creation events = Enabled`.

### Forward to SIEM

Without forwarding, logs are a data graveyard. Use **Windows Event Forwarding (WEF)** for on-prem SIEMs or **Azure Monitor Agent (AMA)** for Sentinel/Log Analytics. Forward at minimum: Security, System, Application, PowerShell/Operational, Sysmon/Operational, Defender/Operational, AppLocker, NTLM/Operational.

## Phase 9: OS surface reduction

Small settings, real attack-surface reduction:

| Setting | GPO / Action | Why |
|---|---|---|
| **Disable Autoplay** for all media | Computer Config → Admin Templates → Windows Components → AutoPlay Policies → Turn off Autoplay = Enabled, All drives | USB drop attacks |
| **Disable Cortana web search** | Computer Config → Admin Templates → Windows Components → Search → Allow Cortana = Disabled, Allow web search = Disabled | Data leak via search |
| **Set telemetry to Security level (Enterprise only)** | Computer Config → Admin Templates → Windows Components → Data Collection → Allow Diagnostic Data = Diagnostic data off (Security only) | Privacy + reduced internet exposure |
| **Disable Optional Features** | `Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2,IIS-WebServerRole,WCF-Services45,Internet-Explorer-Optional-amd64` | Removes legacy attack surface |
| **Update Rings (Intune)** | Endpoint Security → Update Rings → Quality updates: 7d defer; Feature updates: 60d defer; Allow updates from Microsoft only | Patch within SLA, no third-party update spoofing |
| **Disable PowerShell v2** | `Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root` | v2 lacks scriptblock logging — attackers use `powershell -version 2` to evade detection |

## Phase 10: Zero Trust integration

Endpoint hardening is necessary but not sufficient — Zero Trust treats every access request as untrusted until proven otherwise.

### Conditional Access policies

In Entra ID, build these baseline policies:

1. **Require MFA for all users** (no exceptions; use break-glass accounts excluded)
2. **Require compliant device** for accessing Microsoft 365, internal apps
3. **Block legacy auth** (basic auth, IMAP, POP3, EWS, MAPI/HTTP)
4. **Block sign-in from anonymising VPNs / Tor**
5. **Require password change on high-risk sign-in** (Entra ID P2)
6. **Block downloads on unmanaged devices** for SharePoint/OneDrive

### Device compliance (Intune)

Required compliance settings for "compliant" status:

- BitLocker = enabled
- Secure Boot = enabled
- TPM = present and ready
- OS version >= 10.0.26100 (Windows 11 24H2)
- Antivirus = active
- Antispyware = active
- Firewall = active
- Code integrity = enabled
- No-jailbreak / no admin elevation = clean

Non-compliant devices are then blocked by Conditional Access — the loop is closed.

### Continuous Access Evaluation

Enable in Entra ID → Conditional Access → Session → Customise continuous access evaluation. Token revocation becomes near-real-time (typically <5 minutes) instead of waiting for token lifetime. Critical for fast response to compromised accounts.

## Ransomware-specific protections

Five settings deliberately stacked for ransomware resilience:

1. **Controlled Folder Access (enabled)** — already in Phase 4. Protects Documents, Pictures, etc. against unauthorized write.
2. **ASR rule `c1db55ab-c21a-4637-bb3f-a12568109d35`** (Use advanced protection against ransomware) — Defender's behavioral ransomware blocker.
3. **ASR rule `e6db77e5-3df2-4cf1-b95a-636979351e5b`** (Block persistence through WMI event subscription) — kills the most common backdoor for re-infection after cleanup.
4. **Block reboot to Safe Mode** (`33ddedf1-c6e0-47cb-833e-de6133960387`) — ransomware reboots to Safe Mode to evade AV; this rule blocks that.
5. **Backups: 3-2-1, with immutability** — 3 copies, 2 different media, 1 offsite, **at least one immutable**. Veeam Hardened Repository, AWS S3 Object Lock, Azure Immutable Blob.

The 3-2-1 backup with immutability is the last line of defense and the only one that survives a full domain compromise.

## CIS Microsoft Windows 11 Enterprise Benchmark alignment

The CIS Benchmark is the most widely-cited baseline. As of 2026, the current version is **v3.0.0**, with two profiles:

| Profile | Target | Settings |
|---|---|---|
| **Level 1** | General-purpose enterprise endpoints | ~280 settings; balances security and operability |
| **Level 2** | High-security / regulated environments | ~365 settings; includes restrictions that may break legacy apps |

This guide aligns with **Level 1** by default and notes Level 2 deltas where applicable (e.g., the "Block executable files unless prevalence/age/trusted" ASR rule is Level 2 only; BitLocker network unlock is Level 2 only).

**To deploy CIS automatically:** download the **CIS-CAT Pro** tool or the **CIS Build Kit** GPO templates from CIS Workbench. Import into a staging OU, link to a pilot ring, audit failures, then expand.

## Tool comparison: GPO vs Intune vs PowerShell vs SCM

| Tool | Best for | Limitations |
|---|---|---|
| **Group Policy (GPO)** | AD-joined on-prem fleets | Doesn't apply to Entra-joined; no real-time reporting |
| **Intune (MDM)** | Entra-joined / hybrid / BYOD | Some settings only available via CSP; license required (M365 E3+) |
| **PowerShell (Set-MpPreference, etc.)** | One-off baseline scripting, lab work | Drifts on its own; no enforcement loop |
| **Security Compliance Toolkit (SCM)** | Microsoft Security Baseline import | GPO output only; no Intune export |
| **CIS-CAT Pro** | CIS Benchmark assessment + remediation | Subscription-only; not a deployment tool |
| **WDAC Wizard** | Authoring WDAC policies | Single-purpose |

Most enterprises will use **Intune as primary** + **GPO as fallback** for AD-only hosts and Security Baseline import.

## 90-day implementation roadmap

Repeated from the TL;DR for the planner-PMs in your audience. Time-boxed milestones:

| Day | Milestone | Owner |
|---|---|---|
| 1–7 | Baseline import (MS Security Baseline + CIS Level 1) into staging OU | Platform team |
| 8–14 | Identity hardening (CredGuard, LSA Prot, WHfB, LAPS) on Tier 0 servers | Identity team |
| 15–21 | Network hardening (SMB signing, disable legacy protocols, DoH) on all servers | Network team |
| 22–35 | ASR rules in Audit mode on a pilot OU (200 endpoints) | Endpoint team |
| 36–42 | Defender hardening + Tamper Protection on full fleet | Endpoint team |
| 43–49 | Smart App Control / WDAC base policy in audit | App control team |
| 50–56 | BitLocker + TPM + PIN rollout per replacement cycle | Endpoint team |
| 57–63 | Local admin removal + UAC max + JIT admin | Identity team |
| 64–77 | PowerShell logging + Sysmon + SIEM forwarding | SOC team |
| 78–84 | OS surface reduction + Update Rings | Endpoint team |
| 85–90 | Zero Trust (Conditional Access, device compliance, CAE) | Identity team |

Track each in a project board. Weekly status with the executive sponsor. After day 90, run a formal CIS-CAT scan to measure your compliance score; aim for >85% Level 1 in the first quarter.

## Common mistakes (and how to avoid them)

Twelve recurring failures from real Windows 11 hardening projects:

| Mistake | Why it happens | Fix |
|---|---|---|
| ASR rules in Block mode on day one | "We're under attack, hurry" | Always 14-day Audit first; review hits; then Block |
| BitLocker with TPM-only (no PIN) | "PINs are inconvenient" | TPM-only is broken by cold-boot/DMA; TPM+PIN is non-negotiable for enterprise |
| Domain Admins running on workstations | Legacy practice | Hard-separate Tier 0 admin accounts from daily-use accounts |
| PowerShell logging on but no SIEM forwarding | Logging considered "done" | Forward to SIEM with retention; otherwise pointless |
| Tamper Protection off | Set-MpPreference can't enable it | Enable via Intune or Defender for Endpoint portal |
| Credential Guard breaks legacy VPN | Driver incompatibility | Identify with `mdmdiagnosticstool /Area DeviceGuard`; upgrade driver or replace VPN |
| WDAC enforce mode on day one breaks everything | Skipped audit phase | 4–8 weeks of audit per persona; build allow-list iteratively |
| ASR rule blocking PsExec for sysadmins | Sysadmin tooling caught by ASR | Apply rule only to non-admin tier 2 OU; allow PsExec for admin jump hosts |
| SMB signing breaks third-party NAS | Old NAS firmware | Firmware update or replacement; no exception list |
| Removing local admin breaks developer tools | Dev tooling needs elevation | Create a dev-tier with elevated permissions on dev-VMs only; never on the developer's primary laptop |
| Conditional Access without break-glass account | Locked everyone out (including admins) | Always exclude two emergency-only accounts from CA; rotate quarterly |
| Sysmon deployed with default config | "Just install it" | Use Olaf Hartong or SwiftOnSecurity config; tune monthly |

## Windows 11 enterprise hardening audit checklist

Use this quarterly. Each item is yes/no.

### Identity & Auth
- [ ] Credential Guard running on every endpoint
- [ ] LSA Protection enabled (RunAsPPL = 1)
- [ ] Windows Hello for Business deployed with cert-trust model
- [ ] Windows LAPS deployed with encryption + tiered RBAC ([guide](/tutorials/windows-laps-implementation/))
- [ ] NTLM auditing enabled; NTLMv2-only on every host ([guide](/tutorials/disable-ntlm-windows/))

### Network
- [ ] SMBv1 removed
- [ ] SMB signing required (both client and server)
- [ ] LLMNR / NetBIOS / mDNS / WPAD disabled
- [ ] DNS over HTTPS configured
- [ ] Firewall default-deny inbound on all profiles

### ASR & Defender
- [ ] All 19 ASR rules in Block (or audit-justified) mode
- [ ] MAPSReporting = Advanced
- [ ] CloudBlockLevel = High
- [ ] Tamper Protection enabled
- [ ] Controlled Folder Access enabled
- [ ] Network Protection enabled
- [ ] Daily scheduled scan configured

### Application Control
- [ ] Smart App Control on (or evaluation mode where compatible)
- [ ] WDAC base policy in enforce mode for general fleet
- [ ] SmartScreen at "Warn and prevent bypass" for both Apps and Edge
- [ ] Office macros from internet blocked
- [ ] Office VBA macros disabled with notification

### Encryption
- [ ] BitLocker enabled on every endpoint
- [ ] TPM + PIN required (no TPM-only)
- [ ] XTS-AES 256-bit encryption
- [ ] Removable media write-blocked unless BitLocker To Go
- [ ] Recovery keys escrowed in Entra ID / AD

### Privilege
- [ ] Standard users removed from local Administrators (verified via Restricted Groups)
- [ ] UAC at maximum (prompt for credentials on secure desktop)
- [ ] No standing admin accounts (PIM/JIT for cloud, PAM for on-prem)
- [ ] NTLM blocked domain-wide with documented exceptions

### Logging
- [ ] PowerShell ScriptBlock + Module + Transcript logging enabled
- [ ] Sysmon deployed with maintained config (Hartong or SwiftOnSecurity)
- [ ] Audit policy at CIS Level 1 minimum
- [ ] Command-line auditing for Event 4688
- [ ] All logs forwarded to SIEM with 90-day+ retention

### Surface Reduction
- [ ] AutoPlay disabled for all drives
- [ ] Cortana web search disabled
- [ ] Telemetry at Security level (Enterprise SKU)
- [ ] PowerShell v2 disabled
- [ ] IE/legacy components removed via DISM

### Zero Trust
- [ ] Conditional Access enforced (MFA + compliant device for all cloud apps)
- [ ] Legacy auth blocked
- [ ] Continuous Access Evaluation enabled
- [ ] Risk-based sign-in policies in place (P2)
- [ ] Break-glass accounts excluded from CA, with rotation

If you're at <80% on this checklist, prioritize the missing items by phase order — Phase 1 (Identity) gaps are higher-impact than Phase 9 (Surface Reduction) gaps.

## Frequently asked questions

{{< faq >}}
- q: "How do I harden Windows 11 for enterprise use?"
  a: "Follow a phased rollout in this order: (1) Identity hardening — Credential Guard, LSA Protection, LAPS, Windows Hello for Business; (2) Network hardening — disable SMBv1/LLMNR/NetBIOS/WPAD, enforce SMB signing; (3) Attack Surface Reduction rules in audit then block; (4) Microsoft Defender hardening with Tamper Protection; (5) Application Control — Smart App Control / WDAC; (6) BitLocker with TPM + PIN; (7) Privilege management — remove standing local admins, disable NTLM; (8) Logging — PowerShell ScriptBlock, Sysmon, SIEM forwarding; (9) OS surface reduction; (10) Zero Trust — Conditional Access, device compliance. Use the CIS Microsoft Windows 11 Enterprise Benchmark v3 Level 1 as your baseline and Microsoft Security Baseline as the floor."

- q: "Can I harden Windows 11 Pro the same way as Enterprise?"
  a: "Mostly yes, with three notable Enterprise-only features: (1) Windows Defender Application Guard (Edge browser isolation, retired in 2024 but some orgs still use it), (2) DirectAccess and AppLocker (Pro has SmartScreen + WDAC but not full AppLocker GUI), (3) Telemetry set to 'Security' level requires Enterprise/Education. Pro can still deploy 95% of this guide via Intune or GPO — Credential Guard, LAPS, WDAC, BitLocker, ASR, Defender, Smart App Control are all available."

- q: "What is the most important Windows 11 security setting?"
  a: "There's no single 'most important' but if forced to rank: (1) **remove standard users from local Administrators** — eliminates 90% of malware impact; (2) **enable Tamper Protection on Defender** — without it, attackers turn off everything else; (3) **enable Credential Guard** — kills LSASS credential theft; (4) **enable BitLocker with TPM + PIN** — physical theft protection; (5) **deploy LAPS** — kills lateral movement via local admin reuse. Do these five and you've blocked the most common attack chains."

- q: "How long does it take to harden a Windows 11 enterprise environment?"
  a: "A measured rollout takes 90 days for a 1,000–5,000 endpoint environment. Aggressive teams compress to 45 days at the cost of more incident risk during transitions. Start with identity (week 1–2) — that's where the highest-ROI controls live. Save WDAC for last (week 6–8 minimum) because the per-persona policy authoring takes the longest."

- q: "Do I need Intune to harden Windows 11, or can Group Policy do everything?"
  a: "GPO can do ~95% of what's in this guide, but Intune is required for Tamper Protection, Smart App Control management, and modern device compliance signals. The pragmatic split: GPO for AD-joined fleet, Intune for Entra-joined / hybrid / BYOD. Microsoft is investing all new security features in Intune CSPs first; if you're cloud-pivoting, plan Intune adoption."

- q: "What are Attack Surface Reduction rules and which should I enable?"
  a: "ASR rules are Microsoft Defender heuristic blocks for common malware behaviour. There are 19 rules as of 2026 — see the full table in this guide. The high-confidence, low-noise rules to **Block** immediately: Office child processes, Office injection, executable content from email, JS/VBS launching downloaded executables, Win32 API from macros, abuse of vulnerable signed drivers, USB unsigned execution, persistence via WMI, credential theft from LSASS. Run all 19 in Audit mode for 14 days first, then graduate to Block based on hit volume."

- q: "Should I require a BitLocker PIN or is TPM-only enough?"
  a: "**Require a PIN.** TPM-only BitLocker is broken against attackers with physical access via cold-boot attacks, DMA via Thunderbolt/USB-C, and tools like PCIleech. The minimum enterprise standard is TPM + 8-character PIN. Users complain about PIN entry for a week, then adapt. Enforce via GPO `Configure TPM startup PIN = Require startup PIN with TPM`."

- q: "How does Windows 11 hardening map to Zero Trust?"
  a: "Endpoint hardening provides the trust signals Zero Trust evaluates. A 'compliant' device in Conditional Access is defined by Intune compliance policies: BitLocker on, secure boot, TPM, modern OS, AV active, no jailbreak. Without endpoint hardening, every device is non-compliant, every access request gets blocked, and Zero Trust becomes Zero Productivity. Harden first, then layer Conditional Access on top."

- q: "How do I align Windows 11 hardening with the CIS Benchmark?"
  a: "Download the **CIS Microsoft Windows 11 Enterprise Benchmark v3** from CIS Workbench (free for personal use; subscription for the Build Kit GPO templates). Use Level 1 for general-purpose endpoints and Level 2 for high-security tiers. The CIS-CAT Pro assessment tool gives you a compliance score per setting. Realistic target: 85%+ Level 1 in the first quarter, 95%+ within 12 months."

- q: "Does enabling Credential Guard break anything?"
  a: "Yes, in three known-bad cases: (1) legacy VPN clients (Cisco AnyConnect pre-4.10, GlobalProtect pre-5.2) — upgrade or replace; (2) custom AV drivers not signed as PPL — get a signed driver from your vendor; (3) some Citrix Receiver versions — upgrade to current. Audit first with `mdmdiagnosticstool.exe /Area DeviceGuard`, identify any failure events in `Microsoft-Windows-CodeIntegrity/Operational`, then deploy."

- q: "What's the difference between Smart App Control and WDAC?"
  a: "**Smart App Control** is a cloud-driven reputation engine that ships on clean installs of Windows 11 22H2+ — Microsoft decides per-app whether to allow it. Simple to deploy, no policy authoring, but you can't customize allowlists. **WDAC** (Windows Defender Application Control) is real kernel-enforced app allowlisting where you author the policy. More work, more control. Use Smart App Control on general fleet, WDAC on high-security tiers and servers."
{{< /faq >}}

## Conclusion: hardening is a rollout, not a checkbox

Windows 11 enterprise hardening in 2026 is no longer a "lock down a few settings and call it done" exercise — it's a phased, measured, audit-driven program that closes the credential-theft, lateral-movement, ransomware-execution, and exfiltration paths in sequence. The 10-phase framework in this guide is what gets you from a default Windows 11 image to a CIS Benchmark v3 Level 1-compliant endpoint with the operational realities of an enterprise change-control process baked in.

The three most impactful actions you can take this quarter:

1. **Deploy [Windows LAPS](/tutorials/windows-laps-implementation/)** — kills lateral movement via local admin password reuse in one sprint.
2. **Deploy [the NTLM removal rollout](/tutorials/disable-ntlm-windows/)** — kills NTLM relay attacks at the protocol level.
3. **Roll the 19 ASR rules through audit and into block** — the highest-ROI per-hour-of-work Defender feature.

These three controls alone close the most-abused attack chains we see in modern incident response. The remaining phases harden the surface against the long tail.

If you're rolling out this guide and hit something not covered — particularly Intune CSP edge cases or WDAC compatibility quirks with your line-of-business apps — [get in touch](/contact/). We maintain a running list of "what breaks during Windows 11 hardening" with vendor-specific fixes.

## Share this guide

**LinkedIn**:
> The complete Windows 11 enterprise hardening guide for 2026 — 10 phases, 90 days, CIS Benchmark v3-aligned. Includes the full 19-rule ASR reference, BitLocker + PIN config, Credential Guard, LAPS, Smart App Control, WDAC, and Zero Trust integration. Save for your next hardening project. 👇

**X / Twitter**:
> Windows 11 hardening 90-day plan: 1) Identity (CredGuard, LAPS, WHfB) 2) Network (kill SMBv1/LLMNR/WPAD) 3) ASR audit→block 4) Defender + Tamper Protect 5) Smart App Control + WDAC 6) BitLocker + PIN 7) Remove local admin 8) PS logging + Sysmon 9) Surface reduction 10) Zero Trust. Full guide:

## References

- [Microsoft Security Baselines for Windows 11](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines)
- [CIS Microsoft Windows 11 Enterprise Benchmark](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
- [Microsoft Learn: Attack Surface Reduction rules reference](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference)
- [Microsoft Learn: Credential Guard overview](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/)
- [Microsoft Learn: BitLocker management for enterprises](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/)
- [Microsoft Learn: Windows Defender Application Control](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/)
- [Olaf Hartong's Sysmon Modular Config](https://github.com/olafhartong/sysmon-modular) — the community standard
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config) — simpler baseline
- [MITRE ATT&CK Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
- [Microsoft Tier model for privileged access](https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model)
