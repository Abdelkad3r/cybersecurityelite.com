---
title: "Disable SMBv1 on Windows Server: Security Hardening Guide"
slug: "disable-smb1-windows-server"
description: "Kill SMBv1 protocol vulnerabilities in Windows environments. The 6-step rollout — audit usage, enforce modern SMB, remove features, verify compliance."
date: 2026-06-04T12:30:27Z
lastmod: 2026-06-04T12:30:27Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["Tutorials"]
tags: ["windows-server", "smb", "smbv1", "network-security", "windows-hardening", "group-policy", "powershell", "ransomware-defense", "windows-server-2025", "file-sharing", "legacy-protocols", "wannacry"]
keywords: [
  "disable SMBv1 Windows Server",
  "SMBv1 security vulnerabilities",
  "remove SMBv1 Windows",
  "SMB1 disable Group Policy",
  "Windows SMB hardening",
  "SMBv1 WannaCry vulnerability",
  "audit SMBv1 usage Windows",
  "SMBv2 SMBv3 migration",
  "Windows file sharing security",
  "disable SMB1 PowerShell",
  "SMBv1 audit script",
  "Windows Server 2025 SMB",
  "legacy SMB protocol removal",
  "network security hardening",
  "ransomware prevention SMB",
  "MS17-010 mitigation"
]
toc: true
cover:
  image: "/images/articles/disable-smb1-windows-server.png"
  alt: "Disable SMBv1 on Windows Server — complete security hardening guide"
---

SMBv1 should have died in 2017 when **WannaCry** ransomware exploited the EternalBlue vulnerability (MS17-010) to infect 300,000+ Windows systems worldwide in 72 hours. Yet five years later, most enterprise environments still have SMBv1 enabled by default — not because they need it, but because it's legacy technical debt that "works" and nobody wants to break file shares. This guide shows how to **disable SMBv1 on Windows Server safely**: audit current usage, migrate dependencies to modern SMBv2/v3, remove the protocol entirely, and verify compliance across the fleet.

SMBv1 isn't just "legacy and slow" — it's a **fundamental security vulnerability**. The protocol lacks modern security features (no encryption, weak authentication, vulnerable to man-in-the-middle attacks), has known exploitable bugs (EternalBlue, EternalSynergy, EternalRomance), and Microsoft officially deprecated it in 2014. Windows Server 2025 ships with SMBv1 **removed entirely** from clean installs. If your environment still runs SMBv1 in 2026, you're carrying attack surface that nation-state actors actively exploit.

## TL;DR — SMBv1 removal in 6 steps

The complete migration path from "SMBv1 everywhere" to "SMBv1 nowhere":

1. **Audit** — Run `Get-SmbServerConfiguration` and log SMBv1 usage for 2 weeks via Event ID 3000
2. **Inventory** — Identify every client and device still using SMBv1 connections
3. **Migrate** — Update clients to SMBv2/v3, replace legacy NAS appliances, fix applications
4. **Disable** — Turn off SMBv1 server and client via Group Policy or PowerShell
5. **Remove** — Uninstall the SMBv1 feature entirely from Windows installations
6. **Verify** — Confirm SMBv1 is disabled and monitor for residual connection attempts

Total deployment time: 2-4 weeks for most environments. Emergency deployments (active ransomware threat): 48-72 hours with acceptable breakage.

## Why SMBv1 is a critical security vulnerability

Three technical realities that make SMBv1 indefensible in modern networks:

**1. SMBv1 has no encryption.** All data flows in plaintext over the network. File contents, authentication credentials, and metadata are visible to anyone with network access. SMBv2/v3 support AES-based encryption that makes network interception useless.

**2. Multiple critical CVEs target SMBv1 specifically.** The most serious:

| CVE | Year | Impact | Affected |
|---|---|---|---|
| **CVE-2017-0144** (EternalBlue) | 2017 | Remote code execution | All unpatched Windows with SMBv1 |
| **CVE-2017-0145** (EternalSynergy) | 2017 | Remote code execution | Windows XP, Vista, 7, 8, 2003, 2008 |
| **CVE-2017-0146** (EternalRomance) | 2017 | Remote code execution | Windows Vista, 7, 8, 2008, 2012 |
| **CVE-2017-0148** | 2017 | Remote code execution | Windows XP, Vista, 7, 2003, 2008 |

EternalBlue remains actively exploited by ransomware families (Ryuk, Maze, Conti, LockBit) and nation-state actors. Patches exist, but SMBv1 itself remains the attack surface.

**3. SMBv1 authentication is fundamentally weak.** The protocol uses NTLM authentication with no modern protections against relay attacks, credential theft, or brute-force. SMBv2/v3 integrate with modern Kerberos, support message integrity checking, and resist the attack patterns that work against SMBv1.

## SMBv1 vs SMBv2 vs SMBv3: what you gain by upgrading

| Feature | SMBv1 (1984) | SMBv2 (2006) | SMBv3 (2012) |
|---|---|---|---|
| **Encryption** | None | Optional | Transparent AES-256 |
| **Authentication** | NTLM only | Kerberos + NTLM | Kerberos + certificate-based |
| **Message signing** | Optional, weak | Mandatory, HMAC-SHA256 | Mandatory, AES-CMAC |
| **Compound operations** | Single request/response | Up to 128 compound requests | Improved compounding + multichannel |
| **Performance** | 1x baseline | 10-40x faster (depending on workload) | 20-50x faster + RDMA support |
| **Vulnerabilities** | 15+ critical CVEs | 2 moderate CVEs | 0 critical CVEs to date |
| **Windows support** | All versions | Vista+ / 2008+ | Windows 8+ / 2012+ |
| **Default in** | Windows 2000-2008 | Windows Vista-2008R2 | Windows 8+, Server 2012+ |

The performance improvement alone justifies the migration — SMBv2/v3 use pipelining, larger buffer sizes, and modern TCP optimizations that make file operations dramatically faster. The security improvements are the primary justification.

## Prerequisites and planning

Before you disable anything:

- [ ] **Inventory SMBv1 usage** for at least 14 days to capture monthly batch jobs and quarterly processes
- [ ] **Identify legacy devices** that might only support SMBv1 (older NAS appliances, printers, some Linux distributions pre-2010)
- [ ] **Test SMBv2/v3 connectivity** from critical clients to ensure modern SMB works
- [ ] **Document rollback procedure** — how to re-enable SMBv1 if something critical breaks
- [ ] **Plan maintenance windows** for client updates and server reboots
- [ ] **Prepare communication** for users about potential file share disruptions
- [ ] **Backup configurations** before making changes

{{< callout type="warning" title="Emergency vs planned deployment" >}}
If you're responding to active ransomware that's spreading via SMBv1, **disable immediately** via Group Policy and accept that some legacy systems will lose connectivity. The business impact of broken file shares is less than the impact of encrypted file servers. In planned deployments, take 2-4 weeks to do this properly.
{{< /callout >}}

## Step-by-step SMBv1 removal guide

{{< howto title="How to disable SMBv1 on Windows Server safely" totalTime="PT20M" >}}
- name: "Audit current SMBv1 usage across the environment"
  text: "Enable SMBv1 audit logging in Group Policy: `Computer Configuration → Administrative Templates → Network → Lanman Server → Hash Publication Mode for BranchCache = Enabled` and `Audit SMB1 access = Enabled`. Run PowerShell on each file server: `Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol` and `Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol`. Monitor Event ID 3000 in Microsoft-Windows-SMBServer/Audit for 14 days to capture all SMBv1 connections."
- name: "Inventory and migrate SMBv1 dependencies"
  text: "Export SMBv1 usage logs: `Get-WinEvent -LogName 'Microsoft-Windows-SMBServer/Audit' | Where-Object Id -eq 3000`. Identify client IPs, usernames, and accessed shares. For each dependency: update client OS (Windows XP/2003 to supported versions), upgrade NAS firmware to support SMBv2+, replace legacy applications, or configure explicit SMBv2 in Linux/Mac clients."
- name: "Disable SMBv1 server and client protocols"
  text: "Via Group Policy: `Computer Configuration → Administrative Templates → Network → Lanman Server → SMB1 server = Disabled` and `Computer Configuration → Administrative Templates → Network → Lanman Workstation → SMB1 client = Disabled`. Via PowerShell: `Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force` and `Set-SmbClientConfiguration -EnableSMB1Protocol $false -Force`. Apply with `gpupdate /force` and reboot affected systems."
- name: "Remove SMBv1 Windows features entirely"
  text: "Server: `Remove-WindowsFeature FS-SMB1` or `Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -Remove`. Client: `Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol-Client` and `Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol-Server`. This completely removes SMBv1 code from the system — it cannot be re-enabled without reinstalling the feature."
- name: "Verify SMBv1 is disabled and monitor compliance"
  text: "Test with `Test-NetConnection server01 -Port 445` followed by SMBv1-specific connection attempts. Run compliance check: `Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol` should return `False`. Monitor security logs for Event ID 3000 (should stop appearing) and Event ID 1001 (SMBv1 connection attempts blocked). Set up alerting for any future SMBv1 connection attempts."
- name: "Update network security policies and documentation"
  text: "Update firewall rules to explicitly block TCP/445 with legacy SMB negotiation. Document the SMBv1 removal in change management. Update security baselines and compliance checklists. Train support teams on troubleshooting SMBv2/v3 connection issues. Create incident response plan for handling legacy devices that surface after the migration."
{{< /howto >}}

## Step 1: Audit current SMBv1 usage

Before disabling anything, you need visibility into what's actually using SMBv1. Microsoft provides built-in auditing that captures every SMBv1 connection attempt.

**Enable SMBv1 audit logging via Group Policy:**

```text
Computer Configuration
  └ Policies
    └ Administrative Templates
      └ MS Security Guide
        └ SMB1 auditing
          = Enable auditing for SMB1 connections
```

Or via registry on each server:

{{< terminal title="File Server: PowerShell as Admin" >}}
# Enable SMBv1 connection auditing
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
  -Name "RequireSecuritySignature" -Value 1 -Type DWord
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
  -Name "AuditReceivingNTLMTraffic" -PropertyType DWord -Value 2 -Force

# Check current SMB configuration
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol*
{{< /terminal >}}

**Monitor SMBv1 connections for 14 days minimum:**

{{< terminal title="File Server: PowerShell" >}}
# Watch for SMBv1 connection attempts in real-time
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-SMBServer/Audit'; ID=3000} -MaxEvents 50 |
  Select-Object TimeCreated, Id, LevelDisplayName, Message

# Export 2 weeks of SMBv1 usage data
$StartTime = (Get-Date).AddDays(-14)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-SMBServer/Audit'; ID=3000; StartTime=$StartTime} |
  Select-Object TimeCreated, @{N='ClientIP';E={($_.Message -split '\n' | Select-String 'Client Address').ToString().Split(':')[1].Trim()}}, 
                @{N='UserName';E={($_.Message -split '\n' | Select-String 'User Name').ToString().Split(':')[1].Trim()}},
                @{N='ShareName';E={($_.Message -split '\n' | Select-String 'Share Name').ToString().Split(':')[1].Trim()}} |
  Export-Csv -Path C:\SMBv1_Audit.csv -NoTypeInformation
{{< /terminal >}}

The key metrics to track: **which client IPs**, **which user accounts**, **which shares**, and **what time of day** SMBv1 connections occur. Patterns like "every Tuesday at 2 AM" suggest scheduled tasks that need explicit migration.

## Step 2: Inventory and migrate dependencies

Open the CSV from Step 1 and categorize each SMBv1 connection:

- **Windows XP/2003 clients** — Upgrade to supported OS or replace with modern hardware
- **Legacy NAS appliances** — Check vendor firmware updates or plan replacement  
- **Old printers/scanners** — Update firmware or use IP printing instead of SMB
- **Linux/macOS clients** — Configure to use SMBv2/v3 explicitly
- **Applications with hardcoded SMBv1** — Update application or find alternatives
- **Scheduled tasks/scripts** — Update to use modern UNC paths with SMBv2+

**Migration approaches:**
- **Linux clients:** Update `/etc/samba/smb.conf` to set `min protocol = SMB2`
- **Windows clients:** Ensure Vista/2008+ and use `New-SmbMapping` with integrity checking
- **Legacy NAS:** Check vendor firmware updates or plan hardware replacement

## Step 3: Disable SMBv1 via Group Policy

Once you've migrated the dependencies, disable SMBv1 across the environment using Group Policy for consistency.

**Create a new GPO or edit an existing security hardening policy:**

```text
Computer Configuration
  └ Policies
    └ Administrative Templates
      └ Network
        └ Lanman Server
          ├ SMB1 server = Disabled
        └ Lanman Workstation
          ├ SMB1 client = Disabled
```

**Apply via PowerShell for immediate effect:**

{{< terminal title="File Server: PowerShell as Admin" >}}
# Disable SMBv1 server (stops serving files via SMBv1)
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

# Disable SMBv1 client (stops accessing other SMBv1 shares)
Set-SmbClientConfiguration -EnableSMB1Protocol $false -Force

# Verify the changes
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol, EnableSMB3Protocol
Get-SmbClientConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol, EnableSMB3Protocol

# Force Group Policy update
gpupdate /force
{{< /terminal >}}

**Test connectivity after changes:**

{{< terminal title="Client Workstation: PowerShell" >}}
# Test SMBv2/v3 connectivity to file server
Test-NetConnection fileserver01.corp.local -Port 445
New-SmbMapping -LocalPath Z: -RemotePath \\fileserver01\shared -Persistent $false

# Verify SMBv2/v3 is being used
Get-SmbConnection | Select-Object ServerName, Dialect, Encrypted, Signed
{{< /terminal >}}

The `Dialect` field should show `2.002`, `2.100`, `3.000`, `3.002`, or `3.110` — anything except `1.000`.

## Step 4: Remove SMBv1 Windows features entirely

Disabling SMBv1 via configuration leaves the code installed and potentially re-enable-able. For maximum security, remove the SMBv1 Windows features entirely.

**Windows Server (remove server-side SMBv1):**

{{< terminal title="Server: PowerShell as Admin" >}}
# Check if SMBv1 feature is installed
Get-WindowsFeature | Where-Object Name -like "*SMB*"

# Remove SMBv1 feature completely
Remove-WindowsFeature FS-SMB1 -Restart

# Alternative method for Windows 10/11/Server 2016+
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -Remove -All
{{< /terminal >}}

**Windows clients (remove client-side SMBv1):**

{{< terminal title="Workstation: PowerShell as Admin" >}}
# Check current SMBv1 feature status
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol*

# Remove SMBv1 client and server features
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol-Client -Remove -All
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol-Server -Remove -All
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol-Deprecation -Remove -All

# Verify removal
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol* | Select-Object FeatureName, State
{{< /terminal >}}

{{< callout type="info" title="Feature removal requires reboot" >}}
Removing Windows features completely requires a reboot to take effect. Plan maintenance windows accordingly. Once removed, SMBv1 cannot be re-enabled without explicitly reinstalling the feature using `Enable-WindowsOptionalFeature` or `Install-WindowsFeature`.
{{< /callout >}}

## Step 5: Verify compliance and monitoring

After disabling and removing SMBv1, implement monitoring to ensure it stays disabled and catch any legacy devices that attempt connections.

**Compliance verification script:**

```powershell
# SMBv1 Compliance Check Script
$ComputerName = $env:COMPUTERNAME
$Results = @{}

# Check SMB server configuration
try {
    $SmbServer = Get-SmbServerConfiguration -ErrorAction Stop
    $Results.SMB1ServerEnabled = $SmbServer.EnableSMB1Protocol
    $Results.SMB2ServerEnabled = $SmbServer.EnableSMB2Protocol
} catch {
    $Results.SMB1ServerEnabled = "Unable to check"
}

# Check SMB client configuration
try {
    $SmbClient = Get-SmbClientConfiguration -ErrorAction Stop  
    $Results.SMB1ClientEnabled = $SmbClient.EnableSMB1Protocol
} catch {
    $Results.SMB1ClientEnabled = "Unable to check"
}

# Check Windows features
$SMB1Features = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol* -ErrorAction SilentlyContinue
$Results.SMB1FeaturesInstalled = ($SMB1Features | Where-Object State -eq 'Enabled').Count -gt 0

# Check for recent SMBv1 connection attempts
$Recent = (Get-Date).AddDays(-7)
$SMB1Attempts = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-SMBServer/Audit'; ID=3000; StartTime=$Recent} -ErrorAction SilentlyContinue
$Results.RecentSMB1Attempts = $SMB1Attempts.Count

Write-Output "=== SMBv1 Compliance Check for $ComputerName ==="
Write-Output "SMBv1 Server Enabled: $($Results.SMB1ServerEnabled)"
Write-Output "SMBv1 Client Enabled: $($Results.SMB1ClientEnabled)"  
Write-Output "SMBv1 Features Installed: $($Results.SMB1FeaturesInstalled)"
Write-Output "Recent SMBv1 Connection Attempts: $($Results.RecentSMB1Attempts)"

if ($Results.SMB1ServerEnabled -eq $false -and $Results.SMB1ClientEnabled -eq $false -and $Results.SMB1FeaturesInstalled -eq $false) {
    Write-Output "STATUS: COMPLIANT - SMBv1 is fully disabled and removed"
} else {
    Write-Output "STATUS: NON-COMPLIANT - SMBv1 is still present"
}
```

**Set up SIEM alerting for SMBv1 connection attempts:**

Monitor these Event IDs across all Windows file servers:

| Event ID | Log | Meaning | Action |
|---|---|---|---|
| **3000** | Microsoft-Windows-SMBServer/Audit | SMBv1 session established | Alert — investigate client attempting SMBv1 |
| **1001** | Microsoft-Windows-SMBServer/Security | SMBv1 connection blocked | Info — confirming SMBv1 is properly disabled |
| **40961** | Microsoft-Windows-SMBClient/Security | SMBv1 client negotiation failed | Info — client tried SMBv1, fell back to SMBv2+ |

**Splunk query example:**

```spl
index=windows (EventCode=3000 OR EventCode=1001 OR EventCode=40961)
| eval severity=case(EventCode=3000,"high",EventCode=1001,"medium",1=1,"low")
| stats count by src_host, EventCode, severity, _time
| where EventCode=3000
| eval message="SMBv1 connection detected - investigate legacy client"
```

## Network hardening

Once SMBv1 is disabled, configure network firewalls to block SMBv1 traffic. Most enterprise firewalls (Palo Alto, Fortinet, Checkpoint) support application-layer SMB inspection to block only SMBv1 while allowing SMBv2/v3.

## Common migration issues and solutions

| Issue | Symptoms | Root Cause | Solution |
|---|---|---|---|
| "Network path not found" after SMBv1 disable | Applications can't access file shares | Application forcing SMBv1 or client OS too old | Update application config or upgrade client OS to Vista+ |
| Scheduled tasks failing | Backup scripts, batch jobs fail with access denied | Scripts using SMBv1-only UNC paths | Update scripts to use `net use` with SMBv2 or PowerShell `New-SmbMapping` |
| Legacy printers stop working | Scan-to-folder fails, print queue inaccessible | Printer firmware only supports SMBv1 | Update printer firmware or reconfigure to use IP-based printing |
| NAS appliance connectivity lost | Cannot access NAS shares from Windows | NAS running old firmware with SMBv1 only | Upgrade NAS firmware or replace appliance |
| Linux clients can't connect | Mount failures, timeout errors | Linux SMB client defaulting to SMBv1 | Update `/etc/samba/smb.conf` to force SMBv2+ |
| Performance degradation | File operations slower after migration | Misconfigured SMBv2/v3 settings | Verify SMB3 encryption settings, check network MTU |
| Authentication failures | Access denied with valid credentials | Kerberos/NTLM configuration issues | Verify SPN registration, check time sync, test NTLM fallback |

## Emergency rollback

If needed: `Set-SmbServerConfiguration -EnableSMB1Protocol $true` and `Enable-WindowsOptionalFeature -FeatureName SMB1Protocol-Server`. Document all rollbacks and plan re-migration within 30 days.

## Compliance verification

Key compliance checks:
- SMBv1 disabled in server and client configuration
- SMBv1 Windows features removed entirely
- Group Policy blocks SMBv1 organization-wide
- SIEM monitors Event ID 3000 for connection attempts
- All legacy NAS appliances upgraded or replaced

## Frequently asked questions

{{< faq >}}
- q: "What is SMBv1 and why should I disable it?"
  a: "SMBv1 (Server Message Block version 1) is a 1980s-era file sharing protocol with fundamental security flaws: no encryption, weak authentication, and multiple critical vulnerabilities including EternalBlue (CVE-2017-0144) that enabled WannaCry ransomware. Modern SMBv2/v3 protocols are faster, encrypted, and secure. Microsoft deprecated SMBv1 in 2014 and removed it from Windows Server 2025."

- q: "Will disabling SMBv1 break my network file shares?"
  a: "It will only break connections from very old systems that can't use SMBv2/v3. Windows Vista/2008 and newer support SMBv2+ by default. Before disabling, audit for 14 days using Event ID 3000 to identify any legacy clients, then migrate them to modern SMB versions or upgrade the hardware."

- q: "How do I check if my environment is using SMBv1?"
  a: "Run `Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol` on file servers to see if SMBv1 is enabled. Monitor Event ID 3000 in the Microsoft-Windows-SMBServer/Audit log to capture actual SMBv1 connection attempts. Run this audit for at least 14 days to catch periodic processes like monthly batch jobs."

- q: "What's the difference between SMBv1, SMBv2, and SMBv3?"
  a: "SMBv1 (1984) has no encryption, weak authentication, and known vulnerabilities. SMBv2 (2006) added encryption, better performance, and compound operations. SMBv3 (2012) added transparent AES encryption, improved integrity checking, and RDMA support. SMBv3 is 20-50x faster than SMBv1 and has no known critical security vulnerabilities."

- q: "Can Linux and Mac clients connect without SMBv1?"
  a: "Yes. Modern Linux distributions (with Samba 3.6+) and macOS support SMBv2/v3 by default. Older configurations may need explicit updates: in Linux, set `min protocol = SMB2` in `/etc/samba/smb.conf`. macOS 10.9+ uses SMBv2+ automatically when connecting to shares."

- q: "What if I have legacy NAS appliances that only support SMBv1?"
  a: "Check vendor websites for firmware updates that add SMBv2/v3 support. Many NAS vendors (Synology, QNAP, Western Digital) released SMBv2+ firmware for devices as old as 2012. If no updates exist, plan hardware replacement — the security risk outweighs the cost of keeping vulnerable appliances."

- q: "How long should I monitor before disabling SMBv1?"
  a: "Minimum 14 days; ideally 30 days to catch monthly batch jobs. Monitor Event ID 3000 for all connection attempts, paying attention to service accounts and scheduled tasks."

- q: "Does removing SMBv1 affect Windows file and printer sharing?"
  a: "No. Modern Windows file and printer sharing uses SMBv2/v3 by default. Removing SMBv1 only affects connections to/from very old systems (Windows XP/2003 and earlier) and legacy network appliances. All modern functionality continues to work normally."
{{< /faq >}}

## Conclusion: eliminate the EternalBlue attack surface

SMBv1 removal is **table stakes security hygiene** in 2026. The protocol has been deprecated for over a decade, exploited by major ransomware campaigns, and offers no benefits over modern SMBv2/v3. Every day SMBv1 remains enabled is another day your file servers are vulnerable to well-known, actively-exploited attack vectors.

The migration process — audit, inventory, migrate, disable, remove, verify — typically takes 2-4 weeks in most enterprise environments. The alternative is carrying the EternalBlue attack surface indefinitely. Modern SMBv2/v3 delivers better security, better performance, and better compliance posture.

**Start this week:**
1. **Run the audit script** on all file servers to baseline SMBv1 usage
2. **Enable Event ID 3000 logging** to capture connection attempts
3. **Schedule maintenance windows** for client updates and server changes
4. **Document the rollback procedure** before making any changes

Pair SMBv1 removal with the [NTLM hardening guide](/tutorials/disable-ntlm-windows/) and [Windows LAPS implementation](/tutorials/windows-laps-implementation/) to eliminate the three most-exploited Windows attack surfaces in a single security sprint.

## References

- [Microsoft Security Advisory ADV170005: SMBv1 deprecation](https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2017/4013389) — Microsoft's official SMBv1 deprecation notice
- [Microsoft Learn: How to detect, enable and disable SMBv1, SMBv2, and SMBv3 in Windows](https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3)
- [MITRE ATT&CK T1021.002 — Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)
- [CVE-2017-0144 (EternalBlue) Details](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-0144)
- [CISA Alert AA17-132A — SMB Vulnerability](https://www.cisa.gov/news-events/cybersecurity-advisories/aa17-132a)
- [Microsoft Security blog: WannaCrypt ransomware worm targets out-of-date systems](https://blogs.microsoft.com/on-the-issues/2017/05/14/need-urgent-collective-action-keep-people-safe-online-lessons-last-weeks-cyberattack/)
- [SANS: Disabling SMBv1 through Group Policy](https://www.sans.org/white-papers/smbv1-disable/)