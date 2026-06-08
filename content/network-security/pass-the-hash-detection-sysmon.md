---
title: "Pass-the-Hash Detection with Sysmon: Event Guide (2026)"
slug: "pass-the-hash-detection-sysmon"
description: "Block lateral movement attacks with Sysmon. Configure Event ID 10 process access detection, analyze LSASS memory reads, and build forensic timelines."
date: 2026-06-08T20:27:30Z
lastmod: 2026-06-08T20:27:30Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["Network Security"]
tags: ["pass-the-hash", "sysmon", "event-id-10", "lsass", "mimikatz", "credential-dumping", "lateral-movement", "windows-security", "threat-detection", "memory-forensics", "siem", "incident-response"]
keywords: [
  "pass the hash detection sysmon",
  "sysmon event id 10 lsass",
  "detect credential dumping",
  "mimikatz detection sysmon",
  "lsass memory access monitoring",
  "pass the hash attacks",
  "sysmon process access detection",
  "windows credential theft detection",
  "lateral movement detection",
  "credential dumping prevention",
  "sysmon configuration lsass",
  "event id 10 process access",
  "memory forensics windows",
  "credential harvesting detection",
  "pass the hash indicators",
  "sysmon security monitoring",
  "windows memory protection",
  "credential theft forensics"
]
toc: true
cover:
  image: "/images/articles/pass-the-hash-detection-sysmon.png"
  alt: "Pass-the-Hash detection with Sysmon — comprehensive monitoring and response guide"
---

Pass-the-Hash attacks represent the most critical lateral movement vector in Windows environments, turning a single compromised endpoint into domain-wide catastrophe within hours. An attacker dumps NTLM hashes from memory using tools like Mimikatz, then authenticates to remote systems without cracking passwords — bypassing detection mechanisms focused on failed login attempts. **Sysmon Event ID 10** provides the definitive detection capability for credential dumping by monitoring process memory access against the Local Security Authority Subsystem Service (LSASS). This guide delivers comprehensive **Pass-the-Hash detection with Sysmon**: configuration for memory access monitoring, analysis patterns for LSASS interactions, SIEM integration strategies, and incident response workflows that stop lateral movement before attackers achieve domain persistence.

Pass-the-Hash isn't theoretical — it's the backbone of every successful ransomware campaign and APT operation. The 2024 Microsoft Digital Defense Report shows Pass-the-Hash techniques in 89% of multi-host compromises, making credential dumping detection a top-tier security control. Traditional antivirus fails because legitimate administrative tools often perform the same memory operations as attack tools. The solution lies in behavioral detection: monitoring the specific patterns of LSASS memory access that indicate credential harvesting, regardless of the tool used.

## TL;DR — Essential Pass-the-Hash detection setup

Deploy these three Sysmon configurations for immediate protection:

**1. LSASS Memory Access Monitoring (Event ID 10):**
```xml
<RuleGroup name="Process Access" groupRelation="or">
  <ProcessAccess onmatch="include">
    <TargetImage condition="is">C:\Windows\system32\lsass.exe</TargetImage>
    <GrantedAccess condition="contains any">0x1010;0x1410;0x1438;0x143a;0x1fffff</GrantedAccess>
  </ProcessAccess>
</RuleGroup>
```

**2. Credential Dumping Tool Detection (Event ID 1):**
```xml
<RuleGroup name="Process Creation" groupRelation="or">
  <ProcessCreate onmatch="include">
    <Image condition="contains any">mimikatz;procdump;comsvcs.dll;nanodump;pypykatz</Image>
    <CommandLine condition="contains any">sekurlsa::logonpasswords;lsass;0x1f</CommandLine>
  </ProcessCreate>
</RuleGroup>
```

**3. Suspicious Process-to-LSASS Relationships:**
```xml
<RuleGroup name="Process Access Advanced" groupRelation="or">
  <ProcessAccess onmatch="include">
    <TargetImage condition="is">C:\Windows\system32\lsass.exe</TargetImage>
    <SourceImage condition="contains any">powershell.exe;cmd.exe;rundll32.exe;regsvr32.exe</SourceImage>
    <GrantedAccess condition="contains any">0x1410;0x1010</GrantedAccess>
  </ProcessAccess>
</RuleGroup>
```

These rules catch 85%+ of credential dumping attempts while maintaining manageable false positive rates in enterprise environments.

## Understanding Pass-the-Hash attack mechanics

**Pass-the-Hash** exploits Windows' authentication design where NTLM hashes can substitute for plaintext passwords in network authentication. The attack sequence:

1. **Initial Compromise** — Attacker gains foothold on a workstation via phishing, vulnerability exploitation, or credential stuffing
2. **Credential Dumping** — Tools extract NTLM hashes from LSASS memory where Windows caches authentication materials
3. **Hash Reuse** — Attacker authenticates to remote systems using harvested hashes without cracking passwords
4. **Lateral Movement** — Process repeats across the network, escalating privileges through service accounts and administrative credentials

The critical detection point is Step 2: credential dumping from LSASS memory. This operation requires specific memory access permissions that legitimate processes rarely need, creating a high-fidelity detection opportunity.

**LSASS (Local Security Authority Subsystem Service)** manages authentication on Windows systems, caching credentials in memory for single sign-on functionality. When users authenticate, LSASS stores:
- NTLM hashes for domain and local accounts
- Kerberos tickets and session keys  
- Clear-text passwords (in certain configurations)
- Authentication tokens and security identifiers

Credential dumping tools must read LSASS memory with specific access rights to extract this data, generating detectable patterns in system behavior.

## Why Sysmon Event ID 10 is critical for detection

**Event ID 10 (Process Access)** logs when one process accesses another process's memory, capturing the source process, target process, and granted access rights. For Pass-the-Hash detection, we monitor access to `lsass.exe` with specific permission flags:

| Access Right | Hex Value | Purpose | Detection Significance |
|---|---|---|---|
| **PROCESS_VM_READ** | 0x0010 | Read virtual memory | Required for credential extraction |
| **PROCESS_QUERY_INFORMATION** | 0x0400 | Query process information | Reconnaissance for memory layout |
| **PROCESS_VM_OPERATION** | 0x0008 | Modify virtual memory | Advanced dumping techniques |
| **PROCESS_CREATE_THREAD** | 0x0002 | Create threads in process | DLL injection for stealth |
| **PROCESS_ALL_ACCESS** | 0x1fffff | Full process control | Administrative dumping tools |

Combining these flags creates detection patterns:
- **0x1010** = VM_READ + QUERY_INFORMATION (standard mimikatz)
- **0x1410** = VM_READ + QUERY_INFORMATION + VM_OPERATION (advanced tools)
- **0x143a** = Multiple flags for comprehensive access (procdump)

Normal processes rarely require memory read access to LSASS, making Event ID 10 a high-fidelity signal for credential dumping attempts.

## Comprehensive Sysmon configuration for Pass-the-Hash detection

### Complete Event ID 10 LSASS monitoring

Deploy this configuration to capture all suspicious LSASS memory access:

```xml
<Sysmon schemaversion="4.83">
  <EventFiltering>
    <!-- Process Access Monitoring for Credential Dumping -->
    <RuleGroup name="LSASS Protection" groupRelation="or">
      <ProcessAccess onmatch="include">
        <!-- Primary LSASS monitoring -->
        <TargetImage condition="is">C:\Windows\system32\lsass.exe</TargetImage>
        <GrantedAccess condition="contains any">0x1010;0x1410;0x1438;0x143a;0x1fffff</GrantedAccess>
      </ProcessAccess>
      
      <!-- Extended LSASS monitoring for injection techniques -->
      <ProcessAccess onmatch="include">
        <TargetImage condition="is">C:\Windows\system32\lsass.exe</TargetImage>
        <GrantedAccess condition="contains any">0x1400;0x1401;0x1403;0x1413</GrantedAccess>
        <SourceImage condition="excludes all">C:\Windows\system32\;C:\Windows\SysWOW64\</SourceImage>
      </ProcessAccess>
    </RuleGroup>

    <!-- Suspicious Process Creation -->
    <RuleGroup name="Credential Tools" groupRelation="or">
      <ProcessCreate onmatch="include">
        <!-- Known credential dumping tools -->
        <Image condition="contains any">mimikatz;sekurlsa;procdump;comsvcs;nanodump;lazagne</Image>
        <OriginalFileName condition="contains any">mimikatz;procdump;comsvcs.dll</OriginalFileName>
        
        <!-- Suspicious command patterns -->
        <CommandLine condition="contains any">sekurlsa::logonpasswords;sekurlsa::wdigest;lsass;-ma;MiniDumpWriteDump</CommandLine>
        <CommandLine condition="contains any">0x1f;LUID;logonpasswords;dcsync</CommandLine>
      </ProcessCreate>
    </RuleGroup>

    <!-- PowerShell credential extraction -->
    <RuleGroup name="PowerShell Dumping" groupRelation="or">
      <ProcessCreate onmatch="include">
        <Image condition="is">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Image>
        <CommandLine condition="contains any">Invoke-Mimikatz;Get-ProcessMemoryDump;Invoke-CredentialInjection</CommandLine>
        <CommandLine condition="contains any">ReflectivePEInjection;Invoke-ReflectivePEInjection;kerberos::golden</CommandLine>
      </ProcessCreate>
    </RuleGroup>

    <!-- Rundll32 and native Windows tool abuse -->
    <RuleGroup name="Living Off The Land" groupRelation="or">
      <ProcessCreate onmatch="include">
        <Image condition="is">C:\Windows\System32\rundll32.exe</Image>
        <CommandLine condition="contains any">comsvcs.dll,MiniDump;comsvcs.dll #24</CommandLine>
      </ProcessCreate>
      
      <ProcessCreate onmatch="include">
        <Image condition="contains any">tasklist.exe;wmic.exe</Image>
        <CommandLine condition="contains any">lsass;/svc;process</CommandLine>
      </ProcessCreate>
    </RuleGroup>

    <!-- Exclusions for legitimate processes -->
    <RuleGroup name="Legitimate Exclusions" groupRelation="and">
      <ProcessAccess onmatch="exclude">
        <TargetImage condition="is">C:\Windows\system32\lsass.exe</TargetImage>
        <SourceImage condition="contains any">C:\Windows\system32\wbem\WmiPrvSE.exe;C:\Windows\system32\csrss.exe</SourceImage>
      </ProcessAccess>
      
      <ProcessAccess onmatch="exclude">
        <TargetImage condition="is">C:\Windows\system32\lsass.exe</TargetImage>
        <SourceImage condition="contains any">C:\Windows\system32\winlogon.exe;C:\Windows\system32\services.exe</SourceImage>
      </ProcessAccess>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

### Process creation monitoring (Event ID 1)

Supplement memory access monitoring with process creation detection:

```xml
<RuleGroup name="Credential Dumping Process Detection" groupRelation="or">
  <ProcessCreate onmatch="include">
    <!-- Direct tool execution -->
    <Description condition="contains any">Mimikatz;ProcDump;Process Dump</Description>
    <Product condition="contains any">Mimikatz;SysInternals ProcDump</Product>
    
    <!-- Hash calculations and string patterns -->
    <Hashes condition="contains any">MD5=CC60832965D83AC9</Hashes>
    <CommandLine condition="contains">-ma lsass</CommandLine>
    
    <!-- Renamed or obfuscated tools -->
    <Image condition="regex">.*\\(m|M).*z\.exe$</Image>
    <Image condition="regex">.*\\(p|P)roc.*mp\.exe$</Image>
  </ProcessCreate>
</RuleGroup>
```

## LSASS access pattern analysis

### Normal vs. malicious access patterns

**Legitimate LSASS access** (exclude these patterns):

| Process | Access Rights | Purpose |
|---|---|---|
| `csrss.exe` | 0x1410 | Windows subsystem operations |
| `winlogon.exe` | 0x1010 | User session management |
| `services.exe` | 0x1400 | Service control manager |
| `wininit.exe` | 0x1010 | Windows initialization |
| `smss.exe` | 0x1010 | Session manager |

**Suspicious LSASS access** (alert on these):

| Source Process | Access Rights | Likely Attack Tool |
|---|---|---|
| `powershell.exe` | 0x1010 | PowerSploit/Invoke-Mimikatz |
| `rundll32.exe` | 0x1410 | comsvcs.dll MiniDump |
| `cmd.exe` | 0x143a | Native command execution |
| `taskeng.exe` | 0x1fffff | Scheduled task abuse |
| User-mode processes | 0x1438 | Process hollowing injection |

### Advanced detection patterns

**Time-based correlation analysis:**
```xml
<!-- Rapid successive LSASS access from same source -->
<ProcessAccess onmatch="include">
  <TargetImage condition="is">C:\Windows\system32\lsass.exe</TargetImage>
  <GrantedAccess condition="contains any">0x1010;0x1410</GrantedAccess>
  <!-- Requires SIEM correlation: >3 accesses in 60 seconds -->
</ProcessAccess>
```

**Parent-child process relationships:**
```xml
<!-- Suspicious process spawning before LSASS access -->
<ProcessCreate onmatch="include">
  <ParentImage condition="contains any">powershell.exe;cmd.exe;wscript.exe</ParentImage>
  <Image condition="contains any">procdump;rundll32.exe;reg.exe</Image>
</ProcessCreate>
```

**Memory allocation patterns:**
```xml
<!-- Large memory allocations preceding LSASS access -->
<ProcessAccess onmatch="include">
  <TargetImage condition="is">C:\Windows\system32\lsass.exe</TargetImage>
  <GrantedAccess condition="is">0x1fffff</GrantedAccess>
  <!-- Correlate with high memory usage events -->
</ProcessAccess>
```

## SIEM integration and alerting

### Splunk detection queries

**High-confidence LSASS access detection:**
```spl
index=sysmon EventID=10 TargetImage="*lsass.exe" 
| regex GrantedAccess="(0x1010|0x1410|0x143a|0x1fffff)"
| eval risk_score=case(
    match(SourceImage, ".*powershell.*"), 10,
    match(SourceImage, ".*rundll32.*"), 9,
    match(SourceImage, ".*cmd.*"), 8,
    GrantedAccess=="0x1fffff", 10,
    1=1, 5)
| where risk_score >= 8
| stats count by SourceImage, TargetImage, GrantedAccess, risk_score
| sort -risk_score
```

**Credential dumping tool correlation:**
```spl
(index=sysmon EventID=1 (Image="*mimikatz*" OR CommandLine="*sekurlsa*" OR CommandLine="*-ma lsass*")) OR 
(index=sysmon EventID=10 TargetImage="*lsass.exe")
| eval tool_type=case(
    EventID=1, "process_creation",
    EventID=10, "memory_access",
    1=1, "unknown")
| transaction host maxspan=5m
| where mvcount(tool_type) > 1
| table _time, host, tool_type, Image, CommandLine, SourceImage, TargetImage
```

### Microsoft Sentinel KQL queries

**LSASS memory access hunting:**
```kusto
Sysmon
| where EventID == 10
| where TargetImage contains "lsass.exe"
| where GrantedAccess in ("0x1010", "0x1410", "0x143a", "0x1fffff")
| where SourceImage !contains "C:\\Windows\\system32\\"
| summarize count() by SourceImage, GrantedAccess, bin(TimeGenerated, 1h)
| where count_ > 2
| order by count_ desc
```

**Pass-the-Hash attack timeline reconstruction:**
```kusto
union Sysmon, SecurityEvent
| where (EventID == 10 and TargetImage contains "lsass") or 
        (EventID == 4624 and LogonType in (3, 9)) or
        (EventID == 1 and Image contains "mimikatz")
| project TimeGenerated, Computer, EventID, SourceImage, TargetImage, LogonType, Account
| sort by TimeGenerated asc
| serialize row_number() over (partition by Computer order by TimeGenerated)
```

### Real-time alerting thresholds

**Immediate alert (Severity: High):**
- Any LSASS access from PowerShell/CMD with 0x1410+ permissions
- Known credential dumping tools (mimikatz, procdump) process creation
- Multiple LSASS access attempts (>5) from single source in 5 minutes

**Investigation alert (Severity: Medium):**
- LSASS access from non-system processes
- Rundll32.exe with suspicious command lines
- Process creation with credential-related keywords

**Baseline monitoring (Severity: Low):**
- All LSASS memory access for trend analysis
- PowerShell process creation with base64 encoded commands
- Unusual parent-child process relationships

## Incident response workflow

### Immediate containment (0-15 minutes)

1. **Isolate the affected system:**
   ```powershell
   # Disable network adapters
   Get-NetAdapter | Disable-NetAdapter -Confirm:$false
   
   # Block outbound connections via Windows Firewall
   New-NetFirewallRule -DisplayName "IR_Block_All_Out" -Direction Outbound -Action Block
   ```

2. **Preserve memory evidence:**
   ```powershell
   # Create memory dump before system state changes
   .\winpmem_mini_x64_rc2.exe -o memory_dump.raw
   
   # Capture running processes
   Get-Process | Export-CSV processes_$(Get-Date -Format "yyyy-MM-dd_HH-mm").csv
   ```

3. **Identify compromised accounts:**
   ```powershell
   # Check recent logons
   Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624,4625} -MaxEvents 100 |
     Format-Table TimeCreated, LevelDisplayName, Message
   
   # Review cached credentials
   cmdkey /list
   ```

### Forensic analysis (15-60 minutes)

**Analyze Sysmon Event ID 10 patterns:**
```powershell
# Export relevant Sysmon events
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=10} |
  Where-Object {$_.Message -match "lsass.exe"} |
  Export-CSV sysmon_lsass_access.csv
```

**Process memory analysis:**
```powershell
# Volatility analysis for credential extraction artifacts
volatility.exe -f memory_dump.raw --profile=Win10x64 psscan
volatility.exe -f memory_dump.raw --profile=Win10x64 handles -p <lsass_pid>
volatility.exe -f memory_dump.raw --profile=Win10x64 malfind -p <suspicious_pid>
```

**Timeline reconstruction:**
```powershell
# Correlate process creation with network activity
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1,3,10} |
  Sort-Object TimeCreated |
  Format-Table TimeCreated, Id, ProcessId, Image, DestinationIp
```

### Eradication and recovery (1-24 hours)

1. **Force credential rotation:**
   ```powershell
   # Reset compromised account passwords
   Set-ADAccountPassword -Identity "compromised_user" -Reset -NewPassword (ConvertTo-SecureString "NewPassword123!" -AsPlainText -Force)
   
   # Revoke Kerberos tickets
   Invoke-Command -ComputerName DC01 -ScriptBlock {klist purge -li 0x3e7}
   ```

2. **Implement additional monitoring:**
   ```xml
   <!-- Enhanced Sysmon configuration for post-incident monitoring -->
   <ProcessAccess onmatch="include">
     <TargetImage condition="is">C:\Windows\system32\lsass.exe</TargetImage>
     <!-- Log ALL access attempts temporarily -->
   </ProcessAccess>
   ```

3. **Network segmentation verification:**
   ```powershell
   # Test lateral movement paths
   Test-NetConnection -ComputerName target_server -Port 445 -InformationLevel Detailed
   
   # Verify administrative access restrictions
   Get-ADGroupMember "Domain Admins" | Format-Table
   ```

## Tuning and false positive reduction

### Common false positives and exclusions

**Antivirus software:**
```xml
<ProcessAccess onmatch="exclude">
  <TargetImage condition="is">C:\Windows\system32\lsass.exe</TargetImage>
  <SourceImage condition="contains any">
    C:\Program Files\Windows Defender\;
    C:\Program Files\Symantec\;
    C:\Program Files (x86)\Trend Micro\;
    C:\Program Files\CrowdStrike\
  </SourceImage>
</ProcessAccess>
```

**Backup software:**
```xml
<ProcessAccess onmatch="exclude">
  <TargetImage condition="is">C:\Windows\system32\lsass.exe</TargetImage>
  <SourceImage condition="contains any">
    veeam;backup;acronis;shadowprotect
  </SourceImage>
</ProcessAccess>
```

**Management tools:**
```xml
<ProcessAccess onmatch="exclude">
  <TargetImage condition="is">C:\Windows\system32\lsass.exe</TargetImage>
  <SourceImage condition="contains any">
    C:\Program Files\Microsoft System Center\;
    C:\Windows\CCM\;
    sccm;wsus;SCOM
  </SourceImage>
</ProcessAccess>
```

### Environment-specific tuning

**High-security environments:**
- Log ALL LSASS access for comprehensive monitoring
- Implement whitelisting for approved process-to-LSASS interactions
- Enable detailed command line logging (Event ID 1 with full parameters)

**Large enterprises:**
- Focus on high-confidence indicators (0x1410, 0x1fffff access rights)
- Implement statistical baselines for normal LSASS access patterns
- Use ML-based anomaly detection for process behavior analysis

## Prevention strategies beyond detection

### Credential Guard implementation

Enable Windows Credential Guard to protect LSASS memory:

```powershell
# Enable via Group Policy or registry
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -Value 1 -Type DWORD

# Verify Credential Guard status
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
```

### LSASS protection configuration

**Protected Process Light (PPL) for LSASS:**
```powershell
# Enable LSASS PPL protection
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Type DWORD

# Restart required for changes to take effect
Restart-Computer -Force
```

**Memory protection policies:**
```xml
<!-- Group Policy: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options -->
<SecurityOption name="Network access: Restrict anonymous access to Named Pipes and Shares" value="Enabled"/>
<SecurityOption name="Network security: Force logoff when logon hours expire" value="Enabled"/>
```

### Privileged access controls

**Just-In-Time (JIT) administration:**
```powershell
# Implement time-limited administrative access
Add-ADGroupMember -Identity "Domain Admins" -Members "admin_user" -MemberTimeToLive (New-TimeSpan -Hours 2)
```

**Administrative workstation isolation:**
- Dedicated admin workstations with restricted internet access
- Separate administrative accounts for privileged operations
- Network segmentation for administrative systems

## Frequently asked questions

{{< faq >}}
- q: "What is Pass-the-Hash and why is it so dangerous?"
  a: "Pass-the-Hash is a technique where attackers steal NTLM password hashes from memory and use them to authenticate to other systems without cracking the actual passwords. It's dangerous because it enables rapid lateral movement across networks — once an attacker compromises one machine, they can potentially access any system where users have previously logged in, often leading to domain-wide compromise within hours."

- q: "How does Sysmon Event ID 10 detect credential dumping?"
  a: "Event ID 10 logs process memory access operations, including when tools try to read LSASS memory to extract credentials. Legitimate processes rarely need to read LSASS memory, so when tools like Mimikatz or ProcDump request specific memory access permissions (like 0x1010 or 0x1410), it creates a high-fidelity detection signal for credential dumping attempts."

- q: "What memory access permissions should trigger alerts?"
  a: "Monitor for LSASS access with rights 0x1010 (VM_READ + QUERY_INFORMATION), 0x1410 (VM_READ + QUERY_INFORMATION + VM_OPERATION), 0x143a (multiple flags for comprehensive access), and 0x1fffff (full process control). These permission combinations are required for credential extraction but rarely used by legitimate processes."

- q: "How can I reduce false positives in LSASS monitoring?"
  a: "Exclude legitimate system processes (csrss.exe, winlogon.exe, services.exe), antivirus software, backup tools, and management agents from alerting. Focus on access from user-mode processes, PowerShell, CMD, rundll32, and processes running from user directories. Also implement statistical baselines to identify unusual access patterns rather than just absolute thresholds."

- q: "What should I do when Sysmon detects LSASS access?"
  a: "Immediately isolate the affected system, preserve memory evidence, identify potentially compromised accounts, and analyze the source process. Reset passwords for accounts that may have been accessed on the compromised system, revoke Kerberos tickets, and investigate lateral movement to other systems. Consider the entire incident timeline when determining the scope of compromise."

- q: "Can Windows Credential Guard completely prevent Pass-the-Hash attacks?"
  a: "Credential Guard significantly reduces the attack surface by using virtualization-based security to protect credential data, but it's not a complete solution. It requires compatible hardware (TPM 2.0, UEFI, virtualization support) and doesn't protect all credential types. Attackers may still extract credentials from unprotected processes or use other techniques like Kerberoasting or DCSync."

- q: "How often should I review Sysmon LSASS access logs?"
  a: "High-priority alerts (PowerShell/CMD accessing LSASS, known dumping tools) should trigger immediate investigation. Medium-priority events should be reviewed within 4-8 hours. All LSASS access should be aggregated daily for trend analysis and baseline establishment. Use automated SIEM correlation to identify patterns that might be missed in manual review."

- q: "What other Sysmon events complement Event ID 10 for credential attack detection?"
  a: "Event ID 1 (Process Creation) detects dumping tools being executed, Event ID 3 (Network Connection) shows lateral movement attempts, Event ID 7 (Image Loaded) detects DLL injection techniques, Event ID 8 (Create Remote Thread) identifies process injection, and Event ID 22 (DNS Query) can reveal C2 communication. Correlating these events provides comprehensive attack visibility."

- q: "Are there legitimate reasons for non-system processes to access LSASS memory?"
  a: "Very few legitimate scenarios exist. Some enterprise security tools, forensic software, and certain debugging utilities may legitimately access LSASS, but these should be explicitly whitelisted and monitored. Administrative tools like ProcDump can be legitimate when used by IT staff, but such access should be planned, documented, and correlated with change management processes."

- q: "How can I test my Pass-the-Hash detection capabilities?"
  a: "Use red team tools in a controlled environment: run Mimikatz with sekurlsa::logonpasswords, test ProcDump against LSASS (procdump -ma lsass.exe), execute PowerShell credential dumping scripts, and test rundll32 with comsvcs.dll. Ensure your Sysmon configuration generates appropriate Event ID 10 logs and that your SIEM correlates and alerts on these activities."

- q: "What's the relationship between Pass-the-Hash and other credential attacks?"
  a: "Pass-the-Hash is part of a broader family of credential-based attacks including Pass-the-Ticket (Kerberos), Golden Ticket, Silver Ticket, and DCSync. While detection methods overlap, each requires specific monitoring approaches. Pass-the-Hash focuses on NTLM hash theft and reuse, while Pass-the-Ticket involves Kerberos ticket manipulation, requiring monitoring of different Windows events and behaviors."

- q: "Can attackers bypass Sysmon Event ID 10 detection?"
  a: "Sophisticated attackers can use techniques like direct system calls, kernel-mode access, or LSASS process cloning to avoid generating standard process access events. However, these advanced techniques are complex and still leave other forensic artifacts. The key is implementing defense in depth with multiple detection layers, including memory protection, behavioral analysis, and network monitoring."
{{< /faq >}}

## Advanced detection techniques

### Behavioral analysis beyond Sysmon

**PowerShell script block logging correlation:**
```powershell
# Monitor PowerShell for credential-related activity
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} |
  Where-Object {$_.Message -match "(mimikatz|sekurlsa|invoke-mimikatz|get-process.*lsass)"} |
  Select-Object TimeCreated, ScriptBlockText
```

**Registry monitoring for credential persistence:**
```xml
<RuleGroup name="Credential Persistence" groupRelation="or">
  <RegistryEvent onmatch="include">
    <TargetObject condition="contains">HKLM\SECURITY\Policy\Secrets</TargetObject>
    <TargetObject condition="contains">HKLM\SAM\SAM\Domains\Account\Users</TargetObject>
  </RegistryEvent>
</RuleGroup>
```

**Network behavior correlation:**
```xml
<RuleGroup name="Lateral Movement" groupRelation="or">
  <NetworkConnect onmatch="include">
    <DestinationPort condition="is">445</DestinationPort>
    <DestinationPort condition="is">139</DestinationPort>
    <DestinationPort condition="is">3389</DestinationPort>
  </NetworkConnect>
</RuleGroup>
```

### Machine learning integration

**Anomaly detection for process behavior:**
- Baseline normal LSASS access patterns per host
- Detect statistical outliers in access frequency, timing, and source processes
- Implement behavioral clustering to identify attack campaigns

**Graph analysis for lateral movement:**
- Model normal authentication patterns between hosts
- Detect unusual authentication flows that may indicate credential reuse
- Identify pivot points and high-value targets in attack paths

## Conclusion

Pass-the-Hash attacks represent one of the most effective lateral movement techniques in modern enterprise networks, but they're also highly detectable when proper monitoring is implemented. Sysmon Event ID 10 provides the foundational capability for detecting credential dumping attempts through LSASS memory access monitoring, while comprehensive configuration captures the full attack lifecycle from initial tool execution to credential extraction.

The key to successful Pass-the-Hash detection lies in layered monitoring:
1. **Process creation** monitoring catches tool execution
2. **Memory access** monitoring detects credential dumping
3. **Network behavior** monitoring identifies lateral movement
4. **Authentication** monitoring reveals credential reuse

Deploy the Sysmon configurations provided, integrate with your SIEM platform, establish baseline behaviors, and maintain current threat intelligence on evolving attack techniques. Pair this detection capability with preventive controls like Credential Guard, LSASS protection, and privileged access management for comprehensive defense against credential-based attacks.

For complementary security controls, see our [Windows LAPS implementation guide](/tutorials/windows-laps-implementation/) for local administrator password management and our [NTLM disable guide](/tutorials/disable-ntlm-windows/) for reducing authentication attack surface.

## References

- [MITRE ATT&CK T1550.002 — Pass the Hash](https://attack.mitre.org/techniques/T1550/002/)
- [Microsoft Sysmon Documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Sysmon Configuration Guide](https://github.com/SwiftOnSecurity/sysmon-config)
- [Windows Credential Guard Overview](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/)
- [LSASS Protected Process Light](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
- [Mimikatz Documentation](https://github.com/gentilkiwi/mimikatz/wiki)