---
title: "Disable LLMNR and NBT-NS via Group Policy: 2026 Security Guide"
slug: "disable-llmnr-nbt-ns-group-policy"
description: "Stop name resolution poisoning by disabling LLMNR and NBT-NS via Group Policy. Complete configuration, registry paths, and rollback procedures."
date: 2026-06-08T15:22:57Z
lastmod: 2026-06-08T15:22:57Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["Tutorials"]
tags: ["llmnr", "nbt-ns", "group-policy", "name-resolution", "network-security", "responder", "inveigh", "windows-hardening", "active-directory", "dns", "netbios", "windows-11", "windows-server-2025"]
keywords: [
  "disable LLMNR Group Policy",
  "disable NBT-NS Group Policy",
  "LLMNR poisoning attack prevention",
  "NBT-NS poisoning mitigation",
  "name resolution security",
  "disable Link-Local Multicast Name Resolution",
  "disable NetBIOS Name Service",
  "Group Policy LLMNR",
  "Group Policy NBT-NS",
  "Responder attack prevention",
  "Inveigh mitigation",
  "Windows name resolution hardening",
  "registry disable LLMNR",
  "registry disable NBT-NS",
  "PowerShell LLMNR disable",
  "network security hardening",
  "Windows 11 LLMNR disable",
  "Windows Server 2025 NBT-NS"
]
toc: true
cover:
  image: "/images/articles/disable-llmnr-nbt-ns-group-policy.png"
  alt: "Disable LLMNR and NBT-NS via Group Policy — network security hardening guide"
---

LLMNR (Link-Local Multicast Name Resolution) and NBT-NS (NetBIOS Name Service) are legacy name resolution protocols that attackers exploit to capture credentials through poisoning attacks. When a Windows client can't resolve a hostname via DNS, it falls back to broadcasting LLMNR and NBT-NS queries across the network — and attackers respond with malicious answers, capturing authentication attempts. Tools like **Responder** and **Inveigh** make this attack trivial, turning misconfigured name resolution into domain compromise. This guide shows how to **disable LLMNR and NBT-NS via Group Policy**, with registry paths, PowerShell verification, testing procedures, and complete rollback instructions for Windows 11 and Server 2025 environments.

These protocols serve no legitimate purpose in modern Active Directory environments where DNS provides comprehensive name resolution. LLMNR and NBT-NS exist for backward compatibility with legacy systems and workgroup environments, but in domain-joined networks they create unnecessary attack surface. Disabling them eliminates an entire class of network-based credential harvesting attacks without affecting normal domain operations.

## TL;DR — disable LLMNR and NBT-NS in 3 steps

The complete configuration in under 5 minutes:

1. **Create or edit a GPO** linked to your target OUs
2. **Computer Configuration → Administrative Templates → Network → DNS Client → Turn off multicast name resolution** = **Enabled**
3. **Computer Configuration → Windows Components → NetBT → Turn off NetBIOS over TCP/IP** = **Enabled**

Apply with `gpupdate /force`, verify with `Get-ItemProperty` commands, test name resolution, and monitor for any application breakage during your pilot phase.

## Why disable LLMNR and NBT-NS in 2026?

Three factors make this a high-priority hardening control:

**LLMNR and NBT-NS poisoning is the #1 initial access vector in red team engagements.** Every penetration test starts with running Responder on the network segment to capture NetNTLM hashes from name resolution fallbacks. The attack requires zero privileges and works against any domain-joined Windows host that attempts to access a non-existent hostname. Modern red team tooling has automated this to the point where hash capture happens within minutes of network access.

**These protocols have no legitimate use in modern AD environments.** DNS provides complete name resolution for domain-joined hosts. LLMNR was designed for link-local networks without DNS servers, and NBT-NS for pre-DNS Windows environments. In 2026, keeping them enabled is pure technical debt — they create attack surface without providing value.

**Disabling them is risk-free in properly configured domains.** Unlike disabling NTLM or SMBv1, turning off LLMNR and NBT-NS won't break legitimate applications that follow modern naming conventions. The only impact is on misconfigured applications that rely on name resolution fallbacks — and those applications should be fixed anyway.

## Understanding LLMNR and NBT-NS attacks

Both protocols work by broadcasting name resolution requests when DNS fails:

**LLMNR (Link-Local Multicast Name Resolution)** sends multicast UDP queries to 224.0.0.252:5355 when DNS lookup fails. Any host on the network can respond, claiming to be the requested hostname. Windows Vista+ enabled this by default.

**NBT-NS (NetBIOS Name Service)** broadcasts UDP queries to 255.255.255.255:137 for NetBIOS name resolution. Legacy protocol from Windows NT era, still enabled by default for compatibility.

The attack flow:
1. User/application tries to access `\\fileserver\share` but typos it as `\\filserver\share`
2. DNS lookup for `filserver.domain.com` fails
3. Windows falls back to LLMNR/NBT-NS broadcast: "Who has filserver?"
4. Attacker's tool (Responder/Inveigh) responds: "I'm filserver, here's my IP"
5. Client attempts authentication to attacker's fake server
6. Attacker captures NetNTLM hash for offline cracking or relay

This attack requires no elevation, works from any network position, and captures real user credentials — not just reconnaissance data.

## Pre-deployment checklist

Before implementing the policy:

1. **Inventory legacy applications** that might use NetBIOS names or depend on LLMNR fallback
2. **Test in a pilot OU** with a representative sample of workstations and servers
3. **Document current name resolution behavior** with `nslookup`, `ping`, and `net use` tests
4. **Verify DNS infrastructure is healthy** — check forward/reverse lookup zones, conditional forwarders, and suffix search lists
5. **Plan monitoring** for authentication failures and application errors during the transition
6. **Prepare rollback procedure** with exact GPO revert steps documented

{{< callout type="warning" title="Test before deploying domain-wide" >}}
While LLMNR and NBT-NS disabling is generally safe, legacy applications occasionally depend on NetBIOS name resolution or LLMNR fallback for misconfigured hostnames. Always pilot the policy on a test OU with diverse workloads before rolling out organization-wide. Monitor for 48-72 hours to catch batch jobs and periodic processes.
{{< /callout >}}

## Step-by-step: How to disable LLMNR and NBT-NS

The complete Group Policy configuration process:

{{< howto title="How to disable LLMNR and NBT-NS via Group Policy" duration="PT30M" >}}
- name: "Create or edit a Group Policy Object"
  text: "Open Group Policy Management Console (gpmc.msc), create a new GPO named 'Disable Name Resolution Fallbacks' or edit an existing hardening GPO. Link it to your pilot OU first, then expand to target OUs after testing. Ensure the GPO has appropriate security filtering if needed."
- name: "Configure LLMNR disable setting"
  text: "Navigate to Computer Configuration → Policies → Administrative Templates → Network → DNS Client. Find 'Turn off multicast name resolution' and set it to Enabled. This disables LLMNR on all network interfaces. The setting maps to registry key HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\\EnableMulticast = 0."
- name: "Configure NBT-NS disable setting" 
  text: "Navigate to Computer Configuration → Policies → Administrative Templates → Windows Components → Network → NetBT. Find 'Turn off NetBIOS over TCP/IP' and set it to Enabled. This disables NetBIOS name service broadcasts. Alternative path: Network → DNS Client → Turn off NetBIOS Name Service. Both map to HKLM\\SYSTEM\\CurrentControlSet\\Services\\netbt\\Parameters\\NodeType = 2."
- name: "Apply policy and force refresh"
  text: "Run 'gpupdate /force' on target machines or wait for the standard Group Policy refresh cycle (90-120 minutes). Force immediate application for testing with 'Invoke-GPUpdate' if using PowerShell. Reboot may be required for some network adapter settings to take effect."
- name: "Verify configuration with PowerShell"
  text: "Check LLMNR: Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name EnableMulticast. Should return 0. Check NBT-NS: Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\netbt\\Parameters' -Name NodeType. Should return 2 (P-node, broadcasts disabled)."
- name: "Test name resolution behavior"
  text: "Test DNS resolution: 'nslookup validhost.domain.com' should work. Test fallback disabled: 'ping nonexistent-server-name' should fail immediately without broadcast delay. Use Wireshark to confirm no LLMNR (port 5355) or NBT-NS (port 137) traffic when resolution fails."
- name: "Monitor for application impact"
  text: "Watch event logs for name resolution failures (Event ID 1014 in DNS Client log, Event ID 4319 in System log). Monitor user reports of connectivity issues. Check application logs for NetBIOS name resolution errors. Document any legitimate services requiring exceptions."
{{< /howto >}}

## Group Policy configuration details

### LLMNR disable settings

**Group Policy path:**
```
Computer Configuration
  └ Policies  
    └ Administrative Templates
      └ Network
        └ DNS Client
          └ Turn off multicast name resolution = Enabled
```

**Registry location:**
```
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient
Name: EnableMulticast
Type: DWORD
Value: 0 (Disabled)
```

**PowerShell verification:**
{{< terminal title="Administrator: PowerShell" >}}
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast -ErrorAction SilentlyContinue

# Expected output when disabled:
# EnableMulticast : 0
{{< /terminal >}}

### NBT-NS disable settings

**Group Policy path:**
```
Computer Configuration
  └ Policies
    └ Administrative Templates  
      └ Windows Components
        └ Network
          └ NetBT
            └ Turn off NetBIOS over TCP/IP = Enabled
```

**Registry location:**
```
HKLM\SYSTEM\CurrentControlSet\Services\netbt\Parameters
Name: NodeType  
Type: DWORD
Value: 2 (P-node - point-to-point, no broadcasts)
```

**PowerShell verification:**
{{< terminal title="Administrator: PowerShell" >}}
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\netbt\Parameters" -Name NodeType -ErrorAction SilentlyContinue

# Expected output when disabled:
# NodeType : 2

# Alternative check - NetBIOS configuration per adapter
Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object {$_.TcpipNetbiosOptions -ne $null} | Select-Object Description, TcpipNetbiosOptions

# TcpipNetbiosOptions values:
# 0 = Default (uses DHCP setting or enables NetBIOS)
# 1 = Enable NetBIOS over TCP/IP  
# 2 = Disable NetBIOS over TCP/IP
{{< /terminal >}}

## Alternative: Registry-based configuration

For environments that need direct registry configuration without Group Policy:

### LLMNR registry disable
{{< terminal title="Administrator: PowerShell" >}}
# Create the registry path if it doesn't exist
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
if (!(Test-Path $regPath)) {
    New-Item -Path $regPath -Force
}

# Disable LLMNR
Set-ItemProperty -Path $regPath -Name "EnableMulticast" -Value 0 -Type DWord

# Verify setting
Get-ItemProperty -Path $regPath -Name "EnableMulticast"
{{< /terminal >}}

### NBT-NS registry disable
{{< terminal title="Administrator: PowerShell" >}}
# Set NodeType to P-node (2) to disable broadcasts
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\netbt\Parameters" -Name "NodeType" -Value 2 -Type DWord

# Disable NetBIOS over TCP/IP on all adapters
$adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
foreach ($adapter in $adapters) {
    $adapter.SetTcpipNetbios(2)  # 2 = Disable
}

# Verify configuration
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\netbt\Parameters" -Name "NodeType"
Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object {$_.TcpipNetbiosOptions -ne $null} | Select-Object Description, TcpipNetbiosOptions
{{< /terminal >}}

## Testing and verification procedures

### Verify LLMNR is disabled

Test that LLMNR queries are not sent:

{{< terminal title="Command Prompt" >}}
# This should fail quickly without network traffic on port 5355
ping nonexistent-llmnr-host

# Use Wireshark or netstat to confirm no LLMNR traffic:
# netstat -an | findstr :5355
# Should show no UDP connections on port 5355
{{< /terminal >}}

### Verify NBT-NS is disabled

Test that NetBIOS name service broadcasts are blocked:

{{< terminal title="Command Prompt" >}}
# This should fail without broadcasts on port 137
net use * \\nonexistent-netbios-name\share

# Check NBT-NS service status
sc query netbt

# Verify no NetBIOS broadcasts with:
# netstat -an | findstr :137
{{< /terminal >}}

### Comprehensive verification script

PowerShell script to validate both settings:

{{< terminal title="Administrator: PowerShell" >}}
function Test-LLMNRNBTDisabled {
    $results = @{}
    
    # Test LLMNR registry setting
    try {
        $llmnr = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast -ErrorAction Stop
        $results.LLMNR_Disabled = ($llmnr.EnableMulticast -eq 0)
    } catch {
        $results.LLMNR_Disabled = $false
        $results.LLMNR_Error = $_.Exception.Message
    }
    
    # Test NBT-NS NodeType setting
    try {
        $nbtns = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\netbt\Parameters" -Name NodeType -ErrorAction Stop  
        $results.NBTNS_Disabled = ($nbtns.NodeType -eq 2)
    } catch {
        $results.NBTNS_Disabled = $false
        $results.NBTNS_Error = $_.Exception.Message
    }
    
    # Test NetBIOS over TCP/IP per adapter
    $adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
    $nbtDisabledAdapters = ($adapters | Where-Object {$_.TcpipNetbiosOptions -eq 2}).Count
    $results.NetBIOS_Adapters_Disabled = $nbtDisabledAdapters
    $results.Total_Adapters = $adapters.Count
    
    return $results
}

# Run the test
$testResults = Test-LLMNRNBTDisabled
$testResults | Format-Table -AutoSize
{{< /terminal >}}

## Common application compatibility issues

### File server access using NetBIOS names

**Symptom:** UNC paths like `\\SERVER\share` fail after NBT-NS disable
**Solution:** Use FQDN format: `\\server.domain.com\share` or configure DNS suffixes

### Legacy printers using NetBIOS discovery

**Symptom:** Network printers become unreachable after NetBIOS disable
**Solution:** Configure printers with IP addresses or FQDN, update print server DNS records

### SQL Server named instances

**Symptom:** SQL Server browser service fails to respond to client discovery
**Solution:** Use explicit connection strings with server FQDN and port numbers

### Application-specific NetBIOS dependencies

**Symptom:** LOB applications report "network path not found" errors
**Solution:** Update connection strings to use DNS names, configure application-specific DNS entries

### Monitoring and troubleshooting

Monitor these event logs during deployment:

- **System Log Event 4319:** NetBIOS name resolution timeout
- **DNS Client Event 1014:** Name resolution policy table error
- **Application-specific logs** for connectivity failures

## Rollback procedures

If issues arise and you need to restore LLMNR/NBT-NS:

### Group Policy rollback

{{< terminal title="Group Policy Management" >}}
# Method 1: Set policies to Not Configured
1. Open GPMC, edit the GPO
2. Navigate to LLMNR setting: "Turn off multicast name resolution"
3. Set to "Not Configured"
4. Navigate to NBT-NS setting: "Turn off NetBIOS over TCP/IP" 
5. Set to "Not Configured"
6. Run gpupdate /force on affected systems

# Method 2: Disable the policy entirely (if dedicated GPO)
1. Unlink the GPO from all OUs
2. Run gpupdate /force to remove settings
{{< /terminal >}}

### Registry rollback

{{< terminal title="Administrator: PowerShell" >}}
# Re-enable LLMNR
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue

# Re-enable NBT-NS (set to default/hybrid)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\netbt\Parameters" -Name "NodeType" -Value 1

# Re-enable NetBIOS over TCP/IP on adapters
$adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
foreach ($adapter in $adapters) {
    $adapter.SetTcpipNetbios(0)  # 0 = Default (usually enables)
}

# Restart NetBT service to apply changes
Restart-Service netbt -Force
{{< /terminal >}}

## Advanced configuration options

### Selective NetBIOS disabling

For environments that need NBT-NS on specific adapters only:

{{< terminal title="Administrator: PowerShell" >}}
# Disable NetBIOS only on external-facing adapters
$externalAdapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object {$_.DefaultIPGateway -ne $null}

foreach ($adapter in $externalAdapters) {
    $adapter.SetTcpipNetbios(2)  # Disable
    Write-Output "Disabled NetBIOS on: $($adapter.Description)"
}
{{< /terminal >}}

### DHCP Option 43 and NetBIOS scope configuration

For environments using DHCP to manage NetBIOS settings:

```text
DHCP Server → Scope Options → 001 Microsoft Disable Netbios Option
Value: 0x2 (Disable NetBIOS over TCP/IP)
```

### Windows Defender Application Guard compatibility

WDAG requires special consideration for name resolution:

{{< terminal title="Group Policy" >}}
Computer Configuration → Administrative Templates → Windows Components → Windows Defender Application Guard
→ Allow files to download and save to the host operating system from Windows Defender Application Guard = Enabled

# Ensure DNS resolution works within WDAG containers
→ Network isolation settings → DNS suffixes = Configure domain suffixes
{{< /terminal >}}

## Security monitoring and validation

### Detecting LLMNR/NBT-NS attack attempts

Even with protocols disabled, monitor for attack tools:

{{< terminal title="PowerShell - Security monitoring" >}}
# Monitor for Responder-like tools attempting to bind to LLMNR/NBT-NS ports
Get-NetTCPConnection | Where-Object {$_.LocalPort -eq 5355 -or $_.LocalPort -eq 137}

# Check Windows Security log for unusual authentication patterns
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624,4625; StartTime=(Get-Date).AddDays(-1)} | 
  Where-Object {$_.Message -match "LLMNR|NetBIOS"}
{{< /terminal >}}

### Validation with network security tools

Use these tools to verify protocols are disabled:

- **Wireshark:** Filter for `llmnr || nbns` to confirm no broadcast traffic
- **Nmap:** `nmap -sU -p 137,5355 target-host` should show closed/filtered ports
- **PowerShell:** `Test-NetConnection -ComputerName target -Port 5355` should fail

## Frequently asked questions

{{< faq >}}
- q: "What are LLMNR and NBT-NS and why should I disable them?"
  a: "LLMNR (Link-Local Multicast Name Resolution) and NBT-NS (NetBIOS Name Service) are legacy Windows protocols that broadcast name resolution queries when DNS fails. Attackers exploit these broadcasts to capture authentication credentials through poisoning attacks using tools like Responder. They serve no purpose in modern Active Directory environments where DNS provides complete name resolution."

- q: "Will disabling LLMNR and NBT-NS break anything in my domain?"
  a: "In properly configured Active Directory environments, disabling these protocols is risk-free. DNS handles all legitimate name resolution. The only potential impact is on misconfigured applications using NetBIOS names or hardcoded IP addresses instead of proper DNS names — these should be fixed regardless of this security hardening."

- q: "How do I know if my applications depend on LLMNR or NBT-NS?"
  a: "Monitor Event Viewer for System Log Event 4319 (NetBIOS timeouts) and DNS Client Event 1014 after deploying to a pilot group. Use Wireshark to capture network traffic and look for LLMNR (port 5355) or NBT-NS (port 137) broadcasts during normal operations. Test critical applications with non-existent hostnames to see if they trigger fallback resolution."

- q: "Can I disable these protocols on Domain Controllers?"
  a: "Yes, you can and should disable LLMNR and NBT-NS on Domain Controllers. DCs rely on DNS for name resolution and don't need these legacy protocols. However, test thoroughly as some legacy applications might attempt NetBIOS connections to DCs. Apply the same Group Policy settings to your Domain Controllers OU."

- q: "What's the difference between disabling via Group Policy versus registry?"
  a: "Group Policy provides centralized management and easier rollback, while direct registry changes offer immediate effect and work without domain connectivity. Group Policy changes can be overridden by local policy or registry modifications. Registry changes are permanent until manually reversed. Use Group Policy for production deployments."

- q: "How do I rollback if something breaks after disabling these protocols?"
  a: "For Group Policy: Set both policies to 'Not Configured' and run gpupdate /force. For registry: Remove the EnableMulticast value and set NodeType back to 1, then restart the netbt service. For immediate relief, you can manually re-enable NetBIOS per network adapter using network adapter properties in Device Manager."

- q: "Do these settings affect Windows 11 and Server 2025 differently?"
  a: "The Group Policy settings and registry locations are identical across Windows versions. However, newer Windows versions have better default DNS configurations and may show less impact from disabling legacy protocols. Windows 11 22H2+ and Server 2025 have additional security features that complement LLMNR/NBT-NS disabling."

- q: "Can attackers still perform credential harvesting with these protocols disabled?"
  a: "Disabling LLMNR and NBT-NS eliminates name resolution poisoning attacks specifically, but attackers have other vectors like WPAD poisoning, DHCPv6 attacks, and direct SMB relay. This hardening should be combined with other network security controls like SMB signing, WPAD disable, and proper network segmentation for comprehensive protection."

- q: "Is there a way to selectively disable these protocols on certain network interfaces?"
  a: "NBT-NS can be disabled per network adapter through registry settings or WMI calls, allowing you to keep it enabled on internal interfaces while disabling on external-facing adapters. LLMNR is a global setting that affects all interfaces. This selective approach can be useful for servers with multiple network connections."

- q: "How often should I audit that these protocols remain disabled?"
  a: "Include LLMNR and NBT-NS status in your monthly security baseline audits. Use PowerShell scripts to check registry values across your fleet. Monitor for any Group Policy changes that might re-enable these protocols. Consider implementing configuration management tools that enforce these settings continuously."
{{< /faq >}}

## Conclusion

Disabling LLMNR and NBT-NS via Group Policy eliminates a critical attack vector with minimal operational impact. These legacy protocols exist solely for backward compatibility and create unnecessary security exposure in modern Active Directory environments. The Group Policy configuration takes minutes to implement and provides immediate protection against credential harvesting attacks.

Your implementation roadmap:

1. **This week:** Test the Group Policy settings in a lab environment with representative applications
2. **Next week:** Deploy to a pilot OU with monitoring for 72 hours to catch any application dependencies  
3. **Within 30 days:** Roll out organization-wide with documented exceptions for any legitimate dependencies discovered

Combine this hardening with [NTLM disabling](/tutorials/disable-ntlm-windows/) and [SMB hardening](/tutorials/windows-hardening/) to create a comprehensive defense against network-based credential attacks. The overlapping protections ensure that eliminating one attack vector doesn't just push attackers to an equally viable alternative.

## References

- [Microsoft Learn: LLMNR and NetBIOS Name Service Overview](https://learn.microsoft.com/en-us/windows-server/networking/dns/troubleshoot/disable-netbios-name-resolution)
- [MITRE ATT&CK T1557.001 — LLMNR/NBT-NS Poisoning and SMB Relay](https://attack.mitre.org/techniques/T1557/001/)
- [NIST SP 800-53 — Network Security Controls](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [Group Policy Administrative Templates reference](https://learn.microsoft.com/en-us/windows/client-management/group-policies-for-enterprise-and-education-editions)
- [Responder tool documentation and attack methodology](https://github.com/lgandx/Responder)
- [Windows DNS Client configuration reference](https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-client)