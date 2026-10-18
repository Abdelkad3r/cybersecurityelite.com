---
title: "Pass-the-Hash Detection with Sysmon: Event Guide (2026)"
slug: "pass-the-hash-detection-sysmon"
description: "A Sysmon-based detection guide for suspicious process access to LSASS, including Event ID 10 configuration, investigation, and timeline review."
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
  alt: "Dark grid cover card for Pass-the-Hash Detection with Sysmon, with large high-contrast title lettering."
---

Pass-the-Hash (PtH) uses a stolen password hash as alternate authentication material; the hash does not have to be cracked to be used. Sysmon Event ID 10 can help identify a process opening LSASS while an attacker collects credentials, but that is **credential-access telemetry**, not proof that a hash was later reused. A hash obtained elsewhere, or already present in a process, can be used for PtH without a new LSASS access event on the system where authentication occurs.

Use Event ID 10 as one part of a detection strategy. Correlate process access with authentication events, endpoint evidence, and unusual network logons. Avoid describing any single event or access mask as a definitive PtH detector.

## What Sysmon Event ID 10 records

Sysmon ProcessAccess records one process opening another process and includes fields such as `SourceImage`, `TargetImage`, and `GrantedAccess`. Access to `lsass.exe` can be relevant to credential theft, but the event does not guarantee that memory was read successfully or that credentials were extracted. Event 10 can also be noisy, so Microsoft recommends targeted filtering.

### Read the access mask as bits

`GrantedAccess` is a bitmask. Individual process rights are combined with bitwise OR; the displayed number is not a named “attack permission.” The relevant rights include:

| Process right | Bit | Meaning |
|---|---:|---|
| `PROCESS_CREATE_THREAD` | `0x0002` | Create a thread in the process |
| `PROCESS_VM_OPERATION` | `0x0008` | Operate on the process address space |
| `PROCESS_VM_READ` | `0x0010` | Read process memory |
| `PROCESS_VM_WRITE` | `0x0020` | Write process memory |
| `PROCESS_QUERY_INFORMATION` | `0x0400` | Query process information |
| `PROCESS_QUERY_LIMITED_INFORMATION` | `0x1000` | Query limited process information |

For example, `0x1410` is `0x1000 + 0x0400 + 0x0010`: limited query, query information, and VM read. It does **not** include `PROCESS_VM_OPERATION` (`0x0008`). `0x1010` is limited query plus VM read. Masks such as `0x143A` combine several rights; do not assume one exact mask is universal or uniquely identifies a tool. `PROCESS_ALL_ACCESS` also has version-dependent definitions, so avoid treating one hard-coded value as a complete rule.

## Configure focused LSASS process-access collection

This Sysmon configuration fragment records Event 10 when the target image is LSASS. Merge it with your existing configuration and validate it with the Sysmon schema/version installed in your environment. This captures access attempts for analysis; it does not generate a security verdict.

```xml
<RuleGroup name="LSASS ProcessAccess" groupRelation="and">
  <ProcessAccess onmatch="include">
    <TargetImage condition="end with">\lsass.exe</TargetImage>
  </ProcessAccess>
</RuleGroup>
```

Start with this focused collection and review the resulting volume. Maintain exclusions only when you understand their effect: an overly broad exclusion can discard useful events. Do not combine a target-image filter with an exact `GrantedAccess` string list and assume that list covers every mask containing a memory-read right; Sysmon string matching is not a bitwise-mask test.

Process-creation telemetry (Event ID 1), command-line logging, and network or authentication telemetry can add context. Tool names and command lines are easy to change, so use them as supporting evidence rather than a complete detection rule.

## Triage and correlation

For an Event 10 with `TargetImage` set to LSASS, review:

- The source process path, signer, parent process, user, and process GUID.
- The complete `GrantedAccess` value and which rights are set.
- The event’s call trace and neighboring process-creation events, where available.
- Whether the source process and access are expected on that host.
- Nearby authentication activity on the source and destination systems, including NTLM logons and remote service use.

A suspicious LSASS access is a possible credential-theft event. Confirming PtH requires evidence of hash-based authentication or correlated lateral movement; Event 10 alone cannot make that distinction.

## Read-only validation steps

Check that Sysmon is installed, the expected configuration is active, and Event 10 is arriving. These commands only query local state and event logs.

```powershell
# Show Sysmon service state
Get-Service -Name Sysmon* | Select-Object Name, Status, StartType

# Review recent ProcessAccess events from the Sysmon operational log
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id = 10
    StartTime = (Get-Date).AddHours(-24)
} -MaxEvents 20 | Select-Object TimeCreated, Id, Message
```

To verify the bit interpretation locally, parse an observed mask rather than relying on a canned label:

```powershell
$hex = '0x1410' # Replace with a GrantedAccess value from your event
$mask = [Convert]::ToUInt32($hex.Substring(2), 16)
[pscustomobject]@{
    GrantedAccess = $hex
    VmRead = (($mask -band 0x0010) -ne 0)
    VmOperation = (($mask -band 0x0008) -ne 0)
    QueryInformation = (($mask -band 0x0400) -ne 0)
    QueryLimitedInformation = (($mask -band 0x1000) -ne 0)
}
```

For `0x1410`, this reports `VmRead=True`, `VmOperation=False`, `QueryInformation=True`, and `QueryLimitedInformation=True`. Validate the conversion against a known value before using equivalent bit tests in a SIEM.

## Layered prevention and response

Use Microsoft Defender Credential Guard and LSASS protected-process configuration where supported and compatible. Apply least privilege, reduce reuse of privileged accounts across endpoints, and rotate credentials that may have been exposed. Review current product documentation before changing device security settings, because these controls have deployment and compatibility prerequisites.

For investigation, preserve the relevant Sysmon and Windows Security logs, identify the source and target hosts, and review authentication events. If credential exposure is confirmed, follow the organization’s incident-response process for containment and credential rotation. Avoid automatically isolating or resetting accounts from an unvalidated Event 10 alert alone.

For complementary account controls, see the [Windows LAPS implementation guide](/tutorials/windows-laps-implementation/). The [NTLM disable guide](/tutorials/disable-ntlm-windows/) covers policy planning for a separate but related lateral-movement path.

## Frequently asked questions

{{< faq >}}
- q: "Does Sysmon Event ID 10 detect Pass-the-Hash itself?"
  a: "Not by itself. Event 10 records process access and can help identify LSASS credential access. Pass-the-Hash is the later use of a stolen hash for authentication and requires authentication and endpoint context to investigate."
- q: "What does GrantedAccess 0x1410 mean?"
  a: "It combines 0x1000 (PROCESS_QUERY_LIMITED_INFORMATION), 0x0400 (PROCESS_QUERY_INFORMATION), and 0x0010 (PROCESS_VM_READ). It does not include PROCESS_VM_OPERATION, whose bit is 0x0008."
- q: "Should I alert on one exact access mask?"
  a: "No exact mask is universal. GrantedAccess is a bitmask, and tools can request different combinations. Collect focused LSASS ProcessAccess events, interpret the rights, and tune detections using host baselines."
- q: "Does Event 10 prove that LSASS memory was read?"
  a: "It records a process opening another process with the reported access. It is useful evidence, but does not alone prove a successful memory read or credential extraction."
{{< /faq >}}

## References

- [MITRE ATT&CK T1550.002 — Pass the Hash](https://attack.mitre.org/techniques/T1550/002/)
- [Microsoft Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Microsoft Sysmon configuration files and rule logic](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-configuration-files)
- [Microsoft: Process Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [Windows Credential Guard overview](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/)
- [LSASS protected process light](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
- [Mimikatz documentation](https://github.com/gentilkiwi/mimikatz/wiki)
