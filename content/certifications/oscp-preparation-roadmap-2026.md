---
title: "OSCP Preparation Roadmap (2026 Edition)"
slug: "oscp-preparation-roadmap-2026"
description: "A realistic six-month OSCP study plan — labs, books, methodology, AD focus, exam strategy, and reporting tips from candidates who passed on first attempt."
date: 2026-04-28T08:00:00Z
lastmod: 2026-04-28T08:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["Certifications"]
tags: ["oscp", "offensive security", "pentest certification", "career"]
keywords: ["oscp preparation", "oscp roadmap", "oscp study plan", "pen-200"]
weight: 1
toc: true
cover:
  image: "/images/og-default.svg"
  alt: "OSCP preparation roadmap"
---

The OSCP exam changed substantially in 2024 — three Active Directory machines worth 40 points and three standalone hosts worth 60. Pass mark stayed at 70/100. This roadmap reflects the *current* exam, not the legacy one your YouTube favorites prepared for.

## The Six-Month Plan

The realistic full-time commitment is **15 hours per week for six months**, or roughly 360 hours including labs and reporting. Less if you have prior pentest experience; more if you're starting from junior IT.

### Months 1–2: Foundation

- **Linux fluency** — TryHackMe Linux Fundamentals; daily `bash` for at least a week
- **Windows internals** — concepts of tokens, ACLs, services, the registry
- **Networking** — read Wireshark traffic without thinking
- **Scripting** — Python and Bash automation; not full development, but data-shaping comfort

Resources: [TryHackMe Pre-Security Path](https://tryhackme.com), the OSCP-style sections on HackTheBox Academy, and the official PEN-200 PDF.

### Months 3–4: Methodology

This is where most failed candidates stalled. Build a **personal methodology**. For every box:

1. Save scan output (Nmap `-oA`).
2. Maintain a "service → checklist" doc. SMB? Run smbclient `-N`, enum4linux-ng, smbmap. Always.
3. Take screenshots immediately when you find anything — privesc paths often only become obvious when re-reading notes later.

Recommended targets:
- **TJ Null's OSCP-like list** — the canonical HTB/THM list maintained for the new exam
- **OffSec PG Practice** — proxylab-style boxes with rated difficulty
- **TryHackMe AD path** — covers Kerberoasting, ASREP, lateral movement, and BloodHound

### Months 5–6: Active Directory + Exam Sim

40 of 100 points come from one AD chain. Master:

- BloodHound: collect, query, every common attack edge
- Kerberos abuse: AS-REP, Kerberoasting, unconstrained/constrained delegation
- Lateral movement: pass-the-hash, overpass-the-hash, pass-the-ticket
- Privilege escalation: WriteDACL, GenericAll, GenericWrite, AdminSDHolder

Run two exam simulations. Time-box them: **23 hours of testing, 24 hours for reporting**. Most failures are reporting failures, not technical failures.

## The Exam Itself

| Component | Points | Target |
|-----------|--------|--------|
| AD set (3 hosts in a chain) | 40 | Complete or near-complete |
| Standalone 1 | 20 | Local foothold + root |
| Standalone 2 | 20 | Local foothold + root |
| Standalone 3 | 20 | At least foothold |
| Bonus (lab + course exercises) | 10 | Submit before exam |

**70 to pass.** The bonus is free if you submitted lab evidence on time — never skip it.

## Day-Of Strategy

1. **Sleep first.** Tired candidates miss screenshots and get suckered by rabbit holes.
2. **Pick the AD set or one standalone in your strongest topic first.** Quick momentum win.
3. **Hard 45-minute time-box per enumeration vector.** If nothing surfaces, write a note and rotate.
4. **Screenshot every flag, every privilege change, every hash you crack.** Reports without proof get rejected, regardless of technical success.

## Reporting

The report is part of the exam, not an afterthought. Use the official Markdown template. Each finding must include:

- Vulnerability title
- Steps to reproduce (commands + screenshots)
- Local.txt / proof.txt content
- Brief remediation

Submit as a single PDF within 24 hours. Failure to follow the template is the #1 reason solid technical passes get downgraded.

## Common Failure Modes

- **No methodology** — wandering tool to tool, missing obvious enumeration vectors
- **Skipping AD practice** — 40 points is half the exam; you cannot bluff this
- **Bad notes** — `screenshot1.png` everywhere with no context
- **Tool obsession** — autorecon dumps without reading them is just noise

## After the Exam

Whatever the result, the labs and the methodology you built are worth far more than the certificate. Many hiring managers value the labs in your notebook over the OSCP letters.

## References

- [Offensive Security PEN-200](https://www.offsec.com/courses/pen-200/)
- [TJ Null's OSCP List](https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/)
