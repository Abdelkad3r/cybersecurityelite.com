---
title: "HTB CPTS Review (2026): Is Hack The Box's Certified Penetration Testing Specialist Worth It?"
slug: "htb-cpts-review-2026"
description: "Honest HTB CPTS review — the Penetration Tester Academy path, the 10-day hands-on exam and report, difficulty vs OSCP, cost, and who it's actually for."
date: 2026-08-04T00:00:00Z
lastmod: 2026-08-04T00:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["Certifications"]
tags: ["htb cpts", "hack the box", "cpts", "penetration testing certification", "oscp alternative", "active directory", "pentest report", "cybersecurity certifications", "htb academy", "offensive security"]
keywords: ["htb cpts review", "hack the box cpts", "cpts vs oscp", "is cpts worth it", "cpts exam", "cpts difficulty", "hack the box certified penetration testing specialist", "cpts cost", "how to pass cpts", "cpts report", "penetration tester path htb", "cpts active directory"]
toc: true
cover:
  image: "/images/articles/htb-cpts-review-2026.png"
  alt: "A laptop showing a Hack The Box Academy penetration testing lab next to a printed commercial-grade penetration test report on a desk representing the HTB CPTS exam workflow"
---

Hack The Box's **Certified Penetration Testing Specialist (CPTS)** is one of the best-value practical pentest certifications in 2026 — the short answer is yes, it earns its reputation, with two honest caveats: it is enormous in scope and it will fail you on a weak report even if you own the network. If you want a modern, deeply hands-on credential that mirrors real consulting work — enumeration to a full Active Directory compromise, wrapped in a professional deliverable — the CPTS is an easy recommendation. Where it loses ground to the OSCP is raw recruiter name recognition, and that nuance drives most of the "CPTS vs OSCP" debate.

> **Confirm current details before you buy.** Exam format, voucher pricing, and the HTB Academy path structure all evolve. Everything below reflects the situation as of 2026 and is hedged where a figure could shift — always verify the exam length, cost, flag threshold, and renewal terms on Hack The Box's official site before committing.

## What the CPTS Is

The CPTS — **Certified Penetration Testing Specialist**, issued by **Hack The Box (HTB)** — is a fully hands-on penetration testing certification. There is no multiple-choice component. You prepare through a structured HTB Academy learning path and then prove your skills against a live, realistic enterprise network, finishing with a written report the way a working consultant would.

### CPTS at a Glance

| Attribute | Detail (verify current) |
|-----------|-------------------------|
| Issuer | Hack The Box (HTB) |
| Preparation | "Penetration Tester" job-role path on HTB Academy |
| Exam length | Around **10 days** to complete |
| Format | Fully hands-on; realistic enterprise Active Directory network |
| Flags/points threshold | Reported to be around **85%** (commonly cited as 12 of 14 flags) |
| Report required | Yes — a professional, commercial-grade pentest report |
| Approx. exam voucher cost | Around **$490** (verify; Academy learning is a separate subscription) |
| Renewal | Reported to **not require periodic renewal** in the same way as some certs (verify) |

The two things worth internalizing early: this is a long-form, realistic assessment rather than a 24-hour sprint, and the **report is graded, not optional**. Both of those choices are deliberate, and both are what make the credential feel closer to a real engagement than a capture-the-flag marathon.

## The HTB Academy Penetration Tester Path

Preparation runs through the **"Penetration Tester" job-role path on HTB Academy**, and its size is the first thing that surprises people. It is a large path — roughly two-dozen-plus modules — that walks you from fundamentals all the way to a full assessment methodology. Broadly, it covers:

- **Enumeration and information gathering** — the discipline of footprinting hosts and services thoroughly before touching an exploit.
- **Web attacks** — the common application vulnerability classes you will realistically meet on an internal or external test.
- **Active Directory — heavily.** This is the beating heart of the path. Kerberos abuse, ACL attacks, lateral movement, trust relationships, and the enumeration workflow around BloodHound get sustained attention.
- **Pivoting and tunneling** — moving through segmented networks, which the exam absolutely expects you to do.
- **Privilege escalation on both Linux and Windows** — a wide catalog of local escalation paths on each platform.
- **Documentation and reporting** — an explicit, taught module rather than an afterthought.

The AD emphasis cannot be overstated. If you want a sense of the specific skill set the exam rewards, our [Hack The Box Sauna walkthrough](/ctf-writeups/hack-the-box-sauna-walkthrough/) demonstrates the kind of Active Directory reasoning — AS-REP roasting, hash cracking, privilege abuse — that the CPTS tests at greater depth and scale. The path is not light reading; treat it as a genuine curriculum, not a cram sheet.

## The Exam Experience

The exam is where the CPTS distinguishes itself. You are given a generous window — **around 10 days** — to complete it, and you will likely use a real chunk of that time. Rather than a handful of disconnected boxes, it simulates a **realistic enterprise Active Directory environment**: an interconnected network you have to enumerate, breach, pivot through, and ultimately compromise.

To pass you must clear **two independent bars**:

1. **Reach the flag/points threshold.** This is reported to be around **85%** — commonly cited as capturing **12 of 14 flags** — as you work through the network. Treat the exact number as something to verify, but plan for a high bar that leaves little room for skipping large sections.
2. **Submit an acceptable report.** You must deliver a **professional, commercial-grade penetration test report** documenting your findings, methodology, evidence, and remediation guidance. This is the part candidates underestimate. **If your report is inadequate, you can fail even with all the flags.**

That second requirement is the single most important thing to understand about the CPTS. It is not a formality — it is a graded deliverable that mirrors what a client actually pays for. In a real engagement nobody cares that you got Domain Admin if you cannot communicate how, what the business impact is, and how to fix it. The CPTS bakes that reality into the pass/fail line, which is exactly why practitioners rate it so highly.

## CPTS vs OSCP

The comparison everyone wants. Both are practical, report-based pentest exams, and both are respected — but they optimize for different things.

| Factor | HTB CPTS | OSCP |
|--------|----------|------|
| Approx. cost | Lower — voucher around $490 plus Academy subscription (verify) | Higher — bundle typically runs well over $1,500 (verify) |
| Exam length | Around 10 days | 24-hour exam + separate reporting window |
| Recruiter recognition | Growing fast, but still behind OSCP | The most name-recognized offensive cert |
| Active Directory depth | Very deep — a core focus of both path and exam | Significant since the 2024 revamp, but narrower |
| Report | Graded, commercial-grade, heavily weighted | Required and graded, but the exam is shorter-form |
| Difficulty | Broad and demanding; more content, more endurance | Intense time-pressure sprint |
| Scope/breadth | Arguably broader | Focused, canonical scope |

Read fairly: the **OSCP still wins on raw recruiter name recognition** — if a job posting names one cert, it is usually the OSCP, and that matters for résumé filters. The **CPTS wins on price, breadth, AD depth, and reporting realism**, and many practitioners consider it the better *learning experience*. It is a legitimate **OSCP alternative or precursor** — plenty of people do the CPTS first for the skills, then sit the OSCP purely for the name. If you are already committed to the OSCP, our [OSCP preparation roadmap](/certifications/oscp-preparation-roadmap-2026/) lays out a six-month plan, and much of the CPTS Academy path doubles as excellent OSCP prep. For the wider landscape, see our [best cybersecurity certifications guide](/certifications/best-cybersecurity-certifications-2026/).

## Who Should Take the CPTS

**Take the CPTS if you:**

- Want a modern, thorough, hands-on pentest cert and care more about skills and value than about one specific line on a job description.
- Are targeting internal network and Active Directory testing — the CPTS trains and tests exactly that.
- Want to practice real report writing before you are doing it for a paying client.
- Are planning to sit the OSCP later and want the strongest possible preparation while earning a credential along the way.

**Consider doing something else first if you:**

- Are new to offensive security with little Linux, networking, or hands-on hacking experience. Build the base first. Start with the **eJPT** or **PNPT** for a gentler on-ramp, and read our guide to [getting into cybersecurity with CTFs](/career/how-to-get-into-cybersecurity-with-ctfs/) to develop the prerequisite skills before committing to a large path.
- Need a specific recruiter-recognized name *today* for a role that lists the OSCP by name — in that case, prioritize the OSCP and treat the CPTS as skill-building.

The CPTS is not an entry-level cert. It assumes comfort with the fundamentals and rewards patience and depth.

## How to Prepare and Pass

The path teaches you the content; passing is about turning it into a repeatable process. What consistently separates passes from fails:

1. **Do the entire Penetration Tester path — actively.** Don't skim modules. Reproduce every technique in a lab so it lives in your hands, not just your notes.
2. **Build a methodology and a note-taking system now.** Adopt a tool like Obsidian, CherryTree, or Notion and structure notes so that on exam day you can find "what do I do against SMB" or "constrained delegation steps" in seconds. Screenshot everything with context — you will need that evidence for the report.
3. **Master enumeration and pivoting.** Most stalls on the exam are enumeration failures, not exploitation failures. Practice tunneling through networks until it is reflexive.
4. **Grind real Active Directory machines.** Practice on HTB machines and pro labs that chain AD attacks. To choose a platform that fits your level, compare the options in our [Hack The Box Academy vs TryHackMe comparison](/ctf-writeups/hack-the-box-academy-vs-tryhackme-comparison/).
5. **Write a report before exam day.** Take a practice box, own it, and write a full commercial-grade report end to end. Build or adapt a **report template** — executive summary, methodology, findings with severity and impact, evidence, and remediation. Walking into the exam with a proven template removes enormous pressure from the final days.

The candidates who fail with flags in hand almost always skipped step five. Treat the report as a first-class part of your preparation, because the exam does.

## Verdict

The CPTS is one of the strongest practical penetration testing certifications you can earn in 2026. It is rigorous, modern, exceptional value for the depth of learning, and — crucially — it grades the thing that real jobs actually depend on: your ability to compromise a realistic Active Directory environment *and* write it up like a professional. Its only meaningful weakness is that the OSCP still carries more recruiter name recognition. If that specific résumé keyword isn't a hard requirement for the role you want, the HTB CPTS is an easy recommendation — and even if it is, the CPTS remains arguably the best OSCP preparation on the market. Recommended, with the caveats that it is large and that the report is not optional.

## Frequently Asked Questions

**Q: Is the HTB CPTS worth it?**

For most people aiming at a hands-on penetration testing role, yes. It offers deep, modern training — especially in Active Directory — a realistic multi-day exam, and a graded commercial report, all at a lower price than the OSCP. The main trade-off is that it currently has less recruiter name recognition than the OSCP, so weigh it against the specific roles you are targeting.

**Q: How hard is the CPTS exam?**

It is demanding, but in a different way than the OSCP. Instead of a 24-hour sprint, you get around 10 days against a realistic enterprise Active Directory network, and you must both reach a high flag threshold (reported to be around 85%) and submit an acceptable professional report. The difficulty comes from the breadth of skills required and the endurance of a long assessment plus reporting, rather than pure time pressure.

**Q: CPTS vs OSCP — which should I choose?**

Both are respected, practical, report-based exams. Choose the OSCP if you need its stronger recruiter name recognition for a specific role. Choose the CPTS for lower cost, broader scope, deeper Active Directory focus, and a more realistic reporting requirement. Many people do the CPTS first for the skills and then take the OSCP for the name.

**Q: How much does the CPTS cost?**

As of 2026 the exam voucher is reported to be around $490, with the HTB Academy learning delivered through a separate subscription that sometimes includes student discounts, and the two are occasionally bundled. Pricing changes, so confirm the current voucher and subscription costs on Hack The Box's official site before buying.

**Q: Do I need to renew the CPTS?**

The CPTS is reported to not require periodic renewal in the same way that some certifications do, meaning it does not lapse on a fixed cycle. Renewal and validity policies can change, so verify the current terms on Hack The Box's official site before relying on this.

**Q: How should I prepare for the CPTS?**

Complete the full Penetration Tester job-role path on HTB Academy actively, reproducing every technique in a lab. Build a strong note-taking system, master enumeration and network pivoting, grind real Active Directory machines, and — most importantly — write at least one full commercial-grade report before exam day using a template you can reuse.

```json
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {
      "@type": "Question",
      "name": "Is the HTB CPTS worth it?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "For most people aiming at a hands-on penetration testing role, yes. It offers deep, modern training, especially in Active Directory, a realistic multi-day exam, and a graded commercial report, all at a lower price than the OSCP. The main trade-off is that it currently has less recruiter name recognition than the OSCP, so weigh it against the specific roles you are targeting."
      }
    },
    {
      "@type": "Question",
      "name": "How hard is the CPTS exam?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "It is demanding but in a different way than the OSCP. Instead of a 24-hour sprint, you get around 10 days against a realistic enterprise Active Directory network, and you must both reach a high flag threshold reported to be around 85 percent and submit an acceptable professional report. The difficulty comes from the breadth of skills required and the endurance of a long assessment plus reporting rather than pure time pressure."
      }
    },
    {
      "@type": "Question",
      "name": "CPTS vs OSCP - which should I choose?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Both are respected, practical, report-based exams. Choose the OSCP if you need its stronger recruiter name recognition for a specific role. Choose the CPTS for lower cost, broader scope, deeper Active Directory focus, and a more realistic reporting requirement. Many people do the CPTS first for the skills and then take the OSCP for the name."
      }
    },
    {
      "@type": "Question",
      "name": "How much does the CPTS cost?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "As of 2026 the exam voucher is reported to be around 490 dollars, with the HTB Academy learning delivered through a separate subscription that sometimes includes student discounts, and the two are occasionally bundled. Pricing changes, so confirm the current voucher and subscription costs on Hack The Box's official site before buying."
      }
    },
    {
      "@type": "Question",
      "name": "Do I need to renew the CPTS?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "The CPTS is reported to not require periodic renewal in the same way that some certifications do, meaning it does not lapse on a fixed cycle. Renewal and validity policies can change, so verify the current terms on Hack The Box's official site before relying on this."
      }
    },
    {
      "@type": "Question",
      "name": "How should I prepare for the CPTS?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Complete the full Penetration Tester job-role path on HTB Academy actively, reproducing every technique in a lab. Build a strong note-taking system, master enumeration and network pivoting, grind real Active Directory machines, and most importantly write at least one full commercial-grade report before exam day using a template you can reuse."
      }
    }
  ]
}
```
