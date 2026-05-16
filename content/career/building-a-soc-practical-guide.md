---
title: "Building a SOC From Zero: A Practical Guide"
slug: "building-a-soc-practical-guide"
description: "Stand up a Security Operations Center that produces value from day one — staffing, tooling, log sources, processes, and the 90-day milestones that matter."
date: 2026-05-03T09:00:00Z
lastmod: 2026-05-03T09:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["Career"]
tags: ["soc", "siem", "incident response", "security operations"]
keywords: ["build a soc", "soc setup", "soc playbook", "security operations"]
toc: true
cover:
  image: "/images/og-default.svg"
  alt: "Building a SOC"
---

Most newly-built SOCs spend twelve months becoming a dashboard wall before they detect their first real intrusion. Here's how to skip the theatre and ship value from week two.

## Define the Mission First

Before any tool selection, agree on:

1. **Scope** — what assets, what environments, what hours.
2. **Detection vs response split** — are you running 24/7 or business hours + on-call?
3. **Mandate** — does the SOC have authority to isolate hosts, or is it advisory?
4. **Reporting line** — CISO, CIO, Risk?

Without these settled, every tool decision later becomes a politics fight.

## Day-0 Stack

A minimal effective SOC needs five tool categories:

| Category | Open-source baseline | Commercial step-up |
|----------|---------------------|-------------------|
| SIEM | Elastic / OpenSearch + Wazuh | Splunk, Sentinel, Chronicle |
| EDR | Velociraptor, osquery | CrowdStrike, SentinelOne, MDE |
| Network | Suricata + Zeek | Vectra, Corelight |
| Ticketing | TheHive | ServiceNow SecOps, Splunk SOAR |
| Threat intel | MISP | Recorded Future, Mandiant |

Start with open source. Buy commercial when *people-cost* exceeds tool-cost — usually around 8-10 analysts.

## The Log Sources That Matter

Onboard in this order; skipping ahead is a rookie mistake:

1. **Endpoint** — Sysmon (Windows) + auditd (Linux). The single highest-fidelity source.
2. **Identity** — AD logs (4624, 4625, 4768, 4769, 4776) and your IdP (Okta, Entra ID).
3. **Cloud control plane** — CloudTrail, Azure Activity, GCP Cloud Audit Logs.
4. **Email** — M365 / Google Workspace audit and message trace.
5. **DNS** — DNS Firewall logs from your resolver.
6. **Firewall & proxy** — egress visibility.
7. **VPN / ZTNA** — auth and session metadata.
8. **WAF & application** — top-priority apps only.

Most "I want to see everything" SOCs onboard firewall first and choke on volume. Endpoint and identity is 80% of detection value at 10% of the data volume.

## Staffing the Three Tiers

- **Tier 1** — triage alerts, escalate. Read playbooks. Junior.
- **Tier 2** — investigate, contain. Write detection rules. Mid-level.
- **Tier 3** — threat hunt, IR lead, content engineering. Senior.

Realistic minimum for 24/7 operation: 8-10 people (4 shifts × 1 T1, plus T2 day shift, plus 1-2 T3). Hybrid 8x5 + on-call: 4-5 people.

## The 90-Day Roadmap

### Days 1–30: Plumbing

- Pick the stack. Get logs flowing for endpoint + identity.
- Define MSSP boundary (if any).
- Build the on-call rotation. PagerDuty or Opsgenie.
- Document the IR plan — who decides isolation, who calls leadership, who calls legal.

### Days 31–60: Content

- Onboard cloud and email logs.
- Deploy 30-50 starter detections from open content (Sigma → your SIEM, Splunk ESCU, Elastic Detections).
- Tune each detection to <1 false positive per week before deploying the next.
- Stand up the ticketing workflow.

### Days 61–90: Maturity Probes

- Run an internal purple-team exercise. Did detections fire? How long did triage take?
- Onboard remaining log sources.
- Publish your first weekly metrics report — alerts triaged, true positives, MTTD, MTTR.

By day 90 you should have detected something real. If you haven't, your detections are wrong, not your luck.

## Metrics Worth Tracking

Stop tracking "alerts handled". Start tracking:

- **Mean time to detect (MTTD)** — incident timestamp vs alert timestamp
- **Mean time to triage (MTTT)** — alert created to first analyst touch
- **Mean time to contain (MTTC)** — analyst touch to host isolation
- **True positive rate per rule** — a rule under 5% TPR needs tuning or retirement
- **Detection coverage by ATT&CK technique** — use the MITRE Navigator

## Culture Mistakes That Kill SOCs

- **Treating it like a help desk.** Alert volume becomes the metric. Quality drops.
- **No engineering track.** Without detection engineering, T1 analysts burn out triaging noisy rules.
- **Ignoring the response side.** Detection without response capability is theater.
- **Hero culture.** The analyst who never sleeps catches threats nobody else does → single point of failure.

## References

- [SANS — Building a SOC](https://www.sans.org/white-papers/)
- [The DFIR Report](https://thedfirreport.com/) — real intrusion timelines worth studying
- [Atomic Red Team](https://atomicredteam.io/) — purple-team your detections
