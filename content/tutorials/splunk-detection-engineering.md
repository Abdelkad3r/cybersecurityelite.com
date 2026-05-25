---
title: "Splunk Detection Engineering: From Logs to Useful Alerts"
slug: "splunk-detection-engineering"
description: "Stop drowning in Splunk false positives. The detection-engineering playbook mature SOCs use: CIM hygiene, MITRE-aligned content, lifecycle at scale."
date: 2026-04-26T09:00:00Z
lastmod: 2026-04-26T09:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["Tutorials"]
tags: ["splunk", "siem", "detection engineering", "blue team", "soc"]
keywords: ["splunk detection engineering", "splunk siem", "detection rules"]
toc: true
cover:
  image: "/images/articles/splunk-detection-engineering.png"
  alt: "Detection engineering in Splunk"
---

Most SIEMs fail not because the technology can't keep up but because the detection content is bad. This guide walks through how a detection engineer actually thinks about a rule, from data onboarding to deployment.

## The Lifecycle

```text
Threat → Hypothesis → Data → Query → Tuning → Deploy → Measure → Retire
```

Skip any step and you produce noise.

## Step 1: Data Hygiene

A detection on garbage data is a detection that lies.

- **Use the Common Information Model.** Map raw fields to CIM names — `src_ip`, `dest_ip`, `user`, `process_name`. Detections expressed in CIM survive log-source migration.
- **Set TIME_FORMAT and TIME_PREFIX correctly** in `props.conf`. Wrong timestamps blow up time-window correlation.
- **Choose sourcetypes deliberately**, not by guessing. One sourcetype per format.
- **Reject unknown event types early.** A sourcetype with hundreds of rare formats produces unreliable rules.

## Step 2: Hypothesis-Driven Detection

Don't write rules for "things that look bad." Write rules for **specific TTPs**. Reference ATT&CK whenever possible.

Example hypothesis:

> An attacker performing Kerberoasting will request multiple TGS tickets for service accounts within a short window from a single user, using the RC4-HMAC encryption type.

That sentence translates directly into:

```spl
index=windows EventCode=4769 Service_Name="*$" Ticket_Encryption_Type=0x17
| bin _time span=10m
| stats dc(Service_Name) AS unique_services
        values(Service_Name) AS services
        BY _time, Account_Name
| where unique_services >= 5
```

Now the rule isn't "weird Kerberos stuff." It's: "**one account requested five+ RC4 service tickets in ten minutes**" — a precise behavior with documented adversary use.

## Step 3: Quality SPL

Three SPL principles that separate junior from senior detection engineers:

### Anchor with sourcetype + index

```spl
# Bad — scans all data
EventCode=4624 LogonType=10

# Good — anchored, fast
index=windows sourcetype="WinEventLog:Security" EventCode=4624 LogonType=10
```

### Use `tstats` for high-cardinality aggregations

```spl
| tstats summariesonly=true count
    FROM datamodel=Authentication
    WHERE Authentication.action=failure
    BY Authentication.user, Authentication.src
| where count > 50
```

`tstats` against accelerated data models can be 100x faster than `stats` on raw events.

### Time-bin to detect patterns, not single events

```spl
| bin _time span=5m
| stats count BY _time, src_ip, dest_ip
| where count > 1000
```

Bin first; correlate second.

## Step 4: Tuning to Zero False Positives

A rule that fires daily without an analyst caring is **broken**, not "informational."

Tuning checklist:

1. Run the rule against 30 days of historical data. How many hits?
2. Investigate each hit. Is it actually malicious — or routine?
3. For each routine hit pattern, **either narrow the rule** or **add a known-good exception**.
4. Repeat until either zero false positives or you accept the rule isn't precise enough.

The goal is **every alert is worth investigating**. If 1-in-50 alerts on a rule is real, your team will mute it within a week.

## Step 5: Risk-Based Alerting

Modern SOCs don't alert on every rule — they assign risk scores and alert when **per-user/per-asset cumulative risk** crosses a threshold.

```spl
| eval risk_score=case(
    rule_name="kerberoasting", 50,
    rule_name="lateral_smb", 30,
    rule_name="dns_tunneling", 70,
    1=1, 10)
| collect index=risk
```

A single `kerberoasting` hit may not page anyone. A user racking up Kerberoasting + lateral movement + DNS exfil in one hour absolutely will.

## Step 6: Deployment & Measurement

Track for every rule:

- **True positive rate** — analyst confirmation
- **False positive rate** — closed as non-issue
- **Time to triage** — median analyst time
- **Coverage** — ATT&CK techniques covered, % of relevant data sources ingested

A monthly review retires rules with <5% TPR and replaces them with sharper hypotheses.

## Common Anti-Patterns

- **`AND NOT \*` exclusion lists** that grow without limit — refactor with lookups.
- **Detection that fires on the second the attacker triggers a known control.** No attacker will use that exact command line again — you've blown your tripwire on a known-bad test.
- **No documentation.** Every rule must answer: what ATT&CK technique, what data, what the next step in the IR runbook is.

## References

- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [Splunk Security Content (ESCU)](https://research.splunk.com/)
- [Sigma Rules](https://github.com/SigmaHQ/sigma) — cross-SIEM detection language
