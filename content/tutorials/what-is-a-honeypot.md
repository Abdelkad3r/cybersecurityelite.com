---
title: "What Is a Honeypot in Cybersecurity? Types, Deployment, and Detection Use Cases (2026)"
slug: "what-is-a-honeypot"
description: "What is a computer honeypot? Types, deployment patterns, and the SOC use cases that catch attackers in minutes — Cowrie, T-Pot, Canarytokens, AD honeyaccounts."
date: 2026-05-24T14:00:00Z
lastmod: 2026-05-24T14:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["Tutorials"]
tags: ["honeypot", "deception", "blue-team", "detection-engineering", "siem", "canarytokens", "active-directory", "threat-intelligence"]
keywords: [
  "what is a computer honeypot",
  "what is a honeypot",
  "honeypot cybersecurity",
  "honeypot types",
  "honeypot deployment",
  "low interaction honeypot",
  "high interaction honeypot",
  "production honeypot",
  "research honeypot",
  "cowrie honeypot",
  "T-Pot honeypot",
  "canarytokens",
  "honeytoken active directory",
  "honeyaccount",
  "honeypot detection rules",
  "honeypot SIEM integration"
]
toc: true
cover:
  image: "/images/articles/what-is-a-honeypot.png"
  alt: "What is a honeypot in cybersecurity — types, deployment, and detection use cases"
---

A honeypot is a security resource whose value lies entirely in being attacked. It looks like a legitimate target — a database, an admin account, a file share, a misconfigured cloud key — but in reality it has no legitimate users, no real data, and one job: when someone touches it, raise an alarm. The first interaction is the alarm, and that's why honeypots routinely deliver detection in minutes for techniques that signature-based EDR misses entirely. This guide answers **what is a computer honeypot** in 2026, walks through the practical taxonomy (low- vs high-interaction, production vs research), and shows the deployment patterns and SIEM integration that actually catch attackers rather than wasting blue-team time.

## TL;DR — honeypots in one screen

- **A honeypot is a decoy that has no legitimate use.** Any access = malicious by definition. Zero false positives by design.
- Two axes split the field: **interaction level** (low / medium / high) and **purpose** (production / research).
- The 2026 sweet spot for most blue teams: **low-interaction service emulators in production** (Cowrie, Conpot, T-Pot bundle) **plus AD honeyaccounts and Canarytokens scattered through file shares and code repos**.
- High-interaction honeypots (full systems) are research tools — they catch novel tradecraft but need careful network isolation; one compromised honeypot becomes a pivot point.
- The detection model is simple: **forward every honeypot event to your SIEM, alert at threshold = 1**. No tuning needed. No false-positive triage.

## What is a honeypot, exactly?

A **honeypot** is an information system resource whose value lies in being probed, attacked, or compromised. It is not a real production service — it has no real users, no real data, no business function. Its sole purpose is to detect, deflect, or study unauthorised access.

The defining property: **there is no legitimate reason for anyone to touch it.** That makes every interaction a high-fidelity signal. Compare to a typical SIEM rule on `failed login > 100 in 5 minutes` — full of false positives from typo'd passwords, expired credentials, automated scanners. A honeypot fires once per real attacker.

The term traces back to Cliff Stoll's *The Cuckoo's Egg* (1989), and to Lance Spitzner's foundational work on the Honeynet Project in 1999. Two decades later the technique is firmly in mainstream blue-team practice — MITRE D3FEND lists deception as a primary defensive category, and modern detection engineering curriculum (SANS, RangeForce, MITRE Engage) all teach honeypot deployment as a baseline.

## Why deploy honeypots in 2026

Four concrete reasons honeypots remain top-tier blue-team investment:

**1. Modern attackers are quiet inside the network.** Mandiant's 2024 M-Trends report measured median dwell time at 10 days. Most of that time, attackers are doing reconnaissance — querying LDAP, browsing shares, reading SharePoint. Honeypots planted in exactly those reconnaissance paths fire the moment they're touched, compressing detection from days to minutes.

**2. Honeypots catch what signatures miss.** Living-off-the-land techniques (BloodHound enumeration, AD recon via PowerView, SharpHound, SoaPy) generate normal-looking SMB/LDAP traffic. They don't trip Defender. They DO trigger a honeyaccount Kerberos request.

**3. Zero false positives is a real operational win.** SOC analysts spend the majority of their day triaging alerts that turn out to be benign. A honeypot alert is by definition true-positive. It's the highest-fidelity input you can feed into your SOAR playbooks.

**4. Honeypots are cheap.** Cowrie runs on a $5/month VPS. Canarytokens are free. AD honeyaccounts are creating-disabled-user-account free. The detection lift vs. the spend is asymmetric.

## The honeypot taxonomy

### By interaction level

| Type | What attacker sees | Engineering effort | Risk if compromised | Use case |
|---|---|---|---|---|
| **Low-interaction** | Faked banners + scripted responses for specific protocols (SSH, Telnet, RDP, SMB) | Low — install + configure | Low — no real OS underneath | Trip-wire detection at scale |
| **Medium-interaction** | Emulated services with deeper protocol implementation; can capture some attacker behaviour | Medium | Low–medium | Capture credentials, scripts, malware drops |
| **High-interaction** | A real OS / real services; attacker gets a real shell | High — isolation, monitoring, recovery | High — pivot point if uncontained | Research, threat intel, novel TTP capture |

**For most blue teams the answer is low- and medium-interaction.** High-interaction honeypots produce richer intelligence but the operational cost is meaningful: full network isolation, automated rebuild after each compromise, dedicated analyst time. Reserve them for research roles or threat-intel teams.

### By deployment role

| Role | What it is | Where to put it | Typical alert volume |
|---|---|---|---|
| **Production honeypot** | A decoy planted inside your real environment | Same VLAN as real assets; same subnet ranges; valid AD domain | Sparse — only when attackers are present |
| **Research honeypot** | A decoy exposed to the internet at large to study commodity threats | Public IP, isolated network | High — constant noise from internet scanners |

The two roles are not interchangeable. Production honeypots are blue-team detection; research honeypots are threat-intelligence feeds.

## The honeypot tool landscape

A working reference of what to deploy for which use case:

| Tool | Type | Best for |
|---|---|---|
| **Cowrie** | Medium-interaction SSH/Telnet | Catching SSH brute-force + payload retrieval |
| **Dionaea** | Low-interaction multi-protocol (SMB, HTTP, FTP, TFTP) | Catching worm-style propagation; malware capture |
| **Conpot** | Low-interaction ICS/SCADA | Detecting OT-aware attackers (Modbus, S7Comm, IPMI) |
| **HoneyHTTP / Glastopf** | Low-interaction web app | Detecting web-shell drop attempts |
| **HoneyDB / honeyd-modern** | Configurable multi-service | Stand-up of dozens of decoys |
| **T-Pot** | All-in-one Docker bundle of 20+ honeypots | Single-host deployment with dashboards |
| **Canarytokens (Thinkst)** | Embedded tokens (URL, DNS, doc) | Sprinkling tripwires through real systems |
| **Thinkst Canary appliance** | Commercial high-fidelity sensor | Enterprise blue teams; minimal-ops detection |
| **HoneyAccounts in AD** | Disabled-but-tempting AD users with SPNs | Kerberoasting and password-spray detection |
| **HoneyShares (SMB)** | Empty share with auditing | Lateral-movement detection |
| **DeceptionGrid (Attivo/SentinelOne)** | Commercial deception platform | Large enterprise with full AD coverage |

## How to deploy a honeypot in your environment

The full safe-rollout sequence:

{{< howto title="How to deploy a honeypot for SOC detection in your enterprise" duration="PT4H" >}}
- name: "Decide the role: production detection or threat research"
  text: "Production honeypots live **inside** your network with the goal of catching internal attackers; research honeypots live **outside** to study commodity threats. The deployment patterns differ — production gets sparse, high-fidelity alerts; research gets a firehose of internet noise. Most blue teams want production first."
- name: "Choose interaction level"
  text: "Start with low- or medium-interaction (Cowrie, Dionaea, Canarytokens). High-interaction honeypots require full network isolation and dedicated cleanup workflows — leave those for threat-intel roles. Low-interaction tools deliver 80% of the detection value at 10% of the operational cost."
- name: "Plant the honeypot where attackers actually look"
  text: "Decoys outside the attacker's reconnaissance path will never fire. The high-value placements: a fake SQL server in the database VLAN; an unsigned RDP listener on an admin jump-host subnet; an AD account named something like `svc-backup` or `sql-admin` with an SPN; a SharePoint document called `passwords.xlsx` with a Canarytoken; a Git repo named `aws-keys.tar.gz` with a tokenised AWS access key inside."
- name: "Match the honeypot's surface to your real environment"
  text: "If your real servers run Windows Server 2022 and you deploy a Cowrie SSH honeypot, attackers will smell it immediately. Match the OS banners, hostnames, IP ranges, and naming conventions. A 'fileserver-04' honeypot in 10.20.30.0/24 alongside real fileserver-01 through fileserver-03 is invisible."
- name: "Wire alerts to your SIEM with threshold = 1"
  text: "Forward honeypot logs to Splunk / Sentinel / Elastic. Build a single rule: any event from these sources, alert. No tuning, no thresholds, no exceptions. This is the entire reason honeypots are valuable — they don't need triage."
- name: "Add SOAR playbooks for first-response containment"
  text: "When a honeypot fires, the playbook should: 1) snapshot the attacker IP and timestamp; 2) trigger an EDR isolate on any internal host that touched the honeypot in the prior 15 minutes; 3) page the on-call analyst; 4) pull AD logs for the relevant accounts; 5) start a chain-of-custody log."
- name: "Document the honeypot inventory and access permissions"
  text: "Maintain a register of every deployed honeypot — what, where, owner, alert routing. Without a register, someone will eventually 'discover' a honeypot during routine ops, panic, and trigger an incident response for what's actually their own decoy. The register also documents who is allowed to access honeypots for testing (almost no one)."
- name: "Review and rotate quarterly"
  text: "Honeypots that have been in place for a year and never fired might be in the wrong location — or attackers might already know they're there. Quarterly: review fire rates, move underperforming honeypots, rotate Canarytoken filenames, regenerate honeyaccount passwords."
{{< /howto >}}

Each step is expanded with concrete commands below.

## Step-by-step: deploying T-Pot (low-effort starting point)

T-Pot bundles 20+ honeypots (Cowrie, Dionaea, Conpot, ElasticPot, Heralding, Honeytrap, more) into a single Docker-Compose stack with an Elastic dashboard. It's the fastest way to get visibility against opportunistic attackers.

{{< terminal title="root@sensor: Ubuntu 22.04+ host" >}}
# Provision a dedicated host — never on a production server
# Minimum: 8 GB RAM, 64 GB disk, public IP (for internet research role)

apt-get update && apt-get -y install git
git clone https://github.com/telekom-security/tpotce
cd tpotce
./install.sh -t SENSOR -y                  # SENSOR = headless; HIVE adds Kibana

# Confirm services
docker ps --format 'table {{.Names}}\t{{.Status}}'

# Each honeypot logs to /data/<tool>/log/
tail -f /data/cowrie/log/cowrie.json | jq '.username, .src_ip'
{{< /terminal >}}

Within minutes of exposure to the internet you'll have credentials, payload URLs, and attacker IPs piling up. For research-role honeypots that's the goal. For production-role honeypots **do not expose to the internet** — deploy on an internal IP that mirrors a real server.

## Step-by-step: deploying Cowrie inside the network

Cowrie is the most useful single honeypot tool — medium-interaction SSH that captures credentials, command-line activity, and downloaded payloads.

{{< terminal title="cowrie@honeyhost" >}}
adduser cowrie --disabled-password
su - cowrie
git clone https://github.com/cowrie/cowrie
cd cowrie
python3 -m venv cowrie-env && source cowrie-env/bin/activate
pip install -r requirements.txt

# Configure
cp etc/cowrie.cfg.dist etc/cowrie.cfg
# Edit:
#   hostname = fileserver-04           (match your real naming)
#   listen_endpoints = tcp:2222:interface=0.0.0.0
#   download_path = /opt/cowrie/dl

# Redirect port 22 to 2222 (cowrie can't bind <1024 unsupervised)
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222

bin/cowrie start
{{< /terminal >}}

Every credential attempted, command typed, and file downloaded is logged to `var/log/cowrie/cowrie.json` — perfect for SIEM ingest.

## Production honeypot patterns that work

### 1. AD honeyaccount

A disabled, never-logged-on AD account with a tempting name (`svc-backup-2026`, `admin-old`, `sql-svc`). Register an SPN on it so Kerberoasting tools (`Rubeus.exe kerberoast`) request a TGS — and every TGS request for that SPN generates Event ID 4769 with a known, unused account name.

{{< terminal title="DC: PowerShell" >}}
# Create the honeyaccount
$pwd = ConvertTo-SecureString (-join ((33..126) | Get-Random -Count 32 | %{[char]$_})) -AsPlainText -Force
New-ADUser -Name "svc-backup-old" -SamAccountName "svc-backup-old" `
  -AccountPassword $pwd -Enabled $false `
  -Description "Decommissioned backup service account (DO NOT USE)"

# Register a tempting SPN
Set-ADUser svc-backup-old -ServicePrincipalNames @{Add="MSSQLSvc/sql01.corp.local:1433"}

# SIEM rule: any 4769 event with ServiceName CN=svc-backup-old → alert
{{< /terminal >}}

This is one of the highest-ROI honeypots in the entire AD ecosystem. Paired with the [Kerberoasting detection guide](/network-security/active-directory-kerberoasting-deep-dive/), it catches every BloodHound-driven enumeration that touches `kerberoast` mode.

### 2. SharePoint / file-share Canarytoken

Place a file called `passwords.docx` or `aws-credentials.xlsx` somewhere visible (a SharePoint site, a domain admin's user share, the IT department's wiki). Use [Canarytokens.org](https://canarytokens.org) to generate a tokenised Microsoft Word doc. When the file is opened, a DNS / HTTP callback fires to your alerting endpoint.

Attackers in lateral-movement phase always grep for `password`, `secret`, `cred` — and the moment one of them opens this file, you have an IP + UA + timestamp.

### 3. Cloud-key tokens

The same idea, but for AWS / Azure / GCP credentials. Drop an AWS-token-keypair into a Git repo named `prod-keys.tar.gz`. Every time an attacker tries to authenticate with those keys, CloudTrail logs the API call from the attacker's IP. Use **CanaryToken AWS Access Key** or generate via [Thinkst Canary](https://canary.tools/).

### 4. Honey-DNS records

Add a fake DNS A record like `backup-sql.corp.local` pointing to a Cowrie host. Internal attackers running `nslookup -type=A *.corp.local` or DNS sweeps via `dnsrecon` will discover it. Any connection to that IP = alert.

## Detection use cases — wiring honeypots into your SIEM

The detection model is simple: **every honeypot event is a true positive.** No tuning. No thresholds. No allow-lists. Just route the events to your SIEM and alert at threshold = 1.

### Splunk

```spl
index=honeypot
| stats count by src_ip, dest_host, session_id
| eval severity="critical"
| sendalert siemresponse param.message="Honeypot interaction detected"
```

### Microsoft Sentinel (KQL)

```kql
SecurityEvent
| where EventID in (4624, 4625, 4769)
| where TargetAccount has_any (dynamic(["svc-backup-old", "admin-decommissioned"]))
| project TimeGenerated, Computer, Account, IpAddress, ActivityType
| extend Severity="High"
```

### Elastic SIEM

```yaml
- name: "Honeypot interaction"
  index: ["filebeat-cowrie-*", "filebeat-canary-*"]
  query: "*"
  type: query
  severity: critical
```

The simplicity is the point. A honeypot rule has no tuning logic because every event is by-definition malicious.

## Common mistakes (and how to avoid them)

Twelve recurring failures in honeypot deployment:

| Mistake | Why it happens | Fix |
|---|---|---|
| Deploying internet-facing honeypots with the same name/banner as real assets | Convenience | Use distinct hostnames + IPs for research role honeypots |
| Forgetting honeypot exists, panicking when alert fires | No inventory register | Maintain a register; review monthly |
| Letting attackers pivot from a high-interaction honeypot | Insufficient network isolation | High-interaction must be in an isolated VLAN with egress filtering |
| Honeypot fires too often (low signal-to-noise) | Honeypot on internet without filtering | Move to internal placement, or filter out commodity scanner noise |
| Honeypot fires never (no signal) | Wrong placement or wrong protocol | Move closer to attacker reconnaissance paths; match the OS / banner / naming |
| Honeyaccount has same password as real accounts | Lazy provisioning | Use random 32-char passwords; cycle quarterly |
| Forgetting that AD honeyaccount writes 4769 events | Documentation gap | SIEM rule must specifically scope to the honeyaccount SamAccountName |
| Researcher honeypot leaks PII / company data | Used real test data | Use only synthetic, public data |
| Honeypot's outbound traffic is allowed | Set-and-forget firewall | Honeypots should have minimal egress: only to your SIEM ingest endpoint |
| Honeypot patching missed | "It's just a honeypot" attitude | Patch honeypots like production — an attacker shouldn't be able to LPE on your sensor |
| Canarytoken token in a place attackers won't find | Token placed in an obscure repo | Place tokens on the well-trodden paths attackers follow (file shares, wikis, dev repos) |
| One detection rule covering all honeypots | Single-rule fatigue | Per-honeypot rules for clean alerting + post-mortem traceability |

## Operational considerations

A few practical things that bite first-time deployers:

- **Legal review.** In some jurisdictions, deploying a honeypot that captures attacker PII (IP, browser fingerprint) has data-protection implications. Run it past legal before going live.
- **Communication with IT operations.** Network monitoring will flag the honeypot's traffic; your sysadmins will see "strange new VM" in monitoring; document it.
- **Rotation.** Static honeypots eventually get fingerprinted (especially research role). Cycle banners, ports, and filenames every 60-90 days.
- **Detection-engineering pairing.** Use honeypot alerts as input to your detection-engineering pipeline. Each alert is a labelled, high-confidence ground-truth attack event — gold for tuning rules elsewhere in your SIEM. The [Splunk detection-engineering guide](/tutorials/splunk-detection-engineering/) covers how to use these alerts as a feedback loop.

## Frequently asked questions

{{< faq >}}
- q: "What is a computer honeypot in simple terms?"
  a: "A computer honeypot is a fake system, account, or file that exists only to lure attackers. It looks like a legitimate target (a server, an admin account, a document called 'passwords.xlsx') but it has no real users and no real data. Anyone who touches it is, by definition, doing something unauthorised. That's why honeypots have effectively zero false positives — there's no legitimate reason for any access."

- q: "What's the difference between a honeypot and a honeynet?"
  a: "A **honeypot** is a single decoy resource (one host, one account, one file). A **honeynet** is a coordinated network of multiple honeypots arranged to look like a complete environment — typically used for threat-intel research. Honeynets are higher operational effort but capture richer attacker behaviour."

- q: "Is deploying a honeypot legal?"
  a: "Honeypots that you deploy on your own infrastructure to detect unauthorised access are legal in most jurisdictions. Legal complications arise when honeypots are used to collect attacker PII (some GDPR considerations), or to enable counter-attack (illegal almost everywhere). Run a legal review before going live."

- q: "Low-interaction vs high-interaction — which should I use?"
  a: "For most blue teams, **start with low- or medium-interaction.** Cowrie, Dionaea, Canarytokens, AD honeyaccounts give you 80% of the detection value at 10% of the operational cost. High-interaction honeypots (full real systems) capture richer intelligence but require strict network isolation and automated rebuild workflows — leave those for dedicated threat-intel teams."

- q: "Where should I place honeypots inside my network?"
  a: "Wherever attackers actually look during reconnaissance. The high-value placements: same VLAN as real database servers (decoy SQL host); same subnet as real file shares (decoy fileserver); domain accounts named like real service accounts (`svc-backup-2026`, `sql-svc-old`); files called `passwords.xlsx` on SharePoint and IT-team wikis; Git repos named `aws-credentials.tar.gz`."

- q: "Won't sophisticated attackers detect honeypots?"
  a: "Skilled attackers can often fingerprint honeypots — checking banner versions against real installations, looking for filesystem artefacts, watching for unusual response timings. But **the bar isn't 'fool every attacker.'** The bar is 'fool enough attackers to deliver detection signal.' Even if a honeypot only catches commodity attacks, those are the ~80% of incidents that actually hit most enterprises."

- q: "Can attackers use my honeypot to attack other systems?"
  a: "Yes — and this is the biggest operational risk with high-interaction honeypots. If an attacker compromises a real OS underneath your decoy, they can pivot. Mitigations: keep honeypots in isolated VLANs, egress-filter to only the SIEM ingest endpoint, run as non-privileged services, snapshot and rebuild automatically after every interaction."

- q: "How do honeypots compare to canarytokens?"
  a: "Canarytokens are a specific *kind* of low-interaction honeypot — small embedded tripwires (a tokenised Word document, a DNS callback, an AWS credential) rather than full emulated services. They're the lowest-effort deployment in the whole deception space and trip when an attacker reads/uses the token. Pair them with traditional honeypots for layered coverage."

- q: "Are honeypots part of MITRE ATT&CK or D3FEND?"
  a: "Yes — MITRE D3FEND lists multiple deception techniques (**Decoy File, Decoy Network Resource, Decoy Persona, Decoy Public Release**). MITRE Engage (formerly Shield) is dedicated entirely to engagement and deception. ATT&CK itself maps attacker TTPs that honeypots are particularly good at catching: T1078 Valid Accounts, T1083 File and Directory Discovery, T1110 Brute Force, T1558 Kerberoasting."

- q: "How many honeypots should an enterprise deploy?"
  a: "There's no universal number, but a useful benchmark: at least one honeyaccount per privileged-account naming pattern (so attackers running BloodHound see decoy `svc-backup-X` mixed with real `svc-backup-Y`), one Canarytoken per high-value SharePoint site, and one network sensor per DMZ / production VLAN / OT segment. For a 500-seat enterprise that's typically 15-25 honeypots."
{{< /faq >}}

## Conclusion: deploy one honeypot this week

The smallest meaningful step you can take: create one AD honeyaccount with an SPN, wire the Event 4769 alert into your SIEM, and document it in your inventory. That's a one-hour engagement and it catches Kerberoasting from BloodHound, Rubeus, and Impacket — the toolkit of every modern AD attacker.

From there, layer in:
1. One Canarytoken document on the IT-department SharePoint site
2. One Cowrie SSH honeypot mirroring your real server-naming convention
3. A SOAR playbook that auto-isolates any internal host that has touched a honeypot in the prior 15 minutes

That's a complete deception layer in roughly a week of part-time work. The detection lift vs. the spend is the highest in modern blue-team practice — there's nothing else that delivers true-positive alerts with this little effort.

For related Windows and AD hardening that pairs naturally with honeypot detection, see the [Windows LAPS implementation guide](/tutorials/windows-laps-implementation/) (which closes the credential-reuse vector your honeypots are designed to detect being abused), the [Kerberoasting deep dive](/network-security/active-directory-kerberoasting-deep-dive/) (which explains the attack your AD honeyaccount catches), and the [Splunk detection-engineering tutorial](/tutorials/splunk-detection-engineering/) for the SIEM-side rule construction.

## Share this guide

**LinkedIn**:
> A computer honeypot is the cheapest, highest-fidelity detection control in modern blue-team practice — zero false positives by design. The 2026 deployment playbook: AD honeyaccounts, Canarytokens, T-Pot for research role, and the SIEM rule that needs no tuning. 👇

**X / Twitter**:
> Honeypots in 2026: low-interaction (Cowrie/T-Pot) + medium (Canarytokens) + AD honeyaccounts with SPNs = full detection coverage for the techniques EDR misses. Detection rule: threshold=1. No tuning. No false positives. Full guide:

## References

- [MITRE D3FEND: Deception techniques](https://d3fend.mitre.org/) — the defensive framework's deception branch
- [MITRE Engage](https://engage.mitre.org/) — the dedicated engagement and deception framework
- [The Honeynet Project](https://www.honeynet.org/) — the foundational community resource
- [Cowrie SSH/Telnet honeypot](https://github.com/cowrie/cowrie)
- [Dionaea multi-protocol honeypot](https://github.com/DinoTools/dionaea)
- [Conpot ICS honeypot](https://github.com/mushorg/conpot)
- [T-Pot all-in-one bundle](https://github.com/telekom-security/tpotce)
- [Canarytokens.org](https://canarytokens.org/) — free tokenised tripwires from Thinkst
- [Thinkst Canary](https://canary.tools/) — commercial honeypot appliance
- [SANS: Honeypots, Deception, and Cyber Threat Intelligence](https://www.sans.org/blog/) — practitioner research
