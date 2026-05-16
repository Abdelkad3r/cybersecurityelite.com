---
title: "AWS IAM Security Best Practices for 2026"
slug: "aws-iam-security-best-practices"
description: "Modern AWS IAM hardening — root account, MFA, least privilege with permission boundaries, IAM Access Analyzer, and detection of common privilege escalation paths."
date: 2026-05-02T10:00:00Z
lastmod: 2026-05-02T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["Cloud Security"]
tags: ["aws", "iam", "cloud security", "least privilege"]
keywords: ["aws iam best practices", "iam security", "aws security"]
toc: true
cover:
  image: "/images/og-default.svg"
  alt: "AWS IAM best practices"
---

IAM is the AWS control plane. Almost every public AWS breach traces back to an IAM misconfiguration — over-permissive roles, leaked access keys, or trust policies that accidentally trust the entire internet. This is the modern playbook.

## The Foundation

### Lock the Root Account

The root user has powers no other principal can have (closing the account, modifying the support plan). Treat it like nuclear codes:

1. Enable MFA — **hardware token preferred**, not SMS.
2. Delete root access keys if any exist.
3. Use root only for the [seven things that require it](https://docs.aws.amazon.com/IAM/latest/UserGuide/root-user-tasks.html).
4. Set up a CloudTrail alarm on **every root login**.

### Stop Creating IAM Users

In a modern AWS account, humans authenticate through **IAM Identity Center** (formerly SSO) backed by your IdP. Workloads use **IAM roles** assumed via STS or, on EC2/ECS/Lambda, automatically attached.

Long-lived access keys should exist only for break-glass and CI providers that genuinely can't use OIDC federation.

## Least Privilege, Realistically

The principle is easy; the practice is hard. Three working strategies:

### 1. Start from Logs, Not Specs

Generate IAM policies from observed CloudTrail activity:

```bash
aws cloudtrail lookup-events --lookup-attributes \
  AttributeKey=Username,AttributeValue=my-role \
  --start-time 2026-04-01 > activity.json

# Convert to policy with Cloudsplaining or iamlive
iamlive --output-file policy.json --refresh-rate 5
```

### 2. Permission Boundaries

Boundaries are the **maximum permissions** a role can ever obtain, regardless of attached policies. Use them to delegate IAM permission creation safely:

```json
{
  "Effect": "Allow",
  "Action": "iam:CreateRole",
  "Resource": "*",
  "Condition": {
    "StringEquals": {
      "iam:PermissionsBoundary": "arn:aws:iam::123456789012:policy/DevBoundary"
    }
  }
}
```

Developers can now create roles, but only within the safety envelope you defined.

### 3. Service Control Policies (SCPs)

In AWS Organizations, SCPs enforce account-level guardrails — deny disabling CloudTrail, deny operations outside approved regions, deny modifying the security tooling role. Even root cannot bypass SCPs.

## The Eight Most Dangerous Misconfigurations

1. **Trust policy with `"Principal": "*"`** — anyone in any AWS account can assume the role. Almost always a typo of `"AWS": "*"` meant to be scoped with a condition; that condition often gets forgotten.
2. **`iam:PassRole` to `*`** combined with `lambda:CreateFunction` or `ec2:RunInstances` — classic privilege escalation chain.
3. **`s3:GetObject` to a wildcard resource** for a role that shouldn't read every bucket.
4. **Inline policies on shared roles** — invisible to most policy reviews.
5. **Console-created roles with the default trust policy** containing your account number — easy lateral movement if a developer's keys leak.
6. **Long-lived access keys** for "automation" — they leak in CI logs, dotfiles, and GitHub. Rotate or replace with OIDC.
7. **Cross-account trust without `sts:ExternalId`** — vulnerable to the confused-deputy attack.
8. **MFA missing** for break-glass humans.

## Detection With Built-In Tools

- **IAM Access Analyzer** — surfaces external access automatically. Free. Turn it on in every account.
- **CloudTrail + EventBridge** — alert on `iam:PutRolePolicy`, `iam:AttachRolePolicy`, root logins, console logins without MFA.
- **AWS Config Rules** — `iam-policy-no-statements-with-admin-access`, `iam-user-mfa-enabled`, and others enforce continuous compliance.
- **GuardDuty IAM findings** — anomalous API patterns (impossible travel, recon enumeration, credential exfil).

## Attacker's-Eye Tools (For Defenders)

Run these against your own accounts before someone else does:

- [**Pacu**](https://github.com/RhinoSecurityLabs/pacu) — AWS exploitation framework
- [**ScoutSuite**](https://github.com/nccgroup/ScoutSuite) — multi-cloud auditor
- [**Prowler**](https://github.com/prowler-cloud/prowler) — 300+ AWS checks against CIS, NIST, ISO27001
- [**Cloudsplaining**](https://github.com/salesforce/cloudsplaining) — IAM policy analyzer

## A Quarterly IAM Review

Block 90 minutes per quarter per account:

1. Run Prowler and Access Analyzer.
2. Review all IAM users — delete what isn't used in 90 days.
3. Review every role's last-used timestamp — delete what isn't used in 180 days.
4. Audit every `*` action in inline policies.
5. Confirm root MFA still works.

## References

- [AWS Well-Architected: Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
- [HackTricks Cloud — AWS](https://cloud.hacktricks.xyz/pentesting-cloud/aws-pentesting)
