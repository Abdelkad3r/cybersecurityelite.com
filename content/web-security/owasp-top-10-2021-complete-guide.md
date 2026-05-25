---
title: "OWASP Top 10 (2021): The Complete Guide With Examples"
slug: "owasp-top-10-2021-complete-guide"
description: "Every OWASP Top 10 category with real CVEs, exploit chains, the secure-code fix, and the detection signature — the working reference, not a recap."
date: 2026-04-25T10:00:00Z
lastmod: 2026-05-01T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["Web Security"]
tags: ["owasp top 10", "web security", "secure coding", "appsec"]
keywords: ["owasp top 10 2021", "owasp top ten", "web application security risks"]
toc: true
cover:
  image: "/images/og-default.svg"
  alt: "OWASP Top 10 2021 guide"
---

The OWASP Top 10 isn't just a checklist — it's a snapshot of how real-world breaches happen. The 2021 revision reorganized the previous list around **root causes** rather than symptoms, which makes it a much better map for both developers and security engineers. This guide walks through each category with reproducible examples, fixes, and detections.

## A01:2021 — Broken Access Control

Jumped to #1 from #5. Includes IDOR, missing function-level checks, and forced browsing.

**Example (IDOR):**

```http
GET /api/invoices/4178 HTTP/1.1
Authorization: Bearer ey...
```

If the server returns the invoice without verifying ownership, any authenticated user can iterate the ID parameter and steal records.

**Fix:** Enforce object-level authorization on every endpoint. Use a deny-by-default policy and a single authorization layer — not scattered checks. {{< cvss score="8.2" >}}

## A02:2021 — Cryptographic Failures

Renamed from "Sensitive Data Exposure" to highlight the root cause. Common patterns:

- TLS not enforced (HSTS missing)
- Hard-coded keys in source
- Weak algorithms (MD5, SHA-1 for passwords, ECB mode)
- Hashing passwords without a slow KDF

**Fix:** Argon2id for passwords, AES-GCM for symmetric encryption, X25519 + ChaCha20-Poly1305 for modern transport.

## A03:2021 — Injection

Now includes XSS as a subtype. SQL injection, OS command injection, LDAP injection, and template injection all sit here.

```python
# Vulnerable — string concatenation
cursor.execute(f"SELECT * FROM users WHERE id = {request.args['id']}")

# Safe — parameterized query
cursor.execute("SELECT * FROM users WHERE id = %s", (request.args['id'],))
```

{{< callout type="warning" title="ORMs are not a guarantee" >}}
ORM `raw()`, `extra()`, and string-built queries reintroduce injection. SQLAlchemy, Django ORM, and Sequelize have all shipped CVEs from misused unsafe APIs.
{{< /callout >}}

## A04:2021 — Insecure Design

New category covering threat modeling failures and missing security requirements. The classic example: an account-recovery flow that never rate-limits, enabling enumeration and credential brute force.

**Fix:** Threat-model every feature *before* coding. STRIDE works; PASTA scales better for large organizations.

## A05:2021 — Security Misconfiguration

Default credentials, verbose errors, unnecessary features enabled, missing security headers. The XML External Entities (XXE) category from 2017 was merged here.

```http
# Headers every modern app should set
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'; script-src 'self'
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

## A06:2021 — Vulnerable and Outdated Components

Equifax, Log4Shell, and every supply-chain breach lives here. Track inventory with an SBOM, scan with Dependabot/Renovate/Snyk, and patch within agreed SLAs (critical: 7 days, high: 30 days).

## A07:2021 — Identification and Authentication Failures

Predictable session IDs, missing MFA, credential stuffing without rate limits, password reset tokens with no expiry.

**Fix:** Implement WebAuthn or TOTP for MFA. Use credential-stuffing prevention services. Pin session cookies to TLS via the `__Secure-` / `__Host-` prefix.

## A08:2021 — Software and Data Integrity Failures

New category. Covers insecure deserialization, untrusted CI/CD pipelines, and auto-updates without signature verification.

```python
# Never deserialize untrusted input
import pickle
pickle.loads(request.body)   # RCE waiting to happen
```

Use JSON or schema-validated formats. Sign and verify auto-update payloads with code signing.

## A09:2021 — Security Logging and Monitoring Failures

Average dwell time for an undetected breach is still over 200 days. Log:

- Authentication successes and failures
- Access control failures
- Server-side input validation failures
- Privileged operations

Forward to a SIEM (Splunk, Elastic, Sentinel) and alert on anomalies. {{< cvss score="3.7" >}}

## A10:2021 — Server-Side Request Forgery (SSRF)

Promoted to its own category after a wave of cloud-metadata SSRFs (Capital One 2019, SSRF chains in countless bug bounties). Any feature that fetches a URL is suspect.

**Fix:**
1. Validate against an allow-list of domains/IPs.
2. Block private RFC1918 ranges and link-local (169.254.169.254) at the egress firewall.
3. Disable HTTP redirects in the fetch library or follow them safely.
4. Disable IMDSv1 on AWS; require IMDSv2 with hop limit 1.

## How to Use This List

Treat the Top 10 as the **floor**, not the ceiling. Real maturity means going beyond it — ASVS L2/L3 for AppSec teams, OWASP MASVS for mobile, and OWASP API Security Top 10 for API-heavy products.

## References

- [OWASP Top 10:2021](https://owasp.org/Top10/)
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP API Security Top 10](https://owasp.org/API-Security/)
