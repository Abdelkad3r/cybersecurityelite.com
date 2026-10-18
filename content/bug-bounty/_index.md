---
title: "Bug Bounty"
description: "Bug bounty hunting methodology, recon automation, target selection, and writeups of high-impact vulnerabilities."
keywords: ["bug bounty", "bounty hunting", "recon", "hackerone", "bugcrowd"]
---

Bug bounty work is security testing under a program's written authorization. A productive hunt starts with a clear scope and a small, testable hypothesis—not with scanning every host or running a large toolchain by default. This hub lays out a practical workflow and links to the site's focused guides.

## A responsible testing workflow

1. **Read the program rules before touching a target.** Record the in-scope domains, excluded assets, allowed test types, rate limits, account requirements, and disclosure process. Treat ambiguous ownership or scope as a stop condition and ask the program for clarification. Do not test third-party services, use real customer data, or continue after a restriction is reached.
2. **Map the permitted application.** Browse it as an ordinary user. Note the roles, workflows, inputs, and state changes you can reach. Keep a simple endpoint and feature inventory so tests stay tied to the approved asset and do not repeat work.
3. **Choose one security question at a time.** For example: can one authorized account read or change another test account's object? Does the server validate a value that the browser appears to enforce? Use a controlled test account and the least intrusive request that can answer the question. Avoid destructive actions and stop if testing could affect another user.
4. **Validate and document evidence.** Reproduce a suspected issue with the smallest request sequence possible. Keep timestamps, affected in-scope endpoint, test-account roles, sanitized request/response excerpts, and the observed impact. Remove session tokens, personal information, and unrelated data before saving or reporting evidence.
5. **Write a report another engineer can act on.** State the affected asset, prerequisites, concise reproduction steps, expected and actual behavior, demonstrated impact, and any safe remediation direction. Separate what you observed from what you infer. Submit through the program's required channel and follow its disclosure rules.

## Learning path

- **Build recon discipline:** [Bug bounty reconnaissance methodology](/bug-bounty/bug-bounty-recon-methodology/) covers a repeatable approach to discovery and automation. Apply its techniques only to assets and methods the program permits; automation does not expand authorization.
- **Understand web requests:** [The HTTP request lifecycle in PHP](/tutorials/http-request-lifecycle-in-php/) explains how requests move through a web stack, while [PHP fundamentals for security](/tutorials/php-fundamentals-for-security/) builds the language knowledge needed to reason about server-side behavior.
- **Use an intercepting proxy carefully:** [The Burp Suite Professional guide](/tools/burp-suite-professional-complete-guide/) introduces a core tool for inspecting and replaying your own authorized test traffic.
- **Study common input flaws:** The [XSS guide](/web-security/xss-theory-to-practical-exploitation/) and [SQL injection guide](/web-security/sql-injection-detection-to-exploitation/) explain how to recognize and validate these classes of bugs in a controlled, authorized setting.
- **Strengthen prerequisites:** [Learn PHP before advanced web hacking](/tutorials/learn-php-before-advanced-web-hacking/) offers a path for readers who need more programming background first.

## Before you submit

Check that the affected host and action are in scope, the result is reproducible with test data, and the report explains real security impact rather than only a scanner alert. Include enough sanitized evidence to reproduce the issue, but no secrets or data belonging to other people. If any of these checks fail, stop and clarify with the program instead of probing further.
