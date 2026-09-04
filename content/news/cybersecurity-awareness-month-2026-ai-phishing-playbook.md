---
title: "Cybersecurity Awareness Month 2026: The AI-Powered Phishing Playbook Every Employee Should Know"
slug: "cybersecurity-awareness-month-2026-ai-phishing-playbook"
description: "A practical Cybersecurity Awareness Month 2026 (NCSAM 2026) guide for employees, IT teams, and families. Covers the three phishing threats that dominated 2026 — deepfake voice vishing, LLM-crafted spearphishing, and adversary-in-the-middle MFA-bypass proxies — and shows why the old awareness advice (look for typos, hover the link, enable MFA) is no longer sufficient by itself. Maps CISA's Secure Our World pillars (strong unique passwords, phishing-resistant MFA, phishing recognition, keep software updated) onto 2026's threat surface, and gives concrete training scripts, employee checklists, HR/IT campaign templates, and a runnable NCSAM October calendar. Written for the non-technical reader with technical depth in the appendices."
date: 2026-09-04T18:00:00Z
lastmod: 2026-09-04T18:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["News", "Awareness"]
tags:
  - "cybersecurity awareness"
  - "cybersecurity awareness month"
  - "cybersecurity awareness month 2026"
  - "ncsam"
  - "ncsam 2026"
  - "secure our world"
  - "cisa"
  - "phishing"
  - "ai phishing"
  - "generative ai phishing"
  - "llm phishing"
  - "deepfake"
  - "voice cloning"
  - "vishing"
  - "smishing"
  - "spearphishing"
  - "business email compromise"
  - "bec"
  - "ceo fraud"
  - "wire fraud"
  - "mfa"
  - "multi factor authentication"
  - "phishing resistant mfa"
  - "passkeys"
  - "fido2"
  - "webauthn"
  - "adversary in the middle"
  - "aitm phishing"
  - "evilginx"
  - "session hijacking"
  - "employee training"
  - "security awareness training"
  - "small business cybersecurity"
  - "family online safety"
keywords:
  - "cybersecurity awareness month 2026"
  - "cybersecurity awareness 2026"
  - "ncsam 2026"
  - "cybersecurity awareness month theme 2026"
  - "secure our world 2026"
  - "ai phishing 2026"
  - "generative ai phishing awareness"
  - "deepfake voice scam awareness"
  - "how to spot ai phishing emails"
  - "adversary in the middle phishing explained"
  - "phishing resistant mfa for employees"
  - "passkeys vs mfa 2026"
  - "small business cybersecurity awareness"
  - "employee cybersecurity training 2026"
  - "family cybersecurity checklist"
  - "cybersecurity awareness month campaign ideas"
  - "ncsam calendar october 2026"
toc: true
cover:
  image: "/images/articles/cybersecurity-awareness-month-2026-ai-phishing-playbook.png"
  alt: "Cybersecurity Awareness Month 2026 cover — the AI-powered phishing playbook. Three 2026 phishing threats dominate: deepfake voice vishing that clones a CEO or family member in seconds from public audio; LLM-crafted spearphishing that produces grammatically perfect, personalized emails at scale so 'look for typos' no longer works; and adversary-in-the-middle MFA-bypass proxies (Evilginx-style toolkits) that steal live session cookies from realistic proxy portals even when MFA is enabled. The playbook maps CISA's Secure Our World pillars — strong unique passwords, phishing-resistant MFA (passkeys / FIDO2 / WebAuthn), phishing recognition, keep software updated — onto 2026's threat surface, and gives employees a verify-out-of-band callback rule, a passkey-first rollout script, an AI-phishing red-flag checklist, and an HR/IT NCSAM October calendar with runnable training exercises."
---

**Cybersecurity Awareness Month 2026** — the 23rd annual campaign run by [CISA](https://www.cisa.gov/cybersecurity-awareness-month) and the [National Cybersecurity Alliance](https://staysafeonline.org/) — begins on **October 1, 2026** and runs through October 31. The theme is still **"Secure Our World"** (in its fourth year), and the four campaign pillars remain: **use strong unique passwords, turn on phishing-resistant MFA, recognize and report phishing, and keep software updated**. All four are still correct. All four also need a serious 2026 refresh, because the threats an average employee will face this year look nothing like the ones the pillars were originally written to defend against.

This is a practical playbook for the awareness month — written primarily for the **non-technical employee, HR lead, or family member** who has to internalise the new threat surface, and secondarily for the **IT team** running an internal NCSAM campaign that has to actually move behavior. It covers the three phishing threats that dominated the first half of 2026 (deepfake voice vishing, LLM-crafted spearphishing, adversary-in-the-middle MFA-bypass), explains why the old advice is no longer sufficient on its own, and gives concrete scripts, checklists, and a runnable October calendar. Feel free to fork any of it for internal use.

## Why 2026 is a different threat year

Awareness training has spent 20 years teaching people to **look for typos, hover over links, and turn on MFA**. Two things changed in 2024–2026 that broke each of those three heuristics:

1. **Generative AI made "look for typos" useless.** Any large language model — free, hosted, or run locally — will produce grammatically flawless, contextually plausible, correctly localised email or SMS text in whatever tone the attacker asks for. Not just English; not just English written by a native speaker; English written *in the voice of the actual sender the target expects*, because a few LinkedIn posts and one podcast appearance are enough source material. The old training slide that reads "the email had bad grammar so I knew it was phishing" has effectively no signal left.
2. **Consumer-grade voice cloning made "verify by calling them" a trap in itself.** Voice-cloning models trained on 30 seconds of a target's speech will reproduce their voice well enough to fool a friend, a spouse, or a bank's voice-biometric system. Public audio (podcasts, YouTube, corporate all-hands recordings, LinkedIn video) provides the source. A parent gets a call in their child's voice asking for money; an accounts-payable clerk gets a call from what sounds exactly like the CFO authorizing a wire; a support-desk agent gets a call from someone whose voice matches the CEO asking to reset a password.
3. **Adversary-in-the-middle (AiTM) proxies made "just enable MFA" insufficient.** The old advice implicitly assumed that stealing a password was the attacker's goal, and MFA raised the cost. In 2026 the goal is the **session cookie**, not the password. Off-the-shelf toolkits (Evilginx, Modlishka, EvilProxy, and their commercial descendants) run a live reverse-proxy of Microsoft 365, Google Workspace, or Okta between the victim and the real service. The victim types their password *and* completes MFA into a page that looks pixel-perfect because it *is* the real page, proxied. The toolkit captures the resulting session cookie and replays it. From the target's perspective, they logged in successfully; from the attacker's, they have an authenticated session that MFA cannot revoke.

**These three trends are why the pillars need a 2026 refresh.** The pillars are still the right pillars. The tactics under them have changed.

## The 2026 phishing threat trio

Every incident that hit the mainstream news in the first half of 2026 fell into one of three shapes. Recognising the shape is more important than memorising any single example, because the underlying model determines what defence works.

### 1. Deepfake voice vishing (voice phishing)

**How it works.** The attacker gathers 30 seconds to a few minutes of the target's voice from public sources — corporate podcasts, YouTube keynotes, LinkedIn video posts, TikTok clips, all-hands recordings that leaked, or an earlier legitimate call the attacker recorded. Off-the-shelf voice-cloning tools produce a real-time or near-real-time synthetic voice that speaks whatever the attacker types. The attacker then places a call — usually to a subordinate, an accounts-payable team, an executive assistant, or a family member — and asks for a specific action: wire transfer, gift card purchase, password reset, or the shipment of a physical product.

**Why it works.** The victim has been trained to trust voice as a verification channel. "If in doubt, call them" is the default advice from a decade of awareness training. In 2026 that call *does not confirm identity*; it confirms nothing more than that the person on the other end has a computer.

**Real-world shape.** The 2024 UK engineering-firm case where an employee wired 25 million USD to an attacker after a video call with a deepfaked CFO and colleagues is the canonical corporate example. Consumer-side, the FBI's IC3 recorded thousands of "grandparent scam" and "kidnapping scam" variants using cloned voices of family members in 2025 alone.

**What actually defends against it.** A single rule, learned once and drilled: **verify high-impact requests through a channel the requester did not choose**. If the CFO calls asking for a wire, hang up and call the CFO back on the number saved in the phone book — not the number that just called. If a family member calls in distress asking for money, hang up and call them back on the number you have saved. The point is not to be rude; the point is that the attacker chose the inbound channel, and any confirmation on that channel is a confirmation of nothing.

### 2. LLM-crafted spearphishing

**How it works.** The attacker uses a language model — usually a locally-hosted uncensored one, but a jailbroken hosted model works too — to generate personalised phishing emails or SMS messages at scale. The model is given the target's LinkedIn profile, the sender's public writing, the target's employer's press releases, and any leaked email or breach data available, and asked to produce a plausible message from the sender to the target: same tone, same subject-line convention, references to the actual project the target is working on, correct internal jargon.

**Why it works.** The classic phishing signals — bad grammar, generic salutation, misspelled brand names, awkward phrasing — all disappear. The message reads exactly like the sender's real writing. The urgency ("can you sign this by end of day?"), the topic ("Q3 vendor review"), and the requested action ("just click the DocuSign link") are all consistent with what the target actually does at work.

**Real-world shape.** BEC (business email compromise) losses hit 2.9 billion USD in the FBI's 2024 IC3 report, and 2025's number is expected to be higher. In observed campaigns, attackers now generate 200–500 variant messages per target and A/B test them; a single successful click gives them either credentials (into an AiTM proxy, see below) or a beachhead session.

**What actually defends against it.** Two rules that stack:

- **Assume the words are perfect.** Do not use writing quality as a signal. Instead, use the **request shape**: does this email want you to log in via a link, download an attachment, change a bank account number, buy gift cards, or approve a wire? Those are the actions that go wrong; treat any inbound request for one of them as suspect regardless of who "sent" it.
- **Verify the sender's identity through the request's context**, not through the email itself. If your accounting team gets an email from a vendor asking to change their remitting bank account, call the vendor's known contact on their known number and confirm. Do not reply to the email; the email is the attack surface.

### 3. Adversary-in-the-middle (AiTM) MFA-bypass phishing

**How it works.** The attacker sends a phishing email or SMS with a link to what looks like a Microsoft 365 or Google Workspace or Okta login page. When the victim clicks, they land on an attacker-controlled server running a reverse proxy of the real service. The victim types their username and password, gets a real MFA prompt from the real service (because their credentials are being relayed live), completes the MFA, and lands on their real inbox. Nothing looks wrong. Meanwhile, the attacker's proxy captured the session cookie the real service issued in response to the successful authentication. The attacker replays the cookie from their own browser and has a fully authenticated session with the target's identity, mailbox, files, and (in many cases) approval workflows.

**Why it works.** SMS-based MFA, TOTP (authenticator-app codes), and push-notification MFA all authorize the *authentication event*, not the *session*. Once the session cookie is issued, MFA has no further role. AiTM does not need to steal the second factor; it needs the cookie the second factor produced.

**Real-world shape.** The Storm-1167 and DEV-1101 clusters — Microsoft's tracked names for the largest AiTM operators — have been running for years, but 2025–2026 saw commercial AiTM-as-a-service reach a maturity where a non-technical attacker can rent a working Microsoft 365 proxy for hours. Microsoft's own telemetry reported millions of AiTM sessions per month by mid-2026.

**What actually defends against it.** **Phishing-resistant MFA** — specifically FIDO2 / WebAuthn / passkeys. A passkey is a public-key credential bound to the actual origin (`accounts.microsoft.com`, not `accounts.microsoft.attacker.example`). The browser refuses to release the credential to any origin other than the one it was registered against, so an AiTM proxy — which by definition runs on a different origin — cannot solicit the passkey response. TOTP codes and push notifications are not origin-bound and are vulnerable; passkeys are the fix.

## Why the old awareness advice is no longer sufficient

The Secure Our World pillars remain correct, but the *tactics* under each one need refreshing.

| CISA pillar | 2015 advice | 2026 refresh |
|---|---|---|
| Strong unique passwords | 12+ characters, use a password manager | 12+ characters, use a password manager, **and treat every account as if the password will leak** — because SaaS breaches are the norm, not the exception, so uniqueness matters more than complexity |
| Turn on MFA | Any MFA is better than none | **Phishing-resistant MFA (passkeys / FIDO2 / WebAuthn) wherever available**; SMS and TOTP still beat nothing, but they do not stop AiTM. Push notifications alone (especially "just tap approve") are actively dangerous because of MFA-fatigue attacks |
| Recognize and report phishing | Look for typos, hover the link | **Ignore writing quality**; recognise the **request shape** (login link, attachment, bank-account change, wire, gift card, password reset); verify identity **out of band** through a channel the requester did not choose |
| Keep software updated | Turn on auto-updates | Turn on auto-updates; **plus enforce a browser version floor** (AiTM defences and passkey support ship in the browser); **plus audit third-party OAuth grants** at least once a year (compromised sessions often persist through granted app permissions) |

## The individual defence checklist

Print this. Stick it on the fridge. Send it to the group chat.

**Passwords and accounts**

- [ ] Use a password manager (Bitwarden, 1Password, Proton Pass, or your OS-integrated one). If you cannot list every account you have, your password manager should be able to.
- [ ] Every account has its own unique password. If you reuse anything, start with your email, banking, and work SSO account.
- [ ] Enable **passkeys** wherever the service supports them. In 2026 that includes Google, Microsoft, Apple, Amazon, GitHub, PayPal, most major banks, and a growing list of retailers. Passkeys replace both your password and your second factor with a single, phishing-resistant credential bound to the site.
- [ ] Where passkeys are not yet available, use an authenticator app (Aegis, 2FAS, Authy, your password manager's built-in TOTP). Avoid SMS-based MFA when there is an alternative.
- [ ] Turn on account-recovery methods that a stranger cannot reset — a backup security key, printed recovery codes stored somewhere physical, or an emergency-contact person you trust.

**Email and messaging**

- [ ] Any inbound request to click a login link, download an attachment, change a bank account number, buy gift cards, wire money, or reset a password is suspect until verified — regardless of who "sent" it and how well-written it is.
- [ ] Verify through a channel the requester did not choose. Call back on a saved number, walk to the person's desk, message them in a chat channel you know is theirs.
- [ ] Report suspicious messages to your IT team or your email provider's "report phishing" button. Reporting matters even when you did not click; it protects everyone else who receives the same wave.

**Voice and video**

- [ ] Treat unexpected calls from executives, family members, or your bank asking for money, credentials, or gift cards as suspect. Voice is no longer identity in 2026.
- [ ] Agree a **family safe word** with immediate family. If someone claims to be in trouble and cannot say the word, it is not them.
- [ ] For corporate contexts, insist on **callback verification** for any high-value action initiated by phone, video, or email. This is not being rude to the CFO; it is doing your job correctly.

**Software and browsers**

- [ ] Enable auto-updates on your operating system, browser, and phone. This is the single highest-leverage security action a non-technical user can take.
- [ ] Once a year, review the third-party apps you granted access to your Google/Microsoft/Apple/Facebook account. Revoke anything you do not recognise or no longer use.
- [ ] Use a modern browser (current Chrome, Edge, Firefox, or Safari). AiTM defences and passkey support live in the browser; a two-year-old browser is missing both.

**If something looks off**

- [ ] Slow down. Almost every successful phishing attack works because the victim is rushed. If a message creates urgency, the urgency is part of the attack.
- [ ] When in doubt, do nothing. Do not click, do not reply, do not authorize. Report and wait for confirmation.

## The 2026 checklist for HR and IT

If you are running the NCSAM campaign at your organization, here is a runnable four-week structure that maps to the four Secure Our World pillars and rebuilds each one for 2026's threat surface.

### Week 1 (Oct 1–7): Passwords and passkeys

**Announcement email.** Explain what a passkey is in one sentence ("a passkey replaces your password and your second factor with a single, phishing-resistant credential that your device holds") and point to the passkey enrolment page for your identity provider.

**Live session (30 min).** Walk employees through enrolling a passkey on their work laptop and their phone. This is the single most impactful action of the month for phishing resistance. Do it live so that the friction (which is real for first-time users) is handled with a human on hand.

**Individual action.** Everyone rotates one reused password. Even one is a win.

### Week 2 (Oct 8–14): Phishing recognition, refreshed

**Awareness poster.** "Ignore typos. Recognise the request shape." List the six actions to treat as suspect (login link, attachment, bank-account change, wire, gift card, password reset).

**Simulated phishing exercise.** Send a **realistic** simulation — LLM-generated, referencing an actual project, formatted like a real internal email. Report on click-through *and* on report-rate. The report-rate is the more important metric; a workforce that reports is a workforce that has internalised the change.

**Individual action.** Everyone clicks the "report phishing" button at least once during the week (even on a genuine suspicious message from their own inbox).

### Week 3 (Oct 15–21): Voice and video, deepfakes

**Announcement email.** Explain the deepfake voice threat in plain language and introduce the **callback rule**: any high-impact request initiated by voice or video is verified through a saved-number callback before action.

**Tabletop exercise.** Run a 30-minute scenario with a senior stakeholder (CFO, general counsel, or CEO) where the participants receive a "call" from that stakeholder asking to authorize a wire. Score how many participants callback-verify before acting.

**Individual action.** Every team agrees a **team safe word** — a word or phrase that goes over the phone or video call to confirm identity for anything sensitive. Personal safe words for families are worth mentioning too.

### Week 4 (Oct 22–31): Software, browsers, and third-party access

**Announcement email.** Auto-updates on for OS, browser, phone. Modern browser required for work-tools access.

**Third-party OAuth audit.** IT runs an org-wide report of third-party apps granted access to the corporate Microsoft 365 / Google Workspace / Okta tenant. Any app not on the approved list is reviewed and either whitelisted or revoked.

**Individual action.** Employees review the personal third-party apps connected to their own Google/Microsoft/Apple accounts. Revoke anything unused.

**Wrap.** A closing email with the four "keeper" habits — passkeys, request-shape recognition, callback verification, browser auto-updates — and the report-a-phish button as the single most useful ongoing action.

## Common questions from employees (and the answers)

Print or link these; they come up in every NCSAM cycle.

### "I already have MFA. Am I safe from AiTM phishing?"

No, not from AiTM specifically. MFA authorises the login event, but the attacker's goal is the session cookie that the login event produces. A reverse-proxy toolkit relays your MFA to the real service and captures the resulting cookie. Passkeys are the mitigation, because they are origin-bound and the browser refuses to release them to any origin other than the real one.

### "Isn't calling the person back paranoid? The CEO does not have time for that."

The alternative is transferring 25 million USD to an attacker because the voice on the phone sounded right. Every organisation that has run a deepfake tabletop after mid-2024 has adopted the callback rule. It is not paranoid; it is the current standard of care.

### "The email looks completely normal. How can I tell it is phishing?"

You often cannot tell from the email alone in 2026. That is the point. Do not use writing quality as a signal. Use the **shape of the request**: does it ask you to click a login link, download an attachment, change a bank account number, wire money, buy gift cards, or reset a password? Those are the actions that go wrong. Verify any of them through a channel the requester did not choose.

### "What is a passkey, and how is it different from an authenticator app?"

A passkey is a public-key credential stored on your device (or synced via your password manager) that replaces both your password and your second factor. When you log in, your device signs a challenge that includes the site's origin, so the credential only works on the real site. An authenticator app produces a code that you can type into any page — including a fake one. That is why passkeys are called phishing-resistant and authenticator codes are not.

### "Should I turn off SMS-based MFA?"

Not until you have something better in place. SMS MFA is worse than passkeys, but it is still much better than no MFA. Move to a passkey where the service supports one; move to an authenticator app or a security key where it does not; leave SMS as a fallback only.

### "What is MFA fatigue?"

A specific attack where the attacker who has stolen your password fires MFA push notifications at your phone repeatedly (dozens of times, sometimes at 3 AM) until you tap "approve" out of annoyance or confusion. The mitigation on the user side is: **never tap approve for a login you did not initiate**. On the IT side: switch push notifications to number-matching (the user has to type a number from the login screen into the phone), or move to passkeys, which are immune.

### "How do I verify a call from a family member is really them?"

Agree a family safe word in advance — a random word or short phrase that would not come up in normal conversation. If someone calls claiming to be your family member and asking for money, credentials, or help, ask them for the safe word. If they cannot produce it, hang up and call the family member back on the number you have saved.

### "What about deepfake video?"

Real-time deepfake video is now good enough to fool a casual observer in a Zoom call, especially at low resolution or in a poorly-lit setting. Treat video the same way you treat voice: if it is asking you to authorise something significant, verify through a channel the caller did not choose (a callback on a saved number, a chat message in a channel you know is theirs).

### "Is this a US-only campaign?"

No. Although CISA and the National Cybersecurity Alliance run the largest version in the United States, October is Cybersecurity Awareness Month in the EU, UK, Canada, Australia, and most other jurisdictions with a national cyber agency. The materials from CISA, ENISA (EU), NCSC (UK), and CCCS (Canada) are compatible and largely translated across languages.

### "Where do I report a phishing message?"

At work: the "report phishing" button in Outlook or Gmail, or your IT helpdesk. Outside work: forward suspicious emails to `reportphishing@apwg.org` (Anti-Phishing Working Group) and to the impersonated brand's abuse contact if there is one. For US consumers, phone scams go to the FTC at `reportfraud.ftc.gov` and the FBI's IC3 at `ic3.gov`. Reporting matters even when you did not click — it protects everyone else who received the same wave.

## For families and non-work life

The same three threats hit consumers, usually in cheaper and more emotional forms. The two-item family checklist:

1. **Set a family safe word.** Any word that would not come up in normal conversation. If a family member calls in distress, ask for the safe word before doing anything. Write it somewhere physical (a Post-it in a drawer works) so nobody has to remember it under pressure.
2. **Move the household accounts to passkeys.** Start with Google, Apple, Amazon, and PayPal — those account takeovers are the most damaging. Passkey enrolment takes less than a minute per account on a modern phone.

For kids specifically, the CISA / NCSAM materials aimed at K-12 are worth pointing school-age children at. The one addition for 2026: **anything that arrives asking to click a link, especially from social media or gaming platforms, is suspect**. Every major gaming platform in 2026 has had at least one large-scale credential-stealer campaign that targeted teenagers with promises of in-game currency.

## Small businesses: the two-hour cybersecurity awareness plan

If you run a small business without a dedicated IT team, you can meaningfully upgrade your position in two hours across October:

1. **(30 min)** Enrol every employee in a password manager. Bitwarden's Teams plan or 1Password Business are both cheap and painless.
2. **(30 min)** Turn on passkeys or the strongest available MFA on: business email (Google Workspace / Microsoft 365), business banking, accounting software, payment processor. In that order.
3. **(30 min)** Send a one-page memo to the team with the callback-verification rule and the six suspect actions. Ask them to reply "read".
4. **(30 min)** Audit third-party app access on your Google Workspace or Microsoft 365 tenant. Revoke anything unused.

Two hours across the month, done once a year, catches most of what a solo attacker running commercial phishing tools can throw at you.

## Frequently asked questions about NCSAM 2026

### When is Cybersecurity Awareness Month 2026?

October 1, 2026 through October 31, 2026. The campaign has run every October since 2004, with CISA and the National Cybersecurity Alliance as the primary US organisers and equivalent national agencies leading in the EU, UK, Canada, Australia, and elsewhere.

### What is the 2026 theme?

**"Secure Our World"** — the same theme adopted in 2023 and continued each year since, on the basis that the four pillars (strong unique passwords, phishing-resistant MFA, phishing recognition, keep software updated) remain the highest-leverage actions for the average person. The pillars have not changed; the tactics under them have.

### What are the four Secure Our World pillars?

Use **strong, unique passwords** (with a password manager); turn on **phishing-resistant multi-factor authentication** (passkeys, security keys, or as a fallback an authenticator app); **recognize and report phishing**; **keep software updated**.

### Why is this year's awareness campaign more important than usual?

Because the three phishing threats that dominated the first half of 2026 — deepfake voice vishing, LLM-crafted spearphishing, and adversary-in-the-middle MFA-bypass — all defeat pieces of the awareness advice that has been given for the last decade. "Look for typos" no longer works. "Verify by calling them" is no longer safe on its own. "Enable MFA" is necessary but not sufficient. Updating the tactics under the pillars is the whole point of this year's campaign.

### What is phishing-resistant MFA?

MFA whose credential is bound to the actual login origin, so it cannot be released to a phishing site. In practice this means FIDO2 / WebAuthn / passkeys, either synced via your password manager (Apple Keychain, Google Password Manager, 1Password, Bitwarden) or held in a hardware security key (YubiKey, Google Titan, Feitian). SMS codes, TOTP authenticator apps, and push notifications are not phishing-resistant because they can be typed or tapped into any page.

### Are passkeys really phishing-resistant?

Yes, against network-based phishing. A passkey is a public-key credential the browser will only release for the exact origin it was registered against. An attacker's proxy runs on a different origin, so the browser refuses to sign the challenge. This is a cryptographic guarantee, not a heuristic. Passkeys can still be lost to endpoint compromise (malware on the device) or social engineering that convinces the user to enrol a passkey on the attacker's device, but those attacks are much harder and much noisier than credential phishing.

### What is an AiTM (adversary-in-the-middle) phishing attack?

An attack where the phishing site is a live reverse-proxy of the real service. The victim types their password and completes MFA into what looks like the real login page (and functionally is, because the attacker is relaying every request to the real service). The attacker captures the session cookie the real service issues after successful authentication and replays it. MFA does not stop it because MFA authorised the login event, not the session. Passkeys do stop it because they refuse to sign for the wrong origin.

### How can I run an awareness campaign at my company?

Follow the four-week structure in this article — week 1 passwords and passkeys, week 2 phishing recognition, week 3 voice and deepfakes, week 4 software and third-party access — with an announcement email at the start of each week, one action for every employee, and one team exercise. CISA and NCA publish free posters, videos, and social media graphics at [staysafeonline.org](https://staysafeonline.org) that you can adapt without a design budget.

### What is the difference between phishing, spearphishing, vishing, and smishing?

**Phishing** is the general term for fraudulent messages designed to trick recipients into revealing information or performing actions. **Spearphishing** is phishing targeted at a specific individual with personalised content. **Vishing** is voice phishing (phone or voice-app calls). **Smishing** is SMS phishing. In 2026 all four now routinely use AI-generated content — LLM-written text for phishing and smishing, voice-cloning for vishing, deepfake video for the extended version of vishing that reaches Zoom.

### What should employees do if they clicked a phishing link?

Report immediately — the sooner the IT or security team knows, the more they can contain. Change the password for the affected account through the real service (not through the phishing link). If MFA is enabled, revoke active sessions from the account settings page. Watch for follow-on emails from the attacker over the next 24–48 hours, because they will use any beachhead session to move laterally.

### Where do I find free NCSAM 2026 materials?

CISA at [cisa.gov/cybersecurity-awareness-month](https://www.cisa.gov/cybersecurity-awareness-month), the National Cybersecurity Alliance at [staysafeonline.org](https://staysafeonline.org), and equivalent agencies elsewhere (ENISA, NCSC UK, CCCS). All publish free, brand-adjustable posters, videos, social-media graphics, employee training scripts, and family-oriented content.

## Closing

Cybersecurity awareness is not a one-month problem, and no October campaign will substitute for a workforce that has internalised the current threat surface. But October is the annual moment when the whole industry is loud about the same message at once, and that moment is unusually effective for actually moving behaviour. Use it. Roll out passkeys in the first week, drill the callback rule in the third, and audit your third-party OAuth grants in the fourth. If you do nothing else with this article, adopt those three actions.

If you found this playbook useful, sign up to the [CyberSecurity Elite newsletter](/newsletter/) for the follow-up post at the end of October — a review of what worked, what did not, and the incidents that hit during the awareness month itself. And if you are running the campaign at your organisation and want the four-week template as a shareable Google Doc, get in touch through the [contact page](/contact/).

*This article is intentionally not gated. Fork it, share it, print it, adapt it — the point of Cybersecurity Awareness Month is that everyone gets safer at the same time.*
