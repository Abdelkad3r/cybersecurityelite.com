---
title: "Anti-Slop CTF 2026 OSINT Writeup: Observers Are All You Need + Geoguessr"
slug: "anti-slopctf-2026-osint-writeup"
description: "Step-by-step OSINT writeups for Anti-Slop CTF 2026. GitHub artifact-trail pivot for Observers, H3-cell client-side-crypto trick for Geoguessr."
date: 2026-06-24T00:30:00Z
lastmod: 2026-08-04T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["Anti-Slop CTF 2026"]
tags:
  - "anti-slop ctf"
  - "anti-slopctf 2026"
  - "osint"
  - "github osint"
  - "geoguessr ctf"
  - "h3 hex cell"
  - "shamir secret sharing"
  - "client-side crypto"
  - "argon2 key derivation"
  - "base64 artifact"
keywords:
  - "anti-slop ctf 2026 osint writeup"
  - "observers are all you need writeup"
  - "geoguessr ctf writeup"
  - "github company field base64 fragment"
  - "issue pr fragment osint"
  - "h3 resolution 8 cell ctf"
  - "shamir 9 of 10 share recovery ctf"
  - "argon2 location key derivation"
  - "ctf osint step by step"
toc: true
cover:
  image: "/images/articles/anti-slopctf-2026-osint-writeup.png"
  alt: "Anti-Slop CTF 2026 OSINT writeup — Observers GitHub artifact-trail pivot and Geoguessr H3-cell client-side crypto"
---

Seventh and last per-category post in the **CyberSecurity Elite** Anti-Slop CTF 2026 OSINT series. The earlier ones cover [web](/ctf-writeups/anti-slopctf-2026-web-writeup/), [reverse](/ctf-writeups/anti-slopctf-2026-reverse-writeup/), [pwn](/ctf-writeups/anti-slopctf-2026-pwn-writeup/), [crypto](/ctf-writeups/anti-slopctf-2026-crypto-writeup/), [blockchain](/ctf-writeups/anti-slopctf-2026-blockchain-writeup/), and the [misc Baby Maths](/ctf-writeups/anti-slopctf-2026-misc-baby-maths/) prompt-injection trap. This one walks the two OSINT challenges in the same step-by-step format.

**Observers Are All You Need** is the GitHub-pivot variant of OSINT: read a cryptic prompt, identify the right project to pivot to, then walk the project's public artifact trail (profile, issues, PRs) to assemble the flag in three fragments. **Geoguessr** is the cooler hybrid: ten panoramas look like a pure geolocation puzzle, but the web client uses each location as a key derivation input for Shamir-shared decryption, and you only need 9 of 10 locations to recover the flag. Once the verification crypto is understood, you don't need pixel-perfect coordinates. You need the correct H3 resolution-8 cell.

Source READMEs for both challenges are at [Abdelkad3r/Anti-SlopCTF-2026/osint](https://github.com/Abdelkad3r/Anti-SlopCTF-2026/tree/main/osint).

## The two OSINT challenges

| Challenge | Bug class / theme | Points | Flag |
|---|---|---|---|
| Observers Are All You Need | GitHub artifact-trail pivot from a cryptic prompt to a specific user's profile, issues, and PRs; flag split into three fragments across different artifact types | 443 | `slopped{OPH_is_a_rec0nstructi0n_pr0gram_f0r_funD4mentaL_phys1cs}` |
| Geoguessr | Client-side crypto turns a 10-panorama Geoguessr-style game into a Shamir-9-of-10 share recovery; each location's correct H3 resolution-8 cell derives an Argon2 key that decrypts one share | 487 | `slopped{h0w_d0_agent5_sl0p_nmpz?}` |

The pattern that connects both: **OSINT challenges in 2026 reward solvers who follow artifact trails and read client-side code, not solvers who throw prompts at search engines or LLMs.** Observers' prompt rewards the player who pivots from prose to a specific project's commit/issue/PR history. Geoguessr's surface looks like a pure visual-search puzzle, but the actual win condition is recovering a verifiable per-location key, which the client makes computable without ever loading Google Street View. Both are designed to fail "agent-style" solvers that aren't grounded in the artifacts.

## Methodology — pivot on the artifact, not the prose

A pattern that worked for both challenges: don't search the prompt's words; search the prompt's *implied artifact*. The Observers prompt isn't a clue you Google in quotes; it's a hint about what project the trail starts in. The Geoguessr UI isn't a sequence of locations you guess one by one; it's a client whose JavaScript tells you exactly what each guess has to satisfy to decrypt the next piece of the flag.

OSINT challenges are increasingly built on this premise. The era when "Google the unique phrase" was a reliable solve is over for serious CTFs. Modern OSINT challenges hide the win condition behind an artifact trail (Observers) or behind a verifiable cryptographic check (Geoguessr) that filters out lazy guessing. The right response is to read the artifacts the prompt is gesturing at and read the client code the service ships, then construct the solve around what those artifacts actually expose.

Per-challenge walkthroughs follow.

## Observers Are All You Need

### The setup

The prompt is a single paragraph plus two constraints:

```
reality is the timeless process of finding how a self-consistent reality
can explain itself from the inside.
```

Plus the metadata: focus on artifacts produced in **May 2026**, and the flag is **split into three parts**.

The title is the strongest hint. "Observers Are All You Need" is a play on the "Attention Is All You Need" Transformer paper, but the noun is observers, not attention. The cryptic-prose body talks about reality reconstructing itself from the inside. Combined, this points away from generic philosophy searches and toward a specific project whose vocabulary contains *observers* and *reconstruction*.

### Step 1 — Pivot from the prompt to a specific project

Searching the prompt verbatim is a trap. The same paragraph appears in dozens of philosophy blogs, none of which are the right project. The useful query is something like the project's distinguishing vocabulary: "observer", "patch", "reconstruction", "physics", terms that the title and prompt body cluster around without naming explicitly.

That pivot leads to the public GitHub ecosystem around `observer-patch-holography` (OPH). The repository `FloatingPragma/observer-patch-holography` is where the May 2026 activity lives. Its README contains the sentence:

```
OPH is a reconstruction program for fundamental physics.
```

That sentence already looks suspiciously like the *shape* of the final flag: `OPH_is_a_rec0nstructi0n_pr0gram_f0r_funD4mentaL_phys1cs` with the usual leet substitutions. The trap is to stop here and try to guess the exact spelling.

### Step 2 — Resist the guess-the-prose trap

A first attempt at the flag based solely on the README sentence might be:

```
slopped{OPH_is_a_rec0nstruct1on_pr0gram_f0r_fund4ment4l_phys1cs}
slopped{OPH_is_a_rec0nstructi0n_pr0gram_f0r_fundamental_phys1cs}
slopped{OPH_is_a_reconstruct10n_program_for_fundamental_physics}
```

None of these work. The leet substitutions are inconsistent across the real flag, and there's no good way to guess which characters become digits. **The "flag split into three parts" hint is doing real work here.** It tells you the flag is assembled from three discovered artifacts, not derived from one piece of prose.

That hint plus the May-2026 timing pivots the search to the project's *activity* in May 2026: commits, issues, pull requests, contributor profiles. The flag fragments live in artifacts, not in the README.

### Step 3 — Find the key account

Looking at recent activity on the `observer-patch-holography` repo, one user account stands out: `cryptoverse-cyber`. The account's contributions during May 2026 cluster around the project (commits, issue comments, pull requests). The May-2026 constraint maps directly to this account's activity window.

Open `cryptoverse-cyber`'s GitHub profile. The profile metadata fields (bio, company, location, website) are common hiding places for OSINT fragments. The `company` field contains a string that doesn't look like a company name:

```
c2xvcHBlZHtPUEhfaXNfYV8=
```

That's a base64-encoded blob. Decoding:

```python
>>> import base64
>>> base64.b64decode("c2xvcHBlZHtPUEhfaXNfYV8=")
b'slopped{OPH_is_a_'
```

**Fragment 1 of 3.** The opening bracket and first phrase of the flag. The leet substitution `OPH_is_a_` is now confirmed (rather than guessed), and we know there are two more pieces to find.

### Step 4 — Walk the issue and PR trail

The remaining fragments are in the project's issue and PR activity. Filtering issues authored or commented on by `cryptoverse-cyber` in May 2026 surfaces issue `#292` on `FloatingPragma/observer-patch-holography`. One of the comments in that issue contains:

```
rec0nstructi0n_pr0gram_f0r_
```

**Fragment 2 of 3.** The middle phrase, with leet substitutions that wouldn't have been guessable from the README prose alone (notice the mixed `0` and `o` choices; `rec0nstructi0n_pr0gram_f0r_` is not what a guess would produce).

Continuing through `cryptoverse-cyber`'s May activity surfaces pull request `#301`. The PR description contains:

```
funD4mentaL_phys1cs}
```

**Fragment 3 of 3.** The closing phrase plus the right brace. Capital `D`, `4` for the second `a`, `1` for the `i` in `physics`.

### Step 5 — Assemble and submit

Concatenate the three fragments in order:

```
slopped{OPH_is_a_  +  rec0nstructi0n_pr0gram_f0r_  +  funD4mentaL_phys1cs}
=  slopped{OPH_is_a_rec0nstructi0n_pr0gram_f0r_funD4mentaL_phys1cs}
```

Submit and the service accepts.

### Why Observers Are All You Need works

The challenge is built specifically against "search the prompt prose" solvers. The cryptic paragraph and the deliberately leet-substituted final flag both make pure-text retrieval useless. The win condition is structural: find the artifacts, pivot to the account, walk its public activity, decode the base64, read the issue, read the PR. None of those steps require external tools; all of them require the patience to follow the trail past the obvious-prose attractor.

The deeper lesson, and one I think this challenge wants to teach explicitly, is that public artifact trails on platforms like GitHub are still the OSINT gold standard. Profile metadata fields, issue threads, PR descriptions, commit messages, release notes, repo wikis, gists. Each is a different artifact type with a different audit surface. Threat actors hide signals in the same fields. Defenders looking for indicators of compromise should know exactly which fields they're searching, and which they're not.

## Geoguessr

### The setup

Ten panoramas in a Geoguessr-style web client. Each panorama lets you "guess" a latitude/longitude. The naïve expectation is that the server verifies your guess against the panorama's true location with some tolerance, awards points, and unlocks the next panorama. A pure-OSINT play would identify each location from visual clues (signage, foliage, architecture, road markings) and submit coordinates close enough to score.

The actual win condition is more interesting. Each panorama corresponds to an *encrypted Shamir share*. The server doesn't grade your guess at all. The client takes your guess, runs it through a cryptographic key derivation, and uses the derived key to attempt to decrypt the local share. If decryption succeeds, the share is valid. Collect 9 of 10 valid shares and the client reconstructs the AES key for the flag.

That changes the OSINT problem from "guess accurately" to "land in the correct H3 cell," a much easier verification problem.

### Step 1 — Dump the client and read the verification code

The interesting logic is entirely client-side. Save the JavaScript bundle (typically a single `/app.js` or `/static/js/main.*.js`) and inspect the verification function. The relevant flow:

1. Convert the user's guessed `(lat, lon)` to an [H3](https://h3geo.org/) resolution-8 cell string (something like `881eaab10dfffff`).
2. Derive an Argon2id key from `H3_cell || challenge_name`.
3. Hash the derived key (SHA-256 or similar) and compare to a per-challenge target hash that's embedded in the page.
4. If the hash matches, use the unhashed Argon2 key to AES-CBC decrypt the per-challenge encrypted share.
5. Once you have 9 of 10 plaintext shares, run them through a GF(256) Shamir reconstruction to recover the master AES key, which decrypts the flag ciphertext also embedded in the page.

This is a clean client-side verification pattern. The server never sees your guess. The crypto enforces correctness without any tolerance heuristic.

### Step 2 — Build a candidate-checker script

The verification function is small enough to reimplement in Python. Take a `(lat, lon)` plus a `challenge_name`, compute the H3 cell at resolution 8, run Argon2id with the parameters the client uses (memory cost, iterations, parallelism, all readable in the bundle), hash the key, compare against the published target:

```python
import h3, hashlib
from argon2.low_level import hash_secret_raw, Type

def check(lat, lon, challenge_name, target_hash, params):
    cell = h3.latlng_to_cell(lat, lon, 8)
    salt = challenge_name.encode()
    key = hash_secret_raw(
        cell.encode(),                    # password
        salt,
        time_cost=params["t"],
        memory_cost=params["m"],
        parallelism=params["p"],
        hash_len=32,
        type=Type.ID,
    )
    digest = hashlib.sha256(key).hexdigest()
    return digest == target_hash, key
```

That's roughly what each `geoguessr_check.py` invocation does. With this checker, the OSINT workflow becomes: identify a likely region, pass candidate coordinates, see which H3 cell at resolution 8 matches. Resolution 8 H3 cells are roughly 700 m across, so coordinates within ~350 m of the truth land in the right cell.

### Step 3 — Identify panoramas with strong visual anchors first

Not all ten panoramas need to be solved. The Shamir threshold is 9 of 10, so one panorama can be skipped (pick the hardest one). Sort the panoramas by visual difficulty and solve the easy ones first. Distinctive anchors from the live session:

- **`left`**: A church facade with Anglican signage. Searching church-name keywords plus Anglican-style architecture surfaces St John's Anglican Church in Launceston (Tasmania, Australia). Coordinates around `-41.4395, 147.140833` land in the correct H3 cell.
- **`ferris-wheel`**: A harbor-front Ferris wheel with Greek signage. Zakynthos harbor (Greece) matches the layout. Coordinates around `37.7867, 20.8999`.
- **`truck`**: A truck on a rural road in a steppe-like landscape with Mongolian script. Near Ondorshireet, Mongolia. Coordinates around `47.4515, 105.0535`.

Each of those was a one-or-two-iteration solve: identify the country and likely city from anchors, drop coordinates into the checker script, search a small neighbourhood of nearby H3 cells (`-r` flag in the example) until the derived key hashes match. If no nearby cell matches, the location guess is wrong and the search has to widen.

```bash
python3 tools/geoguessr_check.py left -41.4395 147.140833 -r 12 -j 8
python3 tools/geoguessr_check.py ferris-wheel 37.7867 20.8999 -r 45 -j 8
python3 tools/geoguessr_check.py truck 47.4515 105.0535 -r 35 -j 8
```

`-r` is the search radius in H3 cells (so `-r 12` checks the candidate cell plus the 12 nearest neighbours), `-j` is parallelism. Each successful hit yields one share's plaintext.

### Step 4 — Recognise the H3-cell tolerance changes the OSINT difficulty

The conventional Geoguessr scoring rewards pixel-perfect coordinates with a 5000-point maximum that drops off geometrically with distance. The H3-cell verification used here is a binary check: you're in the cell or you're not. Resolution-8 H3 cells are roughly 700 m across, which means a guess within ~350 m of the true location is correct.

That's a *much* easier target than conventional Geoguessr scoring. It collapses the OSINT difficulty from "identify the exact intersection" to "identify the right neighbourhood." For panoramas with distinctive anchors (a named church, a specific landmark, signage in a recognisable script), reaching the correct H3 cell is usually a one-to-three-iteration search.

It also changes the failure mode. Conventional Geoguessr gives partial credit for "right country, wrong city." H3-cell verification doesn't. The cell either matches or it doesn't, so an OSINT-adjacent guess that's 50 km off is worth nothing. The Shamir threshold (9 of 10) is the safety net: one such miss is allowed.

### Step 5 — Collect 9 shares, reconstruct, decrypt

After 9 of the 10 panoramas verify, the client (or the local solver) collects the decrypted shares, runs them through the GF(256) Shamir reconstruction implementation embedded in the page, and obtains the master AES key. That key decrypts the page's flag ciphertext:

```bash
python3 tools/geoguessr_solve.py tools/geoguessr_hits.json
```

Output:

```
slopped{h0w_d0_agent5_sl0p_nmpz?}
```

The flag's wink is in the NMPZ. NMPZ stands for **No Move, No Pan, No Zoom**, a Geoguessr ruleset that strips the panorama-navigation tools and forces you to identify a location from a single static viewpoint. "How do agents slop NMPZ?" is the challenge author asking whether LLM-driven agents are capable of doing real NMPZ Geoguessr (they're famously bad at it, because LLMs hallucinate locations from weak visual evidence and don't have the patience to actually triangulate). The flag itself is the punchline.

### Why Geoguessr works

The challenge mixes two surfaces that are each individually shallow. Conventional Geoguessr is a vision problem. Shamir reconstruction over a GF(256) field is a small crypto problem. Combining them produces a target that's neither pure OSINT nor pure crypto: a verifiable OSINT search where the client tells you exactly how close to truth you need to be, but the truth is still encoded in real-world visual anchors you have to identify.

The reason this is an "Anti-Slop" challenge is the same as the rest of the event. An LLM-based image-recognition pipeline can identify many of the panoramas to the country level but rarely to the H3-cell level. The pipeline produces *confident* guesses for the city or province, hands them to the checker, and gets no hit because the city-level guess is one H3 cell over from the real location. The human OSINT player triangulates from anchors (signage script, church denomination, vegetation, road markings) and lands in the right cell on the first or second iteration. The verification function rewards the human approach and silently penalises the agent approach.

## Cross-cutting OSINT notes

Three patterns recur across modern OSINT-flavoured CTFs.

**Public artifact trails are the gold standard.** GitHub profile fields, issue threads, PR descriptions, gists, repo wikis. Every one of them is a separate searchable surface. Defender takeaway: when you're searching for IOCs, knowing which artifact-type-specific search syntax to use matters more than knowing how to spell the keyword. GitHub's advanced-search query language (`user:`, `author:`, `commenter:`, `is:issue`, `is:pr`, `created:YYYY-MM-DD`) is the bare-minimum literacy for any reviewer doing artifact-trail work.

**Client-side crypto can collapse OSINT search spaces.** Geoguessr's H3-cell verification is a CTF-specific trick, but the same pattern shows up in real-world product analytics, fraud detection, and bot mitigation. Anywhere a client embeds a verification function that's computable offline, the search problem the function gates becomes a verification problem rather than an oracle problem. For OSINT, that means the player can iterate locally without consuming server-side rate limits.

**Agents don't triangulate.** The Anti-Slop event keeps demonstrating this. LLM agents are confident, fast, and bad at the kind of fragmented evidence aggregation that human OSINT players do well. Asking an agent "what church is this" with a single image will produce a one-sentence answer that's plausibly wrong. Asking it "narrow this to an H3 cell" against a checker script produces hallucinated cells that fail verification silently. The CTF version of this is a flag the agent never reaches. The production version is wrong intelligence assessments fed into downstream decisions.

## Frequently asked questions

### What is Anti-Slop CTF?

Anti-Slop CTF is a Jeopardy-style CTF whose challenges are explicitly designed to defeat low-effort, tool-driven, or pattern-matched solving. Most challenges require reading source, reverse-engineering a custom format, or walking artifact trails patiently. The flag prefix is `slopped{...}` and the writeup compilation is at [Abdelkad3r/Anti-SlopCTF-2026](https://github.com/Abdelkad3r/Anti-SlopCTF-2026).

### What's the bug in Observers Are All You Need?

There isn't a bug. The challenge is a pure GitHub pivot. The cryptic prompt points at a specific project (`FloatingPragma/observer-patch-holography`, OPH), and the flag is split into three fragments hidden in different artifact types on a single contributor account (`cryptoverse-cyber`). Fragment 1 is a base64 blob in the GitHub profile's `company` field. Fragment 2 is in an issue comment (issue #292). Fragment 3 is in a PR description (PR #301).

### Why is the flag in three parts in Observers?

The "three parts" hint is what tells you the flag isn't derivable from the repo README's prose alone. The leet substitutions in the final flag (`OPH_is_a_rec0nstructi0n_pr0gram_f0r_funD4mentaL_phys1cs`) aren't guessable from "OPH is a reconstruction program for fundamental physics" because the substitution pattern is inconsistent. The fragments have to be found, not derived.

### How do you find the right GitHub account for Observers?

Filter the project's contributors and recent commenters/PR-authors by activity in May 2026 (the prompt's time window). One account, `cryptoverse-cyber`, has cluster activity in that window. The account's public profile metadata is the first place to look for OSINT fragments. In this case, the `company` field contains the base64-encoded fragment 1.

### What's the trick in Geoguessr?

The web client doesn't grade your guess. It converts your guess to an H3 resolution-8 cell, derives an Argon2id key from the cell plus the challenge name, hashes the key, and compares to a published target hash. If the hash matches, the same key decrypts an AES-CBC-encrypted Shamir share. Collect 9 of 10 shares and the GF(256) reconstruction yields the master AES key for the flag. The OSINT difficulty collapses from "guess exact coordinates" to "land in the right ~700m H3 cell."

### Why H3 resolution 8 specifically?

H3 is Uber's hierarchical hexagonal grid. Resolution 8 has cells roughly 700 m across, which is forgiving enough that a coordinate within ~350 m of the true location lands in the correct cell, but tight enough that "right country, wrong city" doesn't pass. That's the sweet spot for a verifiable OSINT search: the human OSINT player can triangulate to within 350 m using visual anchors, while an LLM-based image-recognition pipeline that confidently guesses the city center is usually one cell over.

### Why is the threshold 9 of 10 shares?

Shamir's Secret Sharing lets you tune the threshold below the total share count. A 9-of-10 threshold means one panorama can be skipped (pick the hardest one). The client implements the threshold in the embedded GF(256) reconstruction code, so the solver can confirm any 9-share combination works before submitting.

### What does NMPZ mean in the Geoguessr flag?

NMPZ stands for No Move, No Pan, No Zoom, a Geoguessr ruleset that strips the panorama-navigation tools and forces you to identify the location from a single static viewpoint. The flag's "h0w_d0_agent5_sl0p_nmpz" is the challenge author's wink: LLM-driven agents are famously bad at NMPZ because they hallucinate locations from weak visual evidence and don't have the patience to triangulate the way a human OSINT player does.

### Where can I find the full writeups?

Per-challenge READMEs for both OSINT challenges are at [Abdelkad3r/Anti-SlopCTF-2026/osint](https://github.com/Abdelkad3r/Anti-SlopCTF-2026/tree/main/osint). The challenges were remote-only and tied to ephemeral GitHub artifacts, so the repository writeups document the reproducible parts (decoder snippets, checker-script shape, anchor lists) rather than bundling the full live-target solver.

### What's the broader lesson from the Anti-Slop OSINT track?

The two challenges teach two halves of the same lesson. Observers teaches that artifact trails are the OSINT primary surface in 2026: profile fields, issues, PRs, gists, wikis. Geoguessr teaches that client-side crypto can collapse the OSINT search problem into a verifiable iteration loop, which favours human triangulation over agent hallucination. Both are designed to fail "search the prompt, ask the agent" solvers and to reward the patient artifact-walking and code-reading habits that human OSINT players actually use.

## Closing notes

This is the seventh and last per-category writeup in the Anti-Slop CTF 2026 series. The full set on this site:

- [Web writeup](/ctf-writeups/anti-slopctf-2026-web-writeup/): Slipstream Cache TLV parser-split + blind RSA, SloppedRider SSRF-to-HMAC-key leak.
- [Reverse writeup](/ctf-writeups/anti-slopctf-2026-reverse-writeup/): Audit Spiral quadratic ECDSA nonce, Parallax Cartridge SHA-256 length extension.
- [Pwn writeup](/ctf-writeups/anti-slopctf-2026-pwn-writeup/): Paper Lantern Bellcore CRT fault, Graceful Exit leak-and-overwrite, Anchorpoint five-stage VM-to-GCM forge chain.
- [Crypto writeup](/ctf-writeups/anti-slopctf-2026-crypto-writeup/): Polynomial Drift HNP CVP, Sealed Signal CBC-MAC splice.
- [Blockchain writeup](/ctf-writeups/anti-slopctf-2026-blockchain-writeup/): Finality Cache receipt commitment patch, Canopy Cache PackBits-after-validation TOCTOU.
- [Misc Baby Maths writeup](/ctf-writeups/anti-slopctf-2026-misc-baby-maths/): Prompt-injection trap inside a 100-question arithmetic stream.
- This post: Observers Are All You Need + Geoguessr.

Fourteen challenges covered across the seven posts. For more OSINT writeups elsewhere on this site, the [BhAcKAri CTF 2026 multi-category writeup](/ctf-writeups/bhackari-ctf-2026-writeup/) and the [HASBL CTF 2026 forensics writeup](/ctf-writeups/hasblctf-2026-forensics-writeup/) both touch on artifact-trail and image-derived OSINT primitives. Full [CTF writeups index](/ctf-writeups/) for everything else.

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type": "Question","name": "What is Anti-Slop CTF?","acceptedAnswer": {"@type": "Answer","text": "Anti-Slop CTF is a Jeopardy-style CTF whose challenges are explicitly designed to defeat low-effort, tool-driven, or pattern-matched solving. Most challenges require reading source, reverse-engineering a custom format, or walking artifact trails patiently. The flag prefix is slopped{...} and the writeup compilation is at github.com/Abdelkad3r/Anti-SlopCTF-2026."}},
    {"@type": "Question","name": "What's the bug in Observers Are All You Need?","acceptedAnswer": {"@type": "Answer","text": "There isn't a bug. The challenge is a pure GitHub pivot. The cryptic prompt points at FloatingPragma/observer-patch-holography (OPH), and the flag is split into three fragments hidden in different artifact types on a single contributor account (cryptoverse-cyber). Fragment 1 is base64 in the profile company field. Fragment 2 is in issue #292. Fragment 3 is in PR #301."}},
    {"@type": "Question","name": "Why is the flag in three parts in Observers?","acceptedAnswer": {"@type": "Answer","text": "The three-parts hint tells you the flag isn't derivable from the repo README prose alone. The leet substitutions in the final flag (rec0nstructi0n_pr0gram_f0r_funD4mentaL_phys1cs) are not guessable from the plain sentence because the substitution pattern is inconsistent. The fragments have to be found, not derived."}},
    {"@type": "Question","name": "How do you find the right GitHub account for Observers?","acceptedAnswer": {"@type": "Answer","text": "Filter the project's contributors and recent commenters/PR-authors by activity in May 2026 (the prompt's time window). One account, cryptoverse-cyber, has cluster activity in that window. The account's profile metadata is the first place to look for OSINT fragments — the company field contains the base64-encoded fragment 1."}},
    {"@type": "Question","name": "What's the trick in Geoguessr?","acceptedAnswer": {"@type": "Answer","text": "The web client doesn't grade your guess. It converts your guess to an H3 resolution-8 cell, derives an Argon2id key from the cell plus the challenge name, hashes the key, and compares to a published target hash. The matching key decrypts an AES-CBC-encrypted Shamir share. Collect 9 of 10 shares and GF(256) reconstruction yields the master AES key for the flag. OSINT difficulty collapses from guess exact coordinates to land in the right ~700m H3 cell."}},
    {"@type": "Question","name": "Why H3 resolution 8 specifically?","acceptedAnswer": {"@type": "Answer","text": "H3 is Uber's hierarchical hexagonal grid. Resolution 8 cells are roughly 700m across — forgiving enough that a coordinate within ~350m lands in the correct cell, but tight enough that right country, wrong city doesn't pass. Sweet spot for verifiable OSINT search."}},
    {"@type": "Question","name": "Why is the threshold 9 of 10 shares?","acceptedAnswer": {"@type": "Answer","text": "Shamir's Secret Sharing lets you tune the threshold below the total share count. A 9-of-10 threshold means one panorama can be skipped — pick the hardest one. The client implements the threshold in the embedded GF(256) reconstruction code."}},
    {"@type": "Question","name": "What does NMPZ mean in the Geoguessr flag?","acceptedAnswer": {"@type": "Answer","text": "NMPZ stands for No Move, No Pan, No Zoom — a Geoguessr ruleset that strips the panorama-navigation tools and forces you to identify a location from a single static viewpoint. The flag's h0w_d0_agent5_sl0p_nmpz is the challenge author's wink: LLM-driven agents are famously bad at NMPZ because they hallucinate locations from weak visual evidence."}},
    {"@type": "Question","name": "Where can I find the full writeups?","acceptedAnswer": {"@type": "Answer","text": "Per-challenge READMEs for both OSINT challenges are at github.com/Abdelkad3r/Anti-SlopCTF-2026/tree/main/osint. The challenges were remote-only and tied to ephemeral GitHub artifacts, so the writeups document the reproducible parts (decoder snippets, checker-script shape, anchor lists)."}},
    {"@type": "Question","name": "What is the broader lesson from the Anti-Slop OSINT track?","acceptedAnswer": {"@type": "Answer","text": "Observers teaches that artifact trails are the OSINT primary surface in 2026: profile fields, issues, PRs, gists, wikis. Geoguessr teaches that client-side crypto can collapse the OSINT search problem into a verifiable iteration loop, which favours human triangulation over agent hallucination. Both are designed to fail search the prompt, ask the agent solvers and to reward patient artifact-walking and code-reading habits."}}
  ]
}
</script>
