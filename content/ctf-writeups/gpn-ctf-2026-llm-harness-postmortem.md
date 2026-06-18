---
title: "GPN CTF 2026 — LLM Harness Post-Mortem: Where Claude Code Got It Right (and Wrong)"
slug: "gpn-ctf-2026-llm-harness-postmortem"
description: "GPN CTF 2026 Meta: the Claude Code harness behind 19 writeups — sub-agent parallelism, scratch-dir caching, six wasted hours on the wrong NTRU framing, and the corrective rules I'd port to any future CTF."
date: 2026-06-07T19:58:00Z
lastmod: 2026-06-07T19:58:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
tags:
  - "gpn ctf 2026"
  - "llm harness"
  - "claude code"
  - "ai assisted ctf"
  - "sub-agent parallelism"
  - "ctf post-mortem"
  - "mihnp ntru wrong direction"
  - "harness design"
  - "kill plans early"
series: ["GPN CTF 2026"]
keywords:
  - "gpn ctf llm harness writeup"
  - "claude code ctf workflow"
  - "ai assisted ctf post-mortem"
  - "sub-agent parallelism ctf"
  - "ctf harness design lessons"
  - "kill plans early llm"
  - "mihnp ntru wrong direction harness"
toc: true
cover:
  image: "/images/articles/gpn-ctf-2026-llm-harness-postmortem.png"
  alt: "GPN CTF 2026 LLM Harness Post-Mortem — what Claude Code got right and wrong across 19 challenges and a six-hour wrong-direction rabbit hole"
---

{{< ctf-meta platform="GPN CTF 2026 (kitctf)" difficulty="Meta — harness post-mortem" os="Tooling — Claude Code (Opus 4.x, 1M context), Bash sandbox, sub-agents" skills="orchestrating Claude Code with parallel sub-agents, using scratch directories as harness cache, keeping main-thread context lean by routing bulk output through sub-agents, building 'kill the wrong plan' as a forcing function, recognising harness hallucinations in less-common ecosystems by grep-confirmation" >}}

**The LLM harness post-mortem** isn't about one challenge — it's about the workflow that produced the other 18 writeups in the [GPN CTF 2026 repository](https://github.com/Abdelkad3r/gpn-ctf-2026). What the harness around Claude Code actually looked like during a 24-hour CTF, what it was good at, where it embarrassed me, and which design choices I'd keep. This writeup is the standalone version of the meta-writeup submitted for the **Best LLM Harness Writeup** prize at GPN CTF 2026.

The thing worth writing about is **when the harness was wrong**, not when it was right. The six-hour rabbit hole on `crypto/guess-the-taste` is the most useful part of this post-mortem.

For the full per-challenge writeups, see the [GPN CTF 2026 master writeup](/ctf-writeups/gpn-ctf-2026-writeup/). For the standalone version in the source repo, [`meta/llm-harness.md`](https://github.com/Abdelkad3r/gpn-ctf-2026/blob/master/meta/llm-harness.md).

## The setup

```
┌───────────────────────────────────────────────────────────────────┐
│  human (me)  ──orchestrates──▶  Claude Code (Opus 4.x, 1M ctx)    │
│                                            │                      │
│                                            ├─ Bash sandbox        │
│                                            ├─ Read / Edit / Write │
│                                            ├─ Explore sub-agent   │
│                                            └─ general-purpose     │
│                                               sub-agents          │
└───────────────────────────────────────────────────────────────────┘
```

A few non-obvious choices that mattered:

- **Sub-agents are the unit of parallelism, not threads.** When I needed to scan a 23 MB `vmlinux` for what changed (`stupidcontract`), I'd kick off three sub-agents in one message: one running `strings | sort | diff`, one running `nm -D`, one running `bindiff`-style section sizing. Each spends its own context window so the main conversation never has to see the 4 MB of `strings` output.
- **Scratch dirs are part of the harness.** `~/gpn/<challenge>/work/` is where Sage scripts, intermediate hex dumps, partially-tested exploits live. The harness treats them as cache: when a sub-agent comes back saying *"I implemented `multi_coppersmith.sage`, here's a 12-line summary"*, I can read the file later instead of asking again.
- **No agentic shopping list.** I never gave Claude a high-level *"solve every challenge"* prompt. Each challenge starts with a fresh conversation, the handout files, and a one-sentence framing. Long-context agents start hallucinating a coherent narrative across challenges if you don't.
- **Memory file pinned in CLAUDE.md, not in the chat.** Repeated patterns (`use lowercase hex offsets, never `cd` inside Bash commands, prefer reading specific file ranges over slurping`) live in `~/.claude/CLAUDE.md` so each new session starts with the same posture.

## What the harness was great at

### Reading a lot of code fast

`reverse/koenigsberg-delivery-problem` is 4500 lines of repetitive state-machine dispatch. The path the harness took:

1. Ask for **structure first**: *"objdump -d cartographer | head -200, then describe the per-state pattern in one paragraph."*
2. Validate the pattern by **grep-counting** the same instruction across the whole disassembly (`250 states ⇒ 250 inc byte ptr [rsp+N]`). One sub-agent does this, returns a one-line confirmation, doesn't dump the matches into the main context.
3. Now I trust the pattern; ask Claude to write a parser. The parser is wrong on the first try (it misses state 0 because state 0 uses `rax` instead of `lea`). The fix is a single follow-up message.

Total wall-clock: ~25 minutes. The actual reading happened in sub-agent context windows that I never saw.

The same shape worked for `reverse/autocooker` (16 KB binary, four involution pipelines), `reverse/specCTF` (43 KB, recognising splitmix64 from three xor-shifts and a multiply), and `crypto/justfollowtherecipe` (reading the AVX2 inner-product loop and noticing it permutes lanes).

### Cheap statistical recon

`misc/organized` is a 7.65 MB file that looks like noise. The trick is that bit-density per 12,500-byte window is *trinary*, not binary. The harness got there in three steps:

1. *"Is this image data?"* — Claude renders 25 candidate widths at 1 bpp in a sub-agent, eyeballs them, reports "all show horizontal stripes."
2. *"What's the smallest periodic structure in popcount?"* — sub-agent computes per-window popcount means and run-lengths, comes back with "every run is a multiple of 125 windows = 12,500 bytes."
3. *"Three peaks or two?"* — 200-bin histogram of per-block popcount.

That's the whole reverse-engineering of the carrier. The human's job is picking the *next* question, not running the analysis.

### Parallel hypothesis testing

`web/pharry`'s PHP source admits two attack surfaces (`md5_file` / `file_get_contents`) and three failure modes (PHP 7.4 PHAR remote restrictions, `data://` nesting, `phar://https://`). I dispatched three sub-agents in one message — *"verify that `phar://data://` works in PHP 7.4"*, *"verify `phar://https://` works"*, *"check what `md5_file` does on an HTTP URL when the response is empty"* — and got three independent answers in parallel. Two were dead ends, one was the kill chain. Without parallelism that's three serial round-trips, each lasting a few minutes because the sub-agent has to actually run PHP.

## What the harness was bad at

### Committing to the wrong direction

`crypto/guess-the-taste` had two versions floating around in my workspace. One was an MIHNP-style "modular inverse hidden number problem" with a 1000-bit prime, 570 low bits zeroed in the inverse samples. The other was the actual GPN challenge: an NTRU instance where the ciphertext is just never reduced mod q, so `c mod p == m` directly.

I gave the harness the MIHNP script. Claude leapt at it, recognised the Xu-Hu-Sarkar lattice attack, started building it, and over the next ~6 hours produced this:

```
~/gpn/taste/work/
  bench.sage  best.sage  bivar_attack.sage  bivar_large_m.sage
  brute_short.sage  double_poly.sage  dp_sim.sage  elim.sage
  elim_simple.sage  explore_threshold.sage  fast_eim.sage
  fast_scan.sage  five_sub.sage  focus.sage  four_sample.sage
  full5.sage  lc_scan.sage  m3_scan.sage  m45_scan.sage
  m4_scan.sage  multi_coppersmith.sage  multi_full.sage
  multi_g.sage  multi_prefix.sage  multi_short.sage
  …
  xhs_attack.sage  xhs_full.sage  xhs_proper.sage  xhs_v2.sage
  xhs_v3.sage
```

70+ unique Sage scripts. Five "xhs" iterations (Xu-Hu-Sarkar) that never recovered the secret. The harness *can't tell from inside* that it's attacking the wrong challenge — it sees a paper that promises the attack should work, a script that doesn't, and infers *"more parameters."* Each sub-agent reports modest progress; the human sees "still iterating." Six hours of compute and one human cup of coffee later, the actual challenge turned out to be a one-line `mod p` away from the flag.

**The corrective move that should have happened sooner:** when a single sub-agent has rebuilt the same attack five different ways without recovering the secret, stop and re-read the challenge handout. The harness does not naturally generate this "step back" reflex. The human has to.

### Confident wrong code

In `crypto/easy-dsa`, Claude wrote the first ECDSA-nonce-reuse solver and recovered a `d` that *didn't match the public key*. Confident commentary: *"Sign of the recovered private key may be flipped, try negating."* Negating worked. But Claude wrote the entire solver before noticing the sign ambiguity, when the canonical write-up of nonce reuse mentions it in the third sentence. Treating Claude's first-pass code as a draft rather than a finished solver caught this in two minutes; treating it as finished would have lost an hour.

### Hallucinated APIs in less-common ecosystems

The `web/restaurant-builder` exploit hangs on a specific behavior of Pydantic v2: `create_model("X", x="some_string")` treats `"some_string"` as a `ForwardRef` that gets `eval`-ed when `model_json_schema()` is called. Claude knew the general shape but mis-named two helpers (`pydantic.create_model_from_typeddict`, which doesn't exist in v2; and `get_type_hints(..., include_extras=True)` not being the path the v2 schema builder takes). I caught both by `grep`-ing the installed package. Less popular libraries: trust nothing without `grep`-confirmation.

### Anything graphical without a screenshot

`misc/knitted-flag` ends with a 978×20 bitmap rendered to a PNG that, by eye, reads `GPNCTF<...>`. Reading **`{` vs `<`** and **`O` vs `0`** is a font-disambiguation task Claude cannot do without literally seeing the image. I had to take the PNG, open it, decide by eye that the angle quotes were braces and the diamond glyphs were zeros, and feed that back. The harness loop is still useful — it built the parser, picked the rotation, produced the PNG — but the final "is this a 0 or an O" step is pure carbon.

## When to kill a research direction

The MIHNP debacle taught one rule the rest of the CTF respected:

> If a sub-agent has produced **N independent re-implementations of the same attack** without progress, the bug is upstream of the attack code.

For `crypto/justfollowtherecipe` we hit this early. fpylll BKZ-40 with defaults landed at norm ~310 — way above the GH bound, no flag. Iteration N+1 would have been "try BKZ-50, then 60, then change pruning." The right move was to step back and ask: *"is the input `A` actually the real `A`?"* — which led to the AVX2 lane-swap discovery and a 45 s solve.

For `reverse/stupidcontract` it took the form of: *"the verifier rejects my program at load time. Have I read every patched-vs-unpatched diff?"* The answer was a five-string deletion that the harness almost missed because the gunzipped vmlinuxes differed in 99% of bytes (section layout shift) and the obvious `diff -q` returned uninformative.

For `web/tinyweb` it was: *"every obvious XSS angle is blocked. Is there a non-XSS sink in this response?"* — which led to the `Link: rel=stylesheet` CSS-injection / attribute-selector path.

The shape is always the same: **the harness will happily refine a wrong plan forever. The human's only essential job is to *kill plans*.**

## Configurations that paid for themselves

### Read-budget discipline

Bash output that exceeds ~50 KB blows the main context's coherence by the end of the day. The harness saves output to files and reads **byte ranges** instead:

```
sub-agent: tshark -r kitchen_log.pcap … > /tmp/syslog.txt
sub-agent: head -n 20 /tmp/syslog.txt | summarize structure
main:     [reads only the summary, never the 12k lines]
```

For `misc/double-fried` (115 syslog packets) the main thread saw maybe 600 bytes of pcap output the entire time.

### Sub-agent reports under 200 words

Every sub-agent prompt ends with *"report in under 200 words."* This isn't aesthetic — it's a forcing function for the sub-agent to extract *conclusions* instead of dumping raw data into the main context. The sub-agent can write any amount to disk; what comes back into the parent's context is a paragraph.

### Plans, not chat

Non-trivial work goes through an explicit Plan (the harness has an `ExitPlanMode` ritual). The plan is two paragraphs: what we're doing and what we're not. Reading the plan back to myself before approving catches half the wrong directions. The MIHNP plan said *"recover `a` from MIHNP samples"* — and *should* have said *"verify the handout matches the server before recovering anything."* That one missing line is six hours.

### Per-challenge memory, not per-session

`~/.claude/projects/-Users-apple-gpn/memory/` holds short notes between sessions — what was tried, what worked, what the challenge was actually about once we figured it out. The memory **does not** contain the writeups themselves; those live in the repo. The split is: memory = "next-time-you-look-here, you'll need to know X"; repo = "next-time-anyone-reads-this, here's the full solve."

## Numbers, for what they're worth

| Challenge                       | Wall-clock (rough) | Sub-agents | Notes                                              |
|---------------------------------|--------------------:|------------:|----------------------------------------------------|
| `crypto/com-petition`           |             45 min |           2 | Sub-agent ran 100 rounds; main wrote the proof     |
| `crypto/easy-dsa`               |          2.5 hours |           4 | Sign ambiguity caught on first verify              |
| `crypto/guess-the-taste`        |           6 hours… |          9+ | …of MIHNP scratch, then 8 min on the real NTRU bug |
| `crypto/justfollowtherecipe`    |          3.5 hours |           5 | 45 s of BKZ; the rest was finding the lane swap    |
| `misc/customer-service`         |          1.5 hours |           3 | holpy reading is human-on-LLM                      |
| `misc/double-fried`             |             40 min |           2 | tshark sub-agent; the R/F split is obvious once seen|
| `misc/knitted-flag`             |          1.5 hours |           3 | Final `{`-vs-`<` disambiguation is human-eye       |
| `misc/organized`                |          2.5 hours |           4 | Three-peak histogram was the key sub-agent output  |
| `misc/supercat`                 |             20 min |           1 | Race window large; first try landed                |
| `pwn/recipe-for-disaster`       |             15 min |           1 | `gets()` is `gets()`                               |
| `reverse/autocooker`            |             40 min |           2 | Four involutions; sub-agent confirmed self-inverse |
| `reverse/koenigsberg-…`         |           2 hours  |           3 | Warnsdorff DFS suggestion came from sub-agent      |
| `reverse/leftovers`             |          3.5 hours |           6 | CDS file format is the cost; bytecode decode fast  |
| `reverse/leftover-leftovers`    |             45 min |           2 | One-byte patch once the parent challenge was solved|
| `reverse/specCTF`               |          1.5 hours |           3 | r14/r15 ABI trick was a "wait, what?" moment       |
| `reverse/stupidcontract`        |           4 hours  |           5 | bzImage unpacking was 70% of the time              |
| `web/pharry`                    |           2 hours  |           5 | Parallel hypothesis-testing on PHP behavior        |
| `web/restaurant-builder`        |          1.5 hours |           4 | Pydantic v2 hallucination caught early             |
| `web/tinyweb`                   |          2.5 hours |           3 | CSS exfil rate-limited by 30s `await sleep`        |

Sub-agent counts are upper bounds — I lost track during long sessions.

## What I'd change next time

1. **Force a "is this the right challenge?" gate.** Before any solve-direction commitment, the harness should verify that the handout file matches what the live service produces. The MIHNP/NTRU split was preventable by a single `nc host port | head` ran against the script's expected I/O shape.
2. **Better cross-session memory hygiene.** I had memory files from a prior CTF still loaded by default; some subtly biased Claude toward a Coppersmith framing on MIHNP. The default should be *no* cross-CTF memory unless explicitly imported.
3. **Per-challenge directory templates.** Every challenge ended up with `work/`, `solve.py`, `README.md` — but the structure emerged ad-hoc. A `gpn-ctf init <category> <name>` command would have saved 10 minutes per challenge and given every writeup the same skeleton from the start.
4. **Pre-commit lint on the writeups themselves.** A second sub-agent reading the freshly-written README and complaining about un-justified claims (*"you say the verifier was removed — quote the diff that shows it"*) would catch about half the rough edges before the human ever reads them.

## Coda

The thing I want to leave with anyone building an LLM-driven CTF harness is that the *interesting* engineering isn't getting Claude to write a fpylll solver. It's getting Claude to **stop** writing fpylll solvers and re-read the problem. The harness has to make stepping-back cheap and default-friendly, or you will burn an evening on the wrong attack and publish a writeup that says the real solve was eight lines.

Everything else in this writeup is a footnote to that.

## Frequently asked questions

### What harness ran the GPN CTF 2026 engagement?

Claude Code (Opus 4.x, 1M-context build) driving a small Bash/Python sandbox with parallel sub-agents and a single human in the loop. No agentic shopping list — each challenge started a fresh conversation with the handout files and a one-sentence framing.

### What was the harness's biggest failure?

Six hours sunk on the MIHNP framing of `crypto/guess-the-taste` before a fresh look at the protocol output revealed the missing `mod q`. Claude built 70+ unique Sage scripts including five Xu-Hu-Sarkar lattice implementations, none of which recovered the secret because the challenge wasn't MIHNP. The corrective move — *kill plans early, verify the handout matches the live service* — has to come from outside the harness.

### What was the harness's biggest win?

`misc/organized`. The entire ternary-UART recovery was three sub-agent runs: histogram, run-length, peak count. The human ran no analysis; the human picked the *next question*. Total: three steps, ~2 hours.

### How are sub-agents used as a parallelism primitive?

For `web/pharry`, three sub-agents verified PHP 7.4 PHAR behaviours in parallel: `phar://data://`, `phar://https://`, and `md5_file` on empty HTTP responses. Two were dead ends, one was the kill chain. Without parallelism that's three serial round-trips of several minutes each. Sub-agents spend their own context windows so the main thread never sees the bulk output.

### When should you kill a research direction?

The rule: *if a sub-agent has produced N independent re-implementations of the same attack without progress, the bug is upstream of the attack code.* For `justfollowtherecipe`, after BKZ-40 with defaults landed at norm ~310 instead of the target ~37, the right move was to question whether the input `A` was correct — leading to the AVX2 lane-swap discovery.

### What are the harness's known weaknesses?

(1) Anything graphical without a screenshot (e.g. font disambiguation `{` vs `<`). (2) Confident hallucination in less-popular libraries (`web/restaurant-builder`'s Pydantic v2 helpers). (3) Refining wrong plans indefinitely (`guess-the-taste`'s six-hour MIHNP detour). (4) First-pass code that "looks finished" but has a sign-ambiguity-style bug missing.

### Where can I find the full post-mortem?

Standalone source at [`meta/llm-harness.md`](https://github.com/Abdelkad3r/gpn-ctf-2026/blob/master/meta/llm-harness.md). Master writeup at [/ctf-writeups/gpn-ctf-2026-writeup/](/ctf-writeups/gpn-ctf-2026-writeup/).

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type": "Question","name": "What harness ran the GPN CTF 2026 engagement?","acceptedAnswer": {"@type": "Answer","text": "Claude Code (Opus 4.x, 1M-context build) driving a small Bash/Python sandbox with parallel sub-agents and a single human in the loop. Each challenge started a fresh conversation with the handout files and a one-sentence framing."}},
    {"@type": "Question","name": "What was the harness's biggest failure?","acceptedAnswer": {"@type": "Answer","text": "Six hours sunk on the MIHNP framing of crypto/guess-the-taste before a fresh look at the protocol output revealed the missing mod q. Claude built 70+ unique Sage scripts including five Xu-Hu-Sarkar lattice implementations, none of which recovered the secret because the challenge wasn't MIHNP."}},
    {"@type": "Question","name": "What was the harness's biggest win?","acceptedAnswer": {"@type": "Answer","text": "misc/organized. The entire ternary-UART recovery was three sub-agent runs: histogram, run-length, peak count. The human ran no analysis; the human picked the next question. Total: three steps, ~2 hours."}},
    {"@type": "Question","name": "How are sub-agents used as a parallelism primitive?","acceptedAnswer": {"@type": "Answer","text": "For web/pharry, three sub-agents verified PHP 7.4 PHAR behaviours in parallel: phar://data://, phar://https://, md5_file on empty HTTP responses. Two were dead ends, one was the kill chain. Sub-agents spend their own context windows so the main thread never sees bulk output."}},
    {"@type": "Question","name": "When should you kill a research direction?","acceptedAnswer": {"@type": "Answer","text": "If a sub-agent has produced N independent re-implementations of the same attack without progress, the bug is upstream of the attack code. For justfollowtherecipe, after BKZ-40 with defaults landed at norm ~310 instead of target ~37, the right move was to question whether the input A was correct — leading to the AVX2 lane-swap discovery."}},
    {"@type": "Question","name": "What are the harness's known weaknesses?","acceptedAnswer": {"@type": "Answer","text": "Anything graphical without a screenshot (e.g. font disambiguation { vs <). Confident hallucination in less-popular libraries (Pydantic v2 helpers). Refining wrong plans indefinitely (guess-the-taste's MIHNP detour). First-pass code that looks finished but has sign-ambiguity-style bugs."}},
    {"@type": "Question","name": "Where can I find the full post-mortem?","acceptedAnswer": {"@type": "Answer","text": "Standalone source at meta/llm-harness.md in github.com/Abdelkad3r/gpn-ctf-2026. Master writeup at cybersecurityelite.com/ctf-writeups/gpn-ctf-2026-writeup/."}}
  ]
}
</script>
