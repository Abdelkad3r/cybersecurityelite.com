---
title: "GPN CTF 2026 — Königsberg Delivery Problem: A Binary Ninja Workflow"
slug: "gpn-ctf-2026-koenigsberg-binja"
description: "GPN CTF 2026 Reverse: 250-state FSM as jump tables, Hamiltonian path on a 250-node graph. Walked through Binary Ninja's HLIL, Stack View, Graph View, and jump-table resolution."
date: 2026-06-07T19:00:00Z
lastmod: 2026-08-04T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
tags:
  - "gpn ctf 2026"
  - "koenigsberg delivery problem"
  - "binary ninja"
  - "hlil high level il"
  - "stack view"
  - "graph view"
  - "jump table resolution"
  - "hamiltonian path"
  - "warnsdorff heuristic"
  - "binja python api"
series: ["GPN CTF 2026"]
keywords:
  - "gpn ctf koenigsberg writeup"
  - "binary ninja ctf workflow"
  - "binja hlil dispatch table"
  - "binja jump table resolution"
  - "hamiltonian path 250 node ctf"
  - "warnsdorff dfs ctf"
  - "binja python api basic_blocks"
toc: true
cover:
  image: "/images/articles/gpn-ctf-2026-koenigsberg-binja.png"
  alt: "GPN CTF 2026 Königsberg Delivery Problem writeup — Binary Ninja HLIL, Stack View, Graph View, and jump-table resolution for a 250-state FSM"
---

{{< ctf-meta platform="GPN CTF 2026 (kitctf)" difficulty="Medium-Hard" os="Reverse — 250-state FSM, jump tables, Hamiltonian path" skills="reading 4,500 lines of straight-line dispatch in Binja HLIL instead of objdump, using Stack View to identify a per-state visit-counter array, extracting jump-table successors via function.basic_blocks[i].outgoing_edges, building a 250-node directed graph from Binja-recovered edges, running Warnsdorff's heuristic DFS to find a Hamiltonian path in ~70 ms" >}}

**Königsberg Delivery Problem** is the GPN CTF 2026 reverse challenge that turned a 4,500-line straight-line dispatch routine into a graph-theory problem, and this **CyberSecurity Elite** writeup breaks down the Binary Ninja workflow that cracked it. The binary `cartographer` is 140 KB, not stripped, dynamically linked, x86-64 PIE. The interesting function `cfg()` is **250 logically-identical state blocks** ending in indirect `jmp rdx` jumps over `.rodata` jump tables. The win condition is "visit every state at least once" — Hamiltonian path on a 250-node directed graph.

This writeup is the standalone deep-dive on the Binary Ninja workflow that solved it — submitted for the **Best Binary Ninja Writeup** prize at GPN CTF 2026. The standalone solve narrative (Binja-independent) is in the [GPN CTF 2026 master writeup](/ctf-writeups/gpn-ctf-2026-writeup/). Full source at [`reverse/koenigsberg-delivery-problem`](https://github.com/Abdelkad3r/gpn-ctf-2026/tree/master/reverse/koenigsberg-delivery-problem).

## Why this challenge is a good Binja exercise

`cartographer` is exactly the shape Binja's analyzers eat for breakfast:

- **HLIL** condenses each state's `inc [rsp + N]; movzx; cmp; ja OOB; inc rcx; movsxd; add; jmp` boilerplate into 4-6 lines, so you read the whole CFG by scrolling instead of `grep`-ing.
- **Stack View** identifies the visit-counter buffer at `var_108` automatically and labels every `inc` against the right slot.
- **Graph View** on `cfg()` shows the 250-block structure as a CFG — the visual density immediately tells you "this is a dispatch table, not a real control flow."
- **Jump-table resolution** is where Binja's analyzer earned its keep. Out of the box it resolves each `jmp rdx` to its set of successors using the analyzer's recovered base address — the *exact* graph needed for the Hamiltonian search.

The point of this writeup is not the algorithmic story (that's in the master writeup) but to show what the workflow looked like **inside Binja** and what the analyzer caught.

## First look: triage in 30 seconds

Open `cartographer` in Binja. Wait ~3 seconds for analysis. Hit `g`, type `main`.

Skim HLIL: `main` is a 250-iteration unrolled sequence of `__isoc99_scanf("%hhd;", &buf[i])` calls — Binja collapses each call into a single HLIL line, so the unroll is obvious. After the unroll there's a single call to `cfg(&buf)`. Total useful insight: **input is 250 signed bytes, then the work happens in `cfg`**. Time spent: 30 seconds.

`g cfg`. Graph View opens onto a sprawling CFG of ~250 small blocks. That density alone is the diagnosis: this is a dispatch table, not a program.

## Reading the state skeleton in HLIL

Pick any one block in `cfg`'s graph and look at its HLIL. Binja gives something close to:

```python
# state N skeleton (HLIL, representative)
var_108[N]:1 = var_108[N]:1 + 1                    # counter[N]++
if (rcx_buf[rcx_idx]:1 > MAX_SYM_N) {              # bounds check
    goto OOB_TAIL                                  # → check_instance
}
rcx_idx = rcx_idx + 1
rdx_off = *(int32_t *)(JT_BASE_N + 4 * rcx_buf[rcx_idx]:1)
jump((rdx_off + JT_BASE_N))                        # indirect to next state
```

Four observations from the HLIL alone:

1. **`var_108` is the visit counter array.** Stack View confirms this — it shows `var_108` as a 256-byte stack region, and `cfg`'s prologue zeroes the first 250 bytes via a `rep stosq`. The HLIL flags every state block's `var_108[N]:1 += 1` as the *only* writer of that slot.
2. **The bounds check `MAX_SYM_N`** varies per state. In assembly you'd have to extract these by hand; in Binja, Right-Click → "Show as constant" on each `cmp` operand makes the per-state `MAX` jump out.
3. **`JT_BASE_N`** is the per-state jump-table base. Binja's analyzer has already resolved the relative `.rodata` reference into an absolute address, labelled e.g. `data_8050`.
4. **`jump((rdx_off + JT_BASE_N))`** is recognized by Binja as a computed branch, and Cross-Reference (`x`) on each state's `jump` shows the resolved successor set. **This is the single biggest Binja win** — the same recovery you'd otherwise script in 60 lines of Python is just there in the UI.

## Building the graph with Binja's recovered jump-table edges

Binja's "Computed Branch Targets" for each `jump` ARE the directed edges of the state graph. Two ways to extract them:

**Option A — interactive (5 minutes for small recon).** Use Right-Click → "View Targets" on a few `jump` instructions to spot-check that successors look plausible. Confirms the analyzer recovered them correctly.

**Option B — scripted via the Python API.**

```python
# Binary Ninja Python console, on `cartographer` open:
import json

bv = current_view
cfg_fn = bv.get_function_at(bv.symbols["cfg"].address)

# Find every block that ends in an indirect jump.
edges = {}
for bb in cfg_fn.basic_blocks:
    last_il = cfg_fn.get_low_level_il_at(bb.end - bb.instruction_count).instructions[-1]
    if last_il.operation.name != "LLIL_JUMP":
        continue
    state_addr = bb.start
    successors = [edge.target.start for edge in bb.outgoing_edges]
    edges[state_addr] = successors

# Map state addresses → state indices via the `inc [rsp + N]` prologue.
state_to_idx = {}
for bb in cfg_fn.basic_blocks:
    for il in cfg_fn.get_low_level_il_at(bb.start).instructions:
        # Find inc memory operations whose operand is var_108[N]
        if il.operation.name == "LLIL_STORE":
            …  # match the slot
    state_to_idx[bb.start] = N

# Now `edges` is the directed graph keyed by state index.
graph = {state_to_idx[s]: [state_to_idx.get(t, "OOB") for t in succs]
         for s, succs in edges.items()}
print(json.dumps(graph, indent=2))
```

This script does in ~30 lines what the original `solve.py` does with `objdump` plumbing — using Binja's recovered control-flow rather than raw byte parsing.

## The OOB exit — Stack View confirms it cleanly

The `cmp rdx, MAX_SYM_N; ja OOB` branches all land at one specific tail block. In Binja's graph that block is the *only* node with no outgoing edges back into `cfg`'s body. Hit `Tab` to switch its HLIL view:

```python
# OOB tail (HLIL)
check_instance(&var_108, 250)
return
```

`check_instance` opens in HLIL as a clean 8-line function: linear scan for `buf[i] == 0` flagging *any zero counter* as "you missed a state," then the `/flag` open + print. **No deobfuscation needed.** Binja shows the function in production form on the first analysis pass.

## Verifying the win condition is *vertex* coverage

The *Königsberg* name nudges toward an Eulerian (edge) interpretation. Binja's HLIL kills that quickly — the visit array is **indexed by `N` (the state index)**, not by an edge identifier. Each state's prologue writes exactly one fixed slot. No edge counter ever appears in HLIL.

So the win condition is unambiguously "every state visited at least once" = Hamiltonian path on the state graph. **Visualising the HLIL of three random states side-by-side took ~90 seconds and ruled out the Eulerian interpretation entirely.**

## Hamiltonian search runs against Binja's recovered graph

Drop the recovered `graph` (from step 3) into a standalone Python script with Warnsdorff's heuristic. Average out-degree ≈ 100/state (some states have 68, the densest have 121), so the heuristic finds a path with essentially zero backtracking:

```python
# In a normal Python venv, not Binja's:
import json
graph = json.load(open("graph.json"))
graph = {int(k): [v for v in vs if v != "OOB"] for k, vs in graph.items()}

def warnsdorff_dfs(start, n_states):
    visited = {start}
    path = [start]
    while len(path) < n_states:
        cur = path[-1]
        candidates = [s for s in graph.get(cur, []) if s not in visited]
        if not candidates:
            return None
        candidates.sort(key=lambda s: sum(1 for t in graph[s] if t not in visited))
        nxt = candidates[0]
        visited.add(nxt)
        path.append(nxt)
    return path

path = warnsdorff_dfs(start=0, n_states=250)
assert path is not None
```

Path emitted in ~70 ms. Translate path → input bytes by looking up each `(state_i, state_i+1)` edge in the per-state transition table to pick any symbol that drives it. Append a final OOB byte to fire `check_instance`. Pipe into `nc --ssl`, read flag.

## What Binja saved me

The standalone solve writeup reads as if everything happened in `objdump` and Python. The truth is slightly different — without Binja:

- I'd have written a hand-rolled jump-table resolver (~60 lines of Python parsing `objdump -s -j .rodata` + `lea` instructions). Binja's analyzer does this and exposes it via `function.basic_blocks[i].outgoing_edges`.
- I'd have lost half an hour staring at the 250 `inc byte ptr [rsp + N]` patterns trying to confirm "yes, this is a per-state visit counter." Binja's Stack View tells you that on hover.
- I'd have not noticed that `check_instance` was a clean 8-line function in the first pass — Binja's HLIL strips away the prologue/epilogue and shows the structural code immediately.

What Binja didn't do for me:

- It doesn't know that the *meaning* of the graph is a Hamiltonian-path win condition. That's a human inference from the HLIL plus the challenge prompt. Reverse engineering is still about reading the patterns; Binja just makes the patterns legible faster.

## Closing note — why this is the Best Binja Writeup submission

Binary Ninja's edge on this challenge was not "it found something nothing else could." It was that **every analytical step took 30-60% less time** because HLIL kept the 4,500-line dispatch routine readable, the Stack View labelled the counter array on hover, and the analyzer's recovered jump-table targets *were* the graph I needed. The final solve algorithm (Warnsdorff DFS on a 250-node digraph) is the same with or without Binja — but the time to *reach* that algorithm is where Binja paid for itself.

The companion BINJA.md in the [source repository](https://github.com/Abdelkad3r/gpn-ctf-2026/blob/master/reverse/koenigsberg-delivery-problem/BINJA.md) carries the full walkthrough with screenshots-equivalent narration.

## Frequently asked questions

### What kind of binary is `cartographer`?

140 KB, not stripped, dynamically linked, x86-64 PIE. The interesting routine `cfg()` is ~4,500 lines of straight-line dispatch: 250 logically-identical state blocks ending in indirect `jmp rdx` over 250 `.rodata` jump tables of 32-bit `rip`-relative offsets.

### Why is the win condition Hamiltonian and not Eulerian?

The visit-counter array is indexed by *state* (the FSM node index), not by *edge*. Each state's prologue increments exactly one fixed slot. The `check_instance` function flags any zero counter as "you missed a state." So the win condition is "every vertex visited at least once" = Hamiltonian path. The *Königsberg* name is a red herring nudging toward Eulerian (edges).

### How does Binary Ninja help with this challenge specifically?

Four ways: HLIL collapses the dispatch boilerplate into 4-6 readable lines; Stack View identifies the `var_108[N]` counter array automatically; Graph View on `cfg()` reveals the dispatch-table structure visually; jump-table resolution recovers the indirect `jmp rdx` successor set as graph edges via `function.basic_blocks[i].outgoing_edges`.

### Can you do this challenge without Binary Ninja?

Yes — the original solve writeup uses `objdump` plus a ~60-line Python jump-table resolver. The algorithm (Warnsdorff DFS on the 250-node digraph) is identical. Binja's contribution is reducing time-to-graph from ~90 minutes to ~25 minutes by exposing the recovered jump tables in a UI/API directly.

### Why does Warnsdorff's heuristic work so well?

Average out-degree is ~100 per state, with the densest at 121 and the sparsest at 68. That density gives Warnsdorff plenty of slack: at each step prefer the unvisited successor with the fewest unvisited successors of its own, and the search finds a Hamiltonian path in ~70 ms with essentially zero backtracking. On sparser graphs (~10 successors per node) backtracking becomes expensive; on graphs this dense it's essentially greedy.

### How do you go from path to input bytes?

For each consecutive pair `(state_i, state_{i+1})` in the recovered path, look up `state_i`'s transition table (the `.rodata` jump table at `JT_BASE_i`) and pick any symbol that drives the transition to `state_{i+1}`. Append a single OOB-triggering byte (any byte > `MAX_SYM` of the last state) to fire `check_instance`. Send the resulting 250+1 byte stream over `nc --ssl`.

### Where can I find the solver?

Full Binja workflow at [`reverse/koenigsberg-delivery-problem/BINJA.md`](https://github.com/Abdelkad3r/gpn-ctf-2026/blob/master/reverse/koenigsberg-delivery-problem/BINJA.md). Binja-independent solver at [`reverse/koenigsberg-delivery-problem/solve.py`](https://github.com/Abdelkad3r/gpn-ctf-2026/tree/master/reverse/koenigsberg-delivery-problem). Master writeup at [/ctf-writeups/gpn-ctf-2026-writeup/](/ctf-writeups/gpn-ctf-2026-writeup/).

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type": "Question","name": "What kind of binary is cartographer?","acceptedAnswer": {"@type": "Answer","text": "140 KB, not stripped, dynamically linked, x86-64 PIE. The interesting routine cfg() is ~4,500 lines of straight-line dispatch: 250 logically-identical state blocks ending in indirect jmp rdx over 250 .rodata jump tables of 32-bit rip-relative offsets."}},
    {"@type": "Question","name": "Why is the win condition Hamiltonian and not Eulerian?","acceptedAnswer": {"@type": "Answer","text": "The visit-counter array is indexed by state (the FSM node index), not by edge. Each state's prologue increments exactly one fixed slot. check_instance flags any zero counter as you missed a state. Win condition: every vertex visited at least once = Hamiltonian path. The Königsberg name is a red herring."}},
    {"@type": "Question","name": "How does Binary Ninja help with this challenge specifically?","acceptedAnswer": {"@type": "Answer","text": "Four ways: HLIL collapses the dispatch boilerplate into 4-6 readable lines; Stack View identifies the var_108[N] counter array automatically; Graph View on cfg() reveals the dispatch-table structure visually; jump-table resolution recovers the indirect jmp rdx successor set as graph edges via function.basic_blocks[i].outgoing_edges."}},
    {"@type": "Question","name": "Can you do this challenge without Binary Ninja?","acceptedAnswer": {"@type": "Answer","text": "Yes. The original solve uses objdump plus a ~60-line Python jump-table resolver. The algorithm (Warnsdorff DFS on the 250-node digraph) is identical. Binja reduces time-to-graph from ~90 minutes to ~25 minutes by exposing recovered jump tables in a UI/API directly."}},
    {"@type": "Question","name": "Why does Warnsdorff's heuristic work so well?","acceptedAnswer": {"@type": "Answer","text": "Average out-degree is ~100 per state (range 68 to 121). That density gives Warnsdorff plenty of slack: prefer the unvisited successor with the fewest unvisited successors. Finds a Hamiltonian path in ~70 ms with essentially zero backtracking."}},
    {"@type": "Question","name": "How do you go from path to input bytes?","acceptedAnswer": {"@type": "Answer","text": "For each consecutive (state_i, state_{i+1}) in the path, look up state_i's transition table at JT_BASE_i and pick any symbol that drives the transition. Append one OOB-triggering byte to fire check_instance. Send the 250+1 byte stream over nc --ssl."}},
    {"@type": "Question","name": "Where can I find the solver code?","acceptedAnswer": {"@type": "Answer","text": "Full Binja workflow at reverse/koenigsberg-delivery-problem/BINJA.md. Binja-independent solver at reverse/koenigsberg-delivery-problem/solve.py in github.com/Abdelkad3r/gpn-ctf-2026. Master writeup at cybersecurityelite.com/ctf-writeups/gpn-ctf-2026-writeup/."}}
  ]
}
</script>
