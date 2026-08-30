---
title: "z0d1akCTF 2026 Qualifiers Misc Writeup: genie, ihateDAA, Control Plane & Sanity Check"
slug: "z0d1akctf-2026-qualifiers-misc-writeup"
description: "Complete z0d1akCTF 2026 Qualifiers Miscellaneous writeup covering all four Misc challenges. genie — Game Boy replay service with a 12-write cheat port; the authenticated gold counter stores gold, gold XOR K(seed), and MAC(seed, gold) at C100 through C105, all inside the writable window, so an atomic three-word write bypasses the frame-loop validator; a 3-selector floor-9 echo machine brute-forces to the 9-selector sequence 2,0,2,1,2,2,0,2,1 that hashes to 0xb14a. ihateDAA — HTTP DAG traversal service disguised as a DAG but actually cyclic (63,236 back edges over 92,358 nodes, 258,532 edges, six roots, exactly one Flag Found sink with in-degree 1 sitting 9 hops from a root); every interior page contains the phrase 'flag' in its h1 so any 'flag' in body detector matches 100 percent of nodes and reports nothing; a parallel BFS keyed on the HTML title element with mark-on-enqueue over 32 keep-alive connections finishes the crawl in about 15 minutes. Control Plane — EVM kernel exposing execute(bytes) that validates then executes an attacker program; a parser differential where the audited validator decodes record lengths little-endian but the executor decodes them big-endian lets a 0x12 skip record with length bytes 00 01 swallow the whole 259-byte batch from the validator (which reads 256 bytes) while advancing the executor by only 4 bytes; the two hidden records that follow do a mode-1 DELEGATECALL to TelemetryModule.rotate(seal) that writes the kernel's own slot 2 and arms the mode-2 gate, then a mode-2 CALL to vault.settle(player, 100 ether, ticket) that drains all 100 ETH via the publicly computable ticket from vault.quote(). Sanity Check — the event's own marketing site z0d1ak.org injects a server-side style tag id=sanity-check-fragment carrying a CSS custom property that never renders; the value is keyed on hostname, and only the apex and www serve fragments (three-way confirmed via DNS-over-HTTPS SecLists-5000, certificate-transparency logs, and wildcard SNI probing) — concatenating apex then www and Base58-decoding yields all the best, we hope you enjoy the ctf."
date: 2026-08-30T18:00:00Z
lastmod: 2026-08-30T18:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["z0d1akCTF 2026 Qualifiers"]
tags:
  - "z0d1akctf"
  - "z0d1akctf 2026"
  - "z0d1ak ctf"
  - "z0d1akctf qualifiers"
  - "ctf writeup"
  - "miscellaneous"
  - "misc"
  - "game boy rom"
  - "game boy replay"
  - "authenticated counter bypass"
  - "checksum bypass"
  - "graph traversal ctf"
  - "cyclic graph"
  - "breadth first search"
  - "keep alive http"
  - "evm bytecode"
  - "parser differential"
  - "endianness bug"
  - "delegatecall storage overwrite"
  - "smart contract kernel"
  - "vault drain"
  - "cloudflare snippet"
  - "cloudflare worker"
  - "server side injection"
  - "base58 decoding"
  - "hostname keyed marker"
  - "css custom property"
  - "sni probing"
  - "certificate transparency"
  - "ctf 2026"
keywords:
  - "z0d1akctf 2026 qualifiers writeup"
  - "z0d1akctf 2026 misc writeup"
  - "z0d1akctf 2026 miscellaneous writeup"
  - "z0d1akctf genie writeup"
  - "z0d1akctf ihateDAA writeup"
  - "z0d1akctf control plane writeup"
  - "z0d1akctf sanity check writeup"
  - "game boy authenticated gold counter bypass ctf"
  - "gb rom cheat port replay attack ctf"
  - "parallel bfs http graph traversal ctf"
  - "cyclic graph dfs recursion trap"
  - "evm kernel parser differential little endian big endian"
  - "delegatecall rotate slot storage arm gate ctf"
  - "vault settle ticket drain ctf"
  - "cloudflare snippet sanity check fragment"
  - "base58 concatenation flag ctf"
  - "hostname keyed cloudflare injection"
  - "z0d1akctf 2026 solutions"
  - "ctf step by step 2026"
toc: true
cover:
  image: "/images/articles/z0d1akctf-2026-qualifiers-misc-writeup.png"
  alt: "z0d1akCTF 2026 Qualifiers Miscellaneous writeup cover — all four Misc challenges solved. genie exploits a Game Boy replay service whose 12-write cheat port lets an atomic three-word write to the C100 through C105 window bypass the frame-loop validator that recomputes gold XOR K and the MAC, then walks a nine-step floor-nine echo machine using the brute-forced selector sequence two zero two one two two zero two one that hashes to 0xb14a. ihateDAA is an HTTP graph traversal service masquerading as a DAG but actually cyclic with 63,236 back edges over 92,358 nodes; every interior page contains the word flag in its h1 so any naive text detector matches every node, and only a title element discriminator paired with a parallel breadth-first search over 32 keep-alive connections with mark on enqueue finds the single Flag Found sink of in-degree one, nine hops from an entry point. Control Plane is an EVM kernel whose audited validator decodes record lengths little-endian while the executor decodes them big-endian; a 0x12 skip record with length bytes zero-zero-one swallows the whole batch from the validator while advancing the executor by only four bytes, letting two hidden records run — a mode-one DELEGATECALL to TelemetryModule rotate that writes the kernel's own storage slot two to the recomputed seal, then a mode-two CALL to vault settle that drains 100 ETH using the publicly computable ticket from vault quote. Sanity Check is the event's marketing site with a Cloudflare-injected style tag whose CSS custom property never renders and is keyed on hostname; the apex serves one fragment and www serves another, concatenating apex then www and Base58 decoding yields the phrase all the best we hope you enjoy the ctf"
---

**z0d1akCTF 2026 Qualifiers**'s Miscellaneous track is a four-challenge lesson in one shared discipline: **read the substrate the system actually operates on, not the surface it presents.** Every challenge in the set is solvable in a few hundred bytes of Python once the substrate is named, and unsolvable — sometimes literally infinite-looping — as long as you keep interacting with the surface. `genie` presents a locked passage in a Game Boy game; the substrate is a writable RAM window that holds the "protected" counter plus its own MAC, so an atomic three-word write from the replay service's cheat port satisfies the ROM's own validator without touching a single instruction. `ihateDAA` presents 92,358 near-identical HTML pages; the substrate is the `<title>` element (the only one of ninety-two thousand titles that reads `Flag Found`) and the edge topology, which is cyclic in a way that punishes naive recursion. `Control Plane` presents a smart-contract kernel whose validator declares your program safe; the substrate is a second byte-length decoder inside the *executor* that reads endianness the other way, so a program the validator approves as one benign skip runs a `DELEGATECALL` + `CALL` pair the validator never saw. `Sanity Check` presents the event's own React marketing site; the substrate is a Cloudflare-injected `<style id="sanity-check-fragment">` tag whose CSS custom property never renders and is keyed on hostname — the apex and `www` each carry one half of a Base58 number.

The unifying pattern is that in every one of these challenges the flag is one indirection below the layer the user experiences, and *the challenge names its own indirection*. genie's `PORT.md` documents the cheat port; ihateDAA's description says *"the way through my heart is very twisted"* (i.e. cyclic); Control Plane says the kernel was *"independently audited from its wire-format specification"* (i.e. audited on the spec, executed on a different spec); Sanity Check's marker element is literally titled `sanity-check-fragment`. Reading those hints as directives — and reading the *actual* substrate they point at — collapses each Hard-feeling problem into a routine one.

Handouts, per-challenge READMEs, solver scripts, and captured session artifacts live at [Abdelkad3r/z0d1akCTF-2026-Qualifiers](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers). This **CyberSecurity Elite** z0d1akCTF 2026 Qualifiers Misc writeup covers all four challenges end to end, with an emphasis on the *substrate* each one operates on and on the disciplined tooling (frame-atomic cheat writes, threaded BFS with mark-on-enqueue, parser-differential wire encoding, Cloudflare-Snippet-vs-origin fingerprinting) that turns the theory into a solve.

## All four Miscellaneous challenges at a glance

| Challenge | Points | Sub-genre | Substrate the exploit reads | Flag |
|---|---:|---|---|---|
| [genie](#geniegame-boy-rom-replay-with-an-authenticated-cheat-port) | 138 | Game Boy ROM replay | RAM `C100–C105` (gold + XOR + MAC) inside writable cheat window | `zdk{7Hree_WOrD5_NiNE_eCHo3S_ON3_oPeN_Seal}` |
| [ihateDAA](#ihatedaaparallel-bfs-over-a-cyclic-web-graph) | 149 | HTTP graph traversal | HTML `<title>` element + cyclic 92k-node adjacency list | `zdk{i_l0Ve_GRaPH_7RAvER5AL_4nd_dyN4mIc_inSTanc35}` |
| [Control Plane](#control-planeevm-kernel-parser-differential) | 163 | EVM parser differential | 1594-byte kernel runtime bytecode; executor's own record-length decoder | `zdk{ENDIan_fIREw4l1_d3L3gA7e_DRaIN}` |
| [Sanity Check](#sanity-checkcloudflare-injected-hostname-keyed-fragment) | 199 | Cloudflare-Snippet OSINT | `<style id="sanity-check-fragment">` injected by a Cloudflare Snippet, keyed on hostname | `zdk{all the best, we hope you enjoy the ctf}` |

Four categories dressed as one: replay + web + smart-contract + OSINT. One repeated pattern.

---

## genie — Game Boy ROM replay with an authenticated cheat port

> *Flag:* `zdk{7Hree_WOrD5_NiNE_eCHo3S_ON3_oPeN_Seal}`
>
> *Prompt:* "do something with the bottle of the genie"

The handout is a 32 KiB Game Boy ROM (`seal.gb`, title `SEAL_NINTH`) plus a `PORT.md` file that specifies a replay-service protocol. The remote service prints a 16-bit session seed, accepts one JSON *movie*, replays it on a pristine seeded cartridge, and returns the flag only if the replay reaches the ROM's `WIN` state.

### The wire format

`PORT.md` is more than documentation — it defines the entire attack surface:

- the service prints `seed=<decimal>` and `movie-json>`;
- the movie is compact JSON with `version`, `seed`, `joypad`, `codes`;
- `joypad[n]` is the button mask for frame `n`;
- each code is `[frame, address, value]`, a little-endian 16-bit RAM write applied *before* the frame runs;
- writes are accepted **only at even addresses in `C100–C1FE` and `C300–C3FE`**;
- **at most 12 code writes per movie.**

That "12 writes into two 256-byte windows" cap looks tight until you realise the entire authenticated state fits inside it.

### The authenticated gold counter

Static reversing with `r2 -a gb -q seal.gb` finds the helper at `0x09f3`. Given a 16-bit gold value in `DE`, it writes:

```text
C100:C101 = gold
C102:C103 = gold XOR K(seed)
C104:C105 = MAC(seed, gold)
```

`K` and `MAC` are derived from the session seed via two small helpers:

```python
K   = ((0x3d29 + rol16(seed ^ 0xa5c3, 7)) & 0xffff) ^ 0x6b71
MAC = rol16(((0x6d2b + rol16(gold ^ K, 3)) & 0xffff) ^ rol16(K, 7), 5)
```

The frame loop calls a validator at `0x0a37` that checks whether the current `C100–C105` tuple is internally consistent. If not, it restores the last valid tuple from the backup at `C400–C405`. So writing only the gold word (`C100 = 0x1388`) is silently reverted; the winning movie must write all three codewords **atomically in one frame**, before the CPU runs that frame.

For the captured live seed `2530`:

```text
K    = 0x268e
gold = 0x1388
C100 = 0x1388
C102 = 0x1388 XOR 0x268e = 0x3506
C104 = 0x49ea
```

Three of the twelve allowed writes are now spent, and the ROM sees an internally consistent 5000-gold balance.

### Skipping to floor 9 with one START press

The START handler at `0x0d73` compares the authenticated gold word at `C100:C101` against `0x1388` (5000). At or above, it calls the final-floor setup routine at `0x10aa`, which:

1. subtracts 5000 gold using the same authenticated writer;
2. sets the floor marker `C406=0x09`, `C407=0xa9`;
3. resets the floor-9 vault state via `0x1084`;
4. draws the final room and three echo hints.

So the first act of the movie is three cheat writes on frame 20 (the authenticated gold tuple) plus a START press on the same frame. No floors 1–3, no cursed-coin hazards.

### The floor-9 echo machine

On floor 9, pressing A arms a pending echo dispatch by setting `C300:C301 = 0x00fe` and `C40A = 1`. Next frame, if `C40A` is set, the helper at `0x0efd` reads `C300:C301`. If the word is `0`, `1`, or `2`, it dispatches through the table at `0x0f32`:

```text
selector 0 -> 0x109c
selector 1 -> 0x10a0
selector 2 -> 0x10a5
```

Each of these calls `0x0ab2` with selector `0`, `1`, or `2`, which loads the current echo state from `C200:C201`, applies the selected transform at `0x05ab`, writes back, hashes with `0x0599`, and stores the hash at `C202:C203`. The final readiness routine at `0x105d` compares that hash with `ROM[0x020f:0x0210] = 0x4a 0xb1` — target hash `0xb14a`.

After final-floor setup, the echo state resets to `0x1d0f`. Three selectors, one target hash, small state — this is a tiny offline search:

```console
$ python3 verify_echo.py
length=9
sequence=2,0,2,1,2,2,0,2,1
state=0x120e
hash=0xb14a
```

Each selector needs two frames — press A to arm, then write the desired selector into `C300:C301`. Only the second frame needs a cheat code, so nine echoes fit exactly in the remaining nine writes.

### The complete 12-write movie

```text
[20,  0xc100, 5000]      authenticated gold word 1
[20,  0xc102, gold ^ K]  authenticated gold word 2
[20,  0xc104, MAC]       authenticated gold word 3

[41,  0xc300, 2]
[53,  0xc300, 0]
[65,  0xc300, 2]
[77,  0xc300, 1]
[89,  0xc300, 2]
[101, 0xc300, 2]
[113, 0xc300, 0]
[125, 0xc300, 2]
[137, 0xc300, 1]
```

Joypad presses: START on frame 20, A on frames 40/52/64/76/88/100/112/124/136. After the ninth echo, `C202:C203 == 0xb14a`, the ROM paints `WIN / SUBMIT MOVIE / TO SERVICE / FOR FLAG`, and the service returns `zdk{7Hree_WOrD5_NiNE_eCHo3S_ON3_oPeN_Seal}`.

### Takeaway

**A checksum is not protection if both the data and the checksum are writable.** The cheat port is intentionally narrow, but the protected state is entirely inside it — the gold value, its XOR obfuscation, and its MAC all sit in `C100–C1FE`, and the final echo dispatch selector sits in `C300–C3FE`. Because the replay applies writes atomically before each frame runs, the ROM's own validator never sees an inconsistent gold tuple. We satisfy the ROM's checks, not bypass them.

---

## ihateDAA — parallel BFS over a cyclic web graph

> *Flag:* `zdk{i_l0Ve_GRaPH_7RAvER5AL_4nd_dyN4mIc_inSTanc35}`
>
> *Prompt:* "The way through my heart is very twisted. Midnight Sun <3"

The service exposes a directed graph over HTTP. Each node is addressed by `/?path=<token>`, and each page renders that node's out-edges as more `?path=` links. Four page kinds, cleanly separable by `<title>`:

| `<title>` | Meaning | HTTP |
|---|---|---|
| `Which way did the flag go?` | Interior node, 2–5 out-edges | 200 |
| `Dead End` | Sink, renders `nope :(` | 200 |
| `Flag Found` | The single goal node | 200 |
| `Missing Path` | Token not in the graph | 404 |

The name — "ihateDAA" (Design and Analysis of Algorithms) — plus the "very twisted" hint is a structural directive: it is **not a DAG**. Every one of the six entry tokens is itself the target of 2–6 incoming edges; the captured instance had **63,236 back edges** across 92,358 nodes and 258,532 edges. A naive recursive descent without a visited set never terminates.

### Ruling out shortcuts

There is no session cookie, no source disclosure, no graph-dump endpoint, no `.git`. Every non-existent path returns a distinctive 578-byte "Unknown path" page (versus stock Express 142–148 byte 404s), so the enumeration is clean:

```console
$ for r in /flag /api /graph /nodes /source /app.js /index.js /.git/HEAD /debug; do
>   printf "%-14s " "$r"
>   curl -s -o /dev/null -w "%{http_code} %{size_download}\n" "https://.../$r"
> done
/flag          404 143
/api           404 142
/graph         404 144
/nodes         404 144
/source        404 145
/app.js        404 145
/index.js      404 147
/.git/HEAD     404 148
/debug         404 144
```

Tokens are base36, 8–15 characters, uniformly distributed across those lengths — roughly `2^41` to `2^77` of keyspace. Guessing the flag token is not viable. **Traversal is the only way through.**

### The fragile-detector trap

Every interior page's `<h1>` contains the literal string `Which way did the flag go?` — so a naive `if "flag" in body` detector matches all 92,358 nodes and tells you nothing. My first crawl did precisely that and reported 100 % of the graph as "interesting." The clean discriminator is `<title>`:

```python
INTERIOR_TITLE = "Which way did the flag go?"

title_match = TITLE_RE.search(body)
title = title_match.group(1) if title_match else ""
if title not in (INTERIOR_TITLE, "Dead End"):
    flag_match = FLAG_RE.search(body)
    ...
```

Anything that is neither an interior node nor a dead end is, by construction, the goal.

### Why DFS is the trap

A quick cycle audit over the captured adjacency list:

```text
back edges (cycles)  : 63236  -> has cycles
nodes with in-degree 0: 0
root in-degrees: {'cvhgfhyvkvq': 4, '0ij436dr': 2, 'j4vnri8vkp': 6,
                  'zoc67o2n1glo': 5, 'r5nbjixy': 2, 'sbp892mmn8n4gnd': 5}
self loops: 3
```

Not a single node has in-degree zero — even the entry tokens are reachable from deeper in the graph. Three nodes link directly to themselves. Recursive descent without a visited set recurses forever. BFS with a global visited set is immune, and its predecessor map yields the shortest path for free.

### Three implementation details that carry all the performance

**1. Keep-alive connections, one per thread.** 92k fresh TLS handshakes over the wire would be the dominant cost. A `threading.local()` holding a persistent `HTTPSConnection` per worker amortises this to a single handshake per thread:

```python
def _conn(self):
    conn = getattr(self._local, "conn", None)
    if conn is None:
        conn = http.client.HTTPSConnection(self.host, context=self.ctx,
                                           timeout=self.timeout)
        self._local.conn = conn
    return conn
```

**2. Mark-on-enqueue, not mark-on-dequeue.** The visited set is updated the moment a token is pushed, inside the same lock that mutates the graph. Marking on dequeue would let several workers enqueue the same token concurrently, inflating the queue by the branching factor:

```python
with self.lock:
    self.graph[token] = out
    fresh = [t for t in out if t not in self.seen]
    self.seen.update(fresh)
for t in fresh:
    self.queue.put(t)
```

**3. Retry with reconnect.** A dropped keep-alive is a normal event over a 15-minute crawl. Each request retries up to five times with linear backoff, discarding the socket first.

### Traversal results

The frontier behaviour tells the whole story:

```text
nodes=646    queue=1138      <- frontier growing faster than the visited set
nodes=4109   queue=6691
nodes=19579  queue=22828
nodes=33169  queue=27411     <- queue plateaus: edges start landing on seen nodes
nodes=49584  queue=25401     <- frontier now shrinking
nodes=77432  queue=10997
nodes=92079  queue=188
DONE nodes 92358 special 18497
```

The inflection near 33k is the signature of a finite graph with high edge reuse: past that point most discovered edges point at already-visited nodes, the queue drains, termination is guaranteed. Final numbers:

| Property | Value |
|---|---|
| Entry points (roots) | 6 |
| Nodes | 92,358 |
| Edges | 258,532 |
| Mean out-degree | 2.799 |
| Dead ends (sinks) | 18,497 (20 %) |
| Out-degree histogram | `{0: 18497, 2: 18494, 3: 18427, 4: 18493, 5: 18391, 6: 56}` |
| Back edges | 63,236 (cyclic) |
| BFS eccentricity | 16 |
| Reachable from roots | 92,358 / 92,358 (100 %) |

The out-degree histogram exposes the generator: node degree is drawn uniformly from `{0, 2, 3, 4, 5}` — no degree-1 nodes anywhere, 56 outlier degree-6 nodes.

### The flag node

Exactly one node out of 92,358 rendered a different title:

```text
special total 18497
18496 'Dead End'
    1 'Flag Found'
```

Nine hops from an entry point — and yet the flag node has **in-degree 1**. Only one predecessor links to it; one edge out of 258,532 leads there. Uniform random guessing would need ~92,358 requests with no memory of where you have been; DFS without a visited set is unbounded because it falls into a cycle first. Exhaustive BFS finds it in one pass, about 15 minutes at 32 concurrent workers.

### Takeaway

**Match your detector to the substrate, not to the surface.** The word `flag` is in every interior page's headline; the discriminator that actually works is the `<title>` element. Cyclic graphs punish DFS; a global visited set + BFS makes them tractable. When the challenge description mentions "twisted paths," take it as structural, not flavour.

---

## Control Plane — EVM kernel parser differential

> *Flag:* `zdk{ENDIan_fIREw4l1_d3L3gA7e_DRaIN}`
>
> *Prompt:* "A settlement gateway accepts compact envelopes produced by several independent implementations. The deployed kernel was independently audited from its wire-format specification. Recover the vault funds without the operator key."

A `Vault` holds 100 ETH and pays out only through `settle(recipient, amount, ticket)`, callable exclusively by its `gateway` — an on-chain **kernel** whose runtime bytecode is deployed but whose source is not in the handout. The kernel exposes `IKernel.execute(bytes program)`. Everything else has to be recovered from the 1594-byte runtime.

The one visible guard on `settle` is `msg.sender == gateway`; the ticket is computable by anyone via the public `vault.quote(recipient, amount)`. The whole challenge reduces to: *make the kernel call `settle(player, 100 ether, ticket)`.*

### Reversing the kernel from bytecode

`eth_getCode` returns 1594 bytes. `pyevmasm` renders `PUSH0`/`0x5f` as `INVALID` but the byte width matches, so PCs stay aligned. The dispatcher exposes five selectors:

| Selector | Meaning | Storage |
|---|---|---|
| `0x09c5eabe` | `execute(bytes)` | — |
| `0x194aac9c` | getter for slot 2 (`uint256`) | slot 2 |
| `0x570ca735` | `operator()` | slot 1 |
| `0xa8ee49fe` | `isModule(address)` → `modules[a]` | slot 3 |
| `0xfbfa77cf` | `vault()` | slot 0 |

Runtime storage is `slot0 = vault`, `slot1 = operator`, `slot2 = 32-byte gate value`, `slot3 = modules` allow-list. The runtime contains **zero `SSTORE`s** — all four slots are frozen at construction. That fact matters twice.

### The wire format

`execute(program)` runs a **validation loop** first (`0x16c → 0x312 → 0x4af`), then an **execution loop** (`0x176 → 0x182 → 0x1c8`). Both walk the same bytes:

```text
envelope := type(1) || len(2, little-endian)      ; 0x08 no-op, 0x31 batch
batch    := header || record*                     ; record region = len bytes
record   := subtag(1) || len(2)                   ; 0x12 skip, 0x2d call, 0xee no-op
            || payload(len)
```

Empty batch `[0x31,00,00]` is accepted; envelope/batch lengths are little-endian in both loops. Fuzzing the header confirms it empirically.

### The `0x2d` call record and its three modes

```text
0x2d.payload := mode(1) || target(20) || calldata(len-21)
```

| mode | operation | gate |
|---|---|---|
| 0 | `CALL` | `modules[target]` registered |
| 1 | `DELEGATECALL` | `modules[target]` registered |
| 2 | `CALL` | `target == vault(slot0)` **and** `slot2 == seal` |

Seal is recomputed on the fly at `0x579`:

```text
seal = keccak256( kernel_addr(20) || vault_addr(20) || chainid(32) ) XOR C
C    = 0x7b8c1e3a95d26f1042a967dca80bf1e771ab93c5dd2a06844f0c3162b16e9d57
```

The vault is not a registered module, so modes 0/1 cannot target it. Mode 2 can (its gate is literally "target == vault"), which makes it the intended drain — **if** `slot2 == seal` can be satisfied.

### The bug: little-endian validator vs big-endian executor

The validator's record loop uses the shared field reader `0x3f1`, which decodes the 2-byte length **little-endian**. The executor's record loop inlines its own decoder at `0x1e6–0x1ff` that computes `len = byte1<<8 | byte2` — **big-endian**.

A `0x12` skip record `12 00 01` therefore means:

- **256 bytes** to the validator (little-endian `0x0100`), and
- **1 byte** to the executor (big-endian `0x0001`).

The validator's `0x12` handler advances by `3 + len`, so with `len = 256` it skips the entire 259-byte batch and reports success **without inspecting a single inner record**. The executor's `0x12` handler advances by `3 + 1 = 4`, then keeps parsing. Anything after the first 4 bytes is invisible to the auditor but live to the executor.

### First attempt, and why it failed

The obvious exploit is one hidden mode-2 record calling `vault.settle`. Locally it works — but only after pre-seeding `slot2 = seal` in the mock. Against the live kernel it reverts because:

```text
0x194aac9c (slot2)         -> 0x0000…0000     # slot2 == 0, NOT the seal
0xa8ee49fe(vault)          -> 0x0000…0000     # vault is not a module
```

`slot2 == 0 != seal`, so mode 2's second gate fails. And with zero `SSTORE`s in the runtime, the kernel can never write `slot2` on its own. Dead end — unless something *else* can write the kernel's storage.

### DELEGATECALL to arm the gate

`TelemetryModule` has:

```solidity
bytes32 public lastRoute;   // slot 0
uint256 public samples;     // slot 1
uint256 public retained;    // slot 2
function rotate(uint256 next) external { retained = next; }   // SSTORE slot 2
```

Mode 1 (`DELEGATECALL`) is allowed to target telemetry because it *is* a registered module. Under DELEGATECALL, `rotate(next)`'s `SSTORE` to *its* slot 2 lands in the **kernel's** slot 2. So `rotate(seal)` sets `kernel.slot2 = seal` and arms the mode-2 gate — using only a whitelisted module and a value we compute ourselves.

### Sizing the differential

Two hidden records behind one `0x12` skip. Choose length bytes `00 01` for the skip. Writing `LE − BE = 255·(b2 − b1)`:

```text
batch body      = 0x12 00 01 || filler(1) || RecordA(60) || RecordB(195)  = 259 bytes
validator (LE):   0x12 len = 256  -> skips 3+256 = 259 = whole batch  (sees one benign skip)
executor  (BE):   0x12 len = 1    -> skips 3+1   = 4, then parses A (60) and B (195) -> 4+60+195 = 259
```

Record A's own length is emitted big-endian (`00 39 = 57` payload) and Record B's (`00 c0 = 192` payload), because the *executor* is the one reading them. Record B is padded to 195 bytes so the arithmetic closes; `settle` ignores the trailing calldata.

### Fire

`solve.py` reads the addresses, computes `ticket = vault.quote(player, balance)`, builds the program, dry-runs it with `eth_call`, then sends `execute(program)` from the player key:

```text
exploit tx 6133dd2d…d57ee2 status=1 gas=92824
isSolved=True
FLAG: {'flag': 'zdk{ENDIan_fIREw4l1_d3L3gA7e_DRaIN}'}
```

The mode-1 DELEGATECALL sets `slot2` from `0x0` to the seal; the mode-2 CALL then passes both gates, `settle` runs with `msg.sender == gateway`, sets `drainedBy = player`, and forwards the entire 100 ETH. Total cost ≈ 93k gas.

### Takeaway

**Parser differentials are TOCTOU on the byte level.** The vulnerability is a classic pattern: two "independent implementations" of one wire format that disagree on integer endianness for a single field. The audit only covered the validator's view; the executor's view was never checked against it. Three concrete lessons:

- Validate and execute must parse identically — share one decoder, or assert the two agree.
- Every privileged operation must re-check its own preconditions in the executor.
- A module that can write arbitrary storage under `DELEGATECALL` is equivalent to giving the caller write access to the kernel's entire state.

---

## Sanity Check — Cloudflare-injected hostname-keyed fragment

> *Flag:* `zdk{all the best, we hope you enjoy the ctf}`
>
> *Prompt:* "z0d1ak.org"

The whole challenge is the event's own marketing site. There is no download, no service, no dynamic endpoint. Every HTML response carries a server-side-injected marker that never renders but is plain in the page source:

```html
<style id="sanity-check-fragment">:root{--sanity-fragment:"26cPm361Zq4WTj89j2HhnestsgA"}</style>
```

### Step 1 — spot the odd element

`z0d1ak.org` is a Vite/React SPA. It serves the same `index.html` for essentially every path (client-side routing), so `robots.txt`, `sitemap.xml`, `/flag`, etc. return the SPA shell. The JS bundle is 195 KB of minified React (the "flag"/"hidden" hits inside it are React fiber internals, not the flag). OpenGraph image and favicon are clean.

The tell is in the raw HTML `<head>`. A path that returns a slightly different byte length — `curl -s https://z0d1ak.org/flag.txt | wc -c` gives 2170 vs 2465 for the SPA shell — makes it easy to spot the odd element. The `<style id="sanity-check-fragment">` line is injected by a Cloudflare Snippet/Worker in front of the origin (there is no such tag in the deployed React build), which is why it appears on *every* HTML response regardless of path.

### Step 2 — the fragment is host-keyed

The element id says `fragment` (singular), and the CSS custom property is `--sanity-fragment`. "Fragment" implies more than one. Probing shows the value is **constant across every path** on a host — but different **per hostname**:

```text
z0d1ak.org      -> 26cPm361Zq4WTj89j2HhnestsgA
www.z0d1ak.org  -> U9aCPzuwzja87fh1RiE83aGLBR7
```

Confirming these are the only two fragment-bearing hosts, three independent ways:

- **DNS brute** of SecLists' top-5000 subdomains via DNS-over-HTTPS — only `www` (and `geoint`, which serves no fragment) resolve.
- **Certificate transparency** (certspotter) — the only zone hosts are `z0d1ak.org`, `www`, `ctf`, `geoint`, `glasshouse.ctf`, `sekai-end-probe`; the CTF-infra hosts inject nothing.
- **Wildcard-cert / SNI probing** — a `*.z0d1ak.org` cert exists, so any hostname completes a TLS handshake. Forcing SNI with `curl --resolve` shows every non-configured host returns Cloudflare **error 1016 (530)**. Only apex and `www` answer with `200` + a fragment.

No path, query-string, header, cookie, or method changes the value. The axis is purely the hostname, and there are exactly two.

### Step 3 — recognise Base58 and assemble

Each fragment is 27 characters from the Base58 alphabet (no `0 O I l`, mixed case + digits). Decoding either fragment alone gives garbage; decoding the **concatenation** is the trick, because Base58 is a positional (big-number) encoding — the whole message is one number, split across two strings:

```python
ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58decode(s):
    n = 0
    for c in s:
        n = n * 58 + ALPHA.index(c)
    return n.to_bytes((n.bit_length() + 7) // 8, "big")

apex = "26cPm361Zq4WTj89j2HhnestsgA"
www  = "U9aCPzuwzja87fh1RiE83aGLBR7"
b58decode(apex + www)   # b'all the best, we hope you enjoy the ctf'
b58decode(www + apex)   # garbage  -> apex is the high-order half (comes first)
```

The decode is a complete, grammatical sentence. Because Base58 is positional, a clean decode of `apex ‖ www` means those two strings *are* the entire number: no third fragment to chase.

Flag:

```text
zdk{all the best, we hope you enjoy the ctf}
```

### Takeaway

**Nothing here is a single well-known path — it's a chain of small realisations.** The flag lives in an injected, non-rendered CSS variable (view-source only), the value is *host*-keyed rather than path-keyed (so you have to notice `www` differs from apex and confirm nothing else does), and the two pieces only mean anything when concatenated and read as one Base58 number. Miss any link and the "sanity check" quietly stays unsolved. The 199-point valuation and the 31-solve count both track that chain length exactly.

---

## Cross-cutting lessons from the z0d1akCTF 2026 Qualifiers Misc set

Four Miscellaneous challenges, four completely different runtime substrates, one repeated pattern — **read the substrate the system operates on, not the surface it presents**:

- **genie**: the surface is a locked game; the substrate is a writable RAM window that includes both the counter and its MAC. Atomically write all three words.
- **ihateDAA**: the surface is 92k identical-looking HTML pages; the substrate is the `<title>` element and a cyclic adjacency list. Discriminate by title, BFS with mark-on-enqueue.
- **Control Plane**: the surface is a validator that approves the program; the substrate is a second byte-length decoder inside the executor that reads endianness the other way. Emit a program the two decoders disagree on.
- **Sanity Check**: the surface is a React SPA; the substrate is a Cloudflare-injected `<style>` tag whose CSS custom property is keyed on hostname. Fetch every host, concatenate, Base58-decode.

Portable techniques the set repeats:

- **Read the "documentation" as attack surface.** genie's `PORT.md` names the cheat port; Control Plane's prompt names "independent implementations" of the wire format; Sanity Check's marker element is literally named `sanity-check-fragment`. When a challenge names its indirection, treat that as a directive.
- **When the check operates on the same medium as the state, both are attacker-writable.** genie's MAC lives in RAM with the counter; Control Plane's `slot2` gate is writable via a whitelisted module under `DELEGATECALL`. If the check-value and the checked-value share a mutation channel, the check is decoration.
- **Match your detector to the substrate.** ihateDAA's `<h1>` contains the word "flag" on every interior page and matches 100 % of nodes; the `<title>` distinguishes cleanly. Any time a naive substring detector reports "everything is interesting," look one layer up in the parse tree for the real discriminator.
- **Two decoders is two attack surfaces.** Whenever a spec is implemented "independently" twice — validator and executor, client and server, ORM and SQL — the differential is a bug class, not an edge case. Assert the two agree, or share one decoder.
- **View-source is a substrate probe.** Sanity Check's flag never renders. Any challenge whose surface is a rendered page begs the question: what does the raw byte stream say that the browser hides? A `curl | grep -oE '<[^>]+id="[^"]+"'` pass catches injected markers a screenshot never will.
- **Parallelism is a substrate concern.** ihateDAA's 15-minute crawl works because 32 threads share a keep-alive pool and mark visited on enqueue. Any large-graph traversal that ignores those two details is throughput-bound on TLS handshakes rather than search progress.
- **Frame-atomic writes beat frame-by-frame patches.** genie's replay applies all writes for a frame *before* that frame runs, which is what lets the three-word MAC tuple satisfy the validator. Any replay/deterministic-execution challenge whose docs describe frame ordering is describing an atomicity primitive.

## Reproduce it yourself

Each challenge ships a standalone solver in the [z0d1akCTF 2026 Qualifiers repository](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers) under `Misc/<challenge>/`:

- [`Misc/genie/`](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers/tree/master/Misc/genie) — end-to-end remote exploit (`solve.py`), offline echo brute force (`verify_echo.py`), full ROM + `PORT.md` handout, address-map notes, captured live-session transcript.
- [`Misc/ihate-daa/`](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers/tree/master/Misc/ihate-daa) — threaded BFS solver (`solve.py`), offline analyser (`analyze.py`), local mock service (`mock_instance.py`), captured 92k-node adjacency dump (`artifacts/graph.json.gz`), annotated shortest path, crawl log.
- [`Misc/control-plane/`](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers/tree/master/Misc/control-plane) — end-to-end solver (`solve.py`), program builder with commented wire format (`build_program.py`), full kernel disassembly, byte-annotated 262-byte exploit program, captured session output.
- [`Misc/sanity-check/`](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers/tree/master/Misc/sanity-check) — dual-host solver (`solve.py`), enumeration notes covering DNS-over-HTTPS SecLists brute + certificate-transparency + SNI probing, captured fragments and Base58 assembly.

All Python solvers use only the standard library except Control Plane, which needs `web3<7` for the EVM call.

Browse the full [CTF writeups](/ctf-writeups/) archive for more Misc and cross-domain walkthroughs, or read the companion [UIUCTF 2026 Miscellaneous writeup](/ctf-writeups/uiuctf-2026-misc-writeup/) covering three jail-escape challenges from the same season for a very different flavour of the same substrate-first reading discipline.

---

*This writeup is part of the CyberSecurity Elite [z0d1akCTF 2026 Qualifiers](/series/z0d1akctf-2026-qualifiers/) series. Handouts, per-challenge READMEs, and dependency-conscious solvers for all four Miscellaneous challenges are published at [github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers).*
