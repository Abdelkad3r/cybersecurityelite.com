---
title: "z0d1akCTF 2026 Qualifiers Binary Exploitation Writeup: All 9 Pwn Challenges Solved"
slug: "z0d1akctf-2026-qualifiers-pwn-writeup"
description: "Complete z0d1akCTF 2026 Qualifiers Binary Exploitation writeup covering all nine pwn challenges. Salvage Protocol — declared-length vs actual-length desync smuggles two frames into vaultd whose auth-write-before-clearance-check turns a failed privileged read into a working ordinary read of vault-slash-flag. rapture — heap manifest redundancy snapshot copies the 32-byte entry including the heap pointer so freeing either alias leaves the other as a readable and writable dangling entry that leaks the safe-linking key, poisons tcache, and drops a libc ROP chain above the canary. House XIII — signed cursor validated only on its wrapped 16-bit effective offset lets a negative offset read the object header, a Star to Orbital conversion leaves a stale table alias, and a 64-query binary search recovers the session secret so a forged callback can invoke the internal sendfile with House marker 13. Dead Reckoning — AArch64 big-endian static PIE where the eight-byte repair validates the destination after clearing the pointer's top byte but stores through the original tagged pointer under top-byte-ignore, then rt_sigreturn SROP + mprotect + shellcode reads the flag from slash proc slash 1 slash environ. Phantom Phase — custom register VM whose validator treats memory immediates as unsigned 12-bit but LOADQ and STOREQ sign-extend them, letting 0xe00 execute as minus-0x200 to reach the hidden pointer that controls guest memory base, then re-encode the callback and repair the integrity seal for a seccomp-approved openat ROP. paperweight — Poppler's SplashOutputDev tilingPatternFill wraps a 32-bit horizontal extent from 0x100000004 to 4 while tilingBitmapSrc keeps copying the full row, delivering a controlled heap overflow to a Folio object; forged vtable plus setcontext ROP reads flag dot txt. Expert Witness — Mixture-of-Experts model uploader where the Python auditor identifies tensors by full name and the native worker identifies them by salted 32-bit hash, so 8-byte tensor names that hash-collide with expert weights bind the native worker to a scratch row containing an encoded copy of the runtime flag. Pelagic Palimpsest — supply-chain pwn where audited memory-safe Python source ships through a Nuitka plugin that injects a hidden _fastmemo ELF into a memfd; the native backend's low-byte length check plus canary-guarded overflow gives arbitrary read, a forged PyTypeObject with tp_dealloc equals setcontext runs system cat flag before the seccomp lockdown method fires. Undertow — checkpoint service where 128 diagnostic sessions produce 128 GF-of-2 equations in the 128-bit UNDERTOW_SEAL secret, Gaussian elimination recovers the seal, inspect decodes PIE and scratch pointers, commit plus allocator churn moves a live checkpoint into the snapshot-overwrite alias, and the forged encoded stack and IP plus recomputed hash restore a two-stage ROP that leaks libc and reads the flag with openat2."
date: 2026-08-30T21:00:00Z
lastmod: 2026-08-30T21:00:00Z
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
  - "binary exploitation"
  - "pwn"
  - "parser differential"
  - "protocol desync"
  - "heap exploitation"
  - "tcache safe-linking"
  - "use after free"
  - "aarch64 top byte ignore"
  - "signed vs unsigned validator"
  - "integer wrap"
  - "poppler splash tiling pattern"
  - "custom vm exploit"
  - "seccomp bypass"
  - "srop signal frame"
  - "ml model parser differential"
  - "moe hash collision"
  - "supply chain pwn"
  - "nuitka plugin injection"
  - "memfd elf loading"
  - "pytypeobject forgery"
  - "setcontext rop"
  - "checkpoint quarantine alias"
  - "gaussian elimination gf2"
  - "openat2 flag read"
  - "salvage protocol"
  - "rapture pwn"
  - "house xiii pwn"
  - "dead reckoning pwn"
  - "phantom phase pwn"
  - "paperweight pwn"
  - "expert witness pwn"
  - "pelagic palimpsest pwn"
  - "undertow pwn"
  - "ctf 2026"
keywords:
  - "z0d1akctf 2026 qualifiers pwn writeup"
  - "z0d1akctf 2026 binary exploitation writeup"
  - "z0d1akctf salvage protocol writeup"
  - "z0d1akctf rapture writeup"
  - "z0d1akctf house xiii writeup"
  - "z0d1akctf dead reckoning writeup"
  - "z0d1akctf phantom phase writeup"
  - "z0d1akctf paperweight writeup"
  - "z0d1akctf expert witness writeup"
  - "z0d1akctf pelagic palimpsest writeup"
  - "z0d1akctf undertow writeup"
  - "aarch64 top byte ignore validator vs store ctf"
  - "vm validator unsigned executor sign extended ctf"
  - "tcache safe-linking bypass ubuntu glibc 2.35 ctf"
  - "poppler tilingpatternfill 32-bit wrap heap overflow ctf"
  - "moepack salted hash collision native worker python auditor ctf"
  - "nuitka plugin memfd elf supply chain pwn"
  - "checkpoint pointer aliasing gaussian elimination gf2 seal recovery"
  - "z0d1akctf 2026 solutions"
  - "ctf pwn step by step 2026"
toc: true
cover:
  image: "/images/articles/z0d1akctf-2026-qualifiers-pwn-writeup.png"
  alt: "z0d1akCTF 2026 Qualifiers Binary Exploitation writeup cover — all nine pwn challenges solved. Salvage Protocol desyncs a declared payload length against the actual bytes to smuggle privileged frames into vaultd whose auth-write-before-check turns a failed clearance into a working read of the flag record. rapture snapshots a heap manifest entry with the same pointer so freeing either alias leaves a dangling readable and writable slot, defeats tcache safe-linking, and drops a libc ROP chain. House XIII wraps a signed 16-bit cursor to read a Star object header, converts Star to Orbital to leave a stale table alias, binary-searches a 64-bit session secret, and forges a callback to invoke the internal sendfile with House marker 13. Dead Reckoning is an AArch64 big-endian static PIE where the top-byte-ignore validator differs from the raw store, letting a tagged pointer write into a protected control block; SROP plus mprotect plus shellcode reads the flag from proc-1-environ. Phantom Phase exploits a VM where the validator treats memory immediates as unsigned 12-bit but LOADQ and STOREQ sign-extend, so 0xe00 executes as minus-0x200 and reaches the hidden pointer controlling guest memory. paperweight exploits a Poppler tilingPatternFill 32-bit horizontal-extent wrap that allocates a tiny line buffer while copying the full row, overflowing a Folio object and forging a vtable to setcontext. Expert Witness exploits a Mixture-of-Experts parser differential where the Python auditor identifies tensors by full name and the native worker by salted 32-bit hash, so 8-byte hash-collision names bind the native worker to a scratch row containing the runtime flag. Pelagic Palimpsest exploits a supply-chain compromise where audited Python source ships through a Nuitka plugin that injects a hidden fastmemo ELF into a memfd whose native backend has a low-byte length check and a canary-guarded overflow that supports arbitrary read plus a forged PyTypeObject that hijacks tp_dealloc to setcontext to system cat flag before the seccomp lockdown fires. Undertow recovers a 128-bit UNDERTOW_SEAL by Gaussian elimination over 128 GF-of-2 diagnostic sessions, decodes PIE and scratch pointers, aliases a live checkpoint through commit-plus-snapshot list churn, and forges an encoded stack and IP for a two-stage ROP that leaks libc and reads the flag with openat2"
---

**z0d1akCTF 2026 Qualifiers**'s Binary Exploitation track is a nine-challenge lesson in one discipline: **every exploit is a parser differential.** In every one of these challenges the intended solve exploits two components of the same system reading the same bytes differently — a validator that says one thing while an executor does another, an audited source that disagrees with the shipped binary, a Python auditor that identifies tensors by name while the native worker identifies them by hash, an AArch64 pointer validated after its top byte is cleared but stored through the original tagged word. The disagreement is always exactly one bit, one byte, one endian convention, or one abstraction level away from the check that was supposed to be sufficient. Recognising the differential is the entire challenge; turning it into arbitrary read/write/execute is engineering.

The track's oceanic theme runs through every flag as a reminder of exactly this — the checkpoint that *sank* below the pointer guard (Undertow), the scanline that *sank* below 32 bits (paperweight), the compiler current that runs *deeper* than the reviewed source (Pelagic Palimpsest), the top byte that *charted a route below the surface* (Dead Reckoning), the seam that Salvage was *smuggled through*, the stale audit record that *rewrites the route* (House XIII). Every one describes the same thing: an unexpected representation of the same state that the primary check never looked at.

Handouts, per-challenge READMEs, and dependency-conscious solvers live at [Abdelkad3r/z0d1akCTF-2026-Qualifiers](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers). This **CyberSecurity Elite** z0d1akCTF 2026 Qualifiers Binary Exploitation writeup covers all nine challenges end to end. Read alongside the paired [z0d1akCTF 2026 Qualifiers Miscellaneous writeup](/ctf-writeups/z0d1akctf-2026-qualifiers-misc-writeup/), the [z0d1akCTF 2026 Qualifiers Forensics writeup](/ctf-writeups/z0d1akctf-2026-qualifiers-forensics-writeup/), and the [z0d1akCTF 2026 Qualifiers Cryptography writeup](/ctf-writeups/z0d1akctf-2026-qualifiers-crypto-writeup/) for eighteen more challenges from the same event.

## All nine Binary Exploitation challenges at a glance

| Challenge | Points | Sub-genre | The parser differential | Flag |
|---|---:|---|---|---|
| [Salvage Protocol](#salvage-protocol--declared-length-vs-actual-length-desync-into-vaultd) | 136 | Two-daemon protocol | `reclaimd` allocates using actual length but declares zero → smuggled frames into `vaultd` | `zdk{5a1VAGEd_thR0UgH_7He_sEAM}` |
| [rapture](#rapture--heap-manifest-snapshot-into-tcache-safelinking-bypass) | 144 | Heap UAF | Manifest snapshot copies pointer → aliased chunk → tcache safe-linking bypass | `zdk{FreeD_ln_tHE_DeeP_But_N3v3R_FORg0t7en}` |
| [House XIII](#house-xiii--signed-cursor-wrap-plus-stale-table-alias) | 143 | Custom VM + heap | Signed cursor validated on wrapped 16-bit offset; Star→Orbital leaves stale table entry | `zdk{HouSe_xLLl_0penS_wHeN_thE_st413_Aud1t_rECOrD_reWrL7e5_7h3_r0uTe}` |
| [Dead Reckoning](#dead-reckoning--aarch64-top-byte-ignore-validator-vs-raw-store) | 251 | AArch64 SROP | AArch64 TBI: validator clears top byte, store uses raw pointer | `zdk{ThE_70P_8YTe_CHARtEd_A_RoU7e_B31OW_th3_suRFACe}` |
| [Phantom Phase](#phantom-phase--vm-validator-unsigned-vs-executor-signextended) | 334 | Custom register VM | Validator: unsigned 12-bit. Executor: sign-extended. `0xe00` = `-0x200` | `zdk{DEAD_rEckon1N6_sl6N3d_the_wr0n6_CoURs3}` |
| [paperweight](#paperweight--poppler-splash-tiling-pattern-32bit-wrap-into-folio-overflow) | 202 | Bundled-library integer wrap | Poppler `tilingPatternFill`: 32-bit horizontal extent wraps `0x100000004 → 4` | `zdk{ThE_Sc4nlIN3_5AnK_8ELOw_32_bI75}` |
| [Expert Witness](#expert-witness--moepack-python-auditor-vs-native-worker-hash-collision) | 347 | ML supply-chain parser differential | Python auditor: full name. Native worker: salted 32-bit hash. Craft collisions | `zdk{the_ExP3Rt_wi7neSS_T3StIFi35_FR0m_b3NEatH_ThE_modeL_R3gIstRY}` |
| [Pelagic Palimpsest](#pelagic-palimpsest--nuitka-plugin-supply-chain-into-hidden-native-backend) | 347 | Supply-chain pwn | Audited Python source vs shipped Nuitka plugin injecting hidden `_fastmemo` ELF | `zdk{ThE_deeP3sT_cUrRENt_WaS_7HE_C0MpILeR_cuRRENt}` |
| [Undertow](#undertow--gaussian-elimination-on-a-128bit-seal-plus-checkpoint-list-aliasing) | 321 | Checkpoint service | GF(2) linear-equation leak recovers 128-bit `UNDERTOW_SEAL`; commit-vs-snapshot list alias | `zdk{4_ST4L3_CheckP0INt_s4nK_BeLOW_The_pOInTER_gUarD}` |

Nine challenges, nine primitives (protocol desync / heap UAF / stale table / TBI / VM sign-extension / bundled-library wrap / ML parser / supply-chain / checkpoint quarantine), one repeated pattern.

---

## Salvage Protocol — declared-length vs actual-length desync into vaultd

> *Flag:* `zdk{5a1VAGEd_thR0UgH_7He_sEAM}`
>
> *Prompt:* "something something protocol"

Two stripped, statically linked x86-64 daemons: public `reclaimd` proxies bytecode requests to private `vaultd`, which stores five public salvage records and a protected `vault/flag`. Both are non-PIE, NX, no canary, static.

The exploit composes two logic flaws:

**1. Length desync between actual and declared payload.** `reclaimd` tracks the actual payload length used for `send()` alongside an attacker-controlled declared length written into the outbound protocol header. By declaring `0` and packing extra bytes in the actual payload, the "extra" bytes are left in the wire buffer for `vaultd` to parse as *additional frames*.

**2. Auth-write-before-check in vaultd.** `vaultd` processes up to 64 frames under one request-wide authorisation state. Its privileged mode resolves the requested record and **writes that record's ID into the authorisation slot before checking the clearance token**. A deliberately failed privileged read therefore *primes* authorisation for a later ordinary read of the same record.

### Chain

Wrap two smuggled frames inside a zero-length list request:

1. First injected frame → intentionally fails clearance but writes `vault/flag` ID into auth slot.
2. Second injected frame → ordinary read of `vault/flag` with the stale authorisation.

`reclaimd` sees a valid outer list with declared length 0. `vaultd` sees the injected frames and returns the flag. Both daemons are structurally correct in isolation; the exploit lives in the seam between them.

**Takeaway:** any protocol where a proxy allocates on one length field but forwards another is a parser-differential smuggling primitive. Any auth mechanism that writes before it checks is a TOCTOU on its own state.

---

## rapture — heap manifest snapshot into tcache safe-linking bypass

> *Flag:* `zdk{FreeD_ln_tHE_DeeP_But_N3v3R_FORg0t7en}`
>
> *Prompt:* "Rapture Deep Station is holding at 2000 fathoms."

A menu-driven heap challenge against Ubuntu glibc 2.35. Up to 64 heap allocations in a global manifest, one read ticket + one write ticket per entry. Full RELRO, canary, NX, PIE — every modern mitigation.

The bug is the **"redundancy snapshot"** operation: it copies all 32 bytes of a manifest entry into another slot, *including its heap pointer, size, occupancy flag, and both tickets*. The allocation itself is not duplicated. Freeing either entry leaves the other as a **readable and writable dangling alias**.

### Three primitives from one alias

**1. ASLR defeat.** Fill the largest tcache bin and place two separated chunks in the unsorted bin. Reading the second chunk leaks a full heap pointer and a `main_arena` pointer — heap base and libc base.

**2. Arbitrary allocation via safe-linking.** For any fresh tcache size class, free an aliased seed into an empty bin and read its encoded `next` value. Because the real next pointer is null, this value equals `seed_address >> 12` — the exact glibc safe-linking key. Rebuild a two-entry bin, overwrite the seed's encoded next pointer, and obtain an allocation at any 16-byte-aligned address.

**3. Stack pivot without touching the canary.** Allocate first at libc's `environ` to leak the stack; allocate across a stack window to locate the saved return address dynamically; poison a small tcache bin directly to `saved_return − 8` and write a libc ROP chain **above** the canary. Never modify the canary; never leak the PIE base.

### Chain

```text
snapshot → free alias → tcache safe-linking key = addr >> 12
                     → arbitrary alloc → environ leak → stack window
                     → tcache poison to saved_return − 8
                     → ROP chain above canary
```

**Takeaway:** modern glibc safe-linking assumes attackers cannot read the encoded `next` of a freshly freed chunk. Any UAF that grants a single read of a fresh tcache head hands over the key for that address class. Any manifest that copies a pointer without incrementing a refcount is an alias in disguise.

---

## House XIII — signed cursor wrap plus stale table alias

> *Flag:* `zdk{HouSe_xLLl_0penS_wHeN_thE_st413_Aud1t_rECOrD_reWrL7e5_7h3_r0uTe}`
>
> *Prompt:* "House XIII is back online. Complete your assignment and return with its authorization material."

Menu-driven service `transit` with two object types (`STARGMTR` = Star, `ORBITAL`), a small bytecode VM, and an authenticated callback mechanism. Full RELRO + canary + NX + PIE + stripped.

Three weaknesses compose:

**1. Signed cursor wrap in the VM.** The VM accepts signed cursor changes but validates only a **wrapped 16-bit** effective offset. Moving the cursor to `-0x50` turns a nominal Star data read into an object-header read. Printing 16 bytes leaks the Star's self pointer and a code pointer → heap base + PIE base.

**2. Stale table alias.** Converting a Star to an Orbital frees the Star and allocates the same `0x180`-byte size, but does not clear the original Star-table entry. The new Orbital inherits a stale Star alias. Control 2 trusts table membership without re-checking the Star magic, providing a controlled write over the Orbital's callback metadata.

**3. Binary-search the 64-bit session secret.** Control 6 compares an attacker-supplied integer with the random 64-bit session secret and returns one of two statuses. 64 queries recover the exact secret — after which the callback credential can be *recomputed* rather than bypassed.

### Chain

Forge callback → point at read-only slot containing internal `sendfile` routine → set source descriptor + House marker to `13` → routine copies pre-opened flag file to stdout.

**Takeaway:** any 16-bit offset validator on a 32-bit or 64-bit displacement is a wraparound waiting to happen. A comparison oracle over a random 64-bit secret is 64 queries of information — a binary search recovers it deterministically. Trust decisions that key on "is this entry in the table?" without re-checking the entry's magic will happily accept a stale alias.

---

## Dead Reckoning — AArch64 top-byte-ignore validator vs raw store

> *Flag:* `zdk{ThE_70P_8YTe_CHARtEd_A_RoU7e_B31OW_th3_suRFACe}`
>
> *Prompt:* "Bring the recovery beacon home."

A stripped **AArch64 big-endian** static PIE served through a TLS wrapper, running under `qemu-aarch64_be-static`. A repair console operates on a freshly mapped `0x2000`-byte "salvage arena" containing a protected control block with a custom stack cookie, a PIE code pointer, and a survey-length field.

Two primitives:

**1. AArch64 top-byte-ignore mismatch.** The eight-byte repair command validates the destination pointer *after clearing the top byte*, but performs the final store through the **original tagged pointer**. Under AArch64 top-byte-ignore (TBI), a tagged pointer therefore writes into the protected control block. Overwriting the survey-length field leaks the custom cookie + PIE base.

**2. Route importer stack overflow with SROP.** The route importer reads up to `0x600` bytes into a `0x100`-byte stack frame. Preserving the leaked cookie gives control of saved `x30`. Returning to the embedded `rt_sigreturn` gadget restores a crafted AArch64 signal frame, calls `mprotect` on the arena, and returns into open/read/write shellcode.

Flag isn't at `/flag` — it's in `/proc/1/environ` (the platform wrapper's `FLAG=` env var, discovered via a `getdents` shellcode-driven directory listing).

**Takeaway:** any AArch64 pointer validator that normalises via `AND` with `0x00FF_FFFF_FFFF_FFFF` but does not *store back* the normalised value creates a TBI differential. SROP (`rt_sigreturn`) is the shortest path from stack control to `mprotect`+shellcode on any static PIE, because no libc gadget hunting is needed — one indirect return through the vsyscall sigreturn stub restores every register from an attacker-controlled sigcontext.

---

## Phantom Phase — VM validator unsigned vs executor sign-extended

> *Flag:* `zdk{DEAD_rEckon1N6_sl6N3d_the_wr0n6_CoURs3}`
>
> *Prompt:* "tuff pwn? dont slop this."

A stripped x86-64 PIE containing a custom register VM. Executes framed `DRV1` programs with eight 64-bit registers and a 4 KiB guest address space; a randomised callback table controls each execution phase; an integrity seal is meant to prevent guests from retargeting callbacks.

The bug is a direct disagreement between the instruction validator and the executor:

- Validator: memory immediates treated as **unsigned 12-bit** offsets.
- Executor: `LOADQ` and `STOREQ` **sign-extend** those same 12 bits.

An immediate such as `0xe00` passes validation as `3584` but executes as `-0x200`. That reaches a hidden pointer controlling the base of guest memory.

### Chain

Read that hidden pointer → recover allocation base → **change** the pointer so the protected callback table becomes addressable → decode the phase-0 callback → derive PIE address of an embedded stack-pivot gadget → re-encode + repair the callback integrity seal → pivot lands on a ROP chain assembled by the VM in the heap → seccomp-approved `openat`/`read`/`write` returns `/run/flag.txt`.

No leaked address in the client, no libc offset, no brute force — every randomised address is derived inside the VM.

**Takeaway:** the same lesson as UIUCTF's Control Plane — when a spec is implemented "independently" twice (validator + executor), the differential is a bug class, not an edge case. Sign-vs-unsigned interpretation of the same immediate field is the single most common instance. Assert the two agree, or share one decoder.

---

## paperweight — Poppler Splash tiling-pattern 32-bit wrap into Folio overflow

> *Flag:* `zdk{ThE_Sc4nlIN3_5AnK_8ELOw_32_bI75}`
>
> *Prompt:* "Every record sent to the Pelagic Archive sinks into cold storage. Its new chart plotter is rated for any pressure."

A stripped x86-64 C++ PIE that renders attacker-supplied PDFs through the bundled Poppler library. The service **forks five workers from one parent** — same PIE, libc, inherited heap addresses across workers, while crash-prone mutations remain private via copy-on-write. That is what makes a leak from one dive usable in the next.

The vulnerable path is Poppler's `SplashOutputDev::tilingPatternFill`. A crafted tiling pattern with `XStep = 82` causes a 32-bit horizontal-extent calculation to wrap from `0x100000004` to `4`. Poppler allocates a line buffer using the wrapped value, while `tilingBitmapSrc` keeps copying the full repeated image row. **Controlled heap overflow.**

### Chain

1. Allocate and free 32 chunks of size `0x1000` around a `Folio` object.
2. Render a one-row, `0x2901`-pixel image through the malicious tiling pattern.
3. Overwrite the `Folio` offset + length fields to read a nearby `DiveAnchor`.
4. Recover PIE + heap address + stable cache buffer address.
5. Next forked worker: read `write@GOT` → libc base.
6. Cache pointer to `setcontext`; overwrite `Folio` vtable; place forged context + ROP in overflowed heap region.
7. Seccomp-approved `openat`/`read`/`write` returns `flag.txt`.

**Takeaway:** integer wraps inside bundled libraries are exploitable exactly the same way as first-party bugs — you don't need to disclose the CVE, you need to find the *fork boundary* that lets a leak survive from one dive to the next. Any service that pre-forks workers from a parent leaks its randomised addresses across those workers unless it re-randomises the ASLR base per fork (which almost nothing does).

---

## Expert Witness — MoEPACK Python auditor vs native worker hash collision

> *Flag:* `zdk{the_ExP3Rt_wi7neSS_T3StIFi35_FR0m_b3NEatH_ThE_modeL_R3gIstRY}`
>
> *Prompt:* "Far below the surface, Pelagos Station trusts a Python auditor to approve new Mixture-of-Experts checkpoints for its native fault classification."

An ML-flavoured supply-chain challenge. Submit a custom Mixture-of-Experts model as a `.moepack` file. A **Python auditor** parses it, checks clean accuracy, environment fairness, routing balance, a session-specific target margin, and distance from the reference model. An accepted model is then loaded by a stripped **native x86-64 worker** that serves inference requests.

The exploit crosses the trust boundary between the two parsers:

**1. Legitimate patch to satisfy the auditor.** Apply a small model patch in the trigger's low-variance latent direction to raise the target-class margin while keeping L2 distance at `2.5` (under the `3.5` limit).

**2. Append unbound extension tensors.** The Python parser sees their distinct names and ignores them during graph resolution and policy evaluation.

**3. Craft hash collisions.** The native worker identifies tensors by a **salted 32-bit name hash** — it never compares the full name. Generate 8-byte names whose hashes collide with the two selected expert weights (session-specific salt, so a per-session collision search).

**4. Rebind at author slot 12.** Mark both colliding records as scratch-backed extensions at author slot 12. The native parser resolves both active expert weights to a scratch row that contains an *encoded copy of the runtime flag*.

**5. Query 48 inputs.** Central differences over 48 carefully chosen inputs recover every entry of the resulting 4×24 native weight matrix. First five floats: 8-byte key + flag length. Remaining floats: decode directly to the flag.

**Takeaway:** any signature scheme that identifies records by a 32-bit hash is a birthday-attack away from collision, and any *parser* that uses a shorter identifier than the *approver* is a bind-different-value primitive on the same admitted bytes. The Python auditor and native worker each behave consistently in isolation; the vulnerability is that they assign different meanings to the same admitted file.

---

## Pelagic Palimpsest — Nuitka plugin supply-chain into hidden native backend

> *Flag:* `zdk{ThE_deeP3sT_cUrRENt_WaS_7HE_C0MpILeR_cuRRENt}`
>
> *Prompt:* "At the surface, every source is clear. In the hadal dark, the current remembers."

A supply-chain pwn disguised as a clean Python memo service. The handout ships audited source for `reviewd.py` + `fastmemo_clean.py`, a compiler capsule, a clean stage-2 compiler image, a divergence root, and a matching libc. **The source is memory safe. The compiler is not honest.**

The suspect Nuitka plugin recognises the exact service AST and replaces:

```python
import fastmemo_clean as _backend
```

with:

```python
_backend = __import__("_fastmemo")
```

It also injects a compressed, XOR-encrypted ELF extension. A constructor loads that ELF from an anonymous `memfd`, so the deployed process runs a hidden native `_fastmemo` backend while preserving the reviewed Python source.

The native backend has two interacting bugs:

- `new()` compares only the **low byte** of `logical_len` against `0xd0`, so `0x1d0` is accepted.
- `write()` allows an overflow when a canary-derived 12-bit expression is at most `0xd0`. A long `show()` leaks the next object's canary, making the condition deterministic.

### Chain

Three adjacent native Python objects:

1. First → leaks second object's address, type, canary.
2. Second → overflows into the third.
3. Third → forge display pointer + length; `show()` becomes arbitrary read; leak implant base + resolved `memcpy` pointer.

Forge a minimal `PyTypeObject` + `ucontext_t` inside the native arena. Victim's `tp_dealloc` = libc `setcontext`, which restores registers from the victim and enters `system("cat /flag")`. Dropping the corresponding Python list entry triggers the forged destructor **before the service ever calls its seccomp-enabling `lockdown()` method**.

**Takeaway:** reviewing source is not reviewing the binary. Any build pipeline that lets a plugin rewrite imports and inject ELFs into memfd is a supply-chain vulnerability regardless of how thorough the source audit was. The flag says it directly: "the deepest current was the compiler current." When a service ships `-clean` and `-shipped` variants of the same module, the shipped variant is the trust boundary.

---

## Undertow — Gaussian elimination on a 128-bit seal plus checkpoint list aliasing

> *Flag:* `zdk{4_ST4L3_CheckP0INt_s4nK_BeLOW_The_pOInTER_gUarD}`
>
> *Prompt:* "i dont even know anymore but checkpointing is hard"

A stripped x86-64 checkpoint service against Ubuntu glibc 2.39. Own pointer encoding, own context save/restore, own integrity hash, own three-list record allocator, own two-entry quarantine, plus a tight seccomp filter before normal commands.

Four separate weaknesses:

**1. GF(2) seal recovery.** A diagnostic command exposes one linear equation in a fixed, secret 128-bit `UNDERTOW_SEAL`. Each process has a random session token, so **opening enough connections produces 128 independent equations**. Gaussian elimination over GF(2) recovers the complete seal.

**2. Pointer decode.** The inspect command discloses encoded pointers to the checkpoint-save routine and a controlled scratch mapping. The recovered seal derives the context codec → decode both pointers → PIE base + scratch base.

**3. Checkpoint-list alias.** Committing a checkpoint leaves the global current-checkpoint pointer intact while placing the same record in a delayed quarantine. Carefully chosen allocator churn moves that record into the list used by the snapshot command. Snapshot then clears and overwrites the record through a second alias — turning the original pointer into an attacker-controlled stale checkpoint.

**4. Forge encoded stack + IP.** With the seal known, encode a forged stack pointer + instruction pointer and recompute the checkpoint hash. Restoring that record starts a ROP chain in the scratch mapping. Stage one leaks the GOT (recovers libc) + receives stage two. Stage two uses `setcontext+0x20` + libc syscall wrapper → `getdents`/`openat2`/read/write with seccomp-approved arguments to list the pre-opened flag directory, open its randomised filename, and send the flag.

**Takeaway:** a 128-bit secret leaked one linear GF(2) equation at a time across 128 sessions is not "hard to recover" — it is Gaussian elimination on a 128×128 matrix, seconds. Any commit-then-quarantine pattern that leaves a live global pointer to the quarantined record is an alias primitive. A checkpoint/restore mechanism that authenticates the record but not the *decoded* pointer offsets is bypassable once the encoding key is known.

---

## Cross-cutting lessons from the z0d1akCTF 2026 Qualifiers Binary Exploitation set

Nine challenges, nine different primitives, one repeated pattern — **every exploit is a parser differential**:

- **Length-declared vs length-actual** (Salvage Protocol): any proxy that allocates on one length and forwards another is a smuggling primitive.
- **Signed vs unsigned validator** (House XIII, Phantom Phase): a 16-bit or 12-bit unsigned validator on a wider signed executor lets carefully chosen values pass one check and become negative on another.
- **Tagged vs raw pointer** (Dead Reckoning): AArch64 TBI validators that normalise the address without storing the normalised value differ from the raw store.
- **32-bit vs 64-bit arithmetic** (paperweight): a 32-bit horizontal-extent wrap allocates too little while the copy uses full width.
- **Name vs hash** (Expert Witness): a Python parser that compares full names cannot tell that a hidden extension tensor collides with an expert weight under a 32-bit salted hash.
- **Source vs shipped binary** (Pelagic Palimpsest): a compiler plugin that rewrites imports and injects a memfd-loaded ELF completely subverts source-level review.
- **Manifest entry vs actual chunk** (rapture): a "snapshot" that copies a pointer without a refcount is an alias.
- **Table membership vs magic check** (House XIII): trusting the presence of an entry without re-checking its magic accepts stale aliases.
- **Commit list vs snapshot list** (Undertow): a quarantine that leaves a global live pointer to the quarantined record aliases the record across lists.
- **Audited plaintext vs encoded pointer** (Undertow): once the encoding key is known, an integrity-hashed record is only integrity-hashed, not authentication-hashed.

Portable techniques from the set:

- **Recognise the validator/executor pattern.** Every time a system parses the same bytes twice — once for admission, once for use — the two parses are a bug class, not an edge case. Assert they agree, or share one decoder.
- **Auth-write-before-check is a state machine bug, not a check bug.** Salvage Protocol's `vaultd` writes the record ID into the auth slot before checking clearance. Any state machine that mutates authorisation state before verifying is exploitable by a deliberately-failed attempt.
- **Safe-linking is 12 bits away from broken.** rapture reads the encoded `next` of a fresh tcache head; the encoded value equals `addr >> 12` on an empty bin. Any single read of a freshly freed tcache chunk's first quadword hands over the key for that address class.
- **SROP is the shortest static-PIE exploit.** `rt_sigreturn` (Linux) or `sigreturn` (BSD) restores every register from an attacker-controlled sigcontext in one gadget. On any binary that includes the sigreturn stub — which every static PIE does — you get `mprotect+shellcode` without any ROP-chain hunting.
- **Fork boundaries preserve leaks.** paperweight's five-worker fork model turns a per-dive leak into a cross-dive primitive. Any pre-forked service without per-worker ASLR re-randomisation leaks addresses across workers.
- **32-bit hashes are birthday-attack territory in seconds.** Expert Witness's salted 32-bit name hash requires ~2¹⁶ collision attempts per pair on average — a few seconds with a small C++ program. Any signature scheme with a 32-bit tag on user-controlled names is bind-different-value with high probability.
- **A compiler plugin is a supply-chain root.** Pelagic Palimpsest shows the entire class: any tool between "audited source" and "shipped binary" that can rewrite imports, inject ELFs, or link native extensions can subvert every source-level guarantee. Reviewing source alone is *insufficient* — the reviewed artifact must be the shipped artifact.
- **Read the flag out-of-band when `/flag` isn't there.** Dead Reckoning's `/proc/1/environ`, Phantom Phase's `/run/flag.txt`, paperweight's `flag.txt`, Pelagic Palimpsest's `system("cat /flag")` — the flag path varies, but every service has a way to expose it via shellcode / `openat` / `system`. When `/flag` returns nothing, list `/` with `getdents` shellcode or read `/proc/1/environ`.

## Reproduce it yourself

Each challenge ships a standalone solver in the [z0d1akCTF 2026 Qualifiers repository](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers) under `Pwn/<challenge>/`:

- [`Pwn/salvage-protocol/`](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers/tree/master/Pwn/salvage-protocol) — dependency-free remote exploit, injected-frame bin, exact desynchronised wire capture, `reclaimd` + `vaultd` handouts.
- [`Pwn/rapture/`](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers/tree/master/Pwn/rapture) — dependency-free end-to-end remote exploit, supplied Ubuntu glibc 2.35 + loader, offsets file, successful remote transcript.
- [`Pwn/house-xiii/`](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers/tree/master/Pwn/house-xiii) — dependency-free TLS exploit, supplied glibc 2.43 + loader, VM leak bytecode, forged-Orbital sample.
- [`Pwn/dead-reckoning/`](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers/tree/master/Pwn/dead-reckoning) — dependency-free remote exploit, arena layout + SROP frame notes, `getdents` shellcode capture, `/proc/1/environ` recovery.
- [`Pwn/phantom-phase/`](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers/tree/master/Pwn/phantom-phase) — dependency-free remote exploit, VM framing + callback equations, seccomp policy dump, DRV1 image builder from the organisers.
- [`Pwn/paperweight/`](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers/tree/master/Pwn/paperweight) — dependency-free TLS exploit, bundled Poppler + supporting libs, protocol + object + heap + ROP notes.
- [`Pwn/expert-witness/`](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers/tree/master/Pwn/expert-witness) — end-to-end HTTP exploit, C++ salted-hash collision finder, offline collision + flag-decoding verifier, accepted `.moepack` payload.
- [`Pwn/pelagic-palimpsest/`](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers/tree/master/Pwn/pelagic-palimpsest) — end-to-end solver performing proof gate + leaks + runtime code resolution + type forgery + flag recovery in one connection.
- [`Pwn/undertow/`](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers/tree/master/Pwn/undertow) — dependency-free remote exploit with automatic or `--seal`-provided seal, offline seal + pointer + route + checkpoint verifier, Ghidra decompilation, protocol map.

All nine live solvers use only Python standard library (Expert Witness additionally uses a small C++ hash-collision generator). Every challenge in this set is instance-based or one-shot; the artifacts preserve the captured session so the solve is auditable after the instance expires.

Browse the full [CTF writeups](/ctf-writeups/) archive for more binary exploitation walkthroughs, or continue the z0d1akCTF 2026 Qualifiers series with the [Miscellaneous writeup](/ctf-writeups/z0d1akctf-2026-qualifiers-misc-writeup/), the [Forensics writeup](/ctf-writeups/z0d1akctf-2026-qualifiers-forensics-writeup/), and the [Cryptography writeup](/ctf-writeups/z0d1akctf-2026-qualifiers-crypto-writeup/) — eighteen more challenges under the same parser-differential discipline.

---

*This writeup is part of the CyberSecurity Elite [z0d1akCTF 2026 Qualifiers](/series/z0d1akctf-2026-qualifiers/) series. Handouts, per-challenge READMEs, and dependency-conscious solvers for all nine Binary Exploitation challenges are published at [github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers).*
