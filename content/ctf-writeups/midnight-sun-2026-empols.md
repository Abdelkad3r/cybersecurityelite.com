---
title: "Midnight Sun 2026 empols: Auto-Solving 20 x86-64 ELFs with radare2"
slug: "midnight-sun-2026-empols"
description: "Midnight Sun CTF 2026 empols writeup — the server hands out 20 randomly-generated ELFs from 3 templates. Solve them all with Python + radare2 static analysis."
date: 2026-05-16T12:30:00Z
lastmod: 2026-08-04T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
tags: ["midnight-sun", "midnight-sun-ctf", "misc", "pwn", "reverse engineering", "radare2", "x86-64", "automation", "static analysis"]
series: ["Midnight Sun CTF 2026 Quals"]
keywords: ["midnight sun ctf 2026 empols writeup", "midnight sun quals 2026", "auto solve ctf binaries radare2", "x86-64 elf static analysis ctf", "templated binary challenge ctf"]
toc: true
cover:
  image: "/images/articles/midnight-sun-2026-empols.png"
  alt: "MIDNIGHT SUN 2026 EMPOLS writeup — CTF challenge breakdown"
---

{{< ctf-meta platform="Midnight Sun CTF 2026 Quals" difficulty="Hard" os="Linux x86-64" skills="Templated binary RE, radare2 scripting, automated static analysis" >}}

`empols` is the kind of **Midnight Sun CTF 2026** challenge that punishes you for trying to solve binaries by hand; this **CyberSecurity Elite** writeup auto-solves all twenty x86-64 ELFs instead. The server hands you twenty fresh, randomly-generated x86-64 ELFs in one session and demands the validating input string for each — and you almost certainly cannot reverse-engineer twenty unique binaries fast enough to fit inside the session timeout. The intended path is to recognise that the binaries are generated from a small set of *templates*, then write a static-analysis engine that detects the template and extracts the answer from disassembly.

Source: [Abdelkad3r/midnight-sun-ctf-2026-quals · empols/](https://github.com/Abdelkad3r/midnight-sun-ctf-2026-quals/tree/main/empols) (full solver code).

## The Challenge

```text
$ nc empols.play.ctf.se 3337
```

The service emits 20 gzipped, hex-encoded Linux x86-64 ELFs one at a time, and asks for the input that makes each binary validate. All 20 must be correct in a single session to get the flag — one wrong answer and the connection drops.

The naïve approach (`r2` each binary by hand) does not fit in the session timeout. The intended approach is to spot that the binaries are generated from a fixed set of templates and automate the extraction.

## Template Discovery

Disassemble a handful of samples with radare2 (`r2 -q -c 'aaaa; pdf @ main' ./bin`) and three recurring shapes emerge.

### Template 1 — `xor_loop`

```c
char buf[10];
memcpy(buf, hardcoded_bytes, 10);
for (int i = 0; i < 10; i++)
    buf[i] ^= K;                       // K is a single-byte constant
if (strcmp(input, buf) == 0) win();
```

The validating input is `hardcoded_bytes[i] ^ K`. Two things to extract:

- The byte array from the stack `mov byte [rbp - 0xNN], 0xXX` writes — sorted by stack offset **descending** (largest offset = first byte on the stack).
- The XOR constant from `xor (eax|al), 0xNN`.

### Template 2 — `memcpy_strcmp`

```c
char target[] = "some_literal_string";
memcpy(buf, target, sizeof(target));
if (strcmp(input, buf) == 0) win();
```

The validating input is literally the embedded string. Extract from the `lea rX, [str.xxx] ; "..."` comment that radare2 attaches to the `memcpy` call site. Fallback: longest printable string in `iz` output.

### Template 3 — `paired_word_add`

```c
int16_t first[N], second[N];   // both embedded as word constants
for (int i = 0; i < N; i++) {
    int16_t v = ((int16_t)input[2*i+1]) | (input[2*i] << 8);
    if ((v + first[i]) & 0xFFFF != second[i]) fail();
}
win();
```

For each pair `(input[2i], input[2i+1])` we need `v = (second[i] - first[i]) mod 2^16`. The interesting part is that the build packs the low byte of `v` through a sign-extending mov, so:

- `lo = diff & 0xFF` becomes `input[2*i+1]`
- `hi = (diff >> 8) & 0xFF` becomes `input[2*i]`

…**unless** `lo` has the high bit set, in which case `hi` must be `0xFF` for the sign extension to land correctly. When that constraint is infeasible, the input position is unconstrained and any printable byte works.

## The Static-Analysis Engine

The core is `extract_answer.py` — a few hundred lines of `r2 -q -c "..."` shelling, regex pattern matches against the disassembly, and per-template solvers. The interesting bits:

### Detection

```python
def detect_template(asm):
    has_xor    = bool(re.search(r"xor\s+(?:eax|al),\s+0x[0-9a-fA-F]+", asm))
    has_memcpy = "sym.imp.memcpy" in asm
    has_strcmp = "sym.imp.strcmp" in asm
    has_shl_8  = bool(re.search(r"shl\s+eax,\s+(?:0x)?8\b", asm))
    has_word_const = bool(re.search(r"mov\s+word\s+\[.*?\],\s+\S", asm))

    if has_memcpy and has_strcmp:         return "memcpy_strcmp"
    if has_word_const and has_shl_8:      return "paired_word_add"
    if has_xor:                            return "xor_loop"
    return "unknown"
```

Order matters — `memcpy_strcmp` first because it's the most specific signature; `xor_loop` is the catch-all fallback.

### XOR-loop solver

```python
def solve_xor_loop(asm):
    xors = find_all_xor_constants(asm)
    K = Counter(xors).most_common(1)[0][0]   # mode beats compiler-emitted noise
    consts = find_byte_constants(asm)        # sorted by stack offset desc
    return bytes(c ^ K for c in consts).decode("latin-1")
```

The "most common XOR constant" trick handles the case where the compiler emits extra `xor eax, eax` zero-idiom instructions that pollute the candidate list.

### Memcpy-strcmp solver

```python
def solve_memcpy_strcmp(path, asm):
    m = re.search(r"lea\s+r[a-z]+,\s+\[[^\]]+\]\s*;\s*0x[0-9a-fA-F]+\s*;\s*\"([^\"]+)\"", asm)
    if m:
        return m.group(1)
    # fallback: longest .rodata string
    return max([s for s in get_strings(path) if len(s) >= 10], key=len)
```

### Paired-word-add solver

The hardest one. Two complications I hit:

{{< callout type="warning" title="Two regex bugs that cost me a session" >}}
**Bug 1: `xor al, 0xNN` vs `xor eax, 0xNN`.** My first XOR regex matched only `eax`. Radare2 sometimes emits the byte-register form for the same operation depending on the surrounding context. Fixed with `(?:eax|al)`.

**Bug 2: reloc-labelled immediates.** When a word-constant immediate happens to match a known address, radare2 renames it as `reloc.some_symbol` and the literal value only appears in the inline `; 0xNNNN` comment. Direct-immediate regex returns nothing. Fixed by adding a *comment-extraction path* that tries the comment first, then falls back to the direct immediate.
{{< /callout >}}

The "two arrays from one stack frame" detection uses the *loop access offsets* (`word [rbp + rax*2 - 0xNN]`) to figure out where `first[]` ends and `second[]` begins:

```python
def find_paired_arrays_from_bases(asm):
    bases = find_paired_array_bases(asm)            # two distinct loop offsets
    base_first, base_second = bases                  # base_first > base_second
    by_off = find_word_constants_dict(asm)
    n = (base_first - base_second) // 2              # elements between them
    first  = [by_off[base_first  - 2*i] for i in range(n)]
    second = [by_off[base_second - 2*i] for i in range(n)]
    return first, second
```

## The Driver

`solve_all.py` connects to the service, parses out each `BINARY i/20: <hex>` block, gunzips, writes to a temp file, calls `extract_answer.solve()`, sends the answer, and repeats:

{{< terminal title="kali ~/ctf/midnight-sun/empols" >}}
$ python3 solve_all.py
[1/20]  'memcpy_strcmp asm-quoted': 'kvBNjJzULfvgwQGl'
[2/20]  'xor_loop K=0x37 N=10':     'BcmoUjthrz'
[3/20]  'paired_word_add N=8 pairs': 'XQjzZvLpdmqRnsKa'
...
[20/20] 'memcpy_strcmp asm-quoted': 'rPmDqWNxJVtFcBhz'
---- final ----
midnight{y0u_4r3_th3_m4st3r_0f_sl0ps0lv3s}
{{< /terminal >}}

All 20 solved in under a minute.

## Flag

```
midnight{y0u_4r3_th3_m4st3r_0f_sl0ps0lv3s}
```

The flag reads "you are the master of slopsolves" — pointed acknowledgement of exactly the technique used: not careful per-binary reverse engineering but bulk pattern-matched static analysis ("sloppy" in the sense that it short-circuits the usual workflow).

## Lessons learned

1. **Multi-binary CTF challenges are template challenges in disguise.** If a service hands you 20+ binaries in one session, do not try to solve them one at a time. Identify the template generator, write the extractor, and let it run.

2. **Radare2 scripting is faster than full IDA pipelines for this kind of work.** `r2 -q -c 'aaaa; pdf @ main' ./bin` produces clean parsable output in milliseconds. The whole driver fits in a few hundred lines of Python with zero non-stdlib dependencies (beyond `r2` in `$PATH`).

3. **Regex against disassembly is brittle for two specific reasons** — register-form variants (`eax` vs `al`, `rdi` vs `edi`) and labelled immediates (radare renaming a literal as `reloc.X`). Plan for both with `(?:eax|al)`-style alternation and comment-fallback patterns.

4. **Stack-offset sort order matters.** When extracting byte arrays from `mov byte [rbp - 0xNN], val` writes, the first byte of the in-memory array lives at the *largest* negative offset (closest to `rbp`). Sort descending by `0xNN` before XORing or concatenating. Got that wrong once.

5. **Modular arithmetic over 16-bit with sign-extended low byte** is a recurring template trick. The check `(v + first[i]) & 0xFFFF == second[i]` is mathematically `v = second - first mod 2^16`, but the *encoding* of `v` from input bytes matters because sign extension on the low byte forces `hi == 0xFF` when `lo >= 0x80`. Always write out the actual byte-level operations the binary performs before assuming the inverse is straightforward subtraction.

## References

- [radare2 documentation](https://book.rada.re/)
- [Midnight Sun CTF](https://midnightsunctf.com/)
- Source repo (full solver code): [midnight-sun-ctf-2026-quals/empols/](https://github.com/Abdelkad3r/midnight-sun-ctf-2026-quals/tree/main/empols)
