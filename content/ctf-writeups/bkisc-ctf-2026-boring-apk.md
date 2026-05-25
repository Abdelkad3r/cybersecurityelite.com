---
title: "BKISC 2026 Boring APK: Android NDK Reverse + Graph-Walk MitM"
slug: "bkisc-ctf-2026-boring-apk"
description: "BKISC CTF 2026 Boring APK writeup — decrypt AES-GCM-protected assets out of an Android NDK binary, then break a graph-walk check with meet-in-the-middle."
date: 2026-05-16T02:15:00Z
lastmod: 2026-05-16T02:15:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
tags: ["bkisc", "bkisc-ctf", "reverse engineering", "android", "apk", "ndk", "aes-gcm", "meet in the middle", "qemu", "arm64"]
series: ["BKISC CTF 2026"]
keywords: ["bkisc ctf 2026 boring apk writeup", "android apk reverse engineering ctf", "aes-gcm asset decryption android", "ndk basic_string layout", "qemu aarch64 standalone .so", "meet in the middle ctf solver"]
toc: true
cover:
  image: "/images/articles/bkisc-ctf-2026-boring-apk.png"
  alt: "BKISC 2026 BORING APK writeup — CTF challenge breakdown"
---

{{< ctf-meta platform="BKISC CTF 2026" difficulty="Hard" points="250" os="Android (arm64-v8a)" skills="APK extraction, AES-GCM, ELF patching, qemu-aarch64, NDK basic_string, meet-in-the-middle" >}}

Boring APK was the 250-point reverse engineering challenge of BKISC CTF 2026. The hook is the title's bait — Android *is* "boring" until you realise the flag check has been moved out of the Java/Kotlin layer into a native library, the assets it depends on are AES-GCM-encrypted, and the check itself is a 27-step graph walk with three running state words whose final values are all that the verifier compares. None of those stages is hard in isolation; stacking them is what makes the challenge.

Source: [Abdelkad3r/bkisc-ctf-2026 · boring-apk/](https://github.com/Abdelkad3r/bkisc-ctf-2026/tree/main/boring-apk).

## Stage 0 — Reconnaissance

Standard APK triage. `unzip` the APK and look at what's interesting:

```
lib/arm64-v8a/libnative.so    ← does the actual flag check
assets/*                      ← high-entropy blobs, clearly encrypted
classes.dex                   ← thin Java/Kotlin wrapper
```

Decompile the DEX with `jadx`. `MainActivity` loads the native library (`System.loadLibrary("native")`) and calls a JNI method that takes the user-entered flag and returns a boolean. Before reaching the native check, the Activity decrypts a handful of asset files from `assets/` into memory.

So the work splits cleanly:

1. Pull the decryption key + scheme out of the bytecode and decrypt the assets.
2. Get `libnative.so` to run standalone, without firing up an Android emulator each iteration.
3. Reverse the check, build a solver.

## Stage 1 — Decrypting the assets

The bytecode hands the parameters to us in plaintext. Asset decryption is **AES-GCM** with:

- a 32-byte key spelled out as a `byte[]` literal in the smali,
- AAD = ASCII `"bkisc01"`,
- per-blob layout: `nonce[12] || ciphertext || tag[16]`.

```python
from Crypto.Cipher import AES

KEY = bytes([...])   # 32 bytes lifted from smali
AAD = b"bkisc01"

for path in encrypted_files:
    blob = open(path, "rb").read()
    nonce, ct, tag = blob[:12], blob[12:-16], blob[-16:]
    cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
    cipher.update(AAD)
    pt = cipher.decrypt_and_verify(ct, tag)
    open(path + ".dec", "wb").write(pt)
```

GCM tag verifies clean — the key is correct first try. The decrypted assets are seven fixed lookup tables that the flag check will use:

| File | Size | Role |
|---|---|---|
| `table_a` | 16 bytes | Per-step XOR mask, indexed by `(node + i) & 0xf` |
| `table_b` | 32 bytes | Per-node additive mixer, indexed by `node & 0x1f` |
| `table_c` | 16 bytes | State-update additive mixer |
| `path_nodes` | 28 bytes | Graph node visited at each step |
| `required_moves` | 27 bytes | The expected output of `maze_compute_move` per step |
| `checkpoint_nodes` | 6 bytes | Six "checkpoint" nodes |
| `checkpoint_tags` | 6 × `u32` | XOR tag mixed into `s12` at each checkpoint |

That structure already telegraphs a graph-walk: 28 nodes (`path_nodes` length 28 = 27 transitions = 27 character positions) and three running state words.

## Stage 2 — Running libnative.so standalone

I didn't want to round-trip through ADB and a live device for every candidate, so the whole solver runs **`libnative.so` under `qemu-aarch64-static`** on x86-64. Two obstacles before the library can be used as a standalone executable.

### Obstacle A — NDK libc++ `basic_string` layout

The exported check function takes a `std::__ndk1::basic_string<char>` by value and returns one. The NDK's libc++ `basic_string` has two internal forms:

- **Short string** — small string optimisation; data lives inline in the struct.
- **Long string** — three pointers: `{capacity, size, data*}`.

Which bit of `capacity` distinguishes the two modes depends on the libc++ build configuration (`_LIBCPP_ABI_ALTERNATE_STRING_LAYOUT`, `_LIBCPP_BIG_ENDIAN`, etc.). I tried four candidate layouts; the one this binary expects is what I'll call **Layout B**:

```cpp
struct NdkLongString {
    size_t cap;        // bit 0 set => long mode
    size_t size;       // length, no terminator
    const char* data;  // points at the 0-terminated buffer
};
```

A trivial C++ runner builds this struct around the candidate flag and calls the exported entry directly.

{{< callout type="warning" title="NDK basic_string is not portable across SDK versions" >}}
The libc++ shipped with the Android NDK has changed its `basic_string` layout multiple times across NDK r18 → r25+. If you're reverse engineering native Android code, expect to enumerate candidate layouts rather than assume — pick the wrong one and the size byte gets read as the data pointer, your "string" looks empty, and the check fails on every input.
{{< /callout >}}

### Obstacle B — getting the linker to load it

`libnative.so` is fine on Android but Linux's loader rejects it for two reasons:

1. **Symbol versions referencing `liblog.so` and `libc.so` versions that Linux doesn't expose.** A small `strip_versions.py` walks the ELF, removes the `.gnu.version_r` and `.gnu.version` sections, and clears the matching `DT_VERSYM`, `DT_VERNEED`, and `DT_VERNEEDNUM` dynamic tags.
2. **`DT_NEEDED` on `liblog.so`** — Android-specific, no Linux equivalent. The flag check never logs anything, so `patchelf --remove-needed liblog.so libnative.so` is safe.

Then:

```bash
patchelf --set-interpreter /lib/ld-linux-aarch64.so.1 libnative.so
patchelf --remove-needed liblog.so libnative.so
```

After that, the runner program builds, the loader is happy, and:

{{< terminal title="kali ~/ctf/bkisc/boring-apk" >}}
$ qemu-aarch64-static ./runner 'BKISC{test_test_test_test_}'
0
$ qemu-aarch64-static ./runner 'BKISC{4nd0rid_m4z3_s0lving}'
1
{{< /terminal >}}

(Spoiler about the second one — but we'll get there honestly.)

## Stage 3 — The Check

Past the obfuscation, the check is a **27-step graph walk** with three 32-bit state words `s4`, `s8`, `s12`. Per step `i` (current node `path_nodes[i]`, next node `path_nodes[i+1]`):

```c
uint8_t maze_compute_move(uint8_t ch, uint8_t node,
                          uint32_t s4, uint64_t i)
{
    uint8_t A   = table_a[(node + i) & 0xf];
    uint8_t B   = (s4 >> ((i & 3) * 8)) & 0xff;   // byte of s4 picked by i
    uint8_t C   = table_b[node & 0x1f];
    uint8_t tmp = (ch ^ A) + B + C;
    return rotl8(tmp, 3) & 7;                      // 0..7
}
```

Character `ch` is accepted at step `i` iff `maze_compute_move(ch, ...) == required_moves[i]`. That's a tight per-step filter — most steps end up with 0–3 valid characters out of the 37-character alphabet `[a-z0-9_]`.

After accepting `ch`, the three state words update:

```c
new_s4  = (s4 * 0x83) ^ (uint32_t)(ch + table_c[(lookup + i) & 0xf] + i);

uint32_t v = (s8 ^ (lookup * 0x045d9f3bU)) ^ ((ch + i) * 0x9e37u);
new_s8  = rotl32(v, (ch & 7) + 1);

new_s12 = apply_checkpoint(s12, lookup, i);
```

`apply_checkpoint` only fires when `lookup` (= `path_nodes[i+1]`) is one of six checkpoint nodes; on those steps it XORs `rotl32(checkpoint_tag, i & 7)` into `s12`. Six checkpoints, six tags.

The check passes iff after step 26:

```c
TARGET_S4  = 0xf9882dbc;
TARGET_S8  = 0xfd1a9600;
TARGET_S12 = 0x24f218ae;
```

Initial states: `s4 = 0x762509d3`, `s8 = 0x4023cc45`, `s12 = 0`.

Flag positions 0..5 are forced (`BKISC{`) and position 26 is forced (`}`). That leaves **21 free positions** over an alphabet of 37, which gives a search space of `37²¹ ≈ 8.7 × 10³²` — hopeless head-on.

## Stage 4 — Meet-in-the-Middle

Two observations make the problem tractable:

1. The per-step move check usually leaves a handful of `ch` candidates per position, so plain depth-first search prunes hard. On its own, that wasn't fast enough on 21 free positions.
2. **All three state updates are invertible.**

Split the walk at step 13.

### Forward direction

DFS from `i = 0` with `BKISC{` already consumed, down to `i = 13`. At each leaf:

- key = `(s4, s8, s12)` after step 13
- value = the 7-character forward suffix

Stored in a hash map.

### Backward direction

Invert the updates starting from `(TARGET_S4, TARGET_S8, TARGET_S12)` at `i = 27`. For each backward step, enumerate the 37 alphabet chars; for each candidate `ch`, recover the predecessor state, check the per-step move constraint at the recovered `i`, recurse. When we reach `i = 13`, look the `(s4, s8, s12)` triple up in the forward map.

### Inverses I needed

- **`s4` step ends in `* 0x83`.** The modular inverse of `0x83` mod `2³²` is `0xc9484e2b`. XOR is self-inverse, so: subtract `(ch + table_c[...] + i)` (in the XOR domain), then multiply by the modular inverse.
- **`s8` step ends in `rotl32(.., (ch & 7) + 1)`.** Once `ch` is enumerated the rotation amount is known, so unrotate, then XOR the two deterministic mixers back out.
- **`s12` step XORs in a constant only at checkpoint steps.** XOR is self-inverse — trivial.

```c
#define SPLIT     13
#define INV_M     0xc9484e2bu

// forward:  build map[(s4, s8, s12)] -> prefix
// backward: from TARGET, walk back to i = SPLIT and look up the map
```

### Run

{{< terminal title="kali ~/ctf/bkisc/boring-apk" >}}
$ ./solver --split 13 --target f9882dbc:fd1a9600:24f218ae
[forward]  4,365,856 entries built in 18.4 s
[backward] collision found at i=13 after 76.0 s
flag       BKISC{4nd0rid_m4z3_s0lving}
{{< /terminal >}}

The backward pass produces exactly one collision. The flag is the title joke completed — Android isn't boring; it's "maze solving."

## Flag

```
BKISC{4nd0rid_m4z3_s0lving}
```

## Lessons learned

1. **Stack the problem; don't solve it head-on.** This challenge looks intimidating because it's three distinct stages, but each one is straightforward in isolation. Identify the stages early: APK extraction is plumbing, asset decryption is GCM, native execution is loader-patching, and the cryptography is just a state machine. None of them is research-grade.

2. **Standalone-running a `.so` under qemu is faster than any Android instrumentation.** If the challenge native library doesn't actually depend on the Android framework (no JNI environment use, no Bionic-only syscalls), strip the version metadata, patch out the Android-only `DT_NEEDED`s, and run it directly. You'll iterate 100× faster than via Frida or ADB.

3. **The NDK's libc++ `basic_string` is a recurring CTF trap.** If a JNI function takes one by value, you must reproduce the exact ABI layout in your runner. Don't assume — enumerate the four canonical variants (short/long × normal/alternate) and pick the one that gives sensible answers.

4. **Meet-in-the-middle pays for itself whenever the state transitions are invertible.** `(s_{i+1}) = f(s_i, ch_i)` becoming `(s_i) = f⁻¹(s_{i+1}, ch_i)` is the whole game. Recognising that the mixers in this challenge — modular multiplication, XOR, rotation — are all invertible is the key insight. A square root of work for a hash table's worth of memory.

5. **`a * b mod 2ⁿ` is invertible iff `b` is odd.** `0x83` is odd, so it has a modular inverse, computed with the extended Euclidean algorithm. The same trick lets you reverse most LCG-style mixers in CTFs.

## References

- [Android NDK libc++ documentation](https://developer.android.com/ndk/guides/cpp-support)
- [`patchelf` — modify ELF dynamic linker info](https://github.com/NixOS/patchelf)
- [QEMU User-Mode Emulation](https://www.qemu.org/docs/master/user/main.html)
- [Meet-in-the-middle attack — Wikipedia](https://en.wikipedia.org/wiki/Meet-in-the-middle_attack)
- Source writeup: [bkisc-ctf-2026/boring-apk/README.md](https://github.com/Abdelkad3r/bkisc-ctf-2026/blob/main/boring-apk/README.md)
