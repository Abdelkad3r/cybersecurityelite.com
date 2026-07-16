---
title: "LYKNCTF 2026 Crack (Reverse) Writeup: 9 Challenges Solved"
slug: "lyknctf-2026-crack-writeup"
description: "Step-by-step LYKNCTF 2026 crack (reverse engineering) writeup — nine keygen and crackme challenges covering RC4-KSA S-box S-box recovery, ARX/Feistel VMs seeded with 0x9E3779B9, SHA-256(.text) self-hash KDFs, anti-debug byte poisoning, control-flow-flattened taint OR-folding, chained per-byte VM state machines, PyInstaller + ChaCha20/AES/marshal layers, Tauri desktop-app string trails, and a character-name Brainfuck esolang."
date: 2026-07-10T22:00:00Z
lastmod: 2026-07-10T22:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["LYKNCTF 2026"]
tags:
  - "lyknctf"
  - "lyknctf 2026"
  - "reverse engineering"
  - "crack"
  - "keygenme"
  - "crackme"
  - "arx cipher"
  - "feistel vm"
  - "self hash anti tamper"
  - "control flow flattening"
  - "pyinstaller reverse"
  - "chacha20 stream cipher"
  - "aes ctr decrypt"
  - "brainfuck esolang"
  - "tauri desktop app"
  - "anti debug"
keywords:
  - "lyknctf 2026 crack writeup"
  - "lyknctf crack writeup"
  - "lyknctf keygenme writeup"
  - "lyknctf activator writeup"
  - "lyknctf serial writeup"
  - "lyknctf inferir student writeup"
  - "lyknctf waguri2 brainfuck writeup"
  - "lyknctf i hate this app writeup"
  - "lyknctf i hate this app revenge writeup"
  - "lyknctf control freak 1 writeup"
  - "lyknctf control freak 2 writeup"
  - "arx feistel vm cipher inversion"
  - "sha-256 dot text self hash kdf"
  - "0x9e3779b9 golden ratio round key"
  - "0x1BADC0DE arx seed"
  - "splitmix64 fisher yates sbox"
  - "control flow flattened state machine reverse"
  - "pyinstaller chacha20 lzma marshal unpacker"
  - "setwindowdisplayaffinity wda_excludefromcapture"
  - "brainfuck token translation ctf"
toc: true
cover:
  image: "/images/articles/lyknctf-2026-crack-writeup.png"
  alt: "LYKNCTF 2026 crack writeup — nine reverse engineering challenges solved covering ARX VMs, self-hash anti-tamper KDFs, chained per-byte state machines, PyInstaller multi-stage packers, and a character-name Brainfuck esolang"
---

LYKNCTF 2026's crack track (reverse engineering) was built around a repeating pattern: build a small cipher out of well-known cryptographic primitives, wrap it in obfuscation that looks harder than it is, then bake a `.text`-derived self-hash into the state so that any patch or debugger attach silently produces wrong output without changing the error message. Nine challenges, nine variations on that theme, from a simple string-import inspection in a Tauri desktop app all the way to a four-layer keygen whose master key mixes account name, license key, `SHA-256(.text)`, and an anti-debug byte.

This writeup walks all nine crack solves in the order they appear in the repository: KeygenMe (RC4-KSA-derived hidden account name + ARX license-key hash + `.text` self-hash KDF); Activator (SHA-256(.text) as bytecode keystream feeding a Feistel-shaped ARX VM with 8 u32 lanes and 32 golden-ratio rounds); Serial (chained per-byte VM where each character's 32-bit output seeds the next character's base state); Inferir Student (PyInstaller wrapper around a seven-stage ChaCha20 + LZMA + marshal packer, ending in a ChaCha20 stream-cipher target); Waguri2 (Brainfuck program with every instruction replaced by a *Kaoru Hana wa Rin to Saku* character name); I HATE THIS APP (Tauri/Rust app whose flag is the Windows API name `SetWindowDisplayAffinity`); I HATE THIS APP REVENGE (same app + an AES-256-CTR encrypted image with an unusual IV layout); Control Freak 1 (three-round per-byte checker with cross-round `+3r` / `+r` accumulator gotchas); and Control Freak 2 (control-flow-flattened five-state machine with four anti-analysis taints OR-folded into the final compare).

Handouts, per-challenge READMEs, and Python solvers live at [Abdelkad3r/LYKNCTF](https://github.com/Abdelkad3r/LYKNCTF). Every challenge here was solved statically or with light Unicorn emulation of pure functions; none of the solutions required a debugger, and several of them are deliberately robust against having one attached.

## The nine LYKNCTF 2026 crack challenges

| # | Challenge | Primitive | Flag |
|---|---|---|---|
| 1 | KeygenMe | 4-layer keygen: RC4-KSA S-box reveals hidden account `th3_LYKN_v3nd0r`; ARX hash produces license `7211-57C4-CD96-CC26-5B67`; SHA-256(.text) + anti-debug byte folded into KDF that decrypts the flag. | `LYKNCTF{k3yg3n_h3ll_s3lfh4sh_4ntidbg_h1dd3n_us3r_2026}` |
| 2 | Activator | 8-lane Feistel-shaped ARX VM (32 rounds, `0x1BADC0DE` seed, `0x9E3779B9` increment). Bytecode is XOR-decrypted with SHA-256(.text) as keystream. Every op invertible; run backwards from target. | `LYKNCTF{V1rtu4l_ARX_VM_LLM_h3ll_LYKN2026}` |
| 3 | Serial | Chained VM checker: SHA-256(.text)[:4] seeds base state; each candidate byte runs a 17-opcode VM, compares low 16 bits, and the full 32-bit result seeds the next character. | `LYKNCTF{Dyn4m1c_0nly_LYKN_2026!!}` |
| 4 | Inferir Student | PyInstaller wrapper around a 7-stage loader (ChaCha20 → LZMA → marshal). Stage 3 is an AES-CBC/zlib/marshal packer. Final checker encrypts input with ChaCha20; decrypt the "target" bytes with the same keystream. | `LYKNCTF{Im_At_The_PayPhone_..._Wr0nG_wh3rE_aRe_Th3_Pl4nS_W3_M4d3_F0r_2}` |
| 5 | Waguri2 | 336 KB Brainfuck program where every instruction is a character-name token. Seven tokens map to seven BF instructions (no `.`). Success = "halts instead of falling into an invariant-loop failure sink." | `LYKNCTF{K40RU_H4N4_W4_R1N_T0_S4KU}` |
| 6 | I HATE THIS APP | Tauri/Rust app. Strings + import table point to `user32.dll!SetWindowDisplayAffinity` called with `EDX=0x11 = WDA_EXCLUDEFROMCAPTURE`. Flag is the API name lowercase. | `LYKNCTF{setwindowdisplayaffinity}` |
| 7 | I HATE THIS APP REVENGE | Same Tauri app + AES-256-CTR encrypted image. `FIXED_ENCRYPTION_KEY` embedded in `.rdata`; IV reconstructed as `file[0:8] || 0x00000000 || file[8:12]`. Decrypt image, recognise Alolan Vulpix. | `LYKNCTF{alolanvulpix}` |
| 8 | Control Freak 1 | 33-byte checker, 3 rounds of `LOAD/XOR/ROL/ADD → PERM[(3+7k) mod 33] → XOR chain`. Cross-round `+3r` / `+r` accumulator offsets are the gotcha (the wrong inverse passes on random inputs but not on the target). | `LYKNCTF{H0W_D1D_Y0U_C0NTR0L_TH4T}` |
| 9 | Control Freak 2 | Control-flow-flattened 5-state machine. Four anti-analysis taints (timing, ptrace, TracerPid, LD_PRELOAD) XOR into `local_2b4`, which is OR-folded into the compare. Offline solve: SplitMix64 Fisher-Yates S-box + FNV-offset keystream + carrier/rotate. | `LYKNCTF{1S_1T_H4RD_T0_C0NTR0L}` |

The pattern that ties the track together: the compiler-visible obfuscation is loud, but the cryptographic constants are quiet. Every crypto-heavy challenge in the track surfaces `0x9E3779B9` or `0x9E3779B97F4A7C15` (the golden ratio, TEA-family fingerprint), `0xD1B54A32D192ED03` (FNV-1a 64-bit offset basis), `0x100000001B3` (FNV-1a prime), `0x6a09e667..0x5be0cd19` (SHA-256 IV), or `0x428a2f98..` (SHA-256 K constants). Naming those constants collapses "reverse this cipher" to "recognise this cipher and inverse it," and every one of the nine challenges here becomes a Python solver of at most a few dozen lines.

## Methodology — name the constants, then peel the layers

A pattern that worked across every challenge: before diving into the disassembly, run `.rodata` through a small script that flags any 32-bit or 64-bit word matching known cryptographic constants. `0x6a09e667` is SHA-256 IV word 0. `0x9E3779B9` is the TEA / XXTEA / SipHash round-key increment. `0xD1B54A32D192ED03` is the FNV-1a 64-bit offset basis. `0x428a2f98` is the first SHA-256 K constant. If any of those appear, half the reversing is done: you know the family and the standard reference implementation, and the challenge author's role reduces to naming which mode and which key material.

The second discipline is treating self-hash primitives as static extractions. Every challenge that folds `SHA-256(.text)` into its state does so on the loaded image. The loaded image is the raw file bytes at the `.text` file offset, up to `VirtualSize` (not `SizeOfRawData`). If nothing in `.reloc` targets `.text`, the loader map is byte-identical to the file, so the same hash can be computed by any Python script that reads the PE header, walks section entries, and hashes `pe[off : off + vs]`. No emulation required. This is what makes KeygenMe, Activator, Serial, and Control Freak 2 all reachable through static solvers.

The third discipline is being willing to read very long SIMD blocks and *not* trust them. Activator's 200-line SSE identity is a compiler-vectorised memcpy dressed up as a scrambler. Control Freak 2's SSE-heavy `iota` fill is a straight `range(256)` behind three shuffle stages per iteration. Feeding either block a probe input through Unicorn and observing that the output is the identity (or `range(256)`) saves hours of tracing what turns out to be no-ops. When a SIMD block's semantics are opaque, treat it as a black-box function of its inputs and test the function.

Per-challenge walkthroughs follow.

## 1. KeygenMe

Four separate layers to peel. The account name is not stored as a string; the license key is deterministic from the account; the flag is XOR-encrypted with a KDF that folds SHA-256(.text) and an anti-debug byte; and a plaintext signature check catches any patch to `.text`.

#### Step 1 — Watch the .rdata file offset

The section table gives `.text @ raw 0x400`, `.rdata @ raw 0x4200`, `.idata @ raw 0x5c00`. Any hand-written `va_to_off` helper that infers the `.rdata` file offset from `.idata` alignment will read `0x5600` and get zeros. Sanity-check by reading the ASCII string `LYKN2026` at a known location before trusting the mapping. This one trap ate hours of my first pass.

#### Step 2 — Rebuild the hidden account name

Function `0x140001f10` calls `0x1400014d0` (S-box builder), then XORs S-box lookups against two hardcoded blobs. The S-box is an RC4 KSA with an unusual pre-swap step and a 15-byte key `"L0i_Y3u_Kh0_N0i"` at `.rdata:0x140006248`:

```python
S = list(range(256))
j = (S[0] + 0x4c) & 0xff        # pre-swap
S[0], S[j] = S[j], S[0]
for i in range(1, 256):
    j = (j + S[i] + key[i % 15]) & 0xff
    S[i], S[j] = S[j], S[i]
```

The account name is then produced by XORing S-box lookups (stride 5) against two blobs:

```python
blob1 = read(0x1400063f0, 8)     # 8 bytes → "th3_LYKN"
blob2 = read(0x140006268, 7)     # 7 bytes → "_v3nd0r"
name  = bytes(blob1[k] ^ S[0x1f + 5*k] for k in range(8)) \
      + bytes(blob2[k] ^ S[0x47 + 5*k] for k in range(7))
# → b"th3_LYKN_v3nd0r"
```

The Vietnamese RC4 key `"L0i_Y3u_Kh0_N0i"` is a nice cultural signature but doesn't affect the algorithm.

#### Step 3 — Compute the license key

Given the account, `0x140001660` runs an ARX-style mixer. Four state words seeded from constants (`0x4c594b4e` = `"LYKN"`, `0x43544632` = `"CTF2"`, `0xae054fb9`, `0xa5a5f00d`) with the debug byte XOR-tainted into the first. Three outer passes with `k ∈ {0, 7, 14}` iterate the name through a 4-step ARX mixer per byte, then four finalisation rounds. The gotcha is instruction ordering: step 4 reads the *new* `r8` for the S-box lookup but the *old* `rdi` as the mixing constant.

The formatter packs the final `(r8, r11, r9, rdi)` into five 16-bit groups with a checksum: `7211-57C4-CD96-CC26-5B67` for `th3_LYKN_v3nd0r`.

#### Step 4 — Recognise the self-hash-keyed KDF

Once both `lstrcmpA` calls pass, a third SHA-256 chain fires. It walks the section header until it finds `.text`, then feeds `VirtualSize` (`0x3a60`) bytes to `sha256_block`:

```
sha256 = hashlib.sha256(pe[0x400:0x400 + 0x3a60]).digest()
       = 540a6fe0dfa677f2a7b1603fd0db282a01d77ba385ab670729f7b5d95670af3d
```

That digest becomes an input to the master-key derivation:

```
master = sha256(account || 0x1f || key || 0x1f || sha256(.text) || bpl)
stream = concat(sha256(master || i.to_bytes(4, "little")) for i in range(3))
plaintext = xor(rdata_blob_at_0x140006280, stream)   # 96 bytes
```

`bpl` is the anti-debug byte: zero on a clean run, non-zero under a debugger. It changes the master key silently: the decryption succeeds but produces garbage, and a downstream `sha256("LYKN2026" + plaintext)[:8] == 0x2679dda8691cb57d` signature check catches the garbage and takes the error path.

#### Step 5 — Run the keygen offline

```python
text_hash = sha256(pe[0x400:0x400+0x3a60]).digest()
master    = sha256(b"th3_LYKN_v3nd0r" + b"\x1f"
                 + b"7211-57C4-CD96-CC26-5B67" + b"\x1f"
                 + text_hash + b"\x00").digest()
stream    = b"".join(sha256(master + bytes([i,0,0,0])).digest() for i in range(3))
flag      = bytes(a ^ b for a, b in zip(enc_table, stream)).rstrip(b"\x00")
# → LYKNCTF{k3yg3n_h3ll_s3lfh4sh_4ntidbg_h1dd3n_us3r_2026}
```

The flag payload literally spells out every mechanism you had to reproduce: `k3yg3n_h3ll` (real keygen, not a strings read), `s3lfh4sh` (SHA-256 of `.text` in the KDF), `4ntidbg` (debug flag byte folded in), `h1dd3n_us3r` (account name not stored), `2026`.

Per-challenge README + `keygen.py`: [crack/keygenme](https://github.com/Abdelkad3r/LYKNCTF/tree/main/crack/keygenme).

## 2. Activator

An 8-lane Feistel-shaped ARX cipher inside a VM whose bytecode is XOR-decrypted with `SHA-256(.text)` as keystream. Every operation is invertible, so the "solve" is one Python pass backwards from the target.

#### Step 1 — Skip the 200-line SSE identity

After the wrapper check (length 41, starts `LYKNCTF{`, ends `}`), a ~200-byte SSE block copies the 32 inner characters to `[rsp+0x80]`. Feeding it identity, `'A' * 32`, and the target constant all through Unicorn confirms it's a straight `memcpy` unrolled over SSE lanes. Compiler artefact, not a scrambler.

#### Step 2 — Decrypt the bytecode

`.rdata:0x140006220` holds 183 bytes of encrypted bytecode. The decryption loop hashes `.text` with SHA-256 (standard IV visible at `.rdata:0x140006410`) and XORs the resulting 32-byte digest against 32-byte slices of the blob, iterated six times. Since `.text` is fixed and SHA-256 is deterministic, the bytecode is a build-time constant; extract it once by breakpointing at the VM entry.

#### Step 3 — Read the VM opcode table

Ten opcodes, dispatched from a 40-entry signed-offset jump table at `.rdata:0x14000611C`. The relevant ones:

| Opcode | Semantics |
|---|---|
| `11 R imm32` | `reg[R] = imm32` |
| `22 R idx`   | `reg[R] = user_word[idx & 7]` |
| `33 R idx`   | `reg[R] = target_word[idx & 7]` |
| `55 R S`     | `reg[R] += reg[S]` via `(a^b)+2(a&b)` |
| `77 R S`     | `reg[R] ^= reg[S]` via `(a\|b)-(a&b)` |
| `99 R imm32` | `reg[R] += imm32` |
| `BB R n`     | `reg[R] = rol(reg[R], n & 0x1F)` |
| `CC R n`     | `reg[R] = ror(reg[R], n & 0x1F)` |
| `DD R`       | `r10 \|= reg[R]` (fail accumulator) |
| `E0 R off16` | `LOOP`: dec + conditional jump |

#### Step 4 — Disassemble to the Feistel loop

The 183 decoded bytes disassemble to:

```
load  reg[0..7] ← user_word[0..7]
reg[9] = 0x1BADC0DE          ; round key
reg[8] = 32                   ; round counter
loop:
  for i in 0..7:
      reg[i] += reg[9]
      reg[i]  = rol(reg[i], N[i])         ; N = [7,9,13,18,3,11,17,5]
      reg[i] ^= reg[(i+1) mod 8]
  reg[9] += 0x9E3779B9                    ; golden-ratio round-key update
  E0 reg[8], loop
```

Then eight `33` loads + XORs against the target words, and `r10` must be zero. `0x1BADC0DE` + `0x9E3779B9` are the TEA-family fingerprint.

#### Step 5 — Invert 32 rounds

Every step is a bijection over u32. Working one round backwards, sibling XOR unwinds cleanly if we go `i = 7, 6, ..., 0` (the "sibling" is the register we've already restored). Rotation cancels with `ror`. Add reverses with subtract of the current round key.

```python
for r in reversed(range(32)):
    key = (KEY0 + r * GOLDEN) & 0xFFFFFFFF
    for i in reversed(range(8)):
        y[i] ^= y[(i + 1) % 8]
        y[i]  = ror(y[i], ROT[i])
        y[i]  = (y[i] - key) & 0xFFFFFFFF
```

Feed the target words in, read the flag off: `LYKNCTF{V1rtu4l_ARX_VM_LLM_h3ll_LYKN2026}`.

Per-challenge README + solver: [crack/activator](https://github.com/Abdelkad3r/LYKNCTF/tree/main/crack/activator).

## 3. Serial

Same self-hash + VM pattern as Activator, but the VM output chains across characters, so brute-force one byte at a time only works if you track the full 32-bit state.

#### Step 1 — Compute the .text virtual-size hash

`.text` at raw `0x400`, virtual size `0x3270`. Hash exactly the virtual size:

```
sha256(.text) = 1fdc57d0b9ee231496585ec9160394a6ca5c8d3de2f715cc8626127ebb53189f
```

The first four bytes read as little-endian dword `0xd057dc1f`. Mix with the startup guard:

```
base_state = 0xb16b00b5 ^ 0xd057dc1f = 0x613cdcaa
vm_seed    = 0x613cdcaa ^ 0xa5a5a5a5  = 0xc499790f
```

Using `SizeOfRawData` (`0x3400`) instead of `VirtualSize` (`0x3270`) hashes 400 extra bytes and gives the wrong seed. Same discipline as KeygenMe: hash exactly what the loader hashes.

#### Step 2 — Extract the bytecode PRNG

The VM bytecode at `.rdata:0x140006180` is decoded with a rolling PRNG:

```python
def mix(prng, byte):
    return (rol32(prng ^ byte, 11) * 0x9c5ab3d7 + 0x3f1e5c2b) & 0xffffffff
```

Note: opcode dispatch advances the PRNG, and the handler receives `pc + 1` as its first operand index. Missing that step desynchronises every decoded operand: the same one-off error that kept my first pass returning garbage.

#### Step 3 — Model the 17-opcode VM

The register machine has 8 u32 registers plus PC. Instructions include: load current base state, load candidate byte, load rolling seed, immediate move, register move, add/sub/xor/multiply, add/xor/multiply immediate, rotate left/right, `x ^= x >> n`, select output register, halt.

#### Step 4 — Recognise the chain

The compare is only on the low 16 bits: `cmp word [target_table + 2*i], ax`. First glance says brute-force per character. But the *full* 32-bit VM result is saved back into the state slot and becomes the next character's base state. The rolling seed evolves separately after each successful character. So each position has exactly one printable match, and the correct character has to satisfy both the 16-bit compare AND leave the state in a form that lets subsequent characters succeed.

#### Step 5 — Brute-force byte by byte with state carried forward

```
Position 0: state = 0xc499790f, brute-force byte, find printable match
Position 1: state = full 32-bit result from position 0, brute-force ...
...
```

Recovered body: `Dyn4m1c_0nly_LYKN_2026!!`. Wrapped: `LYKNCTF{Dyn4m1c_0nly_LYKN_2026!!}`.

Per-challenge README + `exploit.py`: [crack/serial](https://github.com/Abdelkad3r/LYKNCTF/tree/main/crack/serial).

## 4. Inferir Student

A PyInstaller-wrapped Python loader with seven encrypted stages (ChaCha20 → LZMA → marshal). Six stages are noise; stage 3 is a second-layer AES-CBC/zlib/marshal packer that reveals the final checker. The final checker is a ChaCha20 stream cipher; decrypt the "target" bytes with the same keystream and the flag falls out.

#### Step 1 — Recover the stage tuples without executing

The Python source builds a list named `__68a3ce74cb6bc2b44970e0c__` of five-tuples: `(salt, xor_byte, nonce, ciphertext, sha256_digest)`. The loader is:

```python
key = sha256(salt + bytes([xor_byte ^ epsilon])).digest()[:32]
plaintext = ChaCha20.new(key=key, nonce=nonce).decrypt(ciphertext)
assert sha256(plaintext).digest() == sha256_digest
code = marshal.loads(lzma.decompress(plaintext))
exec(code, sys.modules["__main__"].__dict__)
```

`epsilon` is an anti-debug value. In a clean offline extraction every stage verified with `epsilon = 0`, so the key byte is just the stored `xor_byte`. Execute only the prefix before the thread launcher, stub the missing crypto imports, and read the tuple list directly.

#### Step 2 — Disassemble stage 3 with Python 3.12

The seven marshal objects decompress to Python 3.12 bytecode. Loading in 3.11 or 3.13 gives bad disassembly. Stage 3 is 407 KB (the other six are ~500 bytes each: global-state noise). Its readable imports (`lzma`, `hashlib`, `zlib`, `bz2`, `struct`, `base64`, `Crypto.Cipher.AES`, `marshal`, `exec`) betray a second-layer packer.

#### Step 3 — Intercept the AES layer

Near the end of stage 3, a function does:

```python
cipher = AES.new(key, AES.MODE_CBC, iv)
blob = base64.b85decode(encoded)
plain = unpad(cipher.decrypt(blob), ...)
payload = zlib.decompress(plain)
exec(marshal.loads(payload), globals())
```

Replace the final `exec` with a dumper that writes `marshal.dumps(obj)` to a file. The AES key and IV surface:

```
AES key = 6e88e22c0c972988911f27f29f981f632eb7a4423140a6773640dcd833dac7ad
AES IV  = df7b34e42de1c4c08e5ad0cde2a0a072
```

#### Step 4 — Recognise the ChaCha20 target as ciphertext

Disassembling the final checker: it imports `cryptography.hazmat.primitives.ciphers`, reads one line of input, and encrypts it with ChaCha20:

```python
key    = b"...32 bytes..."
nonce  = b"...16 bytes..."
target = b"...145 bytes..."

candidate = input(...).encode()
stream = Cipher(algorithms.ChaCha20(key, nonce), mode=None).encryptor()
if stream.update(candidate) == target:
    print(success)
```

ChaCha20 is a stream cipher: `ciphertext = plaintext XOR keystream`, so `plaintext = ciphertext XOR keystream`. The target bytes are already the encrypted flag. Decrypt them with the same key + nonce and read the flag.

The one practical detail: the `cryptography` API expects a 16-byte ChaCha20 nonce composed of an initial 64-bit little-endian counter and a 64-bit nonce. The solver implements that layout directly.

Flag: `LYKNCTF{Im_At_The_PayPhone_Tryin_To_Home_Allof_My_change_1_Spent_0n_u_Where_have_ThE_T1m3S_G0n3_B4bY_Its_Wr0nG_wh3rE_aRe_Th3_Pl4nS_W3_M4d3_F0r_2}`.

Per-challenge README + solver: [crack/inferir-student](https://github.com/Abdelkad3r/LYKNCTF/tree/main/crack/inferir-student).

## 5. Waguri2

A 336 KB Brainfuck program where every instruction has been replaced by a character-name token from *Kaoru Hana wa Rin to Saku*. Seven tokens map to seven BF instructions (no output). The program has no `.` opcode; success means "halts before falling into a failure-loop sink."

#### Step 1 — Count tokens

Splitting the file on whitespace yields exactly seven unique tokens with the counts:

```
tsumugi_rintaro    5896
usami_shohei       5893
natsusawa_saku     5893
waguri_kaoruko     2664
yorita_ayato       1310
hoshina_subaru     1310
kaoru_hana           34
```

Seven tokens is BF's 8-instruction alphabet minus output. The `kaoru_hana` count of 34 is the number of input operations, so the flag length is 34.

#### Step 2 — Deduce the mapping

The two tokens with matching counts (`yorita_ayato` = `hoshina_subaru` = 1310) are the bracket pair. Testing balance fixes their direction: `yorita_ayato = [`, `hoshina_subaru = ]`. The next pair (`usami_shohei` = `natsusawa_saku` = 5893) is the pointer-move pair. Testing the translated prefix against the expected initialisation shape resolves it as `usami_shohei = >`, `natsusawa_saku = <`. The remaining pair (`waguri_kaoruko`, `tsumugi_rintaro`) is arithmetic. Final map:

| Token | BF |
|---|---|
| `usami_shohei` | `>` |
| `natsusawa_saku` | `<` |
| `waguri_kaoruko` | `+` |
| `tsumugi_rintaro` | `-` |
| `yorita_ayato` | `[` |
| `hoshina_subaru` | `]` |
| `kaoru_hana` | `,` |

#### Step 3 — Recognise the failure-loop pattern

The translated program has no `.`, so we need a halting oracle instead of output. Generated failure loops look like `[>>>++[--]<<<]`: the loop body moves away from the current cell, does something harmless, and returns without touching the loop cell. If the loop cell is nonzero on entry, the body never zeroes it and the loop is infinite.

Detection: for each `[`, walk the body and check whether it can modify the current cell before the matching `]`. If not, entering the loop with nonzero current cell is a definitive failure sink.

#### Step 4 — Brute-force per byte

For each position `i`, try candidate bytes; a candidate is correct if execution advances to the next `,` (or reaches the end, for the last byte) without falling into a detected failure sink.

```
LYKNCTF{K40RU_H4N4_W4_R1N_T0_S4KU}
```

Per-challenge README + solver: [crack/waguri2](https://github.com/Abdelkad3r/LYKNCTF/tree/main/crack/waguri2).

## 6. I HATE THIS APP

A Tauri/Rust desktop application that "prevents screenshots." The flag is the name of the Windows API that actually does the work, lowercase.

#### Step 1 — Grep the strings

The RAR archive extracts a 64-bit Windows GUI PE. `strings` narrows the problem fast:

```
[Security] Screen capture protection activated successfully
enable_capture_protection disable_capture_protection
[Security] Failed to set display affinity:
SetWindowDisplayAffinity
```

Two useful leads: the app exposes Tauri commands named `enable_capture_protection` / `disable_capture_protection`, and the binary imports `SetWindowDisplayAffinity`, the Windows API for screen-capture exclusion.

#### Step 2 — Confirm the import

`objdump -p` shows `SetWindowDisplayAffinity` under `user32.dll`'s import table. That's the actual imported symbol, not a leftover string. `user32.dll` also imports `SetCapture` and `ReleaseCapture` (mouse input, not screenshot protection), but display-affinity is what matches the challenge behaviour.

#### Step 3 — Locate the call site

Cross-referencing the import shows a small wrapper at `0x14098c580`:

```asm
mov  rcx, [rcx + 0x8]      ; native window handle
xor  eax, eax
test dl, dl
mov  edx, 0x11             ; WDA_EXCLUDEFROMCAPTURE
cmove edx, eax             ; 0 when disabling
call [rip + 0x18e50e]      ; -> SetWindowDisplayAffinity
```

`EDX = 0x11` is `WDA_EXCLUDEFROMCAPTURE`, the display-affinity mode that excludes the window from screen capture. Disable path uses `0`. Both match the observed behaviour.

#### Step 4 — Avoid the wrapper trap

Three names look plausible:

| Name | Role |
|---|---|
| `enable_capture_protection` | Tauri command exposed by the app |
| `set_content_protected` | Tauri window API wrapper |
| `SetWindowDisplayAffinity` | Windows API that actually changes capture behaviour |

The challenge asks for the function that prevents screenshots. Wrapper names describe app-level commands; the low-level behaviour is the Windows API. Flag (lowercase per challenge convention): `LYKNCTF{setwindowdisplayaffinity}`.

Per-challenge README + solver: [crack/i-hate-this-app](https://github.com/Abdelkad3r/LYKNCTF/tree/main/crack/i-hate-this-app).

## 7. I HATE THIS APP REVENGE

Same Tauri app plus an encrypted image. Reversing the fixed decrypt routine reveals the key and an unusual CTR IV layout.

#### Step 1 — Find the fixed key path

Strings surface `FIXED_ENCRYPTION_KEY` and error messages like `Invalid IV length: expected 12, got`. A helper at `0x1401ff190` first calls `getenv("FIXED_ENCRYPTION_KEY")` and falls back to an embedded 32-byte default. The fallback function copies two 16-byte constants:

```asm
movaps xmm0, [rip + 0xa65b79]     ; 0x140c5fe10
movups [rcx], xmm0
movaps xmm0, [rip + 0xa65b7f]     ; 0x140c5fe20
movups [rcx + 0x10], xmm0
```

Dumping 32 bytes from `0x140c5fe10`:

```
48 7d 33 74 25 5e 6e 44 77 35 46 3f 63 57 6a 2d
58 41 48 21 44 6a 38 41 61 6b 61 44 39 79 39 4d
```

As ASCII: `H}3t%^nDw5F?cWj-XAH!Dj8AakaD9y9M`.

#### Step 2 — Read the CTR IV layout

The decrypt function rejects inputs of 12 bytes or less, then treats the rest as ciphertext. AES-NI instructions confirm CTR mode. The gotcha is the IV layout:

- Bytes `0..8` of the file: first eight bytes of the counter block.
- Middle four bytes: zero.
- Bytes `8..12` of the file: last four bytes of the counter block.

For the sample:

```
file prefix = 00 11 22 33 44 55 66 77 00 00 00 07
CTR IV      = 00 11 22 33 44 55 66 77 00 00 00 00 00 00 00 07
```

Using the first 12 bytes directly as `nonce || counter` fails.

#### Step 3 — Decrypt and identify

```bash
KEY=487d3374255e6e447735463f63576a2d58414821446a3841616b61443979394d
IV=00112233445566770000000000000007
tail -c +13 encrypted.bin | openssl enc -aes-256-ctr -d -K "$KEY" -iv "$IV" > recovered.jpg
```

Output is a valid 526×684 JPEG showing a small white fox Pokemon in the snow: Alolan Vulpix.

Flag: `LYKNCTF{alolanvulpix}`. Per-challenge README + solver: [crack/i-hate-this-app-revenge](https://github.com/Abdelkad3r/LYKNCTF/tree/main/crack/i-hate-this-app-revenge).

## 8. Control Freak 1

A 33-byte checker that runs three rounds of per-byte transform → permutation → XOR chain, then does an OR-of-XOR-diffs compare against a 33-byte target in `.rodata`. Every step is byte-by-byte invertible, but the round has cross-round `+3r` and `+r` accumulator offsets that trip up the naive inverse.

#### Step 1 — Extract the constants

`.rodata` is 248 bytes total. Four constants matter:

```
TABLE1  = b"RdqQTv-9"                              # 8 bytes @ 0x20f0
TABLE2  = 17 8b 23 42 c1 5e 09 a7                   # 8 bytes @ 0x20e8
PERM    = [3, 10, 17, 24, 31, 5, 12, 19, ...]      # 33 * uint32_t @ 0x2060
TARGET  = 66 15 e4 34 0c 1b 3e d3 ...               # 33 bytes @ 0x2020
```

`PERM[k] = (3 + 7·k) mod 33`, and since `gcd(7, 33) = 1` it's a real permutation.

#### Step 2 — Read the three-stage round

The outer loop runs three rounds (`r ∈ {0, 1, 2}`). Each round is:

**Inner-loop 1 (per-byte transform):**

```
s = ROL8(TABLE1[(k + 3r) & 7] XOR input[k], ((k + r) mod 7) + 1)
c = TABLE2[(r + 5k) & 7] + 29·r + 13·k    (mod 256)
input[k] = (c + s) & 0xFF
```

**Permutation:** `perm_buf[PERM[k]] = input[k]` for `k ∈ 0..33`.

**Inner-loop 2 (XOR chain):**

```
ecx = 0x5a + 0x31·r
for k in 0..33:
    ecx ^= perm_buf[k] ^ ((r + 7k) & 0xFF)
    input[k] = ecx & 0xFF
```

**Check:** OR-of-XOR-diffs between `input` and `TARGET`. Zero means correct.

#### Step 3 — Invert one round

- XOR chain unwinds trivially: `perm_buf[k] = (state[k] XOR state[k-1]) XOR ((r + 7k) & 0xFF)` (with `state[-1] = 0x5a + 0x31·r`).
- Permutation is a gather instead of a scatter: `input[k] = perm_buf[PERM[k]]`.
- Per-byte transform inverts arithmetically:

```
c        = (TABLE2[(r + 5k) & 7] + 29·r + 13·k) & 0xFF
rotated  = (tmp[k] - c) & 0xFF
s        = ROR8(rotated, ((k + r) mod 7) + 1)
input[k] = s XOR TABLE1[(k + 3r) & 7]
```

Three rounds forward, three rounds back: `for r in (2, 1, 0): state = inverse_round(state, r)`.

#### Step 4 — The bug worth naming

My first pass at the inverse used `TABLE1[k & 7]` and `rol8(s, (k % 7) + 1)`, dropping the cross-round `+3r` and `+r` offsets. That inverter passes on random inputs (round-tripped `os.urandom(33)` succeeds because for `r = 0` the offsets are zero and each round is individually a bijection), but fails on the real target because the wrong slice of `TABLE1` is picked and the wrong rotate count is used in rounds 1 and 2.

The fix is two lines each (with mirror lines in the inverse), and the general rule is: if your inverter passes on `os.urandom` but fails on the real target, the inverse is only correct on the first round. Round-trip proves each round is invertible in isolation; it doesn't prove the composition. Always run `forward(recovered) == TARGET` as an end-to-end oracle before submitting.

Flag: `LYKNCTF{H0W_D1D_Y0U_C0NTR0L_TH4T}`. Per-challenge README + solver: [crack/control-freak-1](https://github.com/Abdelkad3r/LYKNCTF/tree/main/crack/control-freak-1).

## 9. Control Freak 2

Control-flow-flattened `main()` with five reachable states. Four independent anti-analysis taints XOR into a single register `local_2b4` whose bytes are OR-folded into the final compare. Under a debugger, LD_PRELOAD, tracer, or slow-timing environment, the compare fails silently regardless of what you feed it. Solve offline; don't attach.

#### Step 1 — Map the state machine

The state machine is a `while (state != 0x3d12f0b7) switch (state) { ... }` loop. Five reachable states, in the order they execute on a valid path:

| Order | State | What it does |
|---|---|---|
| 1 | `0x91cf3a2b` | Four anti-analysis taints XOR into `local_2b4` |
| 2 | `0xd2387a55` | Measure `strlen(input, 0x7f)`, fold into `local_2b8` |
| 3 | `0x0f6d3c2a` | Build 256-byte S-box, generate 30-byte output |
| 4 | `0x58a91e43` | `memcpy` 30-byte TARGET (two overlapping XMM stores) |
| 5 | `0xaf314621` | Per-byte XOR compare + OR-fold `local_2b4` bytes |

Each state also has a dead-code branch of the form `if ((x*x + x) & 1) call FUN_00101c00(...)`. `x*(x+1)` is always even, so the branch is unreachable. Confirmed by dead-code elimination in Ghidra.

#### Step 2 — Recognise the four taints

```c
// Taint 1: timing
if (steady_clock delta > 750'999'999) local_2b4 = (uint32_t)splitmix_result ^ 0x6A09E667;
// Taint 2: TracerPid line in /proc/self/status
if (parsed_int != 0) local_2b4 ^= 0xBB67AE85;
// Taint 3: PTRACE_TRACEME failure
if (ptrace fails with EPERM) local_2b4 ^= 0x3C6EF372 & mask;
// Taint 4: LD_PRELOAD or LD_AUDIT set
if (getenv("LD_PRELOAD") || getenv("LD_AUDIT")) local_2b4 ^= 0xA54FF53A;
```

Two operational details: the strings `"TracerPid:"`, `"LD_PRELOAD"`, `"LD_AUDIT"` are XOR-decoded on the stack right before use, so `strings` never sees them. And the ptrace mask includes the file-open result, so breaking the environment for one taint doesn't disable another.

Under a clean run, `local_2b4 == 0`. `local_2b8` only feeds the dead branches, so its value is irrelevant.

#### Step 3 — Recognise the SplitMix64 S-box

State `0x0f6d3c2a` fills a 256-byte buffer with `iota(0..256)` through three SIMD stages (obfuscation, not real work), then Fisher-Yates shuffles it right-to-left with SplitMix64 seeded at `0x9E3779B97F4A7C15` (golden ratio). No input dependency; the S-box is a fixed 256-byte permutation.

#### Step 4 — Recognise the keystream

Same buffer is used to derive 30 output bytes:

```c
uint64_t st = (uint64_t)local_2b4 * 0x100000001B3 ^ 0xD1B54A32D192ED03;
uint8_t running_key = 0xA5;
uint8_t carrier     = 'Z';   // 0x5A

for (int i = 0; i < 30; i++) {
    st += 0x9E3779B97F4A7C15;
    prng = splitmix64_step_low_byte(st);
    mixed = (prng ^ input[i] + carrier) & 0xFF;
    idx   = rol8(mixed, i & 7);
    running_key ^= sbox[idx];
    output[i] = running_key;
    carrier = (carrier + 0x25) & 0xFF;
}
```

`local_2b4 == 0` collapses the seed to `0xD1B54A32D192ED03`, the FNV-1a 64-bit offset basis, deterministic offline.

#### Step 5 — Invert

`sbox[idx] = output[i] ^ output[i-1]` (with `output[-1] = 0xA5`). Given the S-box and its inverse:

```python
for i in range(30):
    prng = splitmix64_low_byte(state, i)
    needed_sbox_val = TARGET[i] ^ (TARGET[i-1] if i else 0xA5)
    idx = sbox_inv[needed_sbox_val]
    mixed = ror8(idx, i & 7)
    pre_add = (mixed - carrier[i]) & 0xFF
    input[i] = prng ^ pre_add
```

Recovered flag: `LYKNCTF{1S_1T_H4RD_T0_C0NTR0L}` (30 characters, all printable ASCII: sanity check).

Per-challenge README + solver: [crack/control-freak-2](https://github.com/Abdelkad3r/LYKNCTF/tree/main/crack/control-freak-2).

## Cross-cutting defender notes

Seven patterns recur across the crack track and translate directly into anti-reversing hardening (or, for defenders, into what the actual state of the art is).

**Cryptographic constants are recognition primitives.** Every keystream, S-box, or KDF in the track surfaces one of a small set of well-known values: SHA-256 IV words, TEA-family golden-ratio increments, FNV-1a offset bases and primes, SplitMix64 constants. Naming them collapses "reverse this cipher" to "identify this cipher and inverse it." For obfuscation to actually slow analysis, the primitive itself has to be non-standard or the constants have to be masked at rest (as Control Freak 2 does for its taint strings, but not for its SplitMix64 seed).

**Self-hash primitives don't need to be executed.** SHA-256 of `.text` is a static computation on the file bytes at `raw_offset .. raw_offset + VirtualSize`, unless a relocation targets `.text`. If nothing in `.reloc` does, the loader map is byte-identical to the file and Python's `hashlib` gives the same digest as the binary. This is what makes KeygenMe, Activator, Serial, and Control Freak 2 all reachable through static solvers. To defeat this, force a runtime dependency: patch a `.text` byte during startup with data that only exists in memory, or include a section that varies per install (an anti-tamper library license blob, for example).

**Anti-debug byte-poisoning is a good pattern, but only if the "wrong" output is indistinguishable from the "no answer at all" output.** KeygenMe folds the anti-debug byte into the master key so the decryption succeeds but produces garbage; a downstream signature check on the plaintext catches the garbage and takes the error path. Control Freak 2 OR-folds `local_2b4` into the compare so the wrong-flag and debugged-right-flag error messages are identical. Both patterns work by removing the "you triggered a debug check" signal from the user. Silent poisoning is much harder to reverse than a "debugger detected!" popup because the analyst spends hours convincing themselves their algorithm is wrong.

**Control-flow flattening is easy to see through if the states are cheap to run.** Control Freak 2's five states each execute in a straight line and communicate through a small set of stack variables (`local_2b4`, `local_2b8`, output buffer). Once the state graph is mapped, decompiler pattern recognition handles the rest. To make flattening actually hard, each state's work has to depend on the enclosing loop's state variable (so re-ordering breaks the algorithm), and the dispatch has to be opaque (indirect through an encrypted table, not a plain `switch`).

**Dead-code branches with even-parity conditions are a compiler artefact worth naming.** Control Freak 2's `if ((x*(x+1)) & 1)` calls to `FUN_00101c00` never fire; the compiler recognises the parity but leaves the call site in place. Similar patterns in Control Freak 1's outer loop tail. Dead-code elimination in Ghidra flags these correctly; the reviewer's job is to trust the dead-code marker rather than trace what the dead branch would have done.

**"Long SIMD blocks" are usually memcpy or iota.** Activator's 200-line SSE identity, Control Freak 2's three-stage SIMD iota fill. When a SIMD block's semantics are opaque, test it as a black-box function of inputs (identity → identity? all-`A` → all-`A`? counter → counter?). Compiler auto-vectorisation of trivial loops produces the exact same "hairy but semantically trivial" pattern as hand-obfuscated code.

**Multi-stage packers are a chain of "recognise then intercept."** Inferir Student's seven-stage ChaCha20+LZMA+marshal loader plus stage 3's AES+zlib+marshal loader is really just two `exec(marshal.loads(decrypt(blob)))` idioms. At each `exec` boundary, replace the `exec` with a dumper that writes the marshal object to disk, then disassemble. The general principle: any packer's `exec` is the extraction point.

## Frequently asked questions

### What is LYKNCTF 2026?

LYKNCTF 2026 is a CTF whose challenges span multiple categories including web, reverse-engineering (crack), pwn, and forensics. This writeup covers the nine crack (reverse-engineering) challenges I solved. The flag prefix is `LYKNCTF{...}`. Per-challenge READMEs, artifacts, and solver scripts are mirrored at [Abdelkad3r/LYKNCTF](https://github.com/Abdelkad3r/LYKNCTF). The web-track companion to this writeup is at [LYKNCTF 2026 Web Writeup](/ctf-writeups/lyknctf-2026-web-writeup/).

### What's the KeygenMe self-hash KDF and how do you compute it statically?

KeygenMe's master key is `sha256(account || 0x1f || key || 0x1f || sha256(.text) || bpl)`, where `bpl` is an anti-debug byte (zero on a clean run) and `sha256(.text)` is the SHA-256 of the `.text` section as loaded in memory. Since nothing in `.reloc` targets `.text`, the loader map is byte-identical to the raw file bytes at `raw_offset .. raw_offset + VirtualSize`, so `hashlib.sha256(pe[0x400 : 0x400 + 0x3a60]).digest()` produces the same digest as the binary. Three SHA-256 chains derive 96 bytes of keystream that XOR against the `.rdata:0x140006280` encrypted table, and the plaintext is checked with `sha256("LYKN2026" + plaintext)[:8] == 0x2679dda8691cb57d`.

### How does Activator's ARX VM cipher work?

Eight u32 registers seeded from the user's 32 inner characters, plus register 9 = `0x1BADC0DE` (round key) and register 8 = 32 (round counter). Each of 32 rounds runs: `reg[i] += reg[9]; reg[i] = rol(reg[i], N[i]); reg[i] ^= reg[(i+1) mod 8]` for `i ∈ 0..7`, then `reg[9] += 0x9E3779B9`. After all rounds, `reg[i] XOR target_word[i]` is OR-accumulated into a fail flag. `0x1BADC0DE` seed + `0x9E3779B9` (golden ratio) increment is the TEA-family fingerprint. Every op is invertible over u32; run backwards from the target with sibling registers restored in reverse order (7, 6, ..., 0) so each XOR's sibling is already the new value.

### Why does Serial need to chain the 32-bit state across characters?

The Serial checker's compare instruction only tests the low 16 bits of the VM output: `cmp word [target_table + 2*i], ax`. First glance says brute-force per character independently, and that works for character 0. But the *full* 32-bit VM result is saved back into the state slot and becomes the next character's base state. If you brute-force character 1 without threading character 0's full state forward, no candidate matches the low 16 bits of `target_table[1]`. Threading the state forward gives exactly one printable match per position.

### How does Inferir Student's multi-stage packer resolve to a static ChaCha20 decryption?

The PyInstaller wrapper contains a Python loader with seven encrypted stages (`ChaCha20 → LZMA → marshal → exec`). Six are noise; stage 3 is 407 KB and contains a second-layer packer (`AES-CBC → zlib → marshal → exec`). Intercept both `exec` calls with a dumper. The final checker imports `cryptography.hazmat.primitives.ciphers` and encrypts the user's input with ChaCha20, comparing against a 145-byte target. ChaCha20 is a stream cipher: `ciphertext = plaintext XOR keystream`, so the target bytes are the encrypted flag. Decrypt them with the same key and nonce to recover the plaintext directly.

### What are the seven tokens in Waguri2 and how do they map to Brainfuck?

The 336 KB program is made of seven unique whitespace-separated tokens: `tsumugi_rintaro`, `usami_shohei`, `natsusawa_saku`, `waguri_kaoruko`, `yorita_ayato`, `hoshina_subaru`, `kaoru_hana`. Two token pairs have matching counts (`yorita_ayato = hoshina_subaru = 1310`; `usami_shohei = natsusawa_saku = 5893`), identifying the bracket pair and the pointer-move pair. Bracket balance fixes their direction. Testing translation against the expected generated-checker prefix fixes the rest: `> < + - [ ] ,`. No `.` opcode; success means "halts before falling into a detected invariant-loop failure sink."

### Why is the flag for I HATE THIS APP just a Windows API name?

The Tauri/Rust app "prevents screenshots" by calling `user32.dll!SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)` with `WDA_EXCLUDEFROMCAPTURE = 0x11`. That's the Windows API that actually tells the compositor to exclude a window from screen capture. The app has Tauri command wrappers named `enable_capture_protection` / `disable_capture_protection`, but those are UI-level; the low-level primitive is the Win32 call. The flag is that function name in lowercase per the challenge's stated convention.

### What's the CTR IV layout in I HATE THIS APP REVENGE?

The decrypt function rejects inputs of 12 bytes or less. The first 12 bytes of the encrypted file are *not* used directly as `nonce || counter`. Instead, the counter block is reconstructed as `file[0:8] || 0x00000000 || file[8:12]`. For the sample file starting `00 11 22 33 44 55 66 77 00 00 00 07`, the CTR IV is `00 11 22 33 44 55 66 77 00 00 00 00 00 00 00 07`. The AES key is embedded in `.rdata` at `0x140c5fe10` as `H}3t%^nDw5F?cWj-XAH!Dj8AakaD9y9M`.

### What's the cross-round accumulator bug in Control Freak 1?

The three-round checker's outer loop tail includes `add r10d, 3` and `add r11d, 1`. Those registers appear inside the inner loop as `lea eax, [r10 + rdx]` (giving `k + 3·r`, not `k`) and `lea r15d, [r11 + rdx]` (giving `k + r`, which feeds the mod-7 rotate count). For round 0, both offsets are zero and a naive inverse that uses `TABLE1[k & 7]` and `rol8(s, (k % 7) + 1)` succeeds. It also passes on `os.urandom(33)` round-trips because each round is individually a bijection. It fails only on the composed three-round target because in rounds 1 and 2 the wrong slice of `TABLE1` is picked and the wrong rotate count is used. Rule: `os.urandom` round-trip proves each round is invertible in isolation; `forward(recovered) == TARGET` is the end-to-end oracle.

### How does Control Freak 2's silent taint pattern make debugging useless?

The `main()` function is control-flow-flattened into five states. State 1 runs four anti-analysis taints (timing loop threshold, `/proc/self/status TracerPid` parse, `ptrace(PTRACE_TRACEME)` failure, `getenv("LD_PRELOAD")`), each XORing a distinct 32-bit constant into a single register `local_2b4`. State 5 OR-folds the four bytes of `local_2b4` into the compare accumulator alongside the actual XOR-diff-OR against TARGET. So under a debugger, tracer, `LD_PRELOAD`, or slow environment, the compare fails regardless of what input you feed. And the error message ("Nope") is identical to the wrong-flag error, so the analyst has no signal that the environment is the problem. The solve is offline: implement the SplitMix64 S-box, the FNV-offset keystream, and the compare in Python, invert byte-by-byte, and never attach a debugger.

### What's the broader lesson from the LYKNCTF 2026 crack track?

Cryptographic primitives leave fingerprints. `0x9E3779B9` is TEA; `0xD1B54A32D192ED03` is FNV-1a; `0x6a09e667` is SHA-256 IV; `0x9c5ab3d7 * mix + 0x3f1e5c2b` is a rolling PRNG. Every challenge in the track is built out of standard primitives glued together with obfuscation. Once the primitives are recognised, the reversing is complete: the algorithm is documented in reference form and every op is invertible. The obfuscation is loud (long SIMD blocks, control-flow flattening, dead-code branches, per-instruction character-name tokens), but everything that survives the "clean run" condition is a deterministic function of the input. Read `.rodata`, name the constants, and write a Python solver.

### Where can I find the solver scripts?

Per-challenge READMEs, artifacts, and Python solvers are at [Abdelkad3r/LYKNCTF](https://github.com/Abdelkad3r/LYKNCTF). Each crack challenge has a `solve.sh` wrapper and an `exploit.py` (or `keygen.py`) that reproduces the flag statically from the handout files. None of the solvers require running the challenge binaries; every one of them extracts the algorithm from `.rodata` + disassembly and reproduces it in pure Python.

## Closing notes

Nine challenges, nine variations on "recognise the primitive, then invert it." The track's design signature is anti-analysis that punishes debuggers with silent output changes rather than loud "detected!" popups. That's a much harder shape to reverse than the reverse: an analyst who gets the algorithm right but forgets to disable a debugger will spend hours convinced the algorithm is wrong. The corresponding discipline is to solve offline whenever possible, extract constants statically from `.rodata`, and verify the recovered flag by running `forward(candidate) == TARGET` in Python before ever touching the binary.

For more reverse-engineering content on this site, the [LYKNCTF 2026 web writeup](/ctf-writeups/lyknctf-2026-web-writeup/) covers the paired web track from the same event, including a Legacy Profile Importer AES-CBC padding oracle that shares the "recognise the primitive" discipline. The [SEKAI CTF 2026 master writeup](/ctf-writeups/sekai-ctf-2026-writeup/) walks Untitled Encore (an embedded eBPF ELF inside a Windows PE with a nested verifier) alongside blockchain and web challenges. The [V1t CTF 2026 master writeup](/ctf-writeups/v1t-ctf-2026-writeup/) covers a KMDF driver plus a TCC binary in fake-packer costume, and the [RIFFHACK 2026 master writeup](/ctf-writeups/riffhack-2026-writeup/) covers the escrow-terminal format-string primitive. The full [CTF writeups index](/ctf-writeups/) is the home for everything else.

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type": "Question","name": "What is LYKNCTF 2026?","acceptedAnswer": {"@type": "Answer","text": "LYKNCTF 2026 is a CTF whose challenges span multiple categories including web, reverse-engineering (crack), pwn, and forensics. This writeup covers the nine crack (reverse-engineering) challenges I solved. Flag prefix LYKNCTF{...}. Per-challenge READMEs, artifacts, and solver scripts are mirrored at github.com/Abdelkad3r/LYKNCTF."}},
    {"@type": "Question","name": "What's the KeygenMe self-hash KDF and how do you compute it statically?","acceptedAnswer": {"@type": "Answer","text": "KeygenMe's master key is sha256(account || 0x1f || key || 0x1f || sha256(.text) || bpl). Since nothing in .reloc targets .text, the loader map is byte-identical to the raw file bytes at raw_offset .. raw_offset + VirtualSize. hashlib.sha256(pe[0x400:0x400+0x3a60]).digest() produces the same digest as the binary. Three SHA-256 chains derive 96 bytes of keystream that XOR against the .rdata:0x140006280 encrypted table; plaintext is checked with sha256('LYKN2026'+plaintext)[:8] == 0x2679dda8691cb57d."}},
    {"@type": "Question","name": "How does Activator's ARX VM cipher work?","acceptedAnswer": {"@type": "Answer","text": "Eight u32 registers seeded from the 32 inner input characters, plus reg[9] = 0x1BADC0DE (round key) and reg[8] = 32 (round counter). Each of 32 rounds: reg[i] += reg[9]; reg[i] = rol(reg[i], N[i]); reg[i] ^= reg[(i+1) mod 8] for i in 0..7, then reg[9] += 0x9E3779B9. 0x1BADC0DE + 0x9E3779B9 is the TEA-family fingerprint. Every op is invertible over u32; run backwards from target with siblings restored in reverse order."}},
    {"@type": "Question","name": "Why does Serial need to chain the 32-bit state across characters?","acceptedAnswer": {"@type": "Answer","text": "The compare only tests low 16 bits: cmp word [target_table + 2*i], ax. But the full 32-bit VM result becomes the next character's base state. Brute-forcing character 1 without threading character 0's full state forward means no candidate matches the low 16 bits of target_table[1]. Threading state gives exactly one printable match per position."}},
    {"@type": "Question","name": "How does Inferir Student's multi-stage packer resolve to a static ChaCha20 decryption?","acceptedAnswer": {"@type": "Answer","text": "PyInstaller wrapper contains a Python loader with seven encrypted stages (ChaCha20 → LZMA → marshal → exec). Stage 3 is a second-layer packer (AES-CBC → zlib → marshal → exec). Intercept both exec calls with a dumper. The final checker encrypts input with ChaCha20 and compares against a 145-byte target. ChaCha20 is a stream cipher, so target bytes are encrypted flag; decrypt with same key+nonce."}},
    {"@type": "Question","name": "What are the seven tokens in Waguri2 and how do they map to Brainfuck?","acceptedAnswer": {"@type": "Answer","text": "Seven whitespace-separated tokens. Matching counts identify pairs: yorita_ayato = hoshina_subaru = 1310 (brackets); usami_shohei = natsusawa_saku = 5893 (pointer moves). Bracket balance fixes direction. Testing prefix against generated-checker shape fixes the rest: usami_shohei=>, natsusawa_saku=<, waguri_kaoruko=+, tsumugi_rintaro=-, yorita_ayato=[, hoshina_subaru=], kaoru_hana=,. No output opcode; success = halts before failure loop."}},
    {"@type": "Question","name": "Why is the flag for I HATE THIS APP just a Windows API name?","acceptedAnswer": {"@type": "Answer","text": "The Tauri/Rust app calls user32.dll!SetWindowDisplayAffinity(hwnd, 0x11) where 0x11 = WDA_EXCLUDEFROMCAPTURE, the Windows API that excludes a window from screen capture. Tauri command wrappers (enable_capture_protection etc.) are UI-level. The low-level primitive is the Win32 call. Flag is the API name lowercase."}},
    {"@type": "Question","name": "What's the CTR IV layout in I HATE THIS APP REVENGE?","acceptedAnswer": {"@type": "Answer","text": "The first 12 bytes of the encrypted file are NOT used directly as nonce || counter. The counter block is reconstructed as file[0:8] || 0x00000000 || file[8:12]. For a file starting 00 11 22 33 44 55 66 77 00 00 00 07, the CTR IV is 00 11 22 33 44 55 66 77 00 00 00 00 00 00 00 07. AES key is embedded in .rdata at 0x140c5fe10 as H}3t%^nDw5F?cWj-XAH!Dj8AakaD9y9M."}},
    {"@type": "Question","name": "What's the cross-round accumulator bug in Control Freak 1?","acceptedAnswer": {"@type": "Answer","text": "The three-round outer loop tail includes add r10d, 3 and add r11d, 1. Those registers make the inner loop's per-index expressions k + 3*r and k + r, not k. For round 0 both offsets are zero and a naive inverse using TABLE1[k & 7] and rol8(s, (k % 7) + 1) succeeds, including on os.urandom round-trips. It fails only on the composed three-round target. Rule: os.urandom round-trip proves per-round invertibility; forward(recovered) == TARGET is the end-to-end oracle."}},
    {"@type": "Question","name": "How does Control Freak 2's silent taint pattern make debugging useless?","acceptedAnswer": {"@type": "Answer","text": "main() is CFF-flattened into five states. State 1 runs four anti-analysis taints (timing threshold, TracerPid parse, ptrace(PTRACE_TRACEME) failure, LD_PRELOAD/LD_AUDIT env) each XORing a distinct 32-bit constant into local_2b4. State 5 OR-folds local_2b4's bytes into the compare accumulator alongside the XOR-diff-OR against TARGET. Under debugger/tracer/LD_PRELOAD/slow environment, the compare fails regardless of input. Error message identical to wrong-flag. Solve offline in Python; never attach."}},
    {"@type": "Question","name": "What's the broader lesson from the LYKNCTF 2026 crack track?","acceptedAnswer": {"@type": "Answer","text": "Cryptographic primitives leave fingerprints. 0x9E3779B9 is TEA-family; 0xD1B54A32D192ED03 is FNV-1a offset basis; 0x6a09e667 is SHA-256 IV; 0x9c5ab3d7 * mix + 0x3f1e5c2b is a rolling PRNG. Every challenge is built from standard primitives glued together with obfuscation. Recognise the primitive, name the constants, write a Python solver. Everything that survives the clean-run condition is a deterministic function of the input."}},
    {"@type": "Question","name": "Where can I find the solver scripts?","acceptedAnswer": {"@type": "Answer","text": "Per-challenge READMEs, artifacts, and Python solvers at github.com/Abdelkad3r/LYKNCTF. Each crack challenge has a solve.sh wrapper and an exploit.py (or keygen.py) that reproduces the flag statically from the handout files. No solvers require running the binaries; every one extracts the algorithm from .rodata + disassembly and reproduces it in pure Python."}}
  ]
}
</script>
