---
title: "D3CTF 2026 Reverse Engineering Writeup: D3LLVM & PacMan — Mobile RE with OLLVM, MNN Runtime Trap, and Actor VM"
slug: "d3ctf-2026-reverse-writeup"
description: "D3CTF 2026 reverse engineering writeup for D3LLVM and PacMan: D3LLVM hides an ARM64 native validator VM behind OLLVM control-flow flattening inside a self-unpacking Android APK, then anchors half the AES-128-ECB flag key to MNN runtime callback operator names that differ from the static model graph — bypassed by Unicorn emulation plus MNN 3.6.1 Docker execution. PacMan is an iOS Pac-Man game whose flag is RC4-encrypted with a key derived by a 72-record deterministic actor VM baked into the ARM64 Mach-O — solved in 28 VM steps without running the game."
date: 2026-08-01T14:00:00Z
lastmod: 2026-08-01T14:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["D3CTF 2026"]
tags:
  - "d3ctf"
  - "d3ctf 2026"
  - "ctf writeup"
  - "reverse engineering"
  - "android reverse engineering"
  - "ios reverse engineering"
  - "ollvm"
  - "control flow flattening"
  - "arm64"
  - "jni"
  - "mnn"
  - "neural network"
  - "fnv1a"
  - "aes-128-ecb"
  - "actor vm"
  - "state machine"
  - "rc4"
  - "mach-o"
  - "splitmix64"
  - "unicorn emulator"
  - "mobile ctf"
  - "ctf 2026"
keywords:
  - "d3ctf 2026 reverse engineering writeup"
  - "d3llvm android apk ollvm writeup"
  - "ollvm control flow flattening ctf"
  - "mnn neural network runtime trap ctf"
  - "fnv1a64 seed derivation ctf reverse"
  - "aes-128-ecb key derivation splitmix64"
  - "unicorn arm64 emulation android jni ctf"
  - "pacman ios ipa actor vm ctf"
  - "actor state machine vm rc4 reverse"
  - "macho arm64 state machine ctf 2026"
  - "mnn callback operator name seed"
  - "d3ctf reverse engineering 2026"
  - "android native library obfuscation ctf"
  - "ios ipa reverse engineering ctf"
  - "splitmix64 mixer rc4 decrypt ctf"
toc: true
cover:
  image: "/images/articles/d3ctf-2026-reverse-writeup.png"
  alt: "D3CTF 2026 reverse engineering writeup — two challenges solved covering D3LLVM an Android APK with OLLVM control-flow flattening over a self-unpacking ARM64 native library containing a flag validator VM and an encrypted MNN model whose runtime optimizer-rewritten operator names seed a FNV-1a-64 hash XORed with the validated hex input through splitmix64 to produce an AES-128-ECB decryption key; and PacMan an iOS IPA Pac-Man game containing a 72-record deterministic actor VM in the ARM64 Mach-O deriving an RC4 key through 28 SplitMix64-style state transitions decrypting the embedded 40-byte ciphertext without playing the game"
---

D3CTF 2026's reverse engineering track put two mobile binaries in front of solvers and asked them to read the flag without running the apps in the intended way. **D3LLVM** (`app-debug.apk`) wrapped an Android native flag-validator VM inside an OLLVM-obfuscated self-unpacking ARM64 shared library, then anchored half the AES-128-ECB decryption key to the operator names that MNN's graph optimizer assigns at runtime — names that differ from what the static MNN flatbuffer stores, a deliberate trap for anyone who read the model without executing it. **PacMan** (`pacman.ipa`) hid a 72-record deterministic actor VM inside an iOS ARM64 Mach-O whose SplitMix64-style state transitions, traversed in a fixed 28-step path, produce the RC4 key needed to decrypt the flag without ever playing a round of Pac-Man.

Handouts and solver scripts live at [Abdelkad3r/D3CTF-2026](https://github.com/Abdelkad3r/D3CTF-2026/tree/master/reverse). Paired writeups: [D3CTF 2026 web writeup](/ctf-writeups/d3ctf-2026-web-writeup/), [D3CTF 2026 crypto writeup](/ctf-writeups/d3ctf-2026-crypto-writeup/), [D3CTF 2026 pwn writeup](/ctf-writeups/d3ctf-2026-pwn-writeup/).

## Challenges at a glance

| Field | D3LLVM | PacMan |
|---|---|---|
| Category | Reverse Engineering | Reverse Engineering |
| Points | — | 300 |
| Solves | — | 196 |
| Binary | Android APK (`app-debug.apk`) | iOS IPA (`pacman.ipa`) |
| Architecture | ARM64 JNI native library | ARM64 Mach-O executable |
| Core technique | OLLVM CFG flattening + native VM + encrypted MNN model + runtime operator name trap | 72-record actor VM + RC4 flag encryption |
| Flag | `d3ctf{OLLVM_is_still_somewhat_useful_for_AI}` | `d3ctf{GoOdjob!!!Y0u_@re_be5t_P4c-Man!!!}` |

---

## D3LLVM

### D3LLVM — Step 1: APK structure and JNI entry points

The APK is a standard Android debug build. The application presents a 64-character hex input field; the native library decides whether the input is accepted and, if so, reveals the flag. All interesting logic lives in the ARM64 JNI shared object.

Four JNI methods drive the flow:

```java
// FlagNative.java (decompiled)
public static native void   nativeCreate(Context ctx);
public static native void   nativeRun(float[] touchData, int len);
public static native boolean nativeVerifyInput(String hex64);
public static native String  nativeRevealFlag();
```

`nativeCreate` initialises the global state and loads the MNN model from encrypted assets. `nativeVerifyInput` takes the 64-character hex string and returns `true` if it matches the sole accepted input. `nativeRevealFlag` decrypts the flag using a key derived from the accepted input and the MNN session.

The on-disk `.so` does not contain the interesting code directly — the library unpacks a secondary payload at `Payload_OnLoad` (file offset `0x12538`) into a heap region and jumps to it. Five layers of protection are stacked:

1. OLLVM control-flow flattening on the payload's validation VM and flag-reveal path
2. Native self-unpacking (the payload is not in the on-disk `.so` directly)
3. AES-128-ECB encrypted MNN model asset (`touch_model.mnn.enc`) in the APK
4. Static model graph is a trap — MNN rewrites operator names at runtime
5. Flag key derived from both the validated hex input and the runtime MNN operator names

### D3LLVM — Step 2: OLLVM deobfuscation and native payload structure

OLLVM's control-flow flattening passes every function body through a dispatcher switch, replacing natural straight-line code with a loop over opaque state variables. This makes static analysis in IDA/Ghidra produce an incomprehensible graph of basic blocks connected only through the switch variable — useful control-flow information is hidden.

The approach that works: patch the anti-tamper helper in the payload (which checks for debugger presence and verifies the payload's own text segment hash), then emulate the payload with **Unicorn Engine** (ARM64). Unicorn executes the OLLVM-obfuscated code correctly — the obfuscation is opaque to static analysis but transparent to execution.

Key offsets in the unpacked payload (post-`Payload_OnLoad`):

```
Payload_OnLoad            0x12538   ← secondary payload entry
nativeCreate  wrapper     0x11cc0
nativeRun     wrapper     0x15808
nativeVerifyInput wrapper 0x15938
nativeRevealFlag wrapper  0x15954

Global state block:
  0x43150   touch/classifier object pointer
  0x43180   MNN cache pointer
  0x431c8   cached FNV seed value
  0x431d0   cache-ready flag
```

The global classifier state struct that `nativeVerifyInput` reads from:

```c
struct classifier_state {
    void     *interpreter;   // MNN Interpreter*
    void     *session;       // MNN Session*
    uint32_t  seq_len;       // always 64
    uint32_t  channels;      // always 5
    uint32_t  active_count;  // number of active (non-zero) positions
    uint8_t   active[64];    // which positions are active
    uint64_t  values[64];    // per-position uint64 contribution
    uint64_t  aggregate;     // sum of active values
};
```

### D3LLVM — Step 3: Recovering the accepted 64-char input via VM emulation

`nativeVerifyInput` feeds the 64-character hex string into the native VM and checks whether the computed aggregate matches a hardcoded target. Unicorn ARM64 emulation of the payload, with the anti-tamper helper patched to always return success, converges on the sole accepted input in one forward pass:

```
196f0d201332b47deb98221f33c7f4a13d03de6c2a77279c4dbc1f87e4d297a8
```

This is the value that satisfies the VM's aggregate comparison. It is also the first half of the flag key material.

### D3LLVM — Step 4: Decrypting the embedded MNN model

`nativeCreate` reads `touch_model.mnn.enc` from the APK's `assets/` folder. Hooking the native AES decrypt helper during `nativeCreate` (e.g., with Frida or at the emulator level) captures the AES-128-ECB key:

```python
AES_KEY = b"This is 3DES\x00\x00\x00\x00"  # 16 bytes
```

The decryption and decode pipeline:

```python
from Crypto.Cipher import AES
import base64

with open("touch_model.mnn.enc", "rb") as f:
    raw = f.read()

cipher = AES.new(AES_KEY, AES.MODE_ECB)
decrypted = cipher.decrypt(raw)          # raw AES-128-ECB
b64_data  = decrypted.rstrip(b"\x00")   # remove padding
mnn_bytes = base64.b64decode(b64_data)  # base64 decode
mnn_model = mnn_bytes[9:]               # skip 9-byte prefix → valid MNN FlatBuffer
```

The resulting MNN FlatBuffer contains a model graph with 39 operations. Reading operator names from the static FlatBuffer produces names like `touch`, `Unsqueeze2`, `getitem`, `max_pool1d`, `mean`, `logits__matmul_converted`, `logits`. These look like the names to use. They are not — this is the trap.

### D3LLVM — Step 5: The MNN runtime operator name trap

MNN's inference engine rewrites the computation graph at the start of each session. Its optimizer merges, fuses, and renames operators to suit the backend. The names stored in the FlatBuffer are the pre-optimization names. The names that appear in `MNN::Interpreter::runSessionWithCallBackInfo` callbacks are the post-optimization names — and they are different.

The native code derives the seed from the **post-optimization, runtime callback names**, not the static ones. Using the static names produces the wrong seed, producing the wrong AES key, producing garbage output. The only way to get the right names is to actually run the model through MNN's runtime.

Run MNN Python 3.6.1 in Docker (this specific version is required for the graph to match):

```bash
docker run --rm -it python:3.11-slim bash
pip install MNN==3.6.1 numpy
# patch execstack flag if needed:
patchelf --clear-execstack $(python -c "import _mnncengine; print(_mnncengine.__file__)")
```

```python
import MNN
import numpy as np

interp = MNN.Interpreter("touch_model.mnn")
config  = {}
session = interp.createSession(config)
inp     = interp.getSessionInput(session, None)

interp.resizeTensor(inp, [1, 64, 5])
interp.resizeSession(session)

data = np.zeros([1, 64, 5], dtype=np.float32)
inp.copyFrom(MNN.Tensor([1, 64, 5], MNN.Halide_Type_Float,
             data.flatten().tolist(), MNN.Tensor_DimensionType_Caffe))

runtime_names = []
def after_cb(name, forward_type):
    runtime_names.append(name)
    return True

interp.runSessionWithCallBackInfo(session, lambda *a: True, after_cb, False)
print(runtime_names)
```

The actual runtime operator sequence from one full forward pass:

```
getitem_raster_0
getitem
getitem_3_raster_0
getitem_3
max_pool1d_raster_0
max_pool1d
getitem_6_raster_0
getitem_6
mean_raster_0
mean_raster_1
logits__matmul_converted_raster_0
logits__matmul_converted
logits_raster_0
```

These 13 names — with the `_raster_N` suffixes that the optimizer adds — are the real seed inputs.

### D3LLVM — Step 6: Seed derivation and AES flag decryption

The native code applies FNV-1a-64 to each runtime operator name (UTF-8, no null terminator), sums all 13 hashes, multiplies the sum by 64, and uses the result as the seed:

```python
MASK = (1 << 64) - 1
FNV_OFFSET = 0xCBF29CE484222325
FNV_PRIME  = 0x100000001B3

def fnv1a64(data: bytes) -> int:
    h = FNV_OFFSET
    for b in data:
        h = ((h ^ b) * FNV_PRIME) & MASK
    return h

RUNTIME_NAMES = [
    "getitem_raster_0", "getitem",
    "getitem_3_raster_0", "getitem_3",
    "max_pool1d_raster_0", "max_pool1d",
    "getitem_6_raster_0", "getitem_6",
    "mean_raster_0", "mean_raster_1",
    "logits__matmul_converted_raster_0",
    "logits__matmul_converted",
    "logits_raster_0",
]

per_run = sum(fnv1a64(n.encode()) for n in RUNTIME_NAMES) & MASK
# per_run = 0x4280720401113ed2

seed = (per_run * 64) & MASK
# seed = 0xa01c8100444fb480
```

The AES-128-ECB key is derived from the validated password and the seed through SplitMix64:

```python
import struct

def ror64(x, n):
    return ((x >> n) | (x << (64 - n))) & MASK

def splitmix64(x):
    x = (x + 0x9E3779B97F4A7C15) & MASK
    x = ((x ^ (x >> 30)) * 0xBF58476D1CE4E5B9) & MASK
    x = ((x ^ (x >> 27)) * 0x94D049BB133111EB) & MASK
    return (x ^ (x >> 31)) & MASK

password = "196f0d201332b47deb98221f33c7f4a13d03de6c2a77279c4dbc1f87e4d297a8"
h = fnv1a64(password.encode())

key = struct.pack(
    "<QQ",
    splitmix64(h ^ seed ^ 0xD3C7F19A5EED2026),
    splitmix64(seed ^ ror64(h, 47) ^ 0xA11CE5C0DEC0DE42),
)
```

The 48-byte AES-128-ECB ciphertext embedded in the native payload:

```
f154eaeafaebf01674f062267087e584
f3842f342f59283dbf515aacf4cd01d1
51c2a502b36d45be5cb5f9b11942d2c1
```

Decryption:

```python
from Crypto.Cipher import AES

ciphertext = bytes.fromhex(
    "f154eaeafaebf01674f062267087e584"
    "f3842f342f59283dbf515aacf4cd01d1"
    "51c2a502b36d45be5cb5f9b11942d2c1"
)
flag = AES.new(key, AES.MODE_ECB).decrypt(ciphertext).rstrip(b"\x00").decode()
print(flag)
# d3ctf{OLLVM_is_still_somewhat_useful_for_AI}
```

---

## PacMan

### PacMan — Step 1: IPA structure and key Mach-O offsets

The IPA is a standard iOS app archive. Unpack it and extract the main executable:

```bash
unzip -p pacman.ipa Payload/MachActorVM.app/MachActorVM > MachActorVM
file MachActorVM
# MachActorVM: Mach-O 64-bit executable arm64
```

The bundle metadata says `com.ctf.machactorvm`, display name `PacMan`. The game requires collecting enough dots (score ≥ 10,000) to trigger the flag reveal state — but the flag is already in the binary, RC4-encrypted. No game play is needed.

Parse the Mach-O load commands (`LC_SEGMENT_64`) to build a virtual-address → file-offset map. Key constants:

```
Records table:    VA 0x10000A800  (72 entries × 24 bytes each)
Constant blob:    VA 0x10000AEC0  (encrypted VM constants)
Flag ciphertext:  VA 0x10000B3A0  (40 bytes)
Pac-Man board:    VA 0x10000B468

VM initial state: 0x13895CA3BAFED00D
VM initial index: 0x27  (decimal 39)
```

### PacMan — Step 2: Actor VM record format

Each of the 72 records is 24 bytes:

```c
struct vm_record {
    uint16_t tag;                 // transition type
    uint8_t  count;               // used by tag-specific decode
    uint8_t  encoded_next_hint;   // XORed index into next record
    uint32_t qword_index;         // index into the constant blob
    uint64_t check_a;             // verification constant A
    uint64_t check_b;             // verification constant B
};
```

Four tag values define four transition types:

| Tag | Type | Meaning |
|---|---|---|
| `0x71C3` | 3-word | Decode 3 qwords from blob, apply mixer 3 times |
| `0xC4A7` | 2-word | Decode 2 qwords from blob, apply mixer 2 times |
| `0xF06D` | Arith | Arithmetic transition using check constants |
| `0x39E1` | Terminal | Record emits the final state as RC4 key |

The core mixer is SplitMix64:

```python
MASK = (1 << 64) - 1

def mix(x: int) -> int:
    x = (x + 0x9E3779B97F4A7C15) & MASK
    x ^= x >> 30
    x = (x * 0xBF58476D1CE4E5B9) & MASK
    x ^= x >> 27
    x = (x * 0x94D049BB133111EB) & MASK
    x ^= x >> 31
    return x
```

### PacMan — Step 3: Executing the actor VM (28 deterministic steps)

The VM starts at index `0x27` with state `0x13895CA3BAFED00D`. There is a `snapshot_mix` component derived from game state, but it contributes zero to the key because the VM is designed to cancel it out through the XOR chain — you can set `snapshot_mix = 0` and still reach the correct terminal state.

The 28-step traversal path in decimal:

```
27 → 05 → 16 → 37 → 28 → 1f → 32 → 18 → 31 → 04 →
1b → 2c → 2f → 1d → 10 → 0a → 02 → 09 → 06 → 12 →
2d → 17 → 3a → 0b → 3d → 1a → 40 → 34 → 0e  (terminal)
```

The VM emulator:

```python
import struct

def load_vm(binary: bytes, va_base: int):
    """Parse records table and constant blob from Mach-O bytes."""
    rec_offset  = 0x10000A800 - va_base  # adjust for your __TEXT base
    blob_offset = 0x10000AEC0 - va_base
    records = []
    for i in range(72):
        off = rec_offset + i * 24
        tag, count, enc_hint, qw_idx, a, b = struct.unpack_from("<HBBIxx QQ", binary, off)
        records.append((tag, count, enc_hint, qw_idx, a, b))
    return records

def run_vm(records, blob: bytes, init_state: int, init_idx: int) -> int:
    state = init_state
    idx   = init_idx

    for _ in range(100):          # bound the loop
        tag, count, enc_hint, qw_idx, check_a, check_b = records[idx]

        if tag == 0x39E1:         # terminal
            return state

        if tag == 0x71C3:         # 3-word transition
            for k in range(count):
                qw = struct.unpack_from("<Q", blob, (qw_idx + k) * 8)[0]
                state = mix(state ^ qw)

        elif tag == 0xC4A7:       # 2-word transition
            for k in range(count):
                qw = struct.unpack_from("<Q", blob, (qw_idx + k) * 8)[0]
                state = mix(state ^ qw)

        elif tag == 0xF06D:       # arithmetic
            state = mix(state ^ check_a) ^ check_b

        next_idx = enc_hint ^ (state & 0x7F)
        idx = next_idx & 0x7F

    raise RuntimeError("VM did not reach terminal record")
```

After 28 steps, the terminal record at index `0x0e` emits:

```python
rc4_key = 0x5ead5b71a04140a7
```

### PacMan — Step 4: RC4 decryption

The 40-byte ciphertext is embedded at `VA 0x10000B3A0`. RC4 uses the 8-byte little-endian representation of the key:

```python
def rc4_decrypt(key64: int, ciphertext: bytes) -> bytes:
    key = key64.to_bytes(8, "little")   # LE: a7 40 41 a0 71 5b ad 5e
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i & 7]) & 0xFF
        s[i], s[j] = s[j], s[i]
    out = bytearray()
    i = j = 0
    for byte in ciphertext:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(byte ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(out)

ciphertext = bytes.fromhex(
    # 40 bytes from VA 0x10000B3A0
    "..."                # from binary at computed file offset
)
flag = rc4_decrypt(0x5ead5b71a04140a7, ciphertext).decode()
print(flag)
# d3ctf{GoOdjob!!!Y0u_@re_be5t_P4c-Man!!!}
```

The full standalone solver is `reverse/pacman/solve.py` and takes the IPA path as its sole argument. It handles the Mach-O parsing, record extraction, VM execution, and RC4 in a single script.

---

## Cross-cutting observations

**Mobile RE demands multi-architecture fluency.** Both challenges ran on ARM64 with platform-specific binary formats (APK/DEX + `.so` for Android; IPA/Mach-O for iOS). Static analysis tools (IDA Pro, Ghidra, radare2) support both formats, but the control-flow graph produced by OLLVM flattening requires either symbolic execution or actual emulation to resolve — static decompilation alone produces an unreadable dispatcher loop. Unicorn for ARM64 emulation is the practical answer for challenge-scale binaries.

**The MNN runtime trap is a genuine trap, not an accident.** D3LLVM's challenge author specifically chose to key the flag to post-optimizer operator names rather than pre-optimizer names, knowing that any solver who read the static FlatBuffer would get the wrong seed and produce garbage output. The distinguishing feature: the correct runtime names include `_raster_N` suffixes that only appear after MNN's `Raster` fusion pass runs. Noticing that the solver outputs garbage and then questioning whether the static model is what the runtime actually uses is the key insight. This pattern — using a computation that is correct only at runtime, not from the stored artifact — is increasingly common in mobile RE challenges.

**OLLVM remains effective in the post-LLM era.** The flag text `d3ctf{OLLVM_is_still_somewhat_useful_for_AI}` is a direct comment on the challenge design: control-flow flattening cannot be automatically lifted by AI decompilers or pattern-matching passes. Unicorn-based emulation sidesteps the analysis entirely by simply executing the code.

**PacMan's game gate is pure misdirection.** The snapshot check fields (score, bean count, timing, movement hashes) look like they participate in the flag derivation — and the game UI requires a specific score to show the flag. But the VM derives its key entirely from deterministic constants in the Mach-O; `snapshot_mix` XORs in a value that the VM path cancels out to zero. The game gate was designed to make solvers think they need to forge or replay a game session. They do not.

**SplitMix64 appears in both challenges.** D3LLVM uses it in the AES key derivation step; PacMan uses it as the core VM mixer. SplitMix64 is a high-quality bijective 64-bit mixing function widely used in pseudo-random number generators. Its repeated appearance in CTF challenge key-derivation chains is worth recognising: if you see the constants `0x9E3779B97F4A7C15`, `0xBF58476D1CE4E5B9`, or `0x94D049BB133111EB`, you are looking at SplitMix64 or a close variant.

---

## Frequently asked questions

**Q: What is OLLVM control-flow flattening?**
Obfuscator-LLVM (OLLVM) is a fork of LLVM that adds transformation passes targeting software protection. The control-flow flattening pass restructures every function into a single dispatch loop: a central switch variable is set before the loop, and each iteration of the loop reads the switch variable to decide which original basic block's code to execute, then updates the variable to encode the next block. The original structured CFG is destroyed — replaced by an opaque dispatcher that static analysis cannot automatically lift back to readable pseudocode. The obfuscation is transparent to execution, which is why emulation-based approaches (Unicorn, QEMU usermode) bypass it entirely.

**Q: Why does the MNN runtime produce different operator names than the static model?**
MNN's inference engine applies a graph optimization pass before running any session. The optimizer fuses, splits, and renames operations for the target backend. For example, a `slice` node followed by a `transpose` might be fused into a single `Raster` node; the original `slice` name disappears and the fused node gets a generated `_raster_0` suffix appended to the slice's former name. These are backend implementation details that the static FlatBuffer has no way to represent — the FlatBuffer stores the graph as authored by the model exporter, while the runtime stores (and emits in callbacks) the optimizer's rewritten version.

**Q: What is FNV-1a-64 and why does D3LLVM use it for the seed?**
FNV-1a (Fowler–Noll–Vo alternative) is a non-cryptographic hash function. For 64-bit: initialise `h = 0xCBF29CE484222325`; for each byte `b`, compute `h = (h XOR b) * 0x100000001B3 mod 2^64`. It is simple to implement in assembly or C without library dependencies, produces a 64-bit output, and is easy to recognise by its two constants. D3LLVM uses it because the native code was written with minimal dependencies — FNV can be inlined in a few instructions, suitable for an obfuscated native payload that imports nothing.

**Q: What is an actor VM in a CTF reverse engineering challenge?**
An actor VM is a custom interpreter whose execution model is a finite state machine: each state record specifies the current state's transition function, the next-state selector, and optional check constants. Unlike general-purpose VMs (which have instructions, a stack, and a program counter), an actor VM does not need an explicit instruction set — it encodes control flow directly in the transition table. PacMan's 72-record VM is a pure transition system: each record tells the emulator how to transform the current 64-bit state, what verification check to apply, and how to compute the next record index. The terminal record is distinguished by its tag (`0x39E1`) and emits the current state as the output value.

**Q: Why is snapshot_mix zero in the PacMan VM execution?**
The VM path is designed so that the game-state contribution XORs in and then XORs out during the 28-step traversal. The `snapshot_mix` value (derived from the 0x38-byte game-snapshot fields: score, beans, timing, movement hashes) is incorporated at a specific step, but a subsequent record XORs in a constant equal to the same `snapshot_mix` value, cancelling it. This is not an accident — it means the VM can be solved without a valid game snapshot, which is necessary for the offline solver to work. The game gate (score ≥ 10,000) only controls whether the app's UI displays the flag; it has no effect on the cryptographic derivation.

**Q: How does RC4 use the 64-bit VM terminal state as a key?**
RC4 uses an arbitrary-length byte key. The challenge uses the 64-bit VM output as 8 bytes in little-endian order — so `key = 0x5ead5b71a04140a7` becomes `[0xa7, 0x40, 0x41, 0xa0, 0x71, 0x5b, 0xad, 0x5e]`. RC4's key-scheduling algorithm repeats the 8-byte key cyclically across the 256-entry S-box initialisation (each `key[i % 8]`), then the standard keystream XOR is applied to the 40-byte ciphertext. The same keystream is never reused for a different plaintext in this challenge, so RC4's known-plaintext weaknesses are irrelevant.

**Q: What tools work best for ARM64 mobile RE CTF challenges?**
For static analysis: IDA Pro with ARM64 support or Ghidra (both handle APK `.so` files and Mach-O). For OLLVM-obfuscated binaries: Unicorn Engine (ARM64 emulation in Python) to execute code without breaking the obfuscation. For Android dynamic analysis: Frida for JNI hooking to capture runtime values (AES keys, MNN seeds). For iOS: `ipsw` or manual `unzip` to extract the Mach-O, followed by pwndbg/LLDB if dynamic analysis is possible; for purely static challenges like PacMan, a Mach-O parser plus the VM emulator in Python suffices. MNN-specific: install the exact matching version (`pip install MNN==3.6.1`) since graph optimizer behaviour differs across versions.

**Q: What is SplitMix64 and how do you recognise it in disassembly?**
SplitMix64 is a bijective 64-bit integer mixing function: add `0x9E3779B97F4A7C15` (the golden ratio as a 64-bit integer), then apply three `xor-shift-multiply` rounds with constants `0xBF58476D1CE4E5B9` and `0x94D049BB133111EB`. It is bijective (every input maps to a unique output), fast, and produces good statistical mixing. In disassembly it appears as a fixed sequence of `ADD`, `EOR`/`XOR`, `LSR`/`SHR`, and `MUL` instructions with those three constants. Recognising SplitMix64 immediately tells you the code is implementing a pseudo-random mixing step, likely in a key derivation or state transition chain.

---

## Closing notes

D3LLVM and PacMan share a design principle: the flag is always available in the binary without ever running the application in its intended mode, but a naive approach — reading the stored model, reading the static operator names, reading the VM table without executing it — produces wrong answers at every turn. D3LLVM's runtime trap requires running MNN's actual inference engine; PacMan's actor VM requires executing 28 state transitions from fixed initial conditions. In both cases the binary supplies everything needed for an offline solve, but only if you execute the right components rather than reading the right bytes.

For future mobile RE challenges: always run MNN (or any embedded inference runtime) with the exact version used by the challenge app; check whether game-state contributions are truly load-bearing or cancel out in the cryptographic path; and when you see SplitMix64 constants, expect the challenge to derive a key through iterated mixing rather than through a standard KDF.

Full writeup series: [D3CTF 2026 web writeup](/ctf-writeups/d3ctf-2026-web-writeup/), [D3CTF 2026 crypto writeup](/ctf-writeups/d3ctf-2026-crypto-writeup/), [D3CTF 2026 pwn writeup](/ctf-writeups/d3ctf-2026-pwn-writeup/). Full [CTF writeups index](/ctf-writeups/) for all events.

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {
      "@type": "Question",
      "name": "What is OLLVM control-flow flattening in reverse engineering?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Obfuscator-LLVM (OLLVM) control-flow flattening restructures every function into a single dispatch loop: a central switch variable is set before the loop, and each iteration reads the variable to decide which original basic block to execute, then updates the variable for the next block. The original control-flow graph is replaced by an opaque dispatcher that static analysis cannot automatically lift back to readable pseudocode. The obfuscation is transparent to execution — emulation with Unicorn or QEMU usermode executes the code correctly, bypassing the obfuscation entirely."
      }
    },
    {
      "@type": "Question",
      "name": "Why does the MNN runtime produce different operator names than the static model graph in D3LLVM?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "MNN's inference engine applies a graph optimization pass before running any session. The optimizer fuses, splits, and renames operations for the target backend. A slice node might be fused with a subsequent transpose into a single Raster node; the original name disappears and the fused node gets a _raster_N suffix. These runtime names only appear in MNN::Interpreter::runSessionWithCallBackInfo callbacks — they are not stored in the FlatBuffer. D3LLVM deliberately keys the flag to post-optimizer operator names (requiring MNN 3.6.1 specifically), so any solver reading the static model gets the wrong seed and produces garbage output."
      }
    },
    {
      "@type": "Question",
      "name": "What is FNV-1a-64 and how is it used in D3LLVM?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "FNV-1a-64 is a non-cryptographic hash function: initialise h = 0xCBF29CE484222325 (the FNV offset basis), then for each byte b compute h = (h XOR b) * 0x100000001B3 mod 2^64 (the FNV prime). D3LLVM applies FNV-1a-64 to each of the 13 MNN runtime callback operator names (UTF-8, no null terminator), sums all 13 hashes mod 2^64, multiplies the sum by 64, and uses the result as the seed value that feeds into the AES key derivation alongside the validated hex input hash."
      }
    },
    {
      "@type": "Question",
      "name": "What is an actor VM in a CTF reverse engineering challenge?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "An actor VM is a custom interpreter whose execution model is a finite state machine. Each record specifies the transition function, next-state selector, and check constants for one state. Unlike general-purpose VMs, an actor VM has no explicit instruction set — control flow is encoded directly in the transition table. PacMan's 72-record VM applies a SplitMix64-style mixer to a 64-bit state at each record, computes the next record index from the updated state XORed with the record's encoded_next_hint, and terminates at a record tagged 0x39E1 which emits the current state as the RC4 key."
      }
    },
    {
      "@type": "Question",
      "name": "Why is snapshot_mix zero in the PacMan actor VM execution?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "The VM path is designed so that the game-state contribution XORs in at one step and then XORs out at a subsequent step via a record whose constant equals the same snapshot_mix value, cancelling it. This means the 28-step traversal from the fixed initial state (index 0x27, state 0x13895CA3BAFED00D) always produces the same RC4 key (0x5ead5b71a04140a7) regardless of game state. The game gate (score >= 10000) only controls the UI display; it has no effect on the cryptographic key derivation."
      }
    },
    {
      "@type": "Question",
      "name": "How does RC4 use the 64-bit PacMan VM output as a key?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "RC4 accepts an arbitrary-length byte key. The challenge uses the 64-bit VM terminal state 0x5ead5b71a04140a7 as 8 bytes in little-endian order: [0xa7, 0x40, 0x41, 0xa0, 0x71, 0x5b, 0xad, 0x5e]. RC4's key-scheduling algorithm repeats this 8-byte key cyclically (key[i % 8]) across the 256-entry S-box initialisation. The standard keystream XOR is then applied to the 40-byte ciphertext at Mach-O VA 0x10000B3A0, producing the flag."
      }
    },
    {
      "@type": "Question",
      "name": "What is SplitMix64 and how do you recognise it in disassembly?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "SplitMix64 is a bijective 64-bit mixing function: add 0x9E3779B97F4A7C15, then apply three xor-shift-multiply rounds with constants 0xBF58476D1CE4E5B9 and 0x94D049BB133111EB. In ARM64 disassembly it appears as ADD, EOR, LSR, and MUL instructions in a fixed sequence with those three constants. Recognising it tells you the code is implementing a pseudo-random mixing step in a key derivation or state transition chain. Both D3CTF 2026 reverse challenges use it: D3LLVM in the AES key derivation, PacMan as the actor VM's core state mixer."
      }
    },
    {
      "@type": "Question",
      "name": "What tools are most useful for ARM64 mobile reverse engineering CTF challenges?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Static analysis: IDA Pro or Ghidra for APK native libraries and Mach-O binaries. OLLVM deobfuscation: Unicorn Engine for ARM64 emulation (executes obfuscated code without lifting it). Android dynamic analysis: Frida for JNI hooking to capture runtime AES keys and MNN seeds. MNN-specific: install the exact version pip install MNN==3.6.1 since graph optimizer output differs across versions. iOS offline solving: a Python Mach-O parser (struct unpacking of LC_SEGMENT_64 load commands) plus a custom VM emulator in Python. For the PacMan solve specifically, no dynamic analysis is needed — the VM is fully deterministic from the Mach-O constants."
      }
    }
  ]
}
</script>
