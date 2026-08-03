---
title: "BushBashCTF 2026 Reverse Engineering Writeup: COBS Framing, Z3 Template Constraints, a Compile-Time Feistel Cipher & prost Protobuf"
slug: "bushbashctf-2026-reverse-writeup"
description: "BushBashCTF 2026 reverse engineering writeup covering all six challenges: Hack The Vault I (plaintext password in .rodata of a stripped PIE ELF), password (COBS-framed login over a raw socket), the two template-metaprogramming challenges (a C++ constraint oracle solved with Z3, and a compile-time DSL interpreter that turns out to be a 16-round Feistel cipher), mystery server I (a Rust prost + COBS client with a not-yet-implemented readflag serializer built by hand), and Turned Around (a 10 KB Brainfuck program with guarded hidden branches — documented as unresolved)."
date: 2026-08-03T12:00:00Z
lastmod: 2026-08-04T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["BushBashCTF 2026"]
tags:
  - "bushbashctf"
  - "bushbashctf 2026"
  - "ctf writeup"
  - "reverse engineering"
  - "reversing"
  - "cobs"
  - "consistent overhead byte stuffing"
  - "protobuf"
  - "prost"
  - "rust reversing"
  - "template metaprogramming"
  - "c++ templates"
  - "z3"
  - "smt solver"
  - "constraint solving"
  - "feistel cipher"
  - "compile-time interpreter"
  - "brainfuck"
  - "stripped elf"
  - "ghidra"
  - "ctf 2026"
keywords:
  - "bushbashctf 2026 reverse writeup"
  - "hack the vault i ctf writeup"
  - "bushbash password cobs ctf"
  - "cobs framing ctf reverse"
  - "c++ template metaprogramming ctf z3"
  - "enable_if constraint solver ctf"
  - "compile-time feistel cipher ctf"
  - "template dsl interpreter reverse engineering"
  - "mystery server prost protobuf ctf"
  - "rust prost cobs client reverse"
  - "readflag protobuf handcraft ctf"
  - "brainfuck reverse engineering ctf"
  - "turned around bushbash brainfuck"
  - "stripped pie elf rodata password"
  - "bushbashctf reverse challenge"
toc: true
cover:
  image: "/images/articles/bushbashctf-2026-reverse-writeup.png"
  alt: "BushBashCTF 2026 reverse engineering writeup — six challenges covering Hack The Vault I a stripped PIE ELF whose password sits in plaintext in the rodata section; password a login service that speaks COBS Consistent Overhead Byte Stuffing where admin and password must be wrapped in zero-delimited frames; a C++ template metaprogramming file whose hundreds of enable_if constraints form an integer system over 214 flag bytes solved with the Z3 SMT solver; a second templates challenge that is a compile-time interpreter for a tiny imperative DSL that turns out to be a 16-round Feistel cipher inverted to recover the plaintext; mystery server I a Rust prost protobuf plus COBS client whose readflag subcommand is not yet implemented so the ClientToServer read_flag message is hand-encoded as 22 00 then COBS-framed to 02 22 01 00; and Turned Around a 10 KB Brainfuck program with guarded hidden branches extracted and re-executed to reveal two masked password fragments documented as unresolved"
---

Welcome to a **CyberSecurity Elite** reverse engineering writeup on **BushBashCTF 2026** — a tour of *where secrets hide*, and almost none of them hid in machine code. Across six challenges the answer lived in a `.rodata` string, in the framing layer around an obvious login, in a C++ compiler's constraint checker, in a Turing-tarpit DSL evaluated entirely at compile time, in a Rust client's un-implemented serializer, and in the never-taken branches of a Brainfuck program. This writeup walks all six step by step: **Hack The Vault I** (100 pts, beginner), **password** (100 pts, easy), **`\langle\rangle\langle\rangle`** (182 pts, medium), **`\langle\rangle`×6** (210 pts, medium), **mystery server I** (304 pts, medium), and **Turned Around** (292 pts, hard). Five fell cleanly; **Turned Around** is documented honestly as unresolved, with every payload the program emits and the fragment-folding problem that remained.

All binaries, source, and solvers are at [Abdelkad3r/BushBashCTF-2026](https://github.com/Abdelkad3r/BushBashCTF-2026/tree/master/reverse). Companion writeups for the same event: [Cryptography](/ctf-writeups/bushbashctf-2026-crypto-writeup/), [Binary Exploitation](/ctf-writeups/bushbashctf-2026-pwn-writeup/), [Web](/ctf-writeups/bushbashctf-2026-web-writeup/), and [Misc & OSINT](/ctf-writeups/bushbashctf-2026-misc-osint-writeup/).

## Challenges at a glance

| Challenge | Difficulty | Points | Solves | Core technique | Status |
|---|---|---|---|---|---|
| Hack The Vault I | Beginner | 100 | 270 | `strings` on a stripped PIE ELF | Solved |
| password | Easy | 100 | 190 | COBS frame encode/decode | Solved |
| `\langle\rangle\langle\rangle` | Medium | 182 | 206 | Templates → Z3 constraint solve | Solved |
| `\langle\rangle`×6 | Medium | 210 | 176 | Compile-time DSL → Feistel inversion | Solved |
| mystery server I | Medium | 304 | 109 | prost protobuf + COBS handcraft | Solved |
| Turned Around | Hard | 292 | 181 | Brainfuck guarded-branch extraction | **Unresolved** |

---

## Challenge 1 — Hack The Vault I (Beginner, 100 pts, 270 solves)

> Detective Kane here. I found a vault, right by the river, buried two feet
> underground. I dug it up — seems like I need a password. Do you know what it is?

The attachment is a stripped, PIE-enabled Linux ELF named `vault`, plus a
remote (`nc 34.40.133.67 7776`).

### Step 1 — Triage

```console
$ file vault
vault: ELF 64-bit LSB pie executable, x86-64, dynamically linked,
       interpreter /lib64/ld-linux-x86-64.so.2, stripped
```

Stripped and PIE — but the import table is tiny and *descriptive*:
`fgets`, `strlen`, `strncmp`, `fopen`, `fread`, `printf`, `puts`, `setvbuf`,
`putchar`. That import list alone sketches the whole program: print a banner,
`fgets` a line, `strncmp` it against a constant, and `fopen`/`fread`/`print`
`flag.txt` on success.

### Step 2 — Strings

The fast path in any beginner reversing challenge is `strings` before
disassembly:

```console
$ strings -a -t x vault
2348 th3M0ssM4ni5h3re,y0uc4ntcatchm3
2368 Hey. Detective Kane here. I found a vault...
240b Enter the password:
2422 flag.txt
24a0 It worked. The clues he left behind makes me believe that this case is not over just yet...
2544 Better luck next time.
```

The string at `0x2348` is the only short, secret-looking token in the binary.

### Step 3 — Confirm control flow (don't submit a decoy)

Entry passes `0x13f4` to `__libc_start_main`, so `main = 0x13f4`. The branch
that matters:

```asm
146a: call 0x1233        ; check_password()
146f: test eax, eax
1471: je   0x1489        ; failure → "Better luck next time."
1473: lea  rax, [rip+...]; success message
147d: call puts
1482: call 0x1342        ; print flag.txt
```

Inside `check_password` (`0x1233`), the input from `fgets` has its trailing
newline stripped, its length is compared to the expected length, and then a
single `strncmp` against the pointer loaded from the data section — which
points straight at `0x2348`. That `.rodata` string *is* the password; no
decoy.

### Step 4 — Solve

```console
$ printf 'th3M0ssM4ni5h3re,y0uc4ntcatchm3\n' | nc 34.40.133.67 7776
It worked. The clues he left behind makes me believe that this case is not over just yet.
bushbash{th1s-is-just-th3-beginning!}
```

### Flag

```text
bushbash{th1s-is-just-th3-beginning!}
```

**Takeaway:** "stripped + PIE" sounds intimidating but changes nothing when the
secret is a literal string. Always `strings` first; only disassemble to
*confirm* the candidate isn't a decoy.

---

## Challenge 2 — password (Easy, 100 pts, 190 solves)

> username = admin, password = password. It's a cobbled mess.

The description hands you the credentials outright — `admin` / `password` — and
a remote (`nc 34.40.133.67 6768`). Sending them plainly does nothing. The word
"cobbled" is the entire challenge: the service speaks **COBS** (Consistent
Overhead Byte Stuffing).

### Step 1 — Look at the raw bytes

Piping the banner through a hex dump instead of a terminal reveals structure a
plain `nc` hides:

```text
0d 50 6c 65 61 73 65 20 4c 6f 67 69 6e 00
18 57 61 69 74 69 6e 67 20 66 6f 72 20 75 73 65 72 6e 61 6d 65 2e 2e 2e 00
```

Every message ends in `00` and begins with a non-ASCII length byte. The first
frame is `0d` followed by exactly 12 bytes spelling `Please Login`. `0x0d = 13`
= "copy the next 12 non-zero bytes." That is textbook COBS.

### Step 2 — Why plain login fails

```console
$ printf 'admin\npassword\n' | nc 34.40.133.67 6768   # hangs — not newline-delimited
```

Sending a NUL-terminated raw string produces the tell:

```text
Error occured during decoding: 'not enough input bytes for length code'
```

The server COBS-*decodes* input before comparing it. So we must COBS-*encode*
the credentials.

### Step 3 — COBS-encode the credentials

COBS stores each run of non-zero bytes as `length || data`, where the length
byte counts itself. Neither credential contains a zero byte, so:

```text
admin    -> 06 61 64 6d 69 6e   + delimiter 00
password -> 09 70 61 73 73 77 6f 72 64 + delimiter 00
```

### Step 4 — Solve

The solver implements a dependency-free COBS encoder/decoder, reads the
zero-delimited prompts, and replies with framed `admin` then `password`:

```python
def cobs_encode(data: bytes) -> bytes:
    out, idx = bytearray(), 0
    while idx < len(data):
        start = idx; n = 0
        while idx < len(data) and data[idx] != 0 and n < 254:
            idx += 1; n += 1
        out.append(n + 1); out.extend(data[start:start + n])
        if idx < len(data) and data[idx] == 0:
            idx += 1
    if not data:
        out.append(1)
    return bytes(out)

# send_frame(sock, b"admin"); send_frame(sock, b"password")  →  cobs_encode(x) + b"\x00"
```

```text
Please Login
Waiting for username...
Waiting for password...
Your flag is bushbash{i_l0v3_C0bs}
```

### Flag

```text
bushbash{i_l0v3_C0bs}
```

**Takeaway:** the password was never hidden — the *transport* was. Recognizing a
`00`-delimited, length-prefixed stream as COBS is the whole solve. (COBS shows
up again in mystery server I.)

---

## Challenge 3 — `\langle\rangle\langle\rangle` (Medium, 182 pts, 206 solves)

The attachment `out.cpp` is a C++ source file bloated with templates, and the
one line that mattered was deleted:

```cpp
// oops it looks like somebody deleted the flag message. Can you figure out what it is?
FLAGMESSAGE(0,0,0,0,0,0,...)
```

### Step 1 — Read the template vocabulary

An undefined primary template plus a macro that specializes it 214 times means
the deleted `FLAGMESSAGE(...)` was really an array of 214 integers:

```cpp
template<int index> struct FlagValue;                 // xi := FlagValue<i>::Value
template<> struct FlagValue<0> { constexpr static int Value = flag_0; };
// ... through FlagValue<213>
```

The rest of the file is compile-time *checks* built on `std::enable_if_t`:

```cpp
template<int L,int R,typename=std::enable_if_t<L <  R>> struct Lt;
template<int L,int R,typename=std::enable_if_t<L <= R>> struct Lteq;
template<int L,int R,typename=std::enable_if_t<L >= R>> struct Gteq;
template<int L,int R,typename=std::enable_if_t<(L > R)>> struct Gt;
template<int L,int R,typename=std::enable_if_t<(L % R)==0>> struct Divides;
template<int c1,int c2,int t1,int v1,int v2,int v3,int v4,int v5,
    typename=std::enable_if_t<c1*v1 + c2*v2 + t1*v3 == v4 + v5>> struct Equ;
```

So `Equ<c1,c2,t1,v1,v2,v3,v4,v5>` encodes the linear equation
`c1·v1 + c2·v2 + t1·v3 = v4 + v5`. The program is a **constraint oracle**: if
all the integers satisfy every `enable_if_t`, the file compiles; the deleted
values are simply the unique solution.

### Step 2 — Extract the constraints

The file holds 1,581 aliases: 700 `Equ`, 317 `Lteq`, 314 `Gteq`, 106 `Lt`, 88
`Gt`, 56 `Divides`. Each references `FlagValue<i>::Value`, which we treat as a
variable `xi`. For example:

```cpp
using Constraint_0 = Equ<-19,-77,88, FlagValue<0>::Value, FlagValue<1>::Value,
                         FlagValue<4>::Value, FlagValue<91>::Value, FlagValue<191>::Value>;
// →  -19*x0 + -77*x1 + 88*x4 = x91 + x191
using Constraint_2 = Lteq<FlagValue<5>::Value * 31, 3023>;
// →  x5 * 31 <= 3023
```

### Step 3 — Feed it to Z3

The solver parses the aliases and emits SMT-LIB: 214 integer variables plus the
translated assertions.

```smt
(declare-const x0 Int) ... (declare-const x213 Int)
(assert (= (+ (* -19 x0) (* -77 x1) (* 88 x4)) (+ x91 x191)))
...
```

This is linear integer arithmetic with a few divisibility constraints — Z3
solves it instantly. Every recovered value lands in `[32, 125]` (printable
ASCII), and the vector decodes to:

```text
Congratulations on solving the challenge! ... The flag is bushbash{d1d_y0U_Us3_z3?}
```

A second `(assert (or (distinct x0 67) ...))` model asks Z3 for a *different*
solution; it returns `unsat`, proving the message is unique.

### Flag

```text
bushbash{d1d_y0U_Us3_z3?}
```

**Takeaway:** this is not "reverse the binary" — the source never needs to
compile. It's a constraint system wearing a template costume. Translate the
`enable_if_t` predicates to SMT and let Z3 do the reversing. (The flag literally
names the intended tool.)

---

## Challenge 4 — `\langle\rangle`×6 (Medium, 210 pts, 176 solves)

The sequel ships `main.cpp` (12 lines that just print `output[i]`) and a single
header `<><><><><><>.hpp` full of templates. The prompt gives a **key** and an
**encrypted message** as two integer arrays and asks how the message was
encrypted. This time the templates aren't a constraint oracle — they're a
**compile-time interpreter for a tiny imperative DSL**, and the DSL program is a
cipher.

### Step 1 — Decode the interpreter

Every identifier is deliberate four-letter gibberish. Naming each template by
its role from the outside in yields a Lisp-like evaluator:

| Garbled | Role |
|---|---|
| `IDXV<n>` | integer value cell |
| `OWRC<A,B>` | cons cell (pair) |
| `YVDD` | nil / list terminator |
| `TWDL<L,i>` | index into a list |
| `RCYK<K,V>` / `BJDC<K,Env,D>` | environment binding / lookup |
| `IEYF<Op,A,B>` | apply a binary op (`Add`/`Mul`/`Mod`/`Xor`) |
| `XBGW<Expr,Env>` | expression evaluator |
| `JLLV<Name,Expr>` | assignment |
| `JWTR<Name,Expr>` | **prepend** value onto the list stored in `Name` |
| `ITFH<Name,Rest>` | run `Rest`, then restore `Name` (local scope) |
| `KJAT<...>` / `HPFP<Stmt,N>` | sequence / repeat N times |

Once you see that `OWRC` is a cons cell, `RCYK` is a binding, and the statement
stepper threads an environment, the ~7 KB header collapses to ~30 lines of
pseudocode.

### Step 2 — Recognize the Feistel round

The inner loop, relabelled `L = FNHJ`, `R = RLGL`, running state `WVTF`, key
list `WYUQ`:

```text
repeat 16 times (round i):
    K     = key[i] * WVTF + WVTF
    R_new = L_old
    L_new = R_old ^ (((L_old + K) * 17) % 135)
WVTF = WVTF + R + F                 # running state update after each block
```

That's a textbook **16-round Feistel cipher** with round function
`F(x, K) = ((x + K)·17) mod 135`. Because `F` is XOR'd into the half, the round
is invertible by replaying the schedule in reverse. The outer driver processes
9 two-byte blocks of an 18-byte plaintext, and `main.cpp` prints the halves in
`[R1,F1,R2,F2,…,R9,F9]` order — exactly the 18-value ciphertext shape from the
prompt.

### Step 3 — Invert it

The only subtlety is the stateful `WVTF`: it updates from the *final* `R`/`F` of
each block — which are exactly the ciphertext values — so it can be replayed
forward from the ciphertext alone:

```text
WVTF_0 = 1
WVTF_{k+1} = WVTF_k + R_k + F_k     # R_k, F_k are ciphertext pairs
```

Then each block's 16 rounds unwind from `i = 15` down to `0`:

```text
K     = key[i] * WVTF + WVTF
L_old = R_new
R_old = L_new ^ (((L_old + K) * 17) % 135)
```

Running it over the nine pairs:

```text
pt = [109,97,53,66,51,95,115,102,49,78,65,101,95,110,101,88,116,63]
   = b"ma5B3_sf1NAe_neXt?"
```

The solver re-encrypts the recovered plaintext and asserts it reproduces the
ciphertext exactly — confirming the round schedule was read correctly.

### Flag

```text
bushbash{ma5B3_sf1NAe_neXt?}
```

**Takeaway:** the "obfuscation" is naming discipline plus a Turing-tarpit DSL.
The stateful `WVTF` blocks per-block decryption in isolation, but since the full
ciphertext is given, it's just an obfuscated key schedule, not a security
property. Name the primitives, spot the Feistel structure, invert mechanically.

---

## Challenge 5 — mystery server I (Medium, 304 pts, 109 solves)

> Reverse engineer this client-side binary and read the flag from the server.
> This challenge chains into a harder challenge.

The attachment is a 5.6 MB Linux x86-64 ELF `client` that speaks a custom
protocol to `34.40.133.67:6767`. It has four subcommands — `echo`, `store`,
`read`, `readflag` — and the one we want, `readflag`, is a stub that panics
with *"not yet implemented: Implement encode flag reading."* We reimplement the
missing serializer.

### Step 1 — Fingerprint the stack

```console
$ file client
client: ELF 64-bit LSB pie executable, x86-64, ..., with debug_info, not stripped
```

Debug info intact, Rust-mangled symbols. Strings name the crates:

```text
prost/src/message.rs                  → Google Protocol Buffers
cobs::dec::decode_in_place_report     → Consistent Overhead Byte Stuffing
argh_shared::CommandInfo              → tiny CLI parser
```

So the wire format is going to be **protobuf, COBS-framed** — COBS again, same
as challenge 2.

### Step 2 — Recover the .proto from .rodata

The `.rodata` carries the original schema verbatim:

```proto
message ReadFlag {}
message ClientToServer {
    oneof msg {
        string               echo_request   = 1;
        StoreMessage         store_data     = 2;
        uint32               read_msg_index = 3;
        ReadFlag             read_flag      = 4;
        ReadMultipleMessages read_multiple  = 5;
    }
}
```

Note field 5, `read_multiple` — a bulk reader wired to *no* subcommand. That's
the hook for the sequel, mystery server II.

### Step 3 — Confirm the framing from working subcommands

Each subcommand writes its bytes to stdout; redirect and hex-dump:

```text
echo --message HELLO   => 08 0a 05 48 45 4c 4c 4f 00
read  --index 255      => 04 18 ff 01 00
store --message HI      => 07 12 04 0a 02 48 49 00
```

Decoding `echo HELLO`: strip the trailing `00` delimiter, COBS-decode
`08 0a 05 48 45 4c 4c 4f` → protobuf `0a 05 48 45 4c 4c 4f` = field 1 (LEN),
length 5, `"HELLO"`. Framing confirmed: `COBS(protobuf) || 0x00`.

### Step 4 — Hand-build the ReadFlag frame

`ReadFlag` is empty, so `ClientToServer{ read_flag: {} }` is just its tag plus a
zero-length submessage:

```text
tag   = (4 << 3) | 2 (LEN) = 0x22
length = 0
protobuf = 22 00
```

Now COBS-encode `22 00`. The **encoder gotcha** is the whole difficulty of the
challenge: the payload *ends on a `0x00`*, so a naive encoder that stops when
input is exhausted emits `02 22 00` and the server rejects it with *"Bad
protobuf encoding error."* You must emit an extra length-1 (empty) block for the
trailing zero:

```text
02 22 01   +   frame delimiter 00   →   02 22 01 00
```

### Step 5 — Fire it

```text
[+] protobuf: 2200
[+] COBS   : 02220100
[+] decoded: Your flag is bushbash{n0w_d0_t5e_oth4r_tw0}. You should submit
             this flag to the first mystery-server challenge.
```

The response is itself `COBS(ServerResponse protobuf)`: drop the trailing `00`,
COBS-decode, then `0a 6f <111 bytes>` = field 1 string. The solver validates its
COBS encoder against every capture from step 3 so the trailing-zero bug can't
regress.

### Flag

```text
bushbash{n0w_d0_t5e_oth4r_tw0}
```

**Takeaway:** debug-info Rust binaries hand you the protocol — `prost` + `cobs`
in the strings, the `.proto` in `.rodata`, and byte captures from the working
subcommands to validate against. The only real reversing is the COBS
trailing-zero edge case. The unused `read_multiple` arm is the drop-in plumbing
for mystery server II.

---

## Challenge 6 — Turned Around (Hard, 292 pts, 181 solves)

> One of our devices has odd malware installed. Root's password was changed —
> the hacker may have left it within this code somewhere. Flag: `bushbash{password}`.

**Status: unresolved.** I recovered every payload the program emits but could
not fold the two hidden fragments into the exact string the grader accepts. This
section documents the full extraction and the fragment problem that remained.

### Step 1 — Run it naively

`turnedaround.bf` is a 10 KB Brainfuck program. Executed as-is it prints only:

```text
Nice try! Unfortunately it's not that easy...
```

The other ~99% of the code is four *guarded* blocks that the default execution
never enters — their guard cells are all `0` by construction.

### Step 2 — Understand the structure

The recurring prefix is a character generator:

```brainfuck
++++++[>>+++++<++[>>+++++<<-]+++[>>>+++++<<<-]<-]>>++>+++++>+++++++<
```

Six outer iterations leave cell 2 = 32 (`' '`), cell 3 = 65 (`'A'`), cell 4 = 97
(`'a'`); subsequent `+`/`-` are character-offset arithmetic. Stripped of dead
decoration, the program seeds those cells, prints the "Nice try" line, then sets
up four guarded branches whose guards are never satisfied on the default path.

### Step 3 — Extract and force each branch

Each hidden body carries its *own* copy of the seed loop, so it runs standalone
from a clean tape. Extracting each block's character range and executing it in
isolation recovers:

| Body | Output when forced |
|---|---|
| Branch 1 | `You can't break through my program that easy >:3` |
| Branch 2 | `Core Dumped! Recovered partial password: (d0Ub13*_______` |
| Branch 3 | `ACHTUNG! Bzzt! @w@` |
| Big block (~7.7 KB) | `TODO: Remove this note where I hide half my hidden password: ________-*b4ck!` |

The big block builds a NUL-terminated string in cells 8..84 and prints it with
`>>>>>[.>]<[[-]<]` (walk forward printing until a `0`, then walk back zeroing).

### Step 4 — The fragment problem

The two password lines are each 15 characters with complementary masks:

```text
Branch 2 : (d0Ub13*_______     first 8 revealed, last 7 masked
Big block: ________-*b4ck!     first 8 masked, last 7 revealed
```

Overlaying "visible wins" gives `(d0Ub13*-*b4ck!` — a leet reading of
*"(double\*-\*back!"*, matching the title *Turned Around* ("double back"). Both
that overlay and its reversal `!kc4b*-*31bU0d(` were submitted and **rejected**.

Candidate interpretations that remain plausible for a future attempt:

* strip the parenthesis/bang: `d0Ub13*-*b4ck`
* collapse the `*` separators: `(d0Ub13-b4ck!)` / `d0Ub13-b4ck`
* swap-concatenate the halves: `-*b4ck!(d0Ub13*`

### Reproduction

```text
default    : "Nice try! Unfortunately it's not that easy...\n"
branch 2   : 'Core Dumped! Recovered partial password: (d0Ub13*_______\n'
big block  : 'TODO: ... where I hide half my hidden password: ________-*b4ck!\n'
combined   : '(d0Ub13*-*b4ck!'
```

**Takeaway:** the real reversing step is *finding* the hidden branches — every
guard cell is `0`, so normal execution never touches them, and the title's
obvious lure (reverse/negate the source) doesn't unlock them either. Extracting
each guarded body and re-executing from a clean tape works because each body
carries its own seed loop. What remains is deciding exactly how the grader wants
the two fragments folded together.

---

## Cross-cutting notes

**The secret is rarely in the machine code.** Five of these six challenges hide
the answer somewhere *other* than compiled instructions: a `.rodata` string
(Hack The Vault I), a framing layer (password), the compiler's constraint
checker (`\langle\rangle\langle\rangle`), a compile-time DSL (`\langle\rangle`×6),
an un-implemented serializer plus the `.proto` in `.rodata` (mystery server I),
and never-taken branches (Turned Around). Reversing is about locating *where the
computation actually lives* before touching a disassembler.

**COBS is a recurring CTF framing primitive.** It appeared in two separate
challenges here. Any `0x00`-delimited, length-prefixed byte stream is almost
certainly COBS: the first byte of each block is `1 + (number of following
non-zero bytes)`, and a lone `0x00` is the frame boundary. The one trap — as
mystery server I demonstrates — is a payload that *ends* on `0x00`: you must emit
an extra length-1 block before the delimiter, or the decoder sees a truncated
message.

**Template metaprogramming is a computation you can lift, not run.** Both
`\langle\rangle` challenges refuse to be "compiled and stepped" usefully. The
first is a constraint system — translate `enable_if_t` predicates to SMT and let
Z3 solve. The second is an interpreter — name the cons cells, bindings, and
statement stepper, and the header collapses to pseudocode you can re-implement
in Python. Recognizing the *paradigm* (constraint oracle vs. DSL evaluator) is
the whole game.

**Debug info and shipped schemas are gifts — take them.** mystery server I
ships an unstripped Rust binary whose strings name every crate and whose
`.rodata` contains the literal `.proto`. When a challenge author leaves the
protocol lying around, the "reversing" reduces to matching working captures
byte-for-byte and filling the one missing message.

**Read prompts and titles as hints, but verify.** `\langle\rangle\langle\rangle`
names its intended solver in the flag (`z3`), and Turned Around's title
("double back") describes the fragment content — yet the obvious overlay was
still rejected. Titles point you at the *idea*; the grader wants the *exact*
string.

---

## Frequently Asked Questions

**Q: How do you find a password in a stripped ELF like Hack The Vault I?**

Stripping removes symbol names, not string data. Run `strings -a -t x vault`
and look for the single short, secret-looking token among the banner text. Then
confirm it's the real password (not a decoy) by checking the control flow: here,
`main` calls a checker that `strncmp`s the input against a pointer into
`.rodata` that points straight at the candidate. PIE and stripping change
addresses, not the fact that the secret is a literal string.

**Q: What is COBS and how do I recognize it in a CTF?**

COBS (Consistent Overhead Byte Stuffing) is a framing scheme that encodes a
byte stream so a single `0x00` can serve as an unambiguous frame delimiter.
Each block is `length_byte || data`, where the length byte equals `1 + number
of following non-zero bytes`. You recognize it when every message ends in `0x00`
and starts with a small non-ASCII byte that exactly counts the printable bytes
after it — e.g. `0d "Please Login"` where `0x0d = 13` copies the next 12 bytes.

**Q: What is the COBS trailing-zero bug in mystery server I?**

When the payload ends on a `0x00` byte (here the protobuf `22 00`), a naive
encoder that stops at end-of-input emits `02 22 00` — but that's a truncated
frame. COBS requires an additional length-1 (empty) block to represent the
final zero, so the correct encoding is `02 22 01` followed by the `00`
delimiter → `02 22 01 00`. The server rejects the truncated form with "Bad
protobuf encoding error."

**Q: Why solve a C++ template file with Z3 instead of compiling it?**

The `\langle\rangle\langle\rangle` source is a constraint oracle: hundreds of
`std::enable_if_t` predicates over 214 integer "flag" values. It only compiles
if all constraints hold, and the deleted `FLAGMESSAGE(...)` arguments are the
unique solution. Rather than reason through the templates by hand, translate
each alias to a linear-integer / divisibility assertion and let Z3 recover the
214 values directly — they decode to printable ASCII containing the flag.

**Q: How is `\langle\rangle`×6 a Feistel cipher if it's "just templates"?**

The header is a compile-time interpreter for a small imperative DSL. Once the
garbled template names are relabelled (cons cells, environment bindings, a
statement stepper), the DSL program reads as a 16-round loop that swaps two
halves and XORs in `F(x,K) = ((x+K)·17) mod 135` — a textbook Feistel round.
Because the round function is XOR'd, running the same key schedule in reverse
inverts all 16 rounds and recovers the plaintext.

**Q: Why is Turned Around marked unresolved if you recovered the fragments?**

Extracting the guarded Brainfuck branches yields two complementary 15-character
fragments — `(d0Ub13*_______` and `________-*b4ck!` — that overlay to
`(d0Ub13*-*b4ck!`. Both that string and its reversal were submitted and
rejected by the grader, so the exact expected transformation of the two
fragments into the password was never confirmed during the CTF. The writeup
lists the remaining candidate interpretations.

**Q: What are the flags for the BushBashCTF 2026 reverse challenges?**

Hack The Vault I: `bushbash{th1s-is-just-th3-beginning!}`. password:
`bushbash{i_l0v3_C0bs}`. `\langle\rangle\langle\rangle`:
`bushbash{d1d_y0U_Us3_z3?}`. `\langle\rangle`×6: `bushbash{ma5B3_sf1NAe_neXt?}`.
mystery server I: `bushbash{n0w_d0_t5e_oth4r_tw0}`. Turned Around: unresolved.

```json
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {
      "@type": "Question",
      "name": "How do you find a password in a stripped ELF like Hack The Vault I?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Stripping removes symbol names, not string data. Run strings -a -t x on the binary and look for the single short secret-looking token among the banner text, then confirm it via control flow: main calls a checker that strncmp compares the input against a pointer into .rodata that points at the candidate. PIE and stripping change addresses, not the fact that the secret is a literal string. The password is th3M0ssM4ni5h3re,y0uc4ntcatchm3."
      }
    },
    {
      "@type": "Question",
      "name": "What is COBS and how do I recognize it in a CTF?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "COBS (Consistent Overhead Byte Stuffing) is a framing scheme that encodes a byte stream so a single 0x00 byte can serve as an unambiguous frame delimiter. Each block is a length byte followed by data, where the length byte equals 1 plus the number of following non-zero bytes. You recognize it when every message ends in 0x00 and starts with a small non-ASCII byte that exactly counts the printable bytes after it, for example 0x0d followed by the 12 bytes of Please Login."
      }
    },
    {
      "@type": "Question",
      "name": "What is the COBS trailing-zero bug in mystery server I?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "When the payload ends on a 0x00 byte, such as the protobuf 22 00, a naive encoder that stops at end of input emits 02 22 00, which is a truncated frame. COBS requires an additional length-1 empty block to represent the final zero, so the correct encoding is 02 22 01 followed by the 00 delimiter, giving 02 22 01 00. The server rejects the truncated form with a Bad protobuf encoding error."
      }
    },
    {
      "@type": "Question",
      "name": "Why solve a C++ template file with Z3 instead of compiling it?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "The challenge source is a constraint oracle: hundreds of std::enable_if_t predicates over 214 integer flag values. It only compiles if all constraints hold, and the deleted FLAGMESSAGE arguments are the unique solution. Rather than reason through the templates by hand, translate each alias into a linear-integer or divisibility assertion and let the Z3 SMT solver recover the 214 values directly. They decode to printable ASCII containing the flag bushbash{d1d_y0U_Us3_z3?}."
      }
    },
    {
      "@type": "Question",
      "name": "How is the second templates challenge a Feistel cipher if it is just templates?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "The header is a compile-time interpreter for a small imperative DSL. Once the garbled template names are relabelled into cons cells, environment bindings, and a statement stepper, the DSL program reads as a 16-round loop that swaps two halves and XORs in a round function F(x,K) = ((x+K)*17) mod 135, which is a textbook Feistel round. Because the round function is XOR'd into a half, running the same key schedule in reverse inverts all 16 rounds and recovers the plaintext ma5B3_sf1NAe_neXt?."
      }
    },
    {
      "@type": "Question",
      "name": "Why is Turned Around marked unresolved if the fragments were recovered?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Extracting the guarded Brainfuck branches yields two complementary 15-character fragments, (d0Ub13*_______ and ________-*b4ck!, that overlay to (d0Ub13*-*b4ck!. Both that string and its reversal !kc4b*-*31bU0d( were submitted and rejected by the grader, so the exact expected transformation of the two fragments into the accepted password was never confirmed during the CTF window. Remaining candidates include stripping the parenthesis and bang or collapsing the star separators."
      }
    },
    {
      "@type": "Question",
      "name": "What are the flags for the BushBashCTF 2026 reverse engineering challenges?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Hack The Vault I: bushbash{th1s-is-just-th3-beginning!}. password: bushbash{i_l0v3_C0bs}. The first templates challenge: bushbash{d1d_y0U_Us3_z3?}. The second templates challenge: bushbash{ma5B3_sf1NAe_neXt?}. mystery server I: bushbash{n0w_d0_t5e_oth4r_tw0}. Turned Around remained unresolved."
      }
    }
  ]
}
```
