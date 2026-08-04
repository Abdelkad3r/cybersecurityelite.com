---
title: "GPN CTF 2026 — Leftover Leftovers: One-Byte JVM AOT Cache Patch"
slug: "gpn-ctf-2026-leftover-leftovers"
description: "GPN CTF 2026 Reverse: flip iconst_0 to iconst_1 inside the JVM AOT cache to bypass a homemade verifyStuff hash check. verifyStuff hashes class structure, not bytecode."
date: 2026-06-07T18:45:00Z
lastmod: 2026-08-04T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
tags:
  - "gpn ctf 2026"
  - "leftover leftovers"
  - "jvm aot cache"
  - "constmethod bytecode patch"
  - "javalin"
  - "cds archive"
  - "jdk patched"
  - "verifyStuff hash"
  - "iconst_0 iconst_1"
series: ["GPN CTF 2026"]
keywords:
  - "gpn ctf leftover leftovers writeup"
  - "jvm aot cache override"
  - "constmethod bytecode tampering"
  - "javalin verifyStuff bypass"
  - "cds archive patch ctf"
  - "iconst_0 iconst_1 one byte patch"
toc: true
cover:
  image: "/images/articles/gpn-ctf-2026-leftover-leftovers.png"
  alt: "GPN CTF 2026 Leftover Leftovers writeup — one-byte iconst_0 → iconst_1 patch inside the JVM AOT cache bypasses a verifyStuff hash check"
---

{{< ctf-meta platform="GPN CTF 2026 (kitctf)" difficulty="Medium-Hard" os="Reverse — JVM AOT cache, Javalin, JEP 295 CDS archive" skills="reading a JVM AOT cache's ConstMethodView blob, locating a per-method bytecode body inside a 51 MB CDS archive, identifying that the upload validator hashes class structure not bytecode bytes, patching one byte (iconst_0 → iconst_1) to flip a verifier's return, then chaining the original leftovers exploit on Stage 2" >}}

**Leftover Leftovers** is the **GPN CTF 2026** follow-on to `leftovers`, and this **CyberSecurity Elite** reverse writeup walks it end to end. The challenge bolts an upload-and-validate stage on the front: a Javalin server lets you `POST /init` a candidate `cache.aot`, runs `verifyStuff` on it, and if the hash matches the original it writes `/tmp/cache.aot` for the original `leftovers` Server to consume.

The bundled `cache.aot` has the password-check method `Server.lambda$main$15` reduced to **5 bytes**:

```
03 b8 11 00 b0    iconst_0; invokestatic Boolean.valueOf; areturn
```

— password validation hard-wired to return `Boolean.FALSE`. The exploit is a **one-byte patch**: flip `iconst_0` (`0x03`) to `iconst_1` (`0x04`) at file offset `0x1F05A88`. `verifyStuff` doesn't include method bytecode in its hash, so the patched cache survives the upload check. Stage 2 then accepts any password, and the standard `leftovers` exploitation reads `/flag`:

```
GPNCTF{I_HoPE_thE_c4cHE_i5_nevER_Pr0vided_8y_1Ibr4RI35}
```

This is the standalone deep-dive on `reverse/leftover-leftovers` from the [GPN CTF 2026 master writeup](/ctf-writeups/gpn-ctf-2026-writeup/). Full source at [`reverse/leftover-leftovers`](https://github.com/Abdelkad3r/gpn-ctf-2026/tree/master/reverse/leftover-leftovers).

## Two-stage layout

`exec.sh` reveals the structure:

```bash
"$JAVA" ... -XX:AOTCache="$OUTER_CACHE_FILE" \
        -cp "$JAR" de.kitctf.gpn24.leftovers2.OuterServer serve \
            "/tmp/cache.aot" "$CACHE_FILE"
"$JAVA" ... -XX:AOTCache="/tmp/cache.aot" -jar "$JAR"
```

The JAR's `de/kitctf/gpn24/leftovers2/` directory has **no** `.class` files — only `pom.xml` and `pom.properties`. So `OuterServer` is loaded out of `outer-cache.aot` exclusively (JEP 295 AOT cache).

Stage 1 (`OuterServer`) exposes:

- `GET /cache` — returns the original `cache.aot`.
- `POST /init` — multipart upload of a candidate `cache.aot`, runs `verifyStuff(uploaded)`, if hash matches writes to `/tmp/cache.aot` and exits.

Stage 2 is the `leftovers` Server running against the just-written `/tmp/cache.aot`.

## Mapping out `verifyStuff`

`OuterServer`'s class metadata lives in `outer-cache.aot`. Following Symbol-pointer chains (in-memory base `0x800000000`), the class constant pool shows:

| Symbol                                                          | Meaning                |
|-----------------------------------------------------------------|------------------------|
| `verifyStuff`                                                   | the validator method   |
| `(L…/AotCache;)Ljava/lang/String;`                              | signature of validator |
| `(L…/InstanceKlassView;)Ljava/lang/String;`                     | per-class hash lambda  |
| `(L…/MethodView;)Ljava/lang/Long;`                              | per-method hash lambda |

…plus parsers `ArchiveReader`, `ArchiveHeaderView`, `PointerResolver`, `CompactHashtableReader`, `SerializedRootsReader`, `InstanceKlassView`, `ConstantPoolView`, `ConstantPoolView$ConstantPoolEntryView`, `MethodView`, `ConstMethodView`, `RunTimeClassInfoView`, `ArchiveRegionView`. The author wrote a small CDS-format parser and a hash of *selected* metadata.

The challenge hint **"sorting my leftovers first sounds like a good idea"** matters here: `verifyStuff` iterates a `Map<String, InstanceKlassView>`. Without sorting keys, two semantically-equivalent caches whose Klass entries land in different bucket order produce different hashes. To stay deterministic we mustn't add, remove, or relocate any class — patches have to be done in place.

## The cheeky cache

Looking up `lambda$main$15`'s Symbol in `cache.aot` (file offset `0x1467086`) and following the same pointer-table trick to the `ConstMethod` (file offset `0x1F05A50`), the body is just five bytes:

```
[01F05A88]  03 b8 11 00 b0
            ^^ iconst_0  (push 0/false)
               ^^^^^^^^ invokestatic Boolean.valueOf
                        ^^ areturn
```

`return Boolean.FALSE;` — full stop. The Javalin validator's error message is also swapped: the cache contains `Password login is currently disabled`, which the live server returns.

## The one-byte patch

```python
with open("cache_patched.aot", "r+b") as f:
    f.seek(0x1F05A88)
    f.write(bytes([0x04]))   # iconst_0 (0x03) → iconst_1 (0x04)
```

Now the body is `04 b8 11 00 b0` = `return Boolean.TRUE`. Same length, same offsets, every other byte of the 51 MB cache unchanged.

## Why `verifyStuff` doesn't notice

`verifyStuff` combines:

- A per-Klass hash depending only on `ConstantPoolView` and per-method `(name, signature)`.
- A per-method hash from `(name, signature)` — **not** the bytecode bytes inside `ConstMethodView`.

Empirical verification: uploading the patched cache is accepted, and Stage 2 boots with our modified body live.

If the hash *did* include the body, we'd be forced to find a five-byte sequence that (a) returns `true` and (b) collides under whatever per-method `Long` the lambda produces. The "sorting" hint keeps Klass iteration order canonical between the original recording and our upload, but in-place body edits are free.

## Exploitation chain

```
$ python3 solve.py cache.aot https://<instance>.gpn24.ctf.kitctf.de
Patched cache → /tmp/cache_patched.aot  (1 byte at 0x1F05A88: 03 → 04)
Uploading to .../init … (this takes ~90s; Stage 1 closes the connection
after the handoff)
Exploiting Stage 2 …
Flag: GPNCTF{I_HoPE_thE_c4cHE_i5_nevER_Pr0vided_8y_1Ibr4RI35}
```

The Stage 2 chain is the original `leftovers` exploit: with `lambda$main$15` returning `true`, `POST /set-image-dir` accepts any password, we re-point `folderPath` to `/`, `PUT /products/flag` registers a Product, `GET /images/flag` reads `/flag`.

## Reflection — the two-act lesson

The flag spells it out: **"I hope the cache is never provided by libraries"**. The two `leftovers` challenges together teach the same lesson from two angles:

1. **Leftovers I.** The bundled AOT cache replaced a 41-byte method body with a 321-byte ROT13/XOR puzzle. Static analysis of the JAR's `lambda$main$15` showed `equals("supersecret")`, but the *live* method was something else entirely.
2. **Leftovers II.** The bundled AOT cache reduces the same method to five bytes (`return Boolean.FALSE`) **and** wraps the loader in a validation stage that hash-checks any replacement cache. The author tries to convince you that you can't tamper with the cache, but the validator hashes class *structure*, not bytecode — so a single byte still flips the world.

The `-Wno-discarded-qualifiers` flag in the original Dockerfile is the breadcrumb in both challenges: the JDK was patched to allow writing into normally-`const` regions of the CDS archive, which is how the substitute method bodies were stitched in without invalidating the cache header.

## Defender takeaway

- **AOT caches are part of your TCB.** JEP 295 (JVM AOT) caches store compiled method bodies that the runtime trusts. If your deployment ships the JAR plus the AOT cache, the JAR's signature does not cover the cache. Pin the cache hash separately and verify before load.
- **"Hash the structure" is not the same as "hash the bytecode."** The original author's mistake was hashing per-method `(name, signature)` instead of per-method body bytes. The same bug appears in any system that hashes "interesting" metadata while skipping the field that actually matters.
- **Trust boundary across precompiled artefacts is broader than the JVM.** Python `__pycache__`, Ruby YARV, Lua `luac` bytecode all inherit the integrity properties of the artefact, not the source. Any tool that consumes precompiled artefacts inherits the same risk.

## Frequently asked questions

### What's the difference between leftovers and leftover-leftovers?

`leftovers` introduces the AOT-cache override primitive: the bundled `cache.aot` contains a substituted `lambda$main$15` method body that the JVM runs instead of the bytecode in the JAR. `leftover-leftovers` adds an outer Javalin server that hash-checks any uploaded replacement cache. Same delivery vehicle, new validation layer — bypassed with a one-byte patch.

### Why does `verifyStuff` hash only structure?

The author's `verifyStuff` iterates `InstanceKlassView`s and hashes `(constant_pool, (method_name, method_signature))` per method. Method bodies — the `ConstMethodView` bytecode bytes — are not in the hash input. Likely an oversight; including bodies would make the verification fully sound. Empirically confirmed by uploading the patched cache and observing it accepted.

### Why does the patched method body fit in five bytes?

JVM bytecode is byte-coded. `iconst_0` (0x03) pushes 0 onto the stack — 1 byte. `invokestatic Boolean.valueOf` (0xB8) plus 2-byte constant pool index — 3 bytes. `areturn` (0xB0) — 1 byte. Total: 5 bytes for `return Boolean.FALSE`. Flipping `iconst_0` to `iconst_1` gives `return Boolean.TRUE` in the same 5 bytes — no length change, no offset shift.

### Why is the "sorting my leftovers" hint important?

`verifyStuff` iterates a `Map<String, InstanceKlassView>`. HashMaps don't preserve insertion order; the iteration order depends on hash buckets. Two semantically-equivalent caches whose Klass entries land in different bucket order produce different verifier hashes. The hint tells us to keep iteration order canonical — which means in-place patches only, no class additions/removals/reorderings.

### How does Stage 2 exploitation work?

Once `lambda$main$15` returns `true`, the password check passes for any input. `POST /set-image-dir` then accepts a malicious request that re-points `folderPath` to `/`. `PUT /products/flag` registers a Product whose image path resolves to `/flag`. `GET /images/flag` reads `/flag` directly. This is the standard `leftovers` chain.

### How was the substituted method body stitched into the cache?

The Dockerfile builds a patched JDK with `-Wno-discarded-qualifiers`, which lets the JDK write into normally-`const` regions of the CDS archive (the section that contains `ConstMethodView` bodies). With that, the author wrote a recording-time hook that swapped the original 41-byte body for the 5-byte `return Boolean.FALSE` stub. The patched JDK is bundled with the challenge so the JVM accepts the modified cache without verification errors.

### Where can I find the solver?

Full source at [`reverse/leftover-leftovers/solve.py`](https://github.com/Abdelkad3r/gpn-ctf-2026/tree/master/reverse/leftover-leftovers). Master writeup at [/ctf-writeups/gpn-ctf-2026-writeup/](/ctf-writeups/gpn-ctf-2026-writeup/).

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type": "Question","name": "What's the difference between leftovers and leftover-leftovers?","acceptedAnswer": {"@type": "Answer","text": "leftovers introduces the AOT-cache override primitive: the bundled cache.aot contains a substituted lambda$main$15 method body that the JVM runs instead of the bytecode in the JAR. leftover-leftovers adds an outer Javalin server that hash-checks any uploaded replacement cache. Same delivery vehicle, new validation layer — bypassed with a one-byte patch."}},
    {"@type": "Question","name": "Why does verifyStuff hash only structure?","acceptedAnswer": {"@type": "Answer","text": "verifyStuff iterates InstanceKlassViews and hashes (constant_pool, (method_name, method_signature)) per method. Method bodies — ConstMethodView bytecode bytes — are not in the hash input. Likely an oversight; including bodies would make the verification fully sound. Empirically confirmed by uploading the patched cache."}},
    {"@type": "Question","name": "Why does the patched method body fit in five bytes?","acceptedAnswer": {"@type": "Answer","text": "JVM bytecode is byte-coded. iconst_0 (0x03) pushes 0 — 1 byte. invokestatic Boolean.valueOf (0xB8) plus 2-byte CP index — 3 bytes. areturn (0xB0) — 1 byte. Total: 5 bytes for return Boolean.FALSE. Flipping iconst_0 to iconst_1 gives return Boolean.TRUE in the same 5 bytes — no length change, no offset shift."}},
    {"@type": "Question","name": "Why is the sorting my leftovers hint important?","acceptedAnswer": {"@type": "Answer","text": "verifyStuff iterates a Map<String, InstanceKlassView>. HashMaps don't preserve insertion order; iteration depends on hash buckets. Two semantically-equivalent caches whose Klass entries land in different buckets produce different verifier hashes. The hint says keep iteration canonical — in-place patches only."}},
    {"@type": "Question","name": "How does Stage 2 exploitation work?","acceptedAnswer": {"@type": "Answer","text": "Once lambda$main$15 returns true, the password check passes for any input. POST /set-image-dir accepts a malicious request that re-points folderPath to /. PUT /products/flag registers a Product whose image resolves to /flag. GET /images/flag reads /flag directly. Standard leftovers chain."}},
    {"@type": "Question","name": "How was the substituted method body stitched into the cache?","acceptedAnswer": {"@type": "Answer","text": "The Dockerfile builds a patched JDK with -Wno-discarded-qualifiers, letting the JDK write into normally-const CDS archive regions (where ConstMethodView bodies live). A recording-time hook swapped the original 41-byte body for the 5-byte return Boolean.FALSE stub. The patched JDK is bundled so the JVM accepts the modified cache."}},
    {"@type": "Question","name": "Where can I find the solver code?","acceptedAnswer": {"@type": "Answer","text": "Full source at reverse/leftover-leftovers/solve.py in github.com/Abdelkad3r/gpn-ctf-2026. Master writeup at cybersecurityelite.com/ctf-writeups/gpn-ctf-2026-writeup/."}}
  ]
}
</script>
