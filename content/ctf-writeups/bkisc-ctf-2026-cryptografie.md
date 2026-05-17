---
title: "BKISC CTF 2026: Cryptografie Writeup — Java FileSystemPreferences AltBase64 over UTF-16 BE"
slug: "bkisc-ctf-2026-cryptografie"
description: "BKISC CTF 2026 Cryptografie walkthrough — decoding a ciphertext produced by the JDK's FileSystemPreferences.dirName() helper, which uses an unusual 64-symbol no-uppercase Base64 alphabet over the UTF-16 big-endian bytes of the source string."
date: 2026-05-16T02:00:00Z
lastmod: 2026-05-16T02:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
tags: ["bkisc", "bkisc-ctf", "crypto", "base64", "java", "encoding"]
series: ["BKISC CTF 2026"]
keywords: ["bkisc ctf 2026 cryptografie writeup", "java filesystempreferences dirname", "java altbase64 decoder", "altbase64 alphabet", "utf-16 base64 ctf"]
toc: true
cover:
  image: "/images/bkisc.png"
  alt: "BKISC CTF 2026 Cryptografie writeup"
---

{{< ctf-meta platform="BKISC CTF 2026" difficulty="Easy" points="50" os="Encoding" skills="JDK source reading, custom Base64 alphabet, UTF-16 BE" >}}

Cryptografie is a 50-point crypto challenge from BKISC CTF 2026 that hangs off a single, very specific hint: `FileSystemPreferences.dirName()`. If you've never had to look at the OpenJDK source before, this challenge is a tour of an internal Base64-like helper that almost nobody outside the JDK uses — and the decoder only takes about ten lines once you know where to look.

Source: [Abdelkad3r/bkisc-ctf-2026 · Cryptografie/](https://github.com/Abdelkad3r/bkisc-ctf-2026/tree/main/Cryptografie).

## The Challenge

We're handed a single ciphertext string. It starts with a leading underscore and the rest is built from an alphabet that's clearly not standard Base64 — it includes `!`, `"`, `&`, `(`, `'`, backticks, square brackets, and so on:

```text
_!(!!b!"m!'%!bg"6!'`!bg"7!(c!:w":!'w!|w"%!$!!^g!z!#w!|w!w!&)!|w"^!'g!:!"_!'w!~!"f!$%!|w"]!$@!_!"o!$:!`g"f!&:!;!"~!&8!_g!y!&}!cw"i!%:!@g"r!')!:g!5!(`!{g"[!$0!>@"9
```

The only hint is `java.util.prefs.FileSystemPreferences.dirName()`. That's the whole challenge.

## Recon — what dirName() actually does

`FileSystemPreferences` is the on-disk backend for the Java preferences API on Unix-like systems. When a preferences node has a name that isn't safe to use as a directory name, the implementation runs that name through a private helper called `dirName()`, which prefixes an underscore (`_`) and encodes the source string with a homemade Base64-like scheme.

The reason for the homemade scheme — and the reason it matters here — is that **case-insensitive filesystems** (macOS HFS+/APFS, Windows NTFS in many configurations) treat `Foo/` and `foo/` as the same directory. Standard Base64 uses both `A-Z` and `a-z`, so encoded names would collide on those filesystems. The JDK's solution is a custom **64-symbol alphabet that contains no uppercase letters at all** — sometimes called *Java AltBase64*. Reading [OpenJDK's `FileSystemPreferences.java`](https://github.com/openjdk/jdk/blob/master/src/java.prefs/unix/classes/java/util/prefs/FileSystemPreferences.java), the alphabet is:

```text
!"#$%&'(),-.:;<>@[]^`_{|}~abcdefghijklmnopqrstuvwxyz0123456789+?
```

64 symbols, each mapped to a 6-bit value `0..63` in that order. Looking at the ciphertext — `_`, then `!`, `(`, `b`, `m`, `'`, etc. — every character is from that alphabet.

There's one more JDK-specific quirk we need to know about: **`FileSystemPreferences` operates on Java `String` data, which is internally UTF-16.** When `dirName()` turns the name into bytes to feed to its encoder, it uses the **UTF-16 big-endian** representation, not UTF-8. So the bytes we recover from AltBase64 are *not* the flag — they're the UTF-16 BE encoding of the flag.

## Solution

The decoder is now mechanical:

1. Strip the leading `_` (the marker `dirName()` always prepends).
2. Decode the rest as AltBase64 using the alphabet above — each char gives 6 bits, concatenate, regroup into bytes.
3. Decode the resulting bytes as UTF-16 BE.

```python
ALPHABET = "!\"#$%&'(),-.:;<>@[]^`_{|}~abcdefghijklmnopqrstuvwxyz0123456789+?"

def altb64_decode(s: str) -> bytes:
    bits = "".join(format(ALPHABET.index(ch), "06b") for ch in s)
    bits = bits[: len(bits) - (len(bits) % 8)]   # drop dangling sub-byte
    return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))

ct = open("challenge.txt").read().strip()
assert ct.startswith("_")
print(altb64_decode(ct[1:]).decode("utf-16-be"))
```

{{< terminal title="kali ~/ctf/bkisc/cryptografie" >}}
$ python3 solve.py
plfanzen{w3Ll_D0N3,_0R_Sh0Uld_1_R4Th3R_S4Y_V2VsbCBkb29uZQ==}
{{< /terminal >}}

## Flag

```
plfanzen{w3Ll_D0N3,_0R_Sh0Uld_1_R4Th3R_S4Y_V2VsbCBkb29uZQ==}
```

## A nested joke

The flag wrapper is `plfanzen{...}`, not the proper German `pflanzen{...}` ("plants"). The transposed `l`/`f` is part of a running typo gag this CTF leans into — the crypto category itself is tagged "cyrpto" in the platform UI.

Decoding the inner blob `V2VsbCBkb29uZQ==` as standard Base64 gives the ASCII string `Well doone` — same joke, doubled letter. Cute touch.

{{< callout type="tip" title="The takeaway for future similar challenges" >}}
When a crypto challenge points you at a specific class or function in a real-world library, **read the source of that function**, not Wikipedia. OpenJDK, the .NET reference source, the Go standard library, OpenSSL, Bouncy Castle — they all contain dozens of one-off encoders, name-mangling schemes, and serialization helpers that show up in CTFs precisely because they're obscure enough to be a puzzle. The hint is doing the work of telling you where to look.
{{< /callout >}}

## Lessons learned

1. **Custom alphabets are a fingerprint.** Whenever you see a 64-character set that isn't standard Base64, the question is "which library's alphabet is this?" — and the answer is usually a Google search for a few of the unusual symbols. The presence of `!`, `"`, and `(` alongside lowercase letters is *very* unusual.

2. **Underscores at the start of encoded blobs often carry meaning.** `FileSystemPreferences.dirName()` uses `_` as a "I encoded this" marker; LDAP attribute encoding uses prefixes for OID-named attributes; some `:`/`@`-prefixed schemes do the same. Always check whether the leading character is part of the payload or a wrapper.

3. **UTF-16 vs UTF-8 is a recurring trap when reversing Java/Windows-origin payloads.** Both platforms use UTF-16 internally; when their APIs serialize "a string" to bytes, they almost always pick UTF-16 (BE on the JVM, LE on Windows). If a Base64 decode produces plausibly-text bytes that contain a lot of `\x00` interleaved with ASCII, you're looking at UTF-16.

## References

- [OpenJDK source — `FileSystemPreferences.java`](https://github.com/openjdk/jdk/blob/master/src/java.prefs/unix/classes/java/util/prefs/FileSystemPreferences.java)
- [Java Preferences API documentation](https://docs.oracle.com/en/java/javase/21/docs/api/java.prefs/java/util/prefs/Preferences.html)
- Source writeup: [bkisc-ctf-2026/Cryptografie/README.md](https://github.com/Abdelkad3r/bkisc-ctf-2026/blob/main/Cryptografie/README.md)
