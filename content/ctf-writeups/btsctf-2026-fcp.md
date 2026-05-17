---
title: "BtSCTF 2026: FCP Writeup — Recovering an In-Memory RSA Key to Decrypt Resumed TLS Sessions"
slug: "btsctf-2026-fcp"
description: "BreakTheSyntax 2026 FCP walkthrough — dump a Go MCP server's heap, recover the runtime-generated 2048-bit RSA key from big.Int limbs, decrypt the first TLS_RSA session, derive the EMS master secret, and replay it across every resumed stream in the PCAP."
date: 2026-05-16T00:00:00Z
lastmod: 2026-05-16T00:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
tags: ["btsctf", "breakthesyntax", "tls", "rsa", "memory forensics", "go", "mcp", "reverse engineering", "network forensics"]
series: ["BreakTheSyntax CTF 2026"]
keywords: ["btsctf 2026 fcp writeup", "fcp writeup breakthesyntax", "tls_rsa_with_aes_128_cbc_sha decrypt", "go big.int rsa memory dump", "extended master secret prf", "tls session resumption decrypt pcap"]
toc: true
cover:
  image: "/images/bkisc.png"
  alt: "BtSCTF 2026 FCP writeup"
---

{{< ctf-meta platform="BreakTheSyntax CTF 2026" difficulty="Hard" os="Linux" skills="TLS, RSA, Go memory forensics, EMS PRF, session resumption" >}}

FCP was a multi-step reverse-engineering and network-forensics challenge. You get a Go MCP ("Model Context Protocol") server binary plus a PCAP of someone using it earlier. Buried in the capture is a `get_flag` call — but the live server's `get_flag` endpoint has been rewritten to just return `"no"`, so re-running it is useless. The challenge is to decrypt the historical traffic. Two specific design choices make this both possible and nontrivial.

Source: [Abdelkad3r/BreakTheSyntax-ctf-2026 · FCP.md](https://github.com/Abdelkad3r/BreakTheSyntax-ctf-2026/blob/main/FCP.md).

## The Setup

The binary deliberately forces the TLS cipher suite to `TLS_RSA_WITH_AES_128_CBC_SHA`. That's the classic RSA key exchange — the client picks a random pre-master secret, encrypts it under the server's RSA public key, and sends the ciphertext in the ClientKeyExchange. **If we hold the server's RSA private key, we can decrypt the PMS out of the PCAP retroactively.** This is the exact reason TLS 1.3 dropped RSA key exchange in favour of forward-secret (EC)DHE — captured-now-decrypt-later is back on the menu the moment you choose `TLS_RSA_*`.

Complication: the server **does not ship its private key on disk.** It generates a fresh 2048-bit RSA key on startup and the key only ever lives in process memory. So we have to extract the key from a running instance, then use it to decrypt the historical session.

Second complication: only the *first* TLS session in the PCAP does a full handshake. Every subsequent stream is a **session resumption with Extended Master Secret (EMS)**. There's no fresh `ClientKeyExchange` in those — so even with the RSA key, decrypting the resumed sessions requires the master secret itself.

The full solve path:

1. Dump the running server's heap with `gcore`
2. Scan for the in-memory RSA key by recognising Go's `big.Int` limb layout
3. Decrypt stream 1's pre-master secret with the recovered private key
4. Derive the master secret via the EMS PRF
5. Reuse that master secret to decrypt every resumed session in the capture

## Step 1 — Snapshot the server's memory

A regular ELF core file gives us everything Go has allocated on the heap, including any live `*big.Int` instances.

{{< terminal title="kali ~/ctf/fcp" >}}
$ ./fcp-server &
[1] 12847
$ sudo gcore -o core 12847
[Thread debugging using libthread_db enabled]
...
Saved corefile core.12847
{{< /terminal >}}

`core.12847` is a normal ELF that any debugger can introspect, but more importantly we can scan it as raw bytes.

## Step 2 — Find the RSA key by recognising big.Int layout

This is the interesting part of the challenge. Go's `crypto/rsa.PrivateKey` stores its parameters as `*big.Int`. Internally a `big.Int` is just a struct wrapping `nat`, which on `amd64` is a `[]Word` — a slice of `uint64` limbs in **little-endian limb order**. A 2048-bit modulus therefore lives as exactly **32 consecutive 8-byte words = 256 contiguous bytes** on the Go heap.

So instead of disassembling, we treat the dump as a long byte string and slide a 256-byte window across it. At each offset we reinterpret the window as a 2048-bit little-endian integer and ask: *does this look like an RSA modulus?*

A real 2048-bit RSA `N`:

- Has bit length 2040–2048 (top bits set)
- Is odd
- Has no small prime factors

False positives are rare — random heap bytes almost never satisfy all three conditions simultaneously.

```python
def words_to_int(b):
    """Reinterpret 256 bytes as a Go big.Int's nat: 32 little-endian uint64 limbs."""
    n = 0
    for i in range(0, 256, 8):
        n |= int.from_bytes(b[i:i+8], "little") << (i * 8)
    return n

dump = open("core.12847", "rb").read()
candidates = []
for off in range(0, len(dump) - 256, 8):       # 8-byte aligned to match Go's allocator
    w = dump[off:off+256]
    n = words_to_int(w)
    if n.bit_length() not in range(2040, 2049):
        continue
    if n % 2 == 0:
        continue
    candidates.append((off, n))
```

The private exponent `D` lives nearby on the heap with the same 256-byte layout, so the second pass pairs every candidate `N` with a candidate `D` and tries to factor `N` from the `(e, d, n)` tuple.

{{< callout type="tip" title="Recovering p, q from (e, d, n)" >}}
This is a standard textbook routine: because `e·d ≡ 1 (mod λ(n))`, the value `k = e·d − 1` is a multiple of `λ(n)`. Repeatedly halving `k` and exponentiating a random base eventually produces a non-trivial square root of 1 modulo `n` — and `gcd(x − 1, n)` is then `p` or `q`. No factoring of `n` from scratch required.
{{< /callout >}}

```python
import random
from math import gcd

def factor_from_ed(n, e, d):
    k = e * d - 1
    while k % 2 == 0:
        k //= 2
    while True:
        g = random.randrange(2, n - 1)
        t = k
        while t < e * d:
            x = pow(g, t, n)
            if x != 1 and x != n - 1 and pow(x, 2, n) == 1:
                p = gcd(x - 1, n)
                return p, n // p
            t *= 2
```

With `(n, e, d, p, q)` we can assemble a PEM:

```python
from Crypto.PublicKey import RSA
key = RSA.construct((n, e, d, p, q))
open("server.key", "wb").write(key.export_key("PEM"))
```

## Step 3 — Decrypt the first session

Stream 1 is a full handshake. Hand the recovered key to Wireshark/tshark via the `tls.keys_list` preference and the first session decrypts cleanly:

{{< terminal title="kali ~/ctf/fcp" >}}
$ tshark -r capture.pcap \
    -o "tls.keys_list:any,443,http,server.key" \
    -V \
    | head -200
{{< /terminal >}}

This works because we have the `ClientKeyExchange` ciphertext for that session, and our recovered RSA private key decrypts it to recover the pre-master secret. From there `tshark` derives the master secret using the standard TLS 1.2 PRF and decrypts the records.

What this does **not** decrypt is streams 2 through N — all of those reuse the first session via TLS session resumption with the **Extended Master Secret** extension. No fresh ClientKeyExchange means no PMS to decrypt. The RSA key alone is no longer enough.

## Step 4 — Reconstruct the master secret for every resumed session

With Extended Master Secret in play (RFC 7627), the master secret is derived as:

```
master_secret = PRF(pre_master_secret, "extended master secret", session_hash)
```

Where `session_hash = SHA256(all handshake messages from ClientHello through ClientKeyExchange concatenated, record-layer headers stripped)`.

We can compute it for stream 1 directly, because we have the PMS:

```python
from Crypto.Cipher import PKCS1_v1_5
pms = PKCS1_v1_5.new(key).decrypt(client_key_exchange_blob, None)
```

Then implement the TLS 1.2 PRF (HMAC-SHA256 as the underlying PRF, since the negotiated suite uses SHA256):

```python
import hmac, hashlib

def p_hash(secret, seed, length):
    out = b""
    a = hmac.new(secret, seed, hashlib.sha256).digest()
    while len(out) < length:
        out += hmac.new(secret, a + seed, hashlib.sha256).digest()
        a = hmac.new(secret, a, hashlib.sha256).digest()
    return out[:length]

def tls_prf(secret, label, seed, length):
    return p_hash(secret, label + seed, length)

master_secret = tls_prf(pms, b"extended master secret", session_hash, 48)
```

Now the punchline. **TLS session resumption *is* "use the same master secret as the previous session".** Every resumed session in this PCAP shares the same `master_secret` we just computed. The whole point of resumption is to skip the expensive key exchange and reuse the established secret. So we emit one `SSLKEYLOGFILE` line per `ClientHello` in the capture, all using the same MS:

```
CLIENT_RANDOM <client_random_stream_1> <master_secret>
CLIENT_RANDOM <client_random_stream_2> <master_secret>
CLIENT_RANDOM <client_random_stream_3> <master_secret>
CLIENT_RANDOM <client_random_stream_4> <master_secret>
CLIENT_RANDOM <client_random_stream_5> <master_secret>
...
```

Each entry is `CLIENT_RANDOM` followed by the 32-byte client random from that stream's `ClientHello`, then the 48-byte master secret. Feed that file to Wireshark via `Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename`, reload the PCAP, and every stream decrypts.

## Step 5 — Find the flag

Walking the decrypted application data, stream 5 carries the original `get_flag` MCP call — captured *before* the server was rewritten to return `"no"`.

```
BtSCTF{more_like_midcp_67}
```

## Lessons learned

1. **Go does not scrub secret material from the heap.** RSA primes, AES round keys, and JWT signing secrets all linger after the cryptographic operation that used them. A 2048-bit modulus is a 256-byte little-endian aligned blob and is recognisable without symbols.

2. **`TLS_RSA_*` cipher suites are passively decryptable forever if you ever hold the server key.** This is exactly the "harvest now, decrypt later" attack TLS 1.3 was designed to prevent by removing RSA key exchange. If you ship anything that can pin TLS suites — STARTTLS proxies, custom mTLS clients, internal services — confirm you're on `ECDHE` or `DHE` suites only.

3. **Session resumption is a multiplier.** Once one session's master secret is recovered, every resumed session in the capture decrypts for free. This applies to abbreviated handshakes (session ID resumption) and to PSK/`SessionTicket` resumption alike. Operationally, if you suspect TLS compromise, rotate keys *and* invalidate all session caches.

4. **EMS doesn't help here** because we have the underlying PMS. EMS binds the master secret to the handshake transcript, defending against synchronisation attacks like Triple Handshake — but it doesn't add forward secrecy. Static RSA + EMS is still as broken as static RSA without EMS once the server key leaks.

## References

- [RFC 5246 — The Transport Layer Security (TLS) Protocol Version 1.2](https://www.rfc-editor.org/rfc/rfc5246) — full handshake + PRF definition
- [RFC 7627 — TLS Session Hash and Extended Master Secret Extension](https://www.rfc-editor.org/rfc/rfc7627)
- [RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3](https://www.rfc-editor.org/rfc/rfc8446) — explains why TLS 1.3 removed RSA key exchange
- [NSS `SSLKEYLOGFILE` format](https://firefox-source-docs.mozilla.org/security/nss/legacy/key_log_format/index.html)
- Source writeup: [BreakTheSyntax-ctf-2026/FCP.md](https://github.com/Abdelkad3r/BreakTheSyntax-ctf-2026/blob/main/FCP.md)
