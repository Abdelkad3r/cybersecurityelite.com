---
title: "PHP Fundamentals for Security: Comparison Operators, Superglobals, and the Loose-Typing Trap"
slug: "php-fundamentals-for-security"
description: "Half of real-world PHP CVEs come from three primitives: loose comparison, superglobals, and type juggling. Walk-through with vulnerable code, exploits, and fixes."
date: 2026-06-21T15:00:00Z
lastmod: 2026-06-21T15:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["Tutorials"]
series: ["PHP and Web Security Tutorial Series"]
tags: ["php", "web security", "type juggling", "bug bounty", "secure coding"]
keywords: [
  "php fundamentals for security",
  "php comparison operators security",
  "php loose vs strict comparison",
  "php type juggling vulnerability",
  "php superglobals security",
  "host header injection php",
  "php password reset poisoning",
  "in_array strict mode",
  "intval bypass php",
  "magic hash 0e collision",
  "php and web security tutorial series",
  "php superglobals attacker controlled",
  "secure php development",
  "wordpress plugin auth bypass"
]
toc: true
cover:
  image: "/images/articles/php-fundamentals-for-security.png"
  alt: "PHP Fundamentals for Security — comparison operators, superglobals, and the loose-typing trap"
---

This is the second article in the [PHP and Web Security Tutorial Series](/tutorials/learn-php-before-advanced-web-hacking/). The intro made a claim I want to back up here: roughly half of every PHP CVE I read traces back to three language primitives. Not exotic gadget chains, not zero-days in the runtime — just `==`, `$_REQUEST`, and the rules PHP uses to coerce one type to another.

This article walks through those three primitives the way you'd want a senior auditor to walk you through them. Each section follows the five-part shape promised in the series intro: explanation, vulnerable code, exploitation, secure fix, key lessons. Run every snippet locally with `php -S 127.0.0.1:8000 -t .` and a single-file `index.php` — you'll learn faster watching the bugs fire than reading about them.

## 1. Comparison operators: `==` vs `===`

### Explanation

PHP has two comparison families. **Loose comparison** (`==`, `!=`) tries to convert both operands to a common type before comparing. **Strict comparison** (`===`, `!==`) compares both type and value with no coercion.

Loose comparison is where most authentication bypasses live. The conversion table PHP uses is not intuitive — `"abc" == 0` was true before PHP 8, `"0e123" == "0e456"` is true today (both look like floating-point zero in scientific notation), and `null == false` is always true. Auditors should treat every `==` they find in security-sensitive code as a finding until proven otherwise.

### Vulnerable code

```php
<?php
// A password-reset token verifier.
$expected = hash('md5', $user_id . SECRET);

if ($_GET['token'] == $expected) {
    // Reset the password.
    grant_reset($_GET['user_id']);
}
```

The author thought MD5 was the bug. It is, but not the way they thought.

### Exploitation

Every MD5 hash is a hex string. About one in every `2^32` MD5 outputs starts with `"0e"` and is followed only by digits — values like `"0e215962017"`. These are **magic hashes**. PHP's loose `==` parses both sides as floats: `0e215962017` and `0e462097131` both evaluate to `0.0`, and `0 == 0` is true.

So if the attacker can find *any* user whose `md5($user_id . SECRET)` is a magic hash, they can use `?token=0` (or any other valid magic-hash form) and the comparison succeeds without knowing `SECRET`.

This is the same primitive that bit several PHP-CMS bug bounty reports between 2014 and 2020. The fix isn't to change the hash function — it's to fix the comparison.

### Secure fix

```php
if (hash_equals($expected, $_GET['token'])) {
    grant_reset($_GET['user_id']);
}
```

`hash_equals()` does a constant-time string comparison and never coerces. As a bonus it kills the timing side-channel that would let an attacker brute-force the token a byte at a time. For non-secret comparisons, use `===`. There is no security-relevant case where loose `==` is the right choice.

### Key lessons

- `==` is a coercion machine, not a comparison. Treat every occurrence in auth, token, signature, or capability code as a finding.
- "Magic hashes" of the shape `0e\d+` collide under `==`. MD5, SHA-1, and SHA-256 all produce them occasionally. Switching hash function doesn't fix it.
- Use `hash_equals()` for any secret-vs-input comparison. It also kills the timing side-channel.

## 2. The loose-typing trap

### Explanation

PHP performs type juggling on most operators, most built-in functions, and a surprising number of standard-library calls. The rules are documented but rarely intuitive. Three patterns appear in production exploits over and over:

1. **Functions that return one type on success and a *different* type on error.** `strcmp()` returns an int on success and `NULL` on a type error. `NULL == 0` is true. So `strcmp($_GET['pin'], $secret)` returning "no match" can be turned into a pass by sending `pin[]=1` — `strcmp` receives an array, throws, returns `NULL`, the `if (strcmp(...) == 0)` branch fires.
2. **`in_array($needle, $haystack)` defaults to loose comparison.** Without the third `strict` argument it'll happily say `0 in_array(["abc", "xyz"])` is true (because `"abc" == 0` was true in PHP 7 and earlier, and array-vs-non-array coercion still produces surprises in 8).
3. **`intval()` truncates at the first non-digit.** `intval("1; DROP TABLE users")` is `1`. `intval("0xdeadbeef")` is `0` by default. `intval("999999999999")` overflows to `INT_MAX` on 32-bit builds.

### Vulnerable code

```php
<?php
// An API endpoint that requires a numeric "tier" between 1 and 3
// and treats tier 3 as admin.
$tier = intval($_GET['tier']);

if (!in_array($tier, $allowed_tiers)) {     // $allowed_tiers = [1, 2, 3]
    http_response_code(403); exit;
}

if (strcmp($_GET['signature'], expected_sig($tier)) == 0) {
    process_as($tier);
}
```

### Exploitation

```
GET /api?tier=3abc&signature[]=anything
```

- `intval("3abc")` returns `3` — tier check passes.
- `in_array(3, [1, 2, 3])` returns `true` — allow-list passes.
- `strcmp` receives an array as the first argument, raises a warning, returns `NULL`.
- `NULL == 0` is `true` — signature check passes.

The attacker is now executing as `tier=3` without ever producing a valid signature. The endpoint *looks* defended; every individual check is wrong in a different small way and they compose into a complete auth bypass.

### Secure fix

```php
<?php
$tier = filter_input(INPUT_GET, 'tier', FILTER_VALIDATE_INT,
    ['options' => ['min_range' => 1, 'max_range' => 3]]);
if ($tier === false || $tier === null) {
    http_response_code(403); exit;
}

$sig = $_GET['signature'] ?? '';
if (!is_string($sig)) {
    http_response_code(403); exit;
}

if (!hash_equals(expected_sig($tier), $sig)) {
    http_response_code(403); exit;
}
process_as($tier);
```

Three changes, each closes one rung of the bypass:

- `filter_input(..., FILTER_VALIDATE_INT, options)` enforces an integer in the allowed range and returns `false` on anything else. No truncation, no array-coercion surprise.
- `is_string()` rejects arrays before they reach `hash_equals`.
- `hash_equals` replaces the `strcmp(...) == 0` pattern.

### Key lessons

- Functions that return one type on success and another on error are a comparison-bypass primitive. Always check the type, not just the value.
- `in_array($needle, $haystack, true)` — the third argument is `strict` and you almost always want it `true`. Same for `array_search`.
- Prefer `filter_input` / `filter_var` with explicit `FILTER_VALIDATE_*` flags over manual `intval`-and-compare. They return `false` on invalid input rather than silently coercing.
- PHP's type coercion is a security-critical feature, not a developer convenience. The auditor's reflex should be: "what types can reach this comparison, and what does the comparison return for each?"

## 3. Superglobals: where attacker control begins

### Explanation

PHP exposes seven superglobal arrays that hold request data: `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_SERVER`, `$_SESSION`, `$_FILES`. Five of them are entirely attacker-controlled, one is mostly attacker-controlled, and only `$_SESSION` carries server-side state.

The two non-obvious traps:

**`$_REQUEST` merges `GET`, `POST`, and `COOKIE` in the order set by `variables_order`.** Default is `"GPCS"` — GET, POST, COOKIE, Server. With a cookie of the same name as a GET parameter, the cookie overrides — and that's *with default config*. Code that reads `$_REQUEST['user_id']` accepts attacker-set cookies, which often survive longer than URL params and are easier to weaponise across origins.

**`$_SERVER` values come from the HTTP request more often than people think.** `HTTP_X_FORWARDED_FOR`, `HTTP_HOST`, `HTTP_REFERER`, `HTTP_USER_AGENT`, `REQUEST_URI`, `QUERY_STRING` — every one of these is attacker-set on incoming requests, no matter how "server-y" the name sounds. `$_SERVER['REMOTE_ADDR']` is set by the web server and is usually trustworthy (modulo proxies); everything `HTTP_*` is wire data.

### Vulnerable code

```php
<?php
// password_reset.php — generates a reset link emailed to the user.
$token = bin2hex(random_bytes(16));
store_reset_token($user->id, $token);

$reset_url = sprintf(
    "https://%s/reset?token=%s",
    $_SERVER['HTTP_HOST'],     // <- attacker controls this
    $token
);

mail($user->email, "Reset your password", "Click here: $reset_url");
```

### Exploitation

```
POST /password_reset HTTP/1.1
Host: attacker.example.com
Content-Type: application/x-www-form-urlencoded

email=victim@example.com
```

The server reads `$_SERVER['HTTP_HOST']` as `attacker.example.com` and emails the victim a "reset your password" link pointing at the attacker's domain. When the victim clicks it, the token is delivered to the attacker, who replays it to the legitimate `https://example.com/reset?token=...` and takes the account.

This is **host header injection / password reset poisoning** — one of the most common high-severity findings in WordPress, Drupal, and custom-CMS bug bounty reports. The CVE history is long: WordPress core has had variants, dozens of plugins have shipped variants, and the bug class is still being reported in 2026.

### Secure fix

```php
$canonical_host = 'example.com';   // from config, NOT from $_SERVER

$reset_url = sprintf(
    "https://%s/reset?token=%s",
    $canonical_host,
    $token
);
```

The canonical host belongs in configuration — an environment variable, a `config.php` constant, a framework-level service URL. Never read it from the request.

If you must support multiple legitimate hosts (multi-tenant SaaS), validate `$_SERVER['HTTP_HOST']` against an allow-list before using it. A simple `in_array(strtolower($_SERVER['HTTP_HOST']), $allowed_hosts, true)` is enough — with `true` for strict comparison, as covered in Section 2.

### Key lessons

- Every superglobal except `$_SESSION` is attacker-controlled territory until proven otherwise.
- `$_REQUEST` is the trap that masquerades as convenience. Use `$_GET` or `$_POST` explicitly so you know which channel each value came from.
- `$_SERVER` keys starting with `HTTP_` are HTTP request headers. They are not server state. Code that builds URLs, emails, or redirects from them is a host-header-injection finding.
- For any value that should be canonical (your own domain, your own URL, your own email sender), read it from config, not from the request.

## 4. Other quirks that show up in real CVEs

Quick fire — each of these has shipped as a CVE in a WordPress or PHP-CMS plugin within the last three years. They're worth knowing on sight so you don't have to chase down the bug class when you spot one.

- **`0e\d+` magic hashes** under `==`. Covered above; worth repeating because the pattern shows up anywhere a hash is compared with `==`, including session IDs, password resets, and signed-URL tokens.
- **`hash_equals` vs `strcmp` for HMAC verification.** `strcmp` returns `0` when strings match — `if (strcmp(a, b))` does the *opposite* of what a `if (a == b)` reader expects. Plenty of plugin authors get this inverted.
- **`unserialize` on user input is RCE-equivalent.** We'll cover deserialization later in the series, but as a one-line heuristic: `unserialize($_*)` anywhere is a finding. `json_decode` is the safe alternative for data interchange.
- **`include`, `require`, `include_once`, `require_once` with a variable.** Any include whose path comes from user input is potentially LFI or RFI. Series will dedicate a full article to it.
- **`file_get_contents` against user-controlled URLs.** SSRF primitive on its own; combined with `phar://` it's also a deserialization primitive. The PHP 7.4-and-earlier PHAR-auto-deserialize behavior is the bug class that ate several years of bug bounty reports.
- **`extract($_REQUEST)`.** Sets every key in `$_REQUEST` as a local variable. Anywhere this appears, the attacker can overwrite arbitrary locals — `$is_admin = true` from a URL parameter. Treat as critical on sight.
- **`mb_strpos` vs `strpos` for needle-in-haystack checks.** Different return semantics; both return `false` if not found and `0` if found at position 0. Compared with `==` you get the magic-hash bug all over again. Always use `!== false`.

That list is not exhaustive — but if you grep a PHP codebase for those eight patterns and understand each one, you've covered most of the cheap critical findings that any auditor of a WordPress plugin tree will pick up in the first hour.

## Conclusion

PHP's reputation for security bugs is mostly earned. The language ships features that make it easy to write code that looks correct and is exploitable — loose comparison that quietly coerces, superglobals that quietly merge channels, type juggling that quietly produces `NULL == 0`. None of these are bugs in the runtime. They're documented behaviors that work the way the spec says they should. The bug class is *writing security code without knowing the documented behavior*.

The takeaway from this article: when you read PHP, **read the types**. Every comparison is asking "what type is each side, and what does PHP do when the types don't match?" Every superglobal access is asking "where did this value originate, and is the originator trustworthy?" If you can answer those two questions for every line in a sensitive routine, you'll find the bug before the static analyzer does.

**Next in the [PHP and Web Security Tutorial Series](/tutorials/learn-php-before-advanced-web-hacking/):** *The HTTP Request Lifecycle in PHP — from socket to `$_SERVER`*. We'll walk an HTTP request through PHP-FPM end to end so the next vulnerability articles (SQLi, XSS, CSRF, file upload, LFI) have the runtime context you need to read them properly.

If you've spotted a `==` in plugin code today and felt the urge to file a bug report, that's the right reflex. Bookmark the [Tutorials index](/tutorials/) and the rest of the series will land there.

---

*Further reading: [Orange Tsai's blog](https://blog.orange.tw/) — the PHAR-via-`md5_file` series is the canonical example of building a critical finding out of two of the primitives in this article. Worth a careful read once you've finished this one.*
