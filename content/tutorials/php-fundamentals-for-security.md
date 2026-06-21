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

I keep telling new hunters that PHP isn't a bad language. It's a language with a few defaults that will eat your lunch if you don't understand them. After spending most of 2024 and 2025 reviewing WordPress plugin code for paying clients, I'm comfortable saying that roughly half of every PHP CVE I read traces back to three things: `==`, `$_REQUEST`, and the rules PHP uses to convert one type into another.

That's the topic of this second article in the [PHP and Web Security Tutorial Series](/tutorials/learn-php-before-advanced-web-hacking/). Each section below uses the same five-part shape promised in the intro: explanation, vulnerable code, exploitation, secure fix, key lessons. The code is short enough to drop into a single `index.php` and run with `php -S 127.0.0.1:8000`. I'd encourage that. Reading a `var_dump` of your own surprise is more memorable than reading mine.

## 1. Comparison operators: `==` vs `===`

### Explanation

PHP has two comparison families. Loose comparison (`==`, `!=`) tries to convert both operands to a common type before comparing. Strict comparison (`===`, `!==`) compares both type and value with no coercion.

Most of the authentication bypasses I've reported live in the loose family. The coercion rules are not intuitive. `"abc" == 0` was true before PHP 8. `"0e123" == "0e456"` is still true today, because both look like floating-point zero in scientific notation. `null == false` is always true. As an auditor I treat every `==` in security-relevant code as a finding until I've proven otherwise.

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

Every MD5 output is a 32-character hex string. About one in every 4 billion of them happens to start with `"0e"` and continue with only digits. Values like `"0e215962017"`. We call these **magic hashes**.

PHP's loose `==` looks at both sides, sees what it parses as scientific-notation floats, and converts: `0e215962017` and `0e462097131` both evaluate to `0.0`. Comparing `0 == 0` returns true. The attacker did not need to know `SECRET`.

For password resets specifically, that's a needle in a 4-billion haystack — until you realise the attacker can keep requesting resets for new user IDs until one of them lands on a magic hash. With a few hundred million accounts in a leaked breach dump, you'd hit one within minutes.

This is the same primitive that ate several PHP-CMS bug bounty reports between 2014 and 2020. The fix isn't a new hash function. The fix is a new comparison.

### Secure fix

```php
if (hash_equals($expected, $_GET['token'])) {
    grant_reset($_GET['user_id']);
}
```

`hash_equals()` does a constant-time string comparison and never coerces. As a bonus it kills the timing side-channel that lets an attacker brute-force a token byte by byte. For non-secret comparisons, use `===`. I have never found a security-relevant case where loose `==` was the right call.

### Key lessons

- Treat every `==` in auth, token, signature, or capability code as a finding.
- Magic hashes of the shape `0e\d+` collide under `==`. MD5, SHA-1, and SHA-256 all produce them occasionally. Switching hash function doesn't fix it.
- Use `hash_equals()` for any secret-vs-input comparison. It also kills the timing side-channel.

## 2. The loose-typing trap

### Explanation

PHP performs type juggling on most operators, most built-in functions, and a surprising number of standard-library calls. The rules are documented but rarely intuitive. A few patterns show up in production exploits over and over.

The first one is functions that return different types on success and failure. `strcmp()` returns an int on success, but on a type error it returns `NULL`, and `NULL == 0` is true. So a check like `if (strcmp($input, $secret) == 0)` can be flipped to a pass by sending `input[]=1` instead of a string. `strcmp` gets an array, raises a warning, returns `NULL`, the `if` branch fires.

The second is `in_array($needle, $haystack)` defaulting to loose comparison. Without the third `strict` argument it'll happily tell you `0` is in `["abc", "xyz"]`, because `"abc" == 0` was true in PHP 7 and similar surprises survive into 8 around array-versus-scalar coercion.

The third is `intval()`. It truncates at the first non-digit. `intval("1; DROP TABLE users")` is `1`. `intval("0xdeadbeef")` is `0` by default. `intval("999999999999")` overflows to `INT_MAX` on 32-bit builds, which still ship on cheaper hosting.

I reviewed a small e-commerce plugin in early 2025 that combined all three of these in one endpoint. The customer thought their billing API was defended by an HMAC. It wasn't.

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

`intval("3abc")` returns `3`. Tier check passes. `in_array(3, [1, 2, 3])` returns true. Allow-list passes. `strcmp` receives an array as its first argument, raises a warning, returns `NULL`. `NULL == 0` is true. Signature check passes.

The attacker is executing as tier 3 without producing a valid signature. The endpoint *looks* defended. Every individual check is wrong in a different small way, and together they compose into a clean auth bypass. That's the bug class that pays my mortgage.

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

Three changes, each closes one rung of the bypass. `filter_input` with `FILTER_VALIDATE_INT` and a range enforces an actual integer between 1 and 3, and returns `false` on anything else. `is_string()` rejects arrays before they ever reach `hash_equals`. `hash_equals` replaces the `strcmp(...) == 0` pattern entirely.

### Key lessons

- Functions that return one type on success and another on error are a comparison-bypass primitive. Check the type, not just the value.
- `in_array($needle, $haystack, true)` — the third argument is `strict` and you almost always want it `true`. Same for `array_search`.
- Reach for `filter_input` / `filter_var` with explicit `FILTER_VALIDATE_*` flags before reaching for `intval`-and-compare. They return `false` on invalid input instead of silently coercing.

## 3. Superglobals: where attacker control begins

### Explanation

PHP exposes seven superglobal arrays that hold request data: `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_SERVER`, `$_SESSION`, `$_FILES`. Five of them are entirely attacker-controlled, one is mostly attacker-controlled, and only `$_SESSION` carries server-side state.

Two of those are non-obvious to people new to PHP.

`$_REQUEST` merges `GET`, `POST`, and `COOKIE` in the order set by `variables_order`. The default is `"GPCS"`, which means a cookie of the same name as a GET parameter will override the GET value. That happens with the default config, on every shared host you've ever touched. Code that reads `$_REQUEST['user_id']` accepts attacker-set cookies, which often live longer than URL parameters and are easier to weaponise across origins.

`$_SERVER` is more dangerous than its name suggests. Anything starting with `HTTP_` comes straight from the request headers. `HTTP_X_FORWARDED_FOR`, `HTTP_HOST`, `HTTP_REFERER`, `HTTP_USER_AGENT`, `REQUEST_URI`, `QUERY_STRING` are all wire data. The web server sets `$_SERVER['REMOTE_ADDR']` and that's usually trustworthy unless you're behind a misconfigured proxy. Everything else is the attacker's first move.

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

The server reads `$_SERVER['HTTP_HOST']` as `attacker.example.com` and emails the victim a "reset your password" link pointing at the attacker's domain. The victim clicks. The token lands in the attacker's logs. The attacker replays it against the legitimate `https://example.com/reset?token=...` and walks away with the account.

This is host header injection, also called password reset poisoning. I've reported variants of it on three different membership plugins in the last eighteen months. WordPress core has had its own variants. The bug class is still being reported in 2026, mostly because new plugin authors keep discovering `$_SERVER['HTTP_HOST']` and assuming it's a server-side value.

### Secure fix

```php
$canonical_host = 'example.com';   // from config, NOT from $_SERVER

$reset_url = sprintf(
    "https://%s/reset?token=%s",
    $canonical_host,
    $token
);
```

The canonical host belongs in configuration. An environment variable, a `config.php` constant, a framework-level service URL, whatever fits your stack. Never read it from the request.

If you genuinely need to support multiple legitimate hosts (multi-tenant SaaS, white-label deployments), validate `$_SERVER['HTTP_HOST']` against an allow-list before using it. A simple `in_array(strtolower($_SERVER['HTTP_HOST']), $allowed_hosts, true)` is enough, with `true` for strict comparison as covered in Section 2.

### Key lessons

- Every superglobal except `$_SESSION` is attacker-controlled territory until proven otherwise.
- `$_REQUEST` is the trap that looks like convenience. Use `$_GET` or `$_POST` explicitly so you always know which channel a value came from.
- `$_SERVER` keys starting with `HTTP_` are HTTP request headers. They are not server state. Code that builds URLs, emails, or redirects from them is host-header-injection bait.
- For any value that should be canonical — your own domain, your own URL, your own email sender — read it from config, not from the request.

## 4. Other quirks that show up in real CVEs

A handful of other patterns I see often enough to grep for on every audit. Each of these has shipped as a CVE in a WordPress or PHP-CMS plugin within the last three years.

- **`hash_equals` vs `strcmp` for HMAC verification.** `strcmp` returns `0` when strings match. So `if (strcmp($a, $b))` does the *opposite* of what a reader who's used to `if ($a == $b)` would expect. Plenty of plugin authors get this inverted.
- **`unserialize` on user input is RCE-equivalent.** We'll cover deserialization properly later in the series. As a one-line heuristic, `unserialize($_*)` anywhere is a finding. `json_decode` is the safe alternative for data interchange.
- **`include`, `require`, `include_once`, `require_once` with a variable path.** Any include whose path comes from user input is potentially LFI or RFI. There's a whole article coming on this.
- **`file_get_contents` against user-controlled URLs.** SSRF primitive on its own, deserialization primitive when combined with `phar://`. The PHP 7.4-and-earlier PHAR-auto-deserialize behaviour ate several years of bug bounty reports.
- **`extract($_REQUEST)`.** Sets every key in `$_REQUEST` as a local variable. `$is_admin = true` from a URL parameter. Treat as critical on sight.
- **`mb_strpos` vs `strpos` for substring checks.** Both return `false` if not found and `0` if found at position 0. Compared with `==` you get the magic-hash bug all over again. Always use `!== false`.

That list isn't exhaustive, but if you grep a PHP codebase for those six patterns and understand what each one means, you've covered most of the cheap critical findings an auditor will pick up in the first hour with a plugin tree.

## Conclusion

PHP's reputation for security bugs is mostly earned. The language ships features that make it easy to write code that *looks* correct and is exploitable. Loose comparison that quietly coerces. Superglobals that quietly merge channels. Type juggling that quietly produces `NULL == 0`. None of these are bugs in the runtime. They're documented behaviours that work the way the spec says they should. The bug class is writing security-sensitive code without knowing the documented behaviour.

When you read PHP, read the types. Every comparison is asking "what type is each side, and what does PHP do when the types don't match?" Every superglobal access is asking "where did this value originate, and is the originator trustworthy?" Answer those two questions on every line of a sensitive routine and you'll outpace any static analyser I've run.

Next in the [PHP and Web Security Tutorial Series](/tutorials/learn-php-before-advanced-web-hacking/): *The HTTP Request Lifecycle in PHP — from socket to `$_SERVER`*. I want the next vulnerability articles (SQLi, XSS, CSRF, file upload, LFI) to sit on a shared understanding of how a request actually reaches your code, because most of those bugs look different once you know the runtime path.

---

*Further reading: [Orange Tsai's blog](https://blog.orange.tw/). The PHAR-via-`md5_file` series is the canonical example of building a critical finding out of two of the primitives in this article. Worth a careful read once you've finished this one.*
