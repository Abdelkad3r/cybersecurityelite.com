---
title: "The HTTP Request Lifecycle in PHP: From Socket to $_SERVER"
slug: "http-request-lifecycle-in-php"
description: "How an HTTP request travels from TCP socket through Apache or Nginx and PHP-FPM into the $_SERVER superglobal — and the security-relevant decisions each layer makes."
date: 2026-07-16T15:30:00Z
lastmod: 2026-07-16T15:30:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["Tutorials"]
series: ["PHP and Web Security Tutorial Series"]
tags: ["php", "web security", "php-fpm", "nginx", "fastcgi", "http request smuggling", "request lifecycle"]
keywords: [
  "http request lifecycle php",
  "php-fpm fastcgi security",
  "nginx php-fpm misconfiguration",
  "cgi.fix_pathinfo arbitrary file execution",
  "script_filename traversal",
  "php_self xss vulnerability",
  "path_info vs request_uri php",
  "max_input_vars truncation bypass",
  "auto_prepend_file security",
  "session.use_strict_mode php",
  "http request smuggling cl te",
  "php superglobals origin",
  "php and web security tutorial series",
  "how $_server gets populated",
  "mod_php vs php-fpm"
]
toc: true
cover:
  image: "/images/articles/http-request-lifecycle-in-php.png"
  alt: "The HTTP Request Lifecycle in PHP — from TCP socket through Apache or Nginx and PHP-FPM into the $_SERVER superglobal"
---

The previous article in this series treated `$_SERVER['HTTP_HOST']` and friends as "attacker-controlled territory" and moved on. That's the right operational answer, but it hides an interesting question: *how* does a request actually reach your PHP handler in the first place, and which layer decides that `Host: attacker.com` becomes `$_SERVER['HTTP_HOST'] = "attacker.com"` in your process?

This is the third article in the [PHP and Web Security Tutorial Series](/tutorials/learn-php-before-advanced-web-hacking/) and the last one before we start walking specific vulnerability classes (SQLi, XSS, CSRF, file upload, LFI, deserialization, SSRF). I want those articles to sit on a shared understanding of the request lifecycle, because most PHP bugs look different once you know the runtime path. The nginx-plus-PHP-FPM arbitrary file execution class only makes sense if you know what `SCRIPT_FILENAME` is and how `cgi.fix_pathinfo` decides to set it. HTTP request smuggling only makes sense if you know how Apache and PHP-FPM each parse `Content-Length` and `Transfer-Encoding`. `PHP_SELF` XSS only makes sense if you know that the field is *not* the same as `REQUEST_URI` even though they look alike.

Same shape as the last article: each section is explanation, vulnerable code, exploitation, secure fix, key lessons. All snippets run under `php -S 127.0.0.1:8000` unless the section is specifically about a web-server-integrated flow (mod_php or PHP-FPM), in which case the config lives next to the PHP.

## 1. The socket and the web server

### Explanation

An HTTP request arrives at your server as bytes on a TCP socket. Nothing about the protocol so far knows PHP exists. Apache or Nginx accepts the connection, reads the request line (`GET /reset?email=... HTTP/1.1`), reads headers until an empty line, then decides whether there's a body based on the `Content-Length` and `Transfer-Encoding` headers. Only after that does the web server decide which handler to invoke: static file, redirect, reverse proxy, or (for us) PHP.

Two headers control body framing on HTTP/1.1: `Content-Length` (byte count) and `Transfer-Encoding: chunked` (self-describing frame sequence). RFC 9112 says that when both are present the server MUST use `Transfer-Encoding` and either discard or reject the `Content-Length`. In practice, front-end and back-end servers frequently disagree on which one to trust when both are present, when either is malformed, or when the header is duplicated. That disagreement is HTTP request smuggling.

Smuggling looks like a networking bug, but its impact almost always lands on the PHP layer that sits at the end of the chain. A smuggled request becomes a *different request* than the one your access log records, targeted at a *different URL* than the one your WAF sees, from what appears to be an already-authenticated session.

### Vulnerable code

There is no PHP code to be vulnerable here. The bug lives in the disagreement between two HTTP parsers. Typical deployment:

```
[client] --> [CDN / edge proxy] --> [Nginx] --> [PHP-FPM] --> [your PHP]
```

Any two consecutive links can disagree on framing. The classic pair is `CL.TE` (front-end trusts `Content-Length`, back-end trusts `Transfer-Encoding`) or `TE.CL` (the reverse).

### Exploitation

A canonical CL.TE payload against a chunked-aware back-end (illustrative, not intended for use against a system you don't own):

```
POST / HTTP/1.1
Host: victim.example
Content-Length: 6
Transfer-Encoding: chunked

0

X
```

The front-end sees `Content-Length: 6`, forwards 6 bytes of body (`0\r\n\r\nX`) to the back-end. The back-end reads chunked, sees `0\r\n\r\n` as the end-of-body marker, and treats the trailing `X` as the first byte of the *next* request on the keep-alive connection. Whatever the attacker appends after `X` becomes a smuggled request that runs with whatever session and IP context the next legitimate user has.

Impact against PHP: session hijack, WAF bypass, cache poisoning, forced request replay of authenticated actions. James Kettle's PortSwigger research is the definitive reference; a search for "HTTP Desync Attacks: Request Smuggling Reborn" will find the writeup.

### Secure fix

- Terminate HTTP at a single, standards-strict reverse proxy (Nginx `>= 1.17`, HAProxy `>= 2.4`, Envoy) and use HTTP/2 or HTTP/3 upstream to PHP-FPM if the version allows. HTTP/2 doesn't have the CL/TE ambiguity.
- Reject requests with both `Content-Length` and `Transfer-Encoding` at the edge. Nginx does this by default since 1.23; verify with a probe.
- Disable HTTP/1.1 pipelining and keep-alive on the socket between your CDN and your origin if the CDN insists on speaking HTTP/1.1. Loss of that optimisation is cheaper than a smuggling incident.
- On WAF-terminated deployments, subscribe to your WAF's HTTP-smuggling ruleset and monitor it. AWS ALB, Cloudflare, and Fastly all publish smuggling-related deploy notes.

### Key lessons

- The socket and the wire come *before* PHP. Bugs at this layer land in your PHP handler.
- Every hop between the client and PHP is a header-parsing implementation. Two implementations that disagree = smuggling.
- HTTP/1.1's dual body-length rules are the underlying primitive. HTTP/2 removes the primitive but adds different ones (frame prioritisation, HPACK, header validation). Migration doesn't remove the class; it moves it.

## 2. The handoff to PHP: mod_php vs PHP-FPM

### Explanation

Historically PHP ran as `mod_php`: an Apache module loaded into every httpd worker. The web server called into PHP as a library, PHP handed back a response, the same process handled the next request. Simple, but every httpd worker holds a full PHP interpreter and every request pays the request-init cost.

Modern deployments almost universally use PHP-FPM (FastCGI Process Manager). The web server (usually Nginx, occasionally Apache with `mod_proxy_fcgi`) forwards the request over a Unix socket or TCP to a separate PHP-FPM master, which dispatches to a pool of pre-warmed PHP workers. The wire protocol between web server and FPM is FastCGI, a length-prefixed binary format that carries CGI-style *params* and a *stdin* stream (the request body).

The params are the crucial part. Nginx builds them from a config file (typically `/etc/nginx/fastcgi_params`) and hands them to FPM. FPM populates `$_SERVER` from those params. So the question "how does `$_SERVER['SCRIPT_FILENAME']` get set?" has a mundane answer: nginx puts a value in the FastCGI `SCRIPT_FILENAME` param, and PHP-FPM copies it into `$_SERVER`. If you can influence what nginx sends in that param, you can influence which file PHP executes.

### Vulnerable code

The canonical footgun. A copy-pasted `location ~ \.php$` block, `cgi.fix_pathinfo = 1` (the PHP-FPM default until fairly recently), and no `try_files`:

```nginx
location ~ \.php$ {
    fastcgi_pass unix:/run/php/php-fpm.sock;
    fastcgi_index index.php;
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
}
```

```ini
; /etc/php/php.ini
cgi.fix_pathinfo = 1
```

### Exploitation

An attacker uploads an "avatar" or "attachment" that the app stores at `/var/www/uploads/avatar.jpg`. Any user can request it via `https://victim.example/uploads/avatar.jpg` and it serves as a plain image. Now the attacker requests:

```
GET /uploads/avatar.jpg/x.php
```

The nginx `location ~ \.php$` regex matches (the URL ends in `.php`). Nginx builds `$fastcgi_script_name = "/uploads/avatar.jpg/x.php"` and sends `SCRIPT_FILENAME = /var/www/uploads/avatar.jpg/x.php` to PHP-FPM. PHP-FPM tries to `open()` that path, it doesn't exist, and then `cgi.fix_pathinfo = 1` kicks in: PHP strips trailing path components looking for a file that does exist, and *finds* `/var/www/uploads/avatar.jpg`. PHP-FPM then executes that file as PHP.

If the "image" is actually a polyglot JPEG/PHP file (JFIF header followed by `<?php system($_GET['c']); ?>`), the attacker has arbitrary code execution as `www-data`. Every image-upload feature in the app is now an RCE primitive.

### Secure fix

Three independent settings, all applied:

```nginx
location ~ \.php$ {
    try_files $uri =404;               # 1. don't invoke FPM if the file doesn't exist
    fastcgi_pass unix:/run/php/php-fpm.sock;
    fastcgi_index index.php;
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
}

# Optionally, put uploads on a location that never invokes PHP:
location /uploads/ {
    location ~ \.ph(p|tml|ar)$ { return 403; }   # deny inline
    add_header X-Content-Type-Options nosniff;
}
```

```ini
; /etc/php/php.ini
cgi.fix_pathinfo = 0
```

```conf
; /etc/php/php-fpm.d/www.conf
security.limit_extensions = .php
```

`try_files $uri =404` refuses to invoke FPM at all if the requested file doesn't exist as a real file under the document root, which kills the `avatar.jpg/x.php` path. `cgi.fix_pathinfo = 0` disables the "strip and search" behaviour entirely. `security.limit_extensions = .php` tells PHP-FPM to refuse to execute anything whose filesystem extension isn't `.php`, even if the web server asked it to.

Any one of the three is a hard block on the traversal. Deploy all three and you get defence in depth. The Nginx documentation's ["Pitfalls and Common Mistakes"](https://www.nginx.com/resources/wiki/start/topics/tutorials/config_pitfalls/) page has been recommending this pattern since 2013; it's still the top-source-of-truth reference.

### Key lessons

- The web server chooses which file PHP-FPM executes by populating `SCRIPT_FILENAME`. Any misconfiguration that makes the URL-to-filesystem mapping loose becomes an arbitrary-file-execution bug.
- `cgi.fix_pathinfo = 1` is a legacy setting inherited from mod_cgi and is safe to disable on every deployment that doesn't intentionally route on `PATH_INFO`.
- `security.limit_extensions` in FPM is the PHP-side backstop. Set it even if you trust your nginx config, because PHP configs and nginx configs are usually maintained by different people over years.

## 3. How `$_SERVER` gets populated

### Explanation

`$_SERVER` is not one bucket. It's a mixed bag of five different provenance categories, and knowing which is which is the difference between a paranoid audit and a productive one.

- **HTTP request headers** become `HTTP_*` keys, with hyphens converted to underscores and the value lifted verbatim. `X-Forwarded-For: 10.0.0.1` becomes `$_SERVER['HTTP_X_FORWARDED_FOR'] = "10.0.0.1"`. Attacker-controlled.
- **Request-line parsing** produces `REQUEST_METHOD`, `REQUEST_URI`, `QUERY_STRING`. Attacker-controlled.
- **Web-server-config values** produce `SERVER_NAME`, `SERVER_ADDR`, `SERVER_PORT`, `DOCUMENT_ROOT`, `HTTPS`. Server-controlled if the web server config is sane (see below).
- **FastCGI protocol params** produce `SCRIPT_FILENAME`, `SCRIPT_NAME`, `PATH_INFO`, `PATH_TRANSLATED`, `PHP_SELF`. Derived from the URL by nginx or Apache and then handed to PHP-FPM.
- **Network metadata** produces `REMOTE_ADDR`, `REMOTE_PORT`. From the TCP socket; trustworthy on a direct connection, less so behind a reverse proxy.

The "URL-derived" family is the source of most confusion. `REQUEST_URI` is the raw URL from the request line, including the query string. `SCRIPT_NAME` is the URL path segment that maps to the executed script. `PATH_INFO` is any URL segment past the script. `PHP_SELF` is `SCRIPT_NAME + PATH_INFO`. On a request for `/blog/index.php/2026/07/post`, you'd get:

```
REQUEST_URI  = /blog/index.php/2026/07/post
SCRIPT_NAME  = /blog/index.php
PATH_INFO    = /2026/07/post
PHP_SELF     = /blog/index.php/2026/07/post
```

That's fine. The subtlety is that `PHP_SELF` decodes escape sequences that `REQUEST_URI` doesn't, and it splices in `PATH_INFO`, which means an attacker who controls the URL past the script can inject characters into `PHP_SELF` that don't appear in `REQUEST_URI` in the same form.

### Vulnerable code

A pagination widget from a 2015-vintage theme, still shipping in the wild:

```php
<form method="get" action="<?= $_SERVER['PHP_SELF'] ?>">
    <input type="hidden" name="q" value="<?= htmlspecialchars($_GET['q'] ?? '') ?>">
    <button>Next page</button>
</form>
```

The author *knew* to escape `$_GET['q']`. They didn't think about `$_SERVER['PHP_SELF']` because it "looks like a server value."

### Exploitation

The attacker sends the victim a link like:

```
https://victim.example/index.php/"><script>alert(1)</script>
```

Nginx (or Apache) resolves `SCRIPT_NAME = /index.php` and puts the rest into `PATH_INFO = /"><script>alert(1)</script>`. PHP concatenates them into `PHP_SELF = /index.php/"><script>alert(1)</script>`. The rendered HTML becomes:

```html
<form method="get" action="/index.php/"><script>alert(1)</script>">
```

The `</form>` never appears; the script tag executes in the victim's browser. This is stored, reflected, or DOM XSS depending on how the URL propagates.

This is the same PHP_SELF XSS class that WordPress core patched in 2011 (CVE-2011-4106) and that has since resurfaced in dozens of themes and plugins. Every long-lived PHP CMS has shipped this bug at least once.

### Secure fix

Never emit any URL-derived `$_SERVER` field into HTML unfiltered:

```php
<form method="get" action="<?= htmlspecialchars($_SERVER['SCRIPT_NAME'], ENT_QUOTES | ENT_HTML5, 'UTF-8') ?>">
```

Two changes at once. Use `SCRIPT_NAME` (which is *not* attacker-augmented via `PATH_INFO`). Escape it anyway, with quote-mode escaping suitable for an attribute context. If you can, hard-code the action URL from configuration; there is very rarely a good reason to derive form actions from the current request URL.

### Key lessons

- `$_SERVER` is five different provenance buckets in one array. Knowing which key comes from where is the audit-time discipline.
- `PHP_SELF` is not `REQUEST_URI`. `PHP_SELF = SCRIPT_NAME + PATH_INFO`. `PATH_INFO` is any URL segment past the script name, and it's attacker-controlled.
- Any URL-derived string that reaches HTML output needs the same escaping discipline as `$_GET` values. There is no "trusted URL" from `$_SERVER`.

## 4. Body parsing: `$_GET`, `$_POST`, `$_COOKIE`, `$_FILES`, `php://input`

### Explanation

PHP populates the body-related superglobals during request startup, before your script runs. Which ones it populates and how depends on the request method and `Content-Type`.

- `$_GET` is always populated from the query string, URL-decoded, with `[]` bracket notation producing nested arrays.
- `$_POST` is populated *only* if `Content-Type` is `application/x-www-form-urlencoded` or `multipart/form-data`. A JSON API endpoint receiving `application/json` will have empty `$_POST` and the JSON body only accessible via `php://input`. This trips up developers who write `if (!empty($_POST['token']))` for JSON APIs and then wonder why the check "always passes"; it doesn't pass, but the branch does.
- `$_COOKIE` is populated from the `Cookie` header. Duplicate cookie names: PHP keeps whichever appears last in the raw header. Attackers who can set a cookie via XSS or a subdomain misconfiguration can override an existing cookie.
- `$_FILES` is populated by the multipart parser, one entry per uploaded file.
- `php://input` is the raw request body, unparsed. Only readable once per request (unless `enable_post_data_reading` is off).

Two ini settings shape body parsing in ways worth memorising:

- `max_input_vars` (default `1000`): PHP truncates the parsed input if the number of variables exceeds this limit. Extra values are silently dropped. If your `$_POST` array is supposed to have 1500 entries and you're on defaults, you'll receive 1000 and the other 500 will be gone with no error.
- `post_max_size` (default `8M`): request bodies larger than this are dropped and both `$_POST` and `$_FILES` are empty. `$_SERVER['CONTENT_LENGTH']` still shows the intended size, which is a useful detection signal.

### Vulnerable code

An admin-role assignment endpoint that accepts an array of role updates:

```php
<?php
// POST /api/roles/update
// Body: role[jeff]=user&role[sarah]=user&role[admin]=user&...&role[me]=admin
foreach ($_POST['role'] as $username => $role) {
    if (!current_user_can('assign_roles')) {
        http_response_code(403); exit;
    }
    if ($username === 'admin') {
        continue;   // never touch the admin account
    }
    set_user_role($username, $role);
}
```

Looks defensive. Skips the `admin` account, checks capability per iteration.

### Exploitation

The exploitable pattern is *truncation-driven inconsistency*. An attacker submits `role[]` with 1,005 entries: the first 1,000 are the ones the app expects (existing users mapped to `user`), and entries 1,001-1,005 are the ones the app *would have processed if it had received them* (e.g., `role[revoked_user]=none`, `role[csrf_token]=<current>`). PHP silently drops the last five. Downstream, the app thinks the update succeeded and doesn't revoke the flagged user or rotate the token, because those key/value pairs were never in `$_POST` to begin with.

Same primitive appears in bulk-update endpoints, ACL sync jobs, and cart-recalculation handlers. The bug is not that PHP throws; the bug is that PHP *doesn't* throw and the truncation is invisible to code that iterates `$_POST` and doesn't cross-check against `Content-Length` or a manifest field. Any endpoint that relies on "the client sent exactly the fields I expect" without an integrity check is exposed the moment traffic legitimately grows past the `max_input_vars` limit, and that boundary is a security-relevant one.

### Secure fix

For anything sensitive:

- Read the raw body: `$raw = file_get_contents('php://input');`. Parse it explicitly with your own decoder.
- Check `Content-Length` against `strlen($raw)` before parsing. A mismatch means truncation.
- Set `max_input_vars` high enough for legitimate traffic (10-100x expected max) and monitor for requests that hit the limit.
- For JSON APIs, always decode `php://input` with `json_decode(..., true, flags: JSON_THROW_ON_ERROR)` and never touch `$_POST`.
- For form endpoints that accept arrays, cap the array size explicitly in application code: `if (count($_POST['role']) > MAX_ROLE_UPDATES) reject();`.

### Key lessons

- `$_POST` is populated only for form-encoded and multipart requests. JSON APIs need `php://input`.
- `max_input_vars` silently truncates. Any endpoint accepting arrays needs an explicit size cap or an integrity check against `Content-Length`.
- Duplicate cookies: last wins. Subdomain XSS can set a cookie that overrides your primary domain's cookie of the same name.

## 5. Before your code runs

### Explanation

By the time your `index.php` opens its opening `<?php` tag, PHP has already made several decisions the attacker may have influenced.

- `auto_prepend_file` (php.ini or .htaccess): if set, PHP executes the named file before every request. Handy for logging, monitoring, framework bootstraps. Also, if an attacker can write to the ini or .htaccess, arbitrary code execution on every request.
- `session.auto_start = 1`: PHP starts the session before your code runs. The session ID comes from the `PHPSESSID` cookie (attacker-controlled). If your session handler reads or writes files based on the session ID, path traversal via `PHPSESSID=../../etc/passwd` becomes possible on any handler that doesn't sanitise the ID.
- Custom session handlers (`session_set_save_handler`) run before your code. If the handler class's constructor makes a network call, that network call fires on every request, controlled by the attacker's session cookie.
- `session.use_strict_mode` (default `0` on old builds, `1` on newer): whether PHP will accept a session ID that doesn't already exist. When off, an attacker can *set* the session ID: pick a value, get the victim to authenticate with that session ID, and now you're logged in as them. Session fixation.

### Vulnerable code

A shared-hosting deployment where the platform sets `session.auto_start = 1` in a global config, and the application uses the filesystem session handler with default paths:

```php
<?php
// application entry point — but the session started before this line.
if (isset($_SESSION['user_id'])) {
    render_dashboard($_SESSION['user_id']);
}
```

The developer never called `session_start()`. They assume that's fine because "the platform handles it."

### Exploitation

Attacker sends:

```
GET /dashboard HTTP/1.1
Host: victim.example
Cookie: PHPSESSID=../../../var/www/other-tenant/sessions/sess_realuser
```

If `session.use_strict_mode = 0` (the historical default) and the platform's session save path is filesystem-based, PHP reads the "session file" from the attacker-supplied path. On a shared host with lax filesystem permissions, this is a cross-tenant session read.

Even without cross-tenant filesystem access, `session.use_strict_mode = 0` enables session fixation: the attacker picks `PHPSESSID=abcd1234`, sends the victim a link that sets that cookie, waits for the victim to log in, and then uses the same `abcd1234` cookie from the attacker's browser. Same session, same authenticated identity.

### Secure fix

```ini
; php.ini
session.use_strict_mode = 1
session.cookie_httponly = 1
session.cookie_secure = 1
session.cookie_samesite = "Lax"
session.use_only_cookies = 1
session.sid_length = 48
session.sid_bits_per_character = 6
```

In application code, on every successful login:

```php
session_regenerate_id(true);
```

And never trust a session ID's *format* to prevent traversal. Use `session.save_handler = redis` (or `memcached`, or a database handler) so session IDs never touch the filesystem.

### Key lessons

- The session starts before your code runs if `session.auto_start = 1` or your framework calls `session_start()` early. The session ID is attacker-controlled.
- `session.use_strict_mode = 1` is the fix for session fixation. Verify it's set in every environment; it's off by default on older PHP builds.
- `session_regenerate_id(true)` on every authentication state change (login, logout, privilege escalation, MFA step-up). Session hijacking assumes the attacker can steal the session ID; regeneration invalidates the stolen value.

## 6. Case studies

Three real incidents that stop being confusing once you know the lifecycle.

**PHP-FPM `SCRIPT_FILENAME` traversal (2018-2019, various CVEs).** The nginx `alias` directive doesn't append a trailing slash the way `root` does. A `location /admin { alias /var/www/admin; }` block combined with a request to `/admin../etc/passwd` produced `SCRIPT_FILENAME = /var/www/etc/passwd`, which PHP-FPM happily read and executed if it ended in `.php`. Fix: `location /admin/ { alias /var/www/admin/; }` (trailing slashes on both sides) and `try_files` on any PHP location.

**HTTP request smuggling into WordPress admin (2020, disclosed 2021).** A CDN in front of a WordPress site parsed `Transfer-Encoding` per RFC 9112; the origin nginx parsed `Content-Length` first (older nginx builds). A CL.TE smuggling primitive let an attacker inject a `POST /wp-admin/admin-ajax.php` request into another authenticated user's session queue. Impact: any AJAX endpoint the victim's session had access to could be invoked. Fix: upgrade nginx to a build that rejects requests with both headers.

**`PHP_SELF` XSS in a payment plugin (recent enough that I won't name it).** The `pay.php` page had a form whose action was `$_SERVER['PHP_SELF']`. The plugin's routing allowed `PATH_INFO` to reach the script (`/pay.php/anything`). Attacker sent `/pay.php/"><script>...</script>`, form action became `pay.php/"><script>...</script>`, script executed in the checkout flow, credit-card details lifted. Fix: `htmlspecialchars($_SERVER['SCRIPT_NAME'], ENT_QUOTES | ENT_HTML5, 'UTF-8')` and stop using `PHP_SELF` anywhere near HTML output.

Every one of these is a specific vulnerability, but the shared root cause is somebody using `$_SERVER` or `SCRIPT_FILENAME` or a body-parsing default without knowing which layer supplied the value.

## Conclusion

The request lifecycle is why a two-part fix (one at the web server, one in application code) works so often. The web server is where URLs turn into filesystem paths and where request headers become PHP variables. The application is where those values reach a sink (SQL, HTML, filesystem, network, session). A vulnerability lives in the mismatch: the web server assumed the application would sanitise, and the application assumed the web server had. Defence in depth at both layers is the reliable pattern.

Next in the [PHP and Web Security Tutorial Series](/tutorials/learn-php-before-advanced-web-hacking/): *SQL Injection in PHP: From `mysql_query` to PDO Bind-Param Pitfalls*. That article assumes you know how `$_GET`, `$_POST`, and `php://input` reach the query building code (this article) and how loose comparison lets a `null` byte through a `WHERE` clause check (the [previous article](/tutorials/php-fundamentals-for-security/)).

## Coming up in the series

Internal links go live as articles ship.

1. [PHP Fundamentals for Security: Comparison Operators, Superglobals, and the Loose-Typing Trap](/tutorials/php-fundamentals-for-security/)
2. [The HTTP Request Lifecycle in PHP: From Socket to `$_SERVER`](/tutorials/http-request-lifecycle-in-php/) &larr; you are here
3. SQL Injection in PHP: From `mysql_query` to PDO Bind-Param Pitfalls
4. Cross-Site Scripting (XSS) in PHP Applications
5. CSRF and WordPress Nonces Explained
6. File Upload Vulnerabilities: Double Extensions, Magic Bytes, and `.htaccess` Bundling
7. Local File Inclusion (LFI) and `php://filter` Chains to RCE
8. PHP Object Injection: Deserialization, PHAR, and Gadget Chains
9. PHP Type Juggling: Loose Comparison, Hash Collisions, and `0e...` Strings
10. SSRF in PHP: DNS Rebinding and Allow-List Bypasses
11. Apache, Nginx, and PHP-FPM for Web Hackers
12. Source Code Review for WordPress Plugins: A Practical Workflow

---

*Further reading: PortSwigger's HTTP Desync research is the canonical smuggling reference; the Nginx wiki's "Pitfalls and Common Mistakes" page has the definitive PHP-FPM configuration guidance; the PHP manual's [Session Configuration Options](https://www.php.net/manual/en/session.configuration.php) page lists every ini directive relevant to Section 5.*
