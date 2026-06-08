---
title: "GPN CTF 2026 — Customer Service: Three Bugs in a holpy Proof Checker"
slug: "gpn-ctf-2026-customer-service"
description: "GPN CTF 2026 Misc: list == 1 typo, every thm is re-axiomatized, win check matches false by name. Declare a homemade false constant, axiomatize it, ship a one-line proof."
date: 2026-06-07T19:50:00Z
lastmod: 2026-06-07T19:50:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
tags:
  - "gpn ctf 2026"
  - "customer service"
  - "holpy proof checker"
  - "lcf logic"
  - "axiom injection"
  - "thm extension bug"
  - "name vs term comparison"
  - "ex contradictione quodlibet"
series: ["GPN CTF 2026"]
keywords:
  - "gpn ctf customer service writeup"
  - "holpy proof checker bug"
  - "ctf lcf kernel bypass"
  - "thm axiom report bug"
  - "list equals 1 typo ctf"
  - "is_const false name comparison ctf"
  - "ex contradictione quodlibet ctf"
toc: true
cover:
  image: "/images/articles/gpn-ctf-2026-customer-service.png"
  alt: "GPN CTF 2026 Customer Service writeup — three bugs stacked in a holpy proof checker yield ex contradictione quodlibet"
---

{{< ctf-meta platform="GPN CTF 2026 (kitctf)" difficulty="Medium-Hard" os="Misc — holpy proof checker, LCF-style higher-order logic" skills="reading 115 lines of checker glue around holpy's monitor, spotting list == 1 as a dead branch, recognising Theorem.get_extension always re-axiomatizes, exploiting concl.is_const('false') as a name comparison in an EmptyTheory scope, declaring a homemade false constant and proving it with a one-line theorem rule" >}}

**Customer Service** is the GPN CTF 2026 misc challenge that builds an LCF-style higher-order-logic proof assistant from [holpy](https://github.com/Mr-Pine/holpy), pretends to forbid axioms, and gets its guard wrong three ways. The exploit is a three-item JSON payload: declare a `false` constant of our own, axiomatize it, ship a one-line proof. The flag spells the lesson:

```
GPNCTF{Ex-Un4-Line4-VACu4-sEqui7ur-QuOdl1b3t}
```

*Ex contradictione quodlibet* — "from a contradiction, anything follows." The flag's mangled Latin reads *ex una linea vacua sequitur quodlibet* — "from one empty line, anything follows" — naming the lone allowed axiom that breaks soundness.

This is the standalone deep-dive on `misc/customer-service` from the [GPN CTF 2026 master writeup](/ctf-writeups/gpn-ctf-2026-writeup/). Full source at [`misc/customer-service`](https://github.com/Abdelkad3r/gpn-ctf-2026/tree/master/misc/customer-service).

## The oracle

`checker.py`, ~115 lines, in essence:

```python
hex_proof = input("give me your hex proof")
data = json.loads(bytes.fromhex(hex_proof).decode("utf-8"))

with theory.fresh_theory():
    for imp in data.get("imports", []):
        basic.load_theory(imp)

    for raw in data.get("content", []):
        item = items.parse_item(raw)
        if item.error: continue

        if item.ty == "thm":
            result = monitor.check_proof(item, rewrite=False)
            if result["status"] in ["OK", "ProofOK"]:
                exts = item.get_extension()
                report = theory.thy.checked_extend(exts)
                if len(report.get_axioms()) > 1: sys.exit(1)
                elif report.get_axioms() == 1 and item.ty != "thm": sys.exit(1)
                thm = theory.thy.get_theorem(item.name)
                if theorem_proves_false_unconditioned(thm):
                    win()           # prints the flag
                sys.exit(0)
            else: sys.exit(1)
        else:
            exts = item.get_extension()
            report = theory.thy.checked_extend(exts)
        if len(report.get_axioms()) > 1: sys.exit(1)
        elif report.get_axioms() == 1 and item.ty != "thm": sys.exit(1)
```

The win check:

```python
def theorem_proves_false_unconditioned(thm):
    concl_str = str(thm.concl).strip().lower()
    is_false = (thm.concl.is_const("false") or
                concl_str == "false" or concl_str == "?false")
    return is_false and len(thm.assums) == 0 and len(thm.hyps) == 0
```

The author's source comments include `# HELP WTF IS THIS IG` and `# ig we addd it ??` — they're telling you they glued this together and aren't sure why it works. They are correct to be unsure.

## Bug 1 — `list == 1`

```python
if (len(report.get_axioms())) > 1: …                  # OK, length check
elif report.get_axioms() == 1 and item.ty != "thm": … # dead
```

`ExtensionReport.get_axioms()` returns a list of `(name, info)` tuples. `[] == 1`, `[("x", t)] == 1` — both `False`. The `elif` is unreachable. So the real budget is *up to one* axiom per item, not zero.

## Bug 2 — every `thm` is also an axiom

`server/items.py::Theorem(Axiom)` inherits `get_extension()` from `Axiom`:

```python
def get_extension(self):
    res = [extension.Theorem(self.name, Thm(self.prop))]   # prf=None!
    …
```

Then `kernel/theory.py::checked_extend`:

```python
elif ext.is_theorem():
    if ext.prf:
        self.check_proof(ext.prf)
    else:                                  # this branch
        ext_report.add_axiom(ext.name, ext.th)
    self.add_theorem(ext.name, ext.th)
```

So even a `thm` item that just had its proof checked by `monitor.check_proof` is re-installed as an axiomatic theorem and ticks the axiom counter. The `>1` bound is the entire safety net, and it allows exactly this.

## Bug 3 — a homemade `false`

The loader runs in `fresh_theory()` which calls `EmptyTheory()`:

```python
thy.add_type_sig("bool", 0)
thy.add_type_sig("fun", 2)
thy.add_term_sig("equals", …)
thy.add_term_sig("implies", …)
thy.add_term_sig("all", …)
```

That's it. No `false`, no `not`, no `&`. The real `false` constant lives in `library/logic_base.json`, which **isn't shipped** in the installed wheel — `imports: ["logic_base"]` errors with `No such file or directory: '/challenge/.venv/.../library/'`.

`theorem_proves_false_unconditioned` doesn't notice. It just calls `thm.concl.is_const("false")` — true for **any** `Const("false", _)`. So we declare a `false : bool` of our own with `def.ax`.

## The exploit

```json
{
  "imports": [],
  "content": [
    { "ty": "def.ax",  "name": "false",             "type": "bool" },
    { "ty": "thm.ax",  "name": "customer_is_right", "vars": {}, "prop": "false" },
    {
      "ty": "thm", "name": "pwn", "vars": {}, "prop": "false", "num_gaps": 0,
      "proof": [
        { "id": "0", "rule": "theorem", "args": "customer_is_right",
          "prevs": [], "th": "⊢ false" }
      ]
    }
  ]
}
```

Walking the loop:

| # | Item                              | `len(get_axioms())` after | `>1`? |
|---|-----------------------------------|---------------------------|-------|
| 0 | `def.ax false : bool`             | 0 (constants don't count) | ok    |
| 1 | `thm.ax customer_is_right : false`| 1 (axiom)                 | ok    |
| 2 | `thm pwn` with `theorem` rule     | 1 (Bug 2)                 | ok    |

For item 2, `monitor.check_proof` enters the `item.proof` branch, parses one step, and looks it up by `kernel/theory.py:339`:

```python
if seq.rule == "theorem":
    res_th = self.get_theorem(seq.args)   # customer_is_right
```

`res_th` is `Thm(false)` with empty hyps. The advertised `seq.th = "⊢ false"` matches, status is `ProofOK`. `checked_extend` then re-adds `pwn` as a no-proof theorem (Bug 2), the axiom count is 1 (Bug 1 lets it slide), `get_theorem("pwn")` returns `Thm(false)` — `concl.is_const("false")` ✓, `hyps == ()` ✓, `assums == ()` (an unconditioned `false` has no implication prefix) ✓.

`win()` opens `./flag.txt`.

## Running it

```bash
hex=$(python3 -c "print(open('exploit.json').read().encode().hex())")
echo "$hex" | openssl s_client -quiet \
  -connect grilled-souffle-beside-roasted-tomato-juss.gpn24.ctf.kitctf.de:443
```

```
give me your hex proof✓ Proof check passed
Congratulations! You've found the flag: GPNCTF{Ex-Un4-Line4-VACu4-sEqui7ur-QuOdl1b3t}
```

## Why it was solvable at all

In a real LCF kernel none of this would land. The two real load-bearing mistakes:

- The author's intent was "you can ship definitions and theorems but not raw axioms" — they tried to enforce that on the report. But `checked_extend` itself was designed around the assumption that a `Theorem` extension *with* a proof is fine, and a Theorem *without* a proof is by definition an axiom. `Theorem.get_extension()` always produces the second flavour — the proof never makes it past `monitor.check_proof`. So every `thm` accepted by the monitor is then re-typed as an axiom by the kernel. Fixing the `list == 1` typo would *also* lock out every valid theorem; the real fix is to thread the checked proof into the extension.
- The win check uses a string-name comparison instead of comparing the conclusion term to the actual logical `false` in scope. Since the loader runs in `EmptyTheory()` and the `library/` directory isn't shipped, there *is* no logical false to compare to — any opaque `Const("false", bool)` wins.

## Defender takeaway

- **Name-based equality on logical terms is a recurring bug class in proof-checker glue code.** `thm.concl.is_const("false")` matches on the constant's *name string*, not on whether the term *is* the logical false defined in the theory. In a fresh theory with no logical false in scope, any opaque `Const("false", _)` passes — including ones the user declared.
- **List-vs-int comparison (`report.get_axioms() == 1`)** is a Python type-system idiom that should be caught by a linter. `mypy` or `pyright` with strict mode flags `list == int` as a type error. Adopting one in your CI would have caught this bug at PR time.
- **LCF-style proof kernels are only as strong as the smallest interface around them.** holpy itself is well-engineered; the 115-line wrapper that exposes it over a network is the vulnerable surface. Whenever you wrap a trusted kernel in glue code, the glue inherits the kernel's trust assumptions — and the glue is almost always weaker.

## Frequently asked questions

### What's the first bug — `list == 1`?

`ExtensionReport.get_axioms()` returns a list. The comparison `list == 1` is always `False` in Python — `list` and `int` are not equal under `==`. The author wrote the check as a guard against "any axioms" but the comparison shape never fires. The actual guard becomes `len(get_axioms()) > 1` — *up to one* axiom per item is allowed.

### What's the second bug — `thm` re-axiomatization?

`Theorem.get_extension()` inherits from `Axiom.get_extension` and always returns a `Theorem` extension with `prf=None`. The kernel's `checked_extend` sees `prf=None` and re-adds the theorem as an *axiom*, ticking the axiom counter. So even a fully-proved theorem gets axiomatized after acceptance — the budget of one axiom (from Bug 1) covers this re-axiomatization.

### What's the third bug — `is_const("false")`?

`Term.is_const("false")` matches on the constant's *name string*, not on identity with the logical false. The loader runs in `EmptyTheory()` which has no `false` constant in scope. We declare our own `false : bool` opaque constant via `def.ax`, and the win check accepts it because the name matches — even though it has nothing to do with logical falsity.

### Why is the exploit only three items?

Item 0: declare `false : bool` (a constant declaration; doesn't count as an axiom). Item 1: declare an axiom `customer_is_right : false` (one axiom, fits the budget). Item 2: a `thm` named `pwn` with proof rule `theorem customer_is_right` — checks out under the monitor (the axiom is exactly what's claimed), gets re-axiomatized by Bug 2 (axiom count still 1, within budget), and wins under Bug 3 (name-equality match on the opaque `false` constant).

### Why is `imports: []` necessary?

The real `false`, `not`, `and`, etc. live in `logic_base`, which isn't shipped with the installed wheel. Attempting `imports: ["logic_base"]` errors with `No such file or directory`. Leaving `imports` empty runs in `EmptyTheory`, which has no logical false at all — making Bug 3 exploitable.

### How would a real LCF kernel resist this?

Real LCF kernels (HOL Light, Isabelle/HOL, Coq) compare terms by their *type-checked structure*, not by name. The win check would be `thm.concl == constants.false_const`, where `constants.false_const` is the kernel's authoritative reference. Name shadowing wouldn't help; declaring `false : bool` would create a *different* term that `==` would reject. Also, no real LCF kernel re-axiomatizes proven theorems.

### Where can I find the solver?

Full source at [`misc/customer-service`](https://github.com/Abdelkad3r/gpn-ctf-2026/tree/master/misc/customer-service) including `exploit.json` and `solve.sh`. Master writeup at [/ctf-writeups/gpn-ctf-2026-writeup/](/ctf-writeups/gpn-ctf-2026-writeup/).

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type": "Question","name": "What's the first bug — list == 1?","acceptedAnswer": {"@type": "Answer","text": "ExtensionReport.get_axioms() returns a list. list == 1 is always False in Python — list and int are not equal under ==. The author wrote it as a guard against any axioms but the comparison never fires. The actual guard becomes len(get_axioms()) > 1, allowing up to one axiom per item."}},
    {"@type": "Question","name": "What's the second bug — thm re-axiomatization?","acceptedAnswer": {"@type": "Answer","text": "Theorem.get_extension() inherits from Axiom.get_extension and always returns a Theorem extension with prf=None. The kernel's checked_extend sees prf=None and re-adds the theorem as an axiom, ticking the axiom counter. Even a fully-proved theorem gets axiomatized — the budget of one axiom from Bug 1 covers this."}},
    {"@type": "Question","name": "What's the third bug — is_const false?","acceptedAnswer": {"@type": "Answer","text": "Term.is_const('false') matches on the constant's name string, not on identity with the logical false. The loader runs in EmptyTheory() which has no false in scope. We declare our own false : bool via def.ax, and the win check accepts it because the name matches."}},
    {"@type": "Question","name": "Why is the exploit only three items?","acceptedAnswer": {"@type": "Answer","text": "Item 0: declare false : bool (constant declaration; not an axiom). Item 1: axiom customer_is_right : false (one axiom, fits budget). Item 2: thm pwn with proof rule theorem customer_is_right — checks under the monitor, gets re-axiomatized by Bug 2 (count still 1), wins under Bug 3."}},
    {"@type": "Question","name": "Why is imports: [] necessary?","acceptedAnswer": {"@type": "Answer","text": "The real false, not, and live in logic_base, not shipped with the installed wheel. imports: ['logic_base'] errors with No such file or directory. Leaving imports empty runs in EmptyTheory with no logical false at all — making Bug 3 exploitable."}},
    {"@type": "Question","name": "How would a real LCF kernel resist this?","acceptedAnswer": {"@type": "Answer","text": "Real LCF kernels (HOL Light, Isabelle/HOL, Coq) compare terms by type-checked structure, not by name. The win check would be thm.concl == constants.false_const, the kernel's authoritative reference. Name shadowing wouldn't help. Also, no real LCF kernel re-axiomatizes proven theorems."}},
    {"@type": "Question","name": "Where can I find the solver code?","acceptedAnswer": {"@type": "Answer","text": "Full source at misc/customer-service in github.com/Abdelkad3r/gpn-ctf-2026 including exploit.json and solve.sh. Master writeup at cybersecurityelite.com/ctf-writeups/gpn-ctf-2026-writeup/."}}
  ]
}
</script>
