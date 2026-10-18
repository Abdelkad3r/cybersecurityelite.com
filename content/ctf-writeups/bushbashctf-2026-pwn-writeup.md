---
title: "BushBashCTF 2026 Binary Exploitation Writeup: Hack The Vault II — Adjacent Buffer NUL Overwrite & printf %s Overread"
slug: "bushbashctf-2026-pwn-writeup"
description: "BushBashCTF 2026 pwn writeup: a getchar and fread interaction overwrites the buffer terminator and exposes an adjacent password."
date: 2026-08-02T12:00:00Z
lastmod: 2026-08-04T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["BushBashCTF 2026"]
tags:
  - "bushbashctf"
  - "bushbashctf 2026"
  - "ctf writeup"
  - "pwn"
  - "binary exploitation"
  - "buffer overread"
  - "stack layout"
  - "nul overwrite"
  - "printf leak"
  - "c string"
  - "adjacent buffer"
  - "socket exploit"
  - "ctf 2026"
keywords:
  - "bushbashctf 2026 writeup"
  - "hack the vault ii ctf writeup"
  - "adjacent buffer overread ctf"
  - "printf %s overread ctf"
  - "nul overwrite stack buffer ctf"
  - "getchar input terminator exploit"
  - "password leak printf ctf"
  - "buffer password alias stack ctf"
  - "two connection exploit ctf"
  - "binary exploitation ctf 2026"
  - "stack buffer layout exploit"
  - "c string overread ctf challenge"
  - "bushbash ctf binary exploit"
  - "fread nul overwrite ctf"
  - "socket shutdown exploit ctf"
toc: true
cover:
  image: "/images/articles/bushbashctf-2026-pwn-writeup.png"
  alt: "Dark grid cover card for BushBashCTF 2026 Binary Exploitation, with large high-contrast title lettering."
---

BushBashCTF 2026’s binary-exploitation track included **Hack The Vault II**, a small C authentication service. The challenge repository provides the source, solver, and README. Reviewing those artifacts resolves the earlier conflicting explanations: this is not a `fgets` edge case or a race. The source reads input first, writes its terminator at the start of the adjacent password region when the input is exactly 127 bytes, then reads the password over that terminator before printing the input as a C string.

The result is an information disclosure: the `%s` print continues from the input into the password. A second connection submits the recovered password and receives the flag.

Challenge source and solver: [repository](https://github.com/Abdelkad3r/BushBashCTF-2026), [`vault.c`](https://github.com/Abdelkad3r/BushBashCTF-2026/blob/main/pwn/hack-the-vault-ii/vault.c), [`solve.py`](https://github.com/Abdelkad3r/BushBashCTF-2026/blob/main/pwn/hack-the-vault-ii/solve.py), and [challenge README](https://github.com/Abdelkad3r/BushBashCTF-2026/blob/main/pwn/hack-the-vault-ii/README.md).

## Challenge at a glance

| Field | Value |
|---|---|
| CTF | BushBashCTF 2026 |
| Category | PWN / Binary Exploitation |
| Challenge | Hack The Vault II |
| Vulnerability | C-string overread caused by an overwritten terminator |
| Primitive | Password disclosure through `printf("%s", buffer)` |
| Exploit | One connection to leak; a second to authenticate |
| Flag | `bushbash{1nto-th3-bUsh-w3-Go}` |

## 1. Inspect the source and memory layout

The challenge’s `auth()` function allocates a 191-byte local array and points the input and password regions into it:

```c
char array[127 + 64];
char *buffer = &array[0];
char *password = &array[127];
```

The regions are adjacent:

```text
array[0..126]   input bytes (127-byte maximum)
array[127..190] password storage
```

The source reads input with a manual `getchar()` loop. It stops on newline, carriage return, or EOF, then writes a NUL at `buffer[inputlen]`:

```c
while ((c = getchar()) != '\n' && c != '\r' && c != EOF) {
    if (inputlen == 127) {
        printf("input exceeded buffer limit\n");
        return 0;
    }
    buffer[inputlen] = c;
    ++inputlen;
}
buffer[inputlen] = '\0';
```

Exactly 127 input bytes are accepted: after the 127th byte, the next `getchar()` sees EOF (or a line terminator), the loop exits, and the terminator is written at `buffer[127]`. That address is also `password[0]`. A 128th non-terminator byte takes the bounds-check error path.

Next, the program loads up to 48 bytes from `password.txt` into `password` and appends a NUL after the bytes read:

```c
size_t bytesRead = fread(password, 1, 48, pf);
password[bytesRead] = '\0';
```

Because this file read happens **after** the input terminator is written, its first password byte overwrites `array[127]`. The `%s` print then has no terminator between the 127 input bytes and the password bytes.

## 2. Leak the password

The repository solver opens a connection, reads the prompt, sends 127 `A` bytes, and half-closes the write side. The EOF ends the input loop without adding a newline to the payload:

```python
sock.sendall(b"A" * 127)
sock.shutdown(socket.SHUT_WR)
```

The server’s order of operations is now:

1. Store the 127 `A` bytes in `array[0..126]`.
2. Write the input NUL to `array[127]`.
3. Read the password into `array[127..]`, overwriting that NUL, and terminate the password after the bytes read.
4. Print `buffer` using `%s`; the string runs through the input and into the adjacent password until the password terminator.
5. Compare the input length and content with the password. The 127-byte leak request is rejected, but the disclosure has already happened.

The solver locates the echoed prefix and extracts the bytes after it up to the newline. This avoids relying on a fixed password length.

## 3. Submit the recovered password

The first connection is only for disclosure. Open another connection and submit the recovered password followed by a newline. The input loop writes a terminator within the input region, the password is read into its separate adjacent region, and the length plus `strncmp` checks succeed. The service then prints the flag.

The included [`solve.py`](https://github.com/Abdelkad3r/BushBashCTF-2026/blob/main/pwn/hack-the-vault-ii/solve.py) implements both connections and accepts an optional host and port. The remote endpoint and password in the challenge README are challenge-era values; use the endpoint supplied by the CTF platform if it has changed.

## Why earlier explanations were inconsistent

The vulnerable source uses neither `fgets()` nor `dprintf()` and does not read the password from a file named `/flag`. It uses a manual `getchar()` loop, `fread(password, 1, 48, pf)`, and `printf()` to standard output. The disclosure works because the later `fread` overwrites the terminator at the shared boundary. There is no race, and the exploit does not rely on a one-byte NUL persisting across connections.

The repository README says that adding a newline after exactly 127 input bytes fails, but the source’s loop condition checks for newline before entering the bounds-check body. Therefore, a newline after byte 127 also ends the loop before the guard; the provided solver uses `SHUT_WR` and exactly 127 data bytes, which is the behavior directly verified here and keeps the payload unambiguous.

## Local validation

To verify the memory-boundary behavior safely, compile the repository’s `vault.c` in a temporary directory with test-only `password.txt` and `flag.txt` files. Send 127 non-NUL bytes, then EOF; the response should include those bytes followed by the fixture password. Start a fresh process and submit that fixture password with a newline; it should print the fixture flag. The original repository does not include the secret password or flag files, so the fixture validates the vulnerable source behavior rather than reproducing the original secret values.

## Defensive lesson

A length check on user input does not make adjacent logical buffers independent. Here the program accepts all 127 input bytes and places the terminator in the next logical region; a later file read removes that terminator. Keep user input and secrets in separate objects, and print user input with an explicit length rather than relying on a terminator that another write can replace. For example, a bounded write using the validated input length avoids scanning into adjacent memory.

## Frequently asked questions

**Does the exploit use a buffer overflow?** It does not overwrite a return address or write outside the allocated 191-byte array. The bug is an out-of-bounds string read after the password file read replaces the input terminator.

**Why use `SHUT_WR`?** It sends EOF to the server while keeping the client socket open to receive the response. This ends the manual input loop without putting a newline in the 127-byte payload.

**Can the exact original password be reproduced locally?** Not from the public source repository alone: it omits `password.txt` and `flag.txt`. The included remote solver and README document the original challenge result; a local fixture can verify the vulnerable read/print sequence without the original secrets.

**What is the flag?** `bushbash{1nto-th3-bUsh-w3-Go}`
