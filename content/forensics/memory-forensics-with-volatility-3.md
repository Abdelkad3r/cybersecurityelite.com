---
title: "Memory Forensics with Volatility 3: A Hands-On Tutorial"
slug: "memory-forensics-with-volatility-3"
description: "Volatility 3 tutorial — acquiring memory, hunting injected processes, recovering credentials, and identifying rootkits in Windows and Linux memory images."
date: 2026-04-08T10:00:00Z
lastmod: 2026-04-08T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["Digital Forensics"]
tags: ["volatility", "memory forensics", "DFIR", "incident response"]
keywords: ["volatility 3 tutorial", "memory forensics", "windows memory analysis"]
weight: 1
toc: true
cover:
  image: "/images/og-default.svg"
  alt: "Volatility 3 memory forensics tutorial"
---

Memory forensics catches what disk forensics misses — running malware, in-RAM credentials, injected processes, and rootkit hooks. Volatility 3 modernized the framework with Python 3, symbol-driven analysis, and a cleaner plugin model. Here's how to actually use it.

## Acquiring Memory

Windows: WinPmem, FTK Imager, or DumpIt. Linux: LiME or AVML. Always:

- Acquire **before** any other intrusive action — even running `ps` perturbs the image.
- Hash immediately (SHA-256) and chain-of-custody the file.
- Capture page file (`pagefile.sys`) alongside RAM — Volatility 3 can ingest it for completeness.

```bash
# Linux acquisition with AVML
sudo ./avml /case/$(hostname)-$(date +%Y%m%d).lime
sha256sum /case/*.lime > /case/hashes.txt
```

## First-Pass Triage

```bash
# Identify the OS and build
vol -f mem.raw windows.info

# Process list (uses _EPROCESS walking — catches DKOM but not all hiding)
vol -f mem.raw windows.pslist

# Process list cross-referenced with handle and thread tables
vol -f mem.raw windows.psscan

# Tree view — parent/child relationships
vol -f mem.raw windows.pstree
```

The pair `pslist` + `psscan` is the classic anti-rootkit comparison: any process present in `psscan` but missing from `pslist` is hidden via Direct Kernel Object Manipulation.

## Hunting Injected Code

```bash
# Memory regions marked executable but private (classic injection signature)
vol -f mem.raw windows.malfind

# DLL-load anomalies
vol -f mem.raw windows.dlllist --pid 1234

# Network connections (TCP and UDP)
vol -f mem.raw windows.netscan
```

`malfind` flags every RWX private region. False positives include .NET JIT, but in a triage context the noise is manageable. Hits in `lsass.exe`, `svchost.exe`, or `explorer.exe` are particularly suspicious.

## Credential Recovery

Memory often contains:

- **NTLM hashes** (LSASS) via `windows.hashdump`
- **Kerberos tickets** via `windows.lsadump` (and offline replay)
- **Cleartext credentials** in browsers, RDP clients, and forgotten input fields

```bash
vol -f mem.raw windows.hashdump
vol -f mem.raw windows.lsadump
vol -f mem.raw windows.cachedump
```

{{< callout type="warning" title="Legal scope" >}}
Credential recovery from memory is invasive. Verify your engagement scope explicitly covers it — many internal investigations carve out user credentials to prevent privacy violations.
{{< /callout >}}

## Timeline Reconstruction

A timeline of process creation gives you the attack story:

```bash
# Process timeline
vol -f mem.raw timeliner.Timeliner

# Filesystem MFT
vol -f mem.raw windows.mftscan.MFTScan
```

Pipe through `mactime` or import into Plaso for cross-source correlation with disk and event log artifacts.

## Rootkit Hunting

```bash
# SSDT hook check (legacy but still relevant)
vol -f mem.raw windows.ssdt

# Driver list — look for unsigned, unusual loads
vol -f mem.raw windows.modules

# Callbacks (PsSetCreateProcessNotifyRoutine etc.)
vol -f mem.raw windows.callbacks
```

Modern rootkits hide via PG-bypass tricks rather than SSDT hooks, but every once in a while you'll still see a Mimikatz mini-driver or an older toolkit show up.

## Linux Notes

Linux Volatility 3 requires **kernel symbol tables** (`.json.xz` files). Build with `dwarf2json` from the target host's `vmlinux` or matching kernel debug package. Without symbols, you're limited to raw string carving.

```bash
vol -f linux.lime -s ./symbols linux.pslist.PsList
```

## Practical Workflow

For real IR cases:

1. Acquire memory + page file.
2. Run `windows.info`, `pslist`, `pstree`, `netscan`, `malfind` — five plugins that cover 80% of triage.
3. Cross-reference suspicious PIDs against disk artifacts (Prefetch, AmCache, RecentApps).
4. Dump suspicious processes (`windows.dumpfiles --pid X`) for static analysis.

## References

- [Volatility 3 GitHub](https://github.com/volatilityfoundation/volatility3)
- [The Volatility Cheat Sheet](https://www.volatilityfoundation.org/24)
- [The Art of Memory Forensics (book)](https://www.memoryanalysis.net/amf)
