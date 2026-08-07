---
title: "L3akCTF 2026 Forensics Writeup: All 4 Challenges"
slug: "l3akctf-2026-forensics-writeup"
description: "Full L3akCTF 2026 forensics writeup covering all four challenges: carving Windows thumbnail-cache databases to recover a flag from a cached RIZZLER preview after the user already decrypted a 7-Zip archive (L3ak APT); reconstructing a CT sinogram stored in SQLite via filtered back-projection with iradon to read a flag in the reconstructed X-ray image (You Scanned WHAT?!?); scaling that to 617 sinograms into a 3D volume projection (You Scanned HOW?!?!); and parsing Windows Jump Lists as OLE Compound File containers to pull the share path, File Droid GUID, hostname, and rename trail for the NoNeedToWonder folder (Transcendent Renovation)."
date: 2026-08-06T18:00:00Z
lastmod: 2026-08-06T18:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["L3akCTF 2026"]
tags:
  - "l3akctf"
  - "l3akctf 2026"
  - "ctf writeup"
  - "forensics"
  - "digital forensics"
  - "dfir"
  - "windows forensics"
  - "jump lists"
  - "ole compound file"
  - "thumbnail cache"
  - "thumbcache"
  - "mft"
  - "artifact analysis"
  - "file carving"
  - "ct sinogram"
  - "radon transform"
  - "filtered back-projection"
  - "iradon"
  - "sqlite"
  - "image reconstruction"
  - "ctf 2026"
keywords:
  - "l3akctf 2026 forensics writeup"
  - "l3ak apt ctf writeup"
  - "you scanned what ctf writeup"
  - "you scanned how ctf writeup"
  - "transcendent renovation ctf writeup"
  - "windows thumbnail cache carving ctf"
  - "jump list ole compound file forensics"
  - "ct sinogram reconstruction ctf"
  - "filtered back projection iradon ctf"
  - "thumbcache flag recovery forensics"
  - "file droid guid jump list forensics"
  - "forensics ctf 2026"
toc: true
cover:
  image: "/images/articles/l3akctf-2026-forensics-writeup.png"
  alt: "L3akCTF 2026 forensics writeup covering all four challenges — L3ak APT carves Windows thumbnail-cache databases to recover a flag from a cached RIZZLER preview after the user already decrypted a 7-Zip archive, You Scanned WHAT reconstructs a CT sinogram stored in a SQLite projections table via filtered back-projection with iradon to read the flag arched over an X-ray droplet mascot, You Scanned HOW scales that to 617 SQLite slice tables reconstructed into a 3D CT volume whose summed projection spells the flag along the scanned object, and Transcendent Renovation parses Windows Jump Lists as OLE Compound File containers to extract the tsclient HauntedHouse share path, the File Droid GUID, the logging-vm hostname, and the NoNeedToWonder folder rename trail"
---

Forensics at L3akCTF 2026 split cleanly into two disciplines: **Windows artifact analysis** — the kind of DFIR triage that reconstructs a user's activity from Jump Lists, the MFT, and thumbnail caches — and a two-part **signal-processing** pair that hid flags inside CT scan data. Both reward the same instinct: don't attack the obvious locked door (an encrypted archive, a single unreadable slice); find the byproduct the system left behind or the transform that makes the data legible.

This **CyberSecurity Elite** L3akCTF 2026 forensics writeup walks all four challenges end to end, focused on the reasoning and the tooling. Challenge artifacts and solve scripts are at [Abdelkad3r/L3akCTF-2026](https://github.com/Abdelkad3r/L3akCTF-2026). For the rest of the event, see the [pwn](/ctf-writeups/l3akctf-2026-pwn-writeup/), [crypto](/ctf-writeups/l3akctf-2026-crypto-writeup/), [misc](/ctf-writeups/l3akctf-2026-misc-writeup/), [web](/ctf-writeups/l3akctf-2026-web-writeup/), and [OSINT](/ctf-writeups/l3akctf-2026-osint-writeup/) writeups.

## All four challenges at a glance

| Challenge | Difficulty | Points | Solves | Discipline | Key technique |
|---|---|---:|---:|---|---|
| [L3ak APT](#l3ak-apt--let-windows-decrypt-it-for-you) | Easy | 91 | 81 | Windows DFIR | Thumbnail-cache carving |
| [You Scanned WHAT?!?](#you-scanned-what--inverting-a-ct-sinogram) | Medium | 104 | 63 | Signal processing | Filtered back-projection (`iradon`) |
| [You Scanned HOW?!?!](#you-scanned-how--from-one-slice-to-a-3d-volume) | Medium | 119 | 50 | Signal processing | 617-slice CT volume projection |
| [Transcendent Renovation](#transcendent-renovation--reading-windows-jump-lists) | Beginner | 141 | 38 | Windows DFIR | Jump List (OLE CF) parsing |

---

## L3ak APT — let Windows decrypt it for you

> *Flag:* `L3AK{For3nsics_hUm4n$_C4n_c00K_AI}`

A KAPE-style Windows triage image (`$MFT`, `Users`, `Windows`, `ProgramData`). The story reconstructs quickly from browser history, uTorrent state, recent shortcuts, and Sysmon: the user "Max" downloaded `important files.7z` via uTorrent and opened it with 7-Zip, then viewed extracted images under `Projects\media` in Microsoft Photos. The uTorrent resume DB even records the exact path (`C:\Users\Max\Downloads\important files.7z`) and size.

The tempting trap is the **encrypted 7-Zip archive** — you could even re-fetch it from the recovered `.torrent`. But the artifacts prove the user *already decrypted and viewed it*, and that's the shortcut: when Explorer or Photos renders an image, Windows caches a preview in `thumbcache_*.db`. Those cached previews survive even when the original files aren't in the collection. Since thumbnails are embedded image blobs, a magic-byte carve is enough:

```python
JPEG_START = bytes.fromhex("ffd8ff");            PNG_START = bytes.fromhex("89504e470d0a1a0a")
JPEG_END   = bytes.fromhex("ffd9");              PNG_END   = bytes.fromhex("49454e44ae426082")
```

Carving all 15 thumbnail databases recovered 25 cached previews of the extracted Cyberpunk-themed images — and one `RIZZLER` thumbnail had the flag printed right on it. **Takeaway:** the encrypted archive was never the target. The user did the decryption; Windows preserved the result. In DFIR, cached byproducts (thumbnails, Shellbags, prefetch, `$MFT`) often hold evidence the original files no longer can.

---

## You Scanned WHAT?!? — inverting a CT sinogram

> *Flag:* `L3AK{Xr4Y_C0mp1373!}`

The handout is a 1.5 MB SQLite DB with a single `projections` table: 180 rows keyed by `angle_degrees ∈ [0,179]`, each holding a variable-length `light_values` array. A per-degree table of detector arrays over a full semicircle is the unmistakable signature of a **CT sinogram** — the Radon transform of a 2D image, one projection column per angle. Recovering the image is the *inverse* Radon transform, i.e. **filtered back-projection**.

Two implementation details make or break it. `iradon` wants shape `(detectors, angles)`, and the projections have *different* lengths (215–543), so each shorter one must be **center-padded** into the widest row before stacking — naïve stacking scrambles the sinogram into ringing artifacts:

```python
sino = np.zeros((max_len, len(projections)), dtype=np.float32)
for i, p in enumerate(projections):
    offset = (max_len - len(p)) // 2
    sino[offset:offset + len(p), i] = p
recon = iradon(sino, theta=angles, filter_name="ramp", circle=False, output_size=max_len)
```

A vertical flip (to fix `iradon`'s y-down convention) yields a cartoon "X-ray droplet" mascot with the flag arched above it. **Takeaway:** recognize the data *shape* — angles × detector samples over 180° is CT — and reach for the matching inverse transform; the alignment/padding step is the part that actually needs care.

---

## You Scanned HOW?!?! — from one slice to a 3D volume

> *Flag:* `L3AK{CT_Sc4Ns_R_jU57_L0tz_0F_Xr4y5!!}`

The explicit "revenge" of the previous challenge, and the same idea scaled up. Instead of one sinogram, the ~1.1 GB SQLite DB holds **617 tables** named on a regular depth series (`slice_0cm`, `slice_3cm`, … `slice_1848cm`), each a 180-angle CT sinogram with detector widths up to 896. Reconstruct every slice with filtered back-projection and you have a small **3D CT volume** — but the flag isn't in any single slice. It's printed *along* the scanned object, so you need a **volume projection**.

For each reconstructed slice, sum along the `y` axis and stack the results into a depth/width image, then rotate and flip to read it:

```python
sum_zx[z] = reconstructed_slice.sum(axis=0)     # collapse each slice
# stack over all 617 depths → rotate 90° → flip horizontally → readable text
```

The performance trick: reconstruct on a **thin grid** (`512×160`) rather than full square images — the flag text runs along the long axis, so a shallow `y` dimension is plenty and makes the 617-slice pass tractable. The stacked projection spells the flag. **Takeaway:** when a signal hides "through" a stack rather than in any one layer, the answer is a projection across the whole volume — and you can slash cost by only reconstructing the dimension the message lives on.

---

## Transcendent Renovation — reading Windows Jump Lists

> *Flag:* `L3AK{P4r4n0rm4l_P4r4ll3l_P47h5}`

A pure Windows-artifact challenge that's really a guided tour of **Jump Lists**. The password-protected archive (`dead7852`) yields `.automaticDestinations-ms` files — per-application recent-item databases that are internally **OLE Compound File** containers (`file` reports "Composite Document File V2 Document", so the quiz answer is `OLE CF`). Inside are a `DestList` table and numbered streams, each usually an embedded `.lnk` shortcut preserving paths, network shares, timestamps, and Distributed Link Tracker GUIDs.

Searching the automatic destinations for the mysterious `NoNeedToWonder` folder pinpoints `f01b4d95cf55d32a.automaticDestinations-ms`; unpacking its streams with `7z` and grepping lands on **stream 46**, the shortcut record for `C:\Users\Administrator\Desktop\NoNeedToWonder`. That stream carries the forensic payload:

- a **Distributed Link Tracker** block (`0xa0000003` signature) decoding to machine identifier `logging-vm` and File Droid GUID `ec2ab952-7e4d-11f1-89ad-a2dead7852ad`;
- a neighboring stream (45) with the RDP share path `\\tsclient\HauntedHouse` — the classic Remote Desktop drive-redirection artifact;
- a **rename trail** across streams 42–46 (`New folder → L3AK`, `Ghosts → Voices`, `Artificial Intelligence → The Intelligence`), with stream 46 preserving the UTF-16LE stem `SoulSearch`.

The challenge terminal asks seven questions; the one genuinely subtle answer is the original folder name — the artifact gives the `SoulSearch` stem, but the accepted answer is the naturalized `SoulSearching`. Submitting all seven returns the flag. **Takeaway:** Jump Lists are OLE CF goldmines — even after folders are renamed, the embedded shell items, tracker GUIDs, and `\\tsclient\` share paths survive as a timeline of user activity.

---

## Cross-cutting lessons from the L3akCTF 2026 forensics set

Four challenges, two disciplines, one mindset — **read the byproduct, not the locked original:**

- **Cached and residual artifacts beat locked data.** L3ak APT skips a 7-Zip password entirely by carving the thumbnail cache; Transcendent Renovation recovers renamed-folder history from Jump List shell items and tracker GUIDs. When the primary file is encrypted or missing, the OS almost always kept a copy of the *result*.
- **Recognize the data's shape, then apply the matching transform.** Both CT challenges hinge on spotting "angles × detector samples over 180°" as a sinogram and inverting the Radon transform — the win is identification plus careful projection alignment/padding, not exotic math.
- **Project across the whole volume for stacked signals.** You Scanned HOW hides its flag *through* 617 slices; only a summed volume projection reveals it, and reconstructing just the needed dimension keeps it fast.
- **Know your Windows artifact formats.** Jump Lists = OLE CF; thumbnails = `thumbcache_*.db` image blobs; the `$MFT`, Sysmon, and uTorrent resume DBs corroborate the timeline. Fluency with these formats is what turns a triage image into a narrative.

## Reproduce it yourself

Every challenge ships a standalone Python solver at [Abdelkad3r/L3akCTF-2026](https://github.com/Abdelkad3r/L3akCTF-2026) under `forensics/<challenge>/`. L3ak APT's carver and both CT reconstruction scripts run offline against their handouts (the CT solvers use `numpy`/`scikit-image`; the 617-slice DB is fetched from the committed `scan2.7z` since the extracted 1.1 GB SQLite exceeds GitHub's file limit). Transcendent Renovation's solver automates the OLE extraction, evidence parsing, and optional remote submission. Each per-challenge `README.md` records the exact streams, GUIDs, and reconstruction parameters.

Pair this with the [L3akCTF 2026 pwn](/ctf-writeups/l3akctf-2026-pwn-writeup/), [crypto](/ctf-writeups/l3akctf-2026-crypto-writeup/), [misc](/ctf-writeups/l3akctf-2026-misc-writeup/), [web](/ctf-writeups/l3akctf-2026-web-writeup/), and [OSINT](/ctf-writeups/l3akctf-2026-osint-writeup/) writeups, or browse the full [CTF writeups](/ctf-writeups/) archive for more DFIR and forensics deep-dives.

---

*This writeup is part of the CyberSecurity Elite [L3akCTF 2026](/series/l3akctf-2026/) series. Artifacts and solver scripts for all four forensics challenges are published at [github.com/Abdelkad3r/L3akCTF-2026](https://github.com/Abdelkad3r/L3akCTF-2026).*
