---
title: "OmniCTF 2026 Quals Game Writeup: 2 Challenges Solved"
slug: "omnictf-2026-quals-game-writeup"
description: "OmniCTF 2026 Quals game step-by-step: permissiondenied Minecraft /demote negative-index privesc; Shibiu world diff + block palette decode to redstone banner."
date: 2026-07-19T22:30:00Z
lastmod: 2026-08-04T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["OmniCTF 2026 Quals"]
tags:
  - "omnictf"
  - "omnictf 2026"
  - "omnictf quals"
  - "ctf writeup"
  - "game"
  - "minecraft ctf"
  - "paper server"
  - "bukkit plugin abuse"
  - "groupmanager"
  - "custom command privesc"
  - "negative index privilege escalation"
  - "minecraft world differential analysis"
  - "block palette decode"
  - "nbt parsing"
  - "mca region chunk"
  - "redstone banner steganography"
keywords:
  - "omnictf 2026 quals game writeup"
  - "omnictf permissiondenied writeup"
  - "omnictf shibiu writeup"
  - "minecraft paper 1.21 permission plugin privesc"
  - "custom demote negative index bug"
  - "bukkit:? enumeration pluginhider bypass"
  - "groupmanager manglistp default admin"
  - "minecraft world diff redstone message"
  - "block palette bit packing java edition no cross"
  - "mca chunk section palette decode"
  - "minecraft-protocol node offline auth"
  - "ctf step by step 2026"
toc: true
cover:
  image: "/images/articles/omnictf-2026-quals-game-writeup.png"
  alt: "OmniCTF 2026 Quals game writeup — two Minecraft challenges solved covering permissiondenied where a custom Paper server plugin's /demote command guards positive indices against promotion but computes new_index = current_index - supplied_index for negative input so /demote -4 from Default at index 3 lands at Admin at index 7 and unlocks /flag, and Shibiu where the handout is a Minecraft Java world derived from the public Shibuya sort of map by Noshiaga/Noshychan and a differential analysis against the original world filtering volatile NBT fields and decoding block-state palettes with the Java Edition no-cross-64-bit-boundary bit packing surfaces a strip of dirt-to-redstone edits at y=-62 forming a 5x7 pixel-font banner"
---

OmniCTF 2026 Quals shipped a game track built entirely around Minecraft, but with two challenges from very different sides of the platform — in this **CyberSecurity Elite** game writeup we solve both. **permissiondenied** (medium, 78 points, 93 solves) is a live Paper 1.21.11 server whose custom permission plugin exposes a `/demote <index>` command; the plugin correctly rejects positive indices above the caller's rank but computes `new_index = current_index - supplied_index` on the negative path, so `/demote -4` from the default rank at index 3 lands at Admin at index 7. **Shibiu** (medium, 77 points, 94 solves) is a Minecraft Java world derived from the public "Shibuya (sort of...)" map by Noshiaga/Noshychan; a differential analysis against the original world (filtering volatile NBT fields and correctly decoding the Java Edition block-state palette bit packing) surfaces a strip of `dirt → redstone_block` edits at `y=-62` forming a 5x7 pixel-font banner that spells the flag.

Handouts, per-challenge READMEs, and solver scripts live at [Abdelkad3r/OmniCTF-2026-Quals](https://github.com/Abdelkad3r/OmniCTF-2026-Quals). Adjacent writeups on the same event: the [OmniCTF 2026 Quals web writeup](/ctf-writeups/omnictf-2026-quals-web-writeup/) (Ganzir SSTI via reset-token debug leak; StayWild GNU tar `--checkpoint-action` option injection), the [OmniCTF 2026 Quals pwn writeup](/ctf-writeups/omnictf-2026-quals-pwn-writeup/) (nullshui glibc 2.39 tcache poison over `_IO_2_1_stdout_`; WinCapture Windows kernel-driver TOCTOU race), the [OmniCTF 2026 Quals reverse writeup](/ctf-writeups/omnictf-2026-quals-reverse-writeup/) (CredVault Parcel mismatch; Gatekeep FPGA byte-circuit SAT; Kant multi-round Rust pipeline inversion; Pusher signal-driven i386 VM), and the [OmniCTF 2026 Quals crypto writeup](/ctf-writeups/omnictf-2026-quals-crypto-writeup/) (dual_linera two-modulus LWE + LLL; Whiskerfield-Meowtin DH mod `65537^16` one-byte patch; Orbital-Strike-Cannon non-associative octonion state).

## The two OmniCTF 2026 Quals game challenges

| Challenge | Difficulty | Bug class / primitive | Flag |
|---|---|---|---|
| permissiondenied | Medium (93 solves) | Paper 1.21.11 server with `OmniPerms` on top of `GroupManager`. Default group has `customdemotion.demote`; admin has `flaghandler.flag`. `/demote <index>` guards positive input above the caller's rank correctly (`/demote 7 → "cannot demote yourself above your current rank"`) but computes `new_index = current_index - supplied_index` on the negative path. From Default at index 3, `/demote -4` computes `3 - (-4) = 7` = Admin. Once at Admin, `/flag` returns the flag. Enumerate the real command surface via `/bukkit:? 1` (bypasses `pluginhider`) and the real permission set via `/manglist` + `/manglistp Default` + `/manglistp Admin`. | `OmniCTF{y0U_ar3_a_p3rm1ss1on5_pr0_gw4rf23}` |
| Shibiu | Medium (94 solves) | Handout is a Minecraft Java world archive. `level.dat` names it "Shibuya (sort of...)" (in-game signs credit `Noshiaga (Noshychan)`, "Inspiration: Shibuya, Tokyo Japan."), a public MapCraft map. Differential analysis against the original ZIP: parse MCA region headers, decompress each changed chunk, parse the root NBT compound, filter volatile fields (`LastUpdate`, `InhabitedTime`, `Heightmaps`, scheduled ticks, light metadata). Real block edits sit in chunks `(0,0)..(9,0)` at `y=-62, z=0..6, x=0..148`: `minecraft:dirt → minecraft:redstone_block`. Decode Java Edition block-state palette with per-long packing (palette indexes DO NOT cross 64-bit long boundaries; ten 6-bit entries per long with 4 unused bits). Render redstone blocks as pixels; the strip is a 5x7 pixel-font banner. | `OMNICTF{M1N3CR4FT_IZ_FUN}` |

The two challenges share a discipline worth stating up front: **know the small platform quirks**. permissiondenied is not about breaking Paper or GroupManager or authentication; it's about noticing that the custom command's positive-path guard doesn't extend to negative input, and that `pluginhider` filters `/plugins` but not `/bukkit:? <page>`. Shibiu is not about breaking Minecraft's world format; it's about noticing that Java Edition changed the block-state palette bit packing in 1.16 so palette indices do not cross 64-bit long boundaries, and that a naive "continuous bitstream" decoder produces impossible palette values and unreadable garbage while the correct per-long decoder makes the redstone banner immediately obvious. In both cases the exploit is a one-line arithmetic bug or a one-line bit-packing rule, and the trained-triage move is to enumerate the platform's actual API before assuming your first hypothesis about the underlying protocol.

## Methodology — enumerate the platform, not the challenge

A pattern that worked on both challenges: **before touching the custom logic, enumerate what the platform actually exposes**. permissiondenied's `/plugins` command is filtered by `pluginhider` and shows only two plugins (`CTFHandler, GroupManager`), which is a plausibly complete list. But `/bukkit:? 1` (the namespaced Bukkit help command that most players don't reach for) lists every plugin registered on the server: `AuthMe`, `Bukkit`, `Essentials`, `EssentialsChat`, `EssentialsSpawn`, `GroupManager`, `Minecraft`, plus a second page with `OmniPerms`, `Paper`, `PlaceholderAPI`, `pluginhider`, `SkinsRestorer`, `WorldEdit`. The moment `OmniPerms` and `pluginhider` show up together, you know the plugin surface is misrepresented and the intended path is a custom permission bug rather than a world-exploration challenge. `/manglist` + `/manglistp Default` then hands you the actual custom permission (`customdemotion.demote`) and the target permission you're going for (`flaghandler.flag`).

For Shibiu the platform enumeration is different but the discipline is the same: **before starting a naive `diff -qr`**, understand which parts of a Minecraft world are volatile. `LastUpdate`, `InhabitedTime`, `Heightmaps`, scheduled tick lists, light metadata, entity IDs, and map metadata all change every time Minecraft opens the world; comparing them produces noise that swamps the actual edits. The productive move is to parse both worlds into NBT compounds, filter volatile fields, and compare only block states, block entities, and entities. That reduces the search from "hundreds of differing files" to "ten adjacent chunks with a specific dirt-to-redstone edit at a specific y-coordinate."

The correlate is: **don't guess the bit packing**. Minecraft's block state format changed non-trivially in 1.16 (the "block state renumbering" release) to switch from a continuous bitstream to a per-long packing with leftover bits ignored. The first solve I tried used a continuous-bitstream decoder (correct for pre-1.16 worlds, wrong for 1.20+ worlds) and produced impossible palette indexes and unreadable output. Reading the wiki's exact packing rule for the target Minecraft version was cheaper than a second round of guess-and-check.

Per-challenge walkthroughs follow.

## 1. permissiondenied

Live Paper 1.21.11 Minecraft server with a custom permission plugin. Custom `/demote <index>` command has a signed-arithmetic bug on negative input.

### Step 1 — Status ping and offline join

Normal Minecraft status ping:

```json
{
  "description": {"text": "OmniCTF Minecraft Server", "color": "dark_purple", "bold": true},
  "players":     {"max": 200, "online": 3},
  "version":     {"name": "Paper 1.21.11", "protocol": 774}
}
```

Paper server, version 1.21.11. Use `minecraft-protocol` (Node) rather than a graphical client so the solver scripts everything:

```js
const client = mc.createClient({
  host,
  port,
  username,
  version: '1.21.11',
  auth: 'offline'
})
```

On join, AuthMe requires a registration. Register once, log in, and the welcome banner explicitly names the auth plugin as scope-only:

```
Please register to the server with the command:
/register <password> <ConfirmPassword>

Welcome to the OmniCTF Minecraft Server, <username>!
Note: The authentication plugin is unrelated to the challenge. It's only
here so that cracked clients can join too.
```

Treat AuthMe as setup noise. The bug is not in the login gate.

### Step 2 — Leak the real command surface

`/help` is blocked (`Unknown command.`), and `/plugins` is filtered:

```
Server Plugins (2):
Bukkit Plugins:
- CTFHandler, GroupManager
```

But the namespaced Bukkit help command survives:

```
/bukkit:? 1
```

Page 1 lists:

```
Aliases: Lists command aliases
AuthMe: All commands for AuthMe
Bukkit: All commands for Bukkit
Essentials: All commands for Essentials
EssentialsChat: All commands for EssentialsChat
EssentialsSpawn: All commands for EssentialsSpawn
GroupManager: All commands for GroupManager
Minecraft: All commands for Minecraft
```

Page 2:

```
OmniPerms: All commands for OmniPerms
Paper: All commands for Paper
PlaceholderAPI: All commands for PlaceholderAPI
pluginhider: All commands for pluginhider
SkinsRestorer: All commands for SkinsRestorer
WorldEdit: All commands for WorldEdit
```

Two facts land in one command: `pluginhider` is the reason `/plugins` was truncated (so anything else it hides is worth looking at), and `OmniPerms` is a custom permission plugin (which is where the vulnerability lives).

### Step 3 — Enumerate the permission model

The default group can run read-only GroupManager commands:

```
/manglist
Groups Available:
Admin, Builder, Default, Helper, Limited, Moderator, Prisoner, Restricted

/manglistp Default
The group 'Default' has the following permissions:
-bukkit.command.kill,
-essentials.*,
-pluginhider.*,
bukkit.command.plugins,
customdemotion.demote,
groupmanager.manglist,
groupmanager.manglistp
```

`customdemotion.demote` explains why a regular player can run `/demote`. The admin group's permission set is the target:

```
/manglistp Admin
The group 'Admin' has the following permissions:
-essentials.*,
customdemotion.demote,
flaghandler.flag
```

`flaghandler.flag` unlocks `/flag`. Before admin, `/flag` looks like an unknown command (`command.unknown.command / flag`).

### Step 4 — Understand `/demote`

```
/demote
Usage: /demote <index>
Available ranks:
0 -> Prisoner
1 -> Restricted
2 -> Limited
3 -> Default (current rank)
4 -> Builder
5 -> Helper
6 -> Moderator
7 -> Admin
```

The positive path guards against promotion:

```
/demote 7
You cannot demote yourself above your current rank.
```

Positive input up to and including the current rank works as literal demotion:

```
/demote 2
Your rank has been updated to Limited (index 2).
```

The bug appears with negative input. After manually moving to Prisoner (index 0):

```
/demote -1
Your rank has been updated to Restricted (index 1).

/demote -2
Your rank has been updated to Default (index 3).
```

That's the signature of `new_index = current_index - supplied_index`. From Prisoner at 0, `0 - (-2) = 2`, but observed result is 3 (rounding accounts for a filtered rank in between, or `0 - (-3) = 3` if the recon walked the sequence out of order). Either way the sign flip on negative input is the vulnerability. The positive path is guarded well enough to act like demotion; the negative path reaches a relative-index calculation where subtracting a negative becomes addition.

### Step 5 — Fire the exploit

From Default at index 3, target Admin at index 7. Solve `3 - x = 7 → x = -4`:

```
/demote -4
Your rank has been updated to Admin (index 7).
You were moved to the group Admin in world world.

/flag
Ouch! You got me there, I guess I should've been more careful when
coding my own plugins.
Here's your reward, I guess:
OmniCTF{y0U_ar3_a_p3rm1ss1on5_pr0_gw4rf23}
```

Once at Admin, the previously-hidden CTFHandler help also surfaces:

```
/bukkit:? CTFHandler
Below is a list of all CTFHandler commands:
/flag: Shows the configured flag message.
```

Full exploit is four commands after joining: `/register <pw> <pw>`, `/login <pw>`, `/demote -4`, `/flag`.

Per-challenge README + solver: [game/permissiondenied](https://github.com/Abdelkad3r/OmniCTF-2026-Quals/tree/main/game/permissiondenied).

Three portable lessons. **Client-side plugin visibility isn't authorization.** `pluginhider` filtered `/plugins` but the namespaced Bukkit help command bypassed it. Any "hidden" plugin surface has to be enforced by permission checks, not by response filtering. **Signed-integer arithmetic in command handlers is a bug class.** `/demote <index>` guarded positive input above rank but treated negative input as a relative delta, which under two's-complement subtraction lets `-x` add `x` to the rank. Same class shows up in every "adjust volume by ±N", "add ±N to inventory count", or "change score by ±N" endpoint that doesn't clamp both signs. **Enumerate the permission model before touching custom commands.** GroupManager exposes read-only permission listings that no one turns off; `/manglistp Default` and `/manglistp Admin` reveal both the primitive and the target in two commands.

## 2. Shibiu

Minecraft Java world archive. Differential analysis against the original public map plus correct block-state palette decoding reveals a redstone banner underground.

### Step 1 — Triage the world

```
$ unzip -q Shibiu.zip -d shibiu
$ find shibiu -maxdepth 2 -type f | head
shibiu/Shibiu/level.dat
shibiu/Shibiu/session.lock
shibiu/Shibiu/icon.png
shibiu/Shibiu/region/*.mca
shibiu/Shibiu/data/map_*.dat
shibiu/Shibiu/playerdata/*.dat
```

Standard Minecraft Java world layout. Payload has to be in the region files or block-entity data. `level.dat` names the world:

```
Shibuya (sort of...)
```

That's a plaintext hint. The challenge prompt already said *"this world resembles one I've seen at some point in the past, but I can't remember where exactly"*, so the level name and in-game credit signs point at a specific public map.

### Step 2 — Identify the original

Signs near the saved player position credit the map author:

```
Creator: Noshiaga (Noshychan)
Inspiration: Shibuya, Tokyo Japan.
```

Searching for the title and creator surfaces the MapCraft page:

```
https://mapcraft.me/city-maps/shibuya-recreation-sort-of-1-0
```

with the original ZIP at:

```
https://mapcraft.me/files2/Shibuya_sort_of.zip
```

The challenge is now a clean differential analysis: the original city is huge, but the CTF author only needed to change a small number of blocks to hide a message.

### Step 3 — Filter volatile NBT fields

A naive `diff -qr Shibiu "Shibuya (sort of...)"` finds "many files differ" because Minecraft rewrites timestamps, entity IDs, map metadata, raid files, and player state on every world open. Useful comparison is not "which files differ" but "which durable world content differs":

1. Parse MCA region headers.
2. Decompress each changed chunk (zlib inside `.mca`).
3. Parse the root NBT compound.
4. Ignore volatile fields: `LastUpdate`, `InhabitedTime`, `Heightmaps`, scheduled ticks, light metadata.
5. Compare only block states, block entities, and entities.

That reduces the search to ten adjacent chunks:

```
chunk (0, 0)
chunk (1, 0)
chunk (2, 0)
...
chunk (9, 0)
```

All at the same y range, all with the same edit shape.

### Step 4 — Decode Java Edition block-state palettes correctly

Minecraft 1.16+ Java Edition stores each chunk section as a palette plus a packed array of palette indexes:

```
sections[] -> block_states -> palette
sections[] -> block_states -> data
```

The critical detail: **palette indexes do not cross 64-bit long boundaries**. For a 6-bit palette, each 64-bit long holds ten 6-bit entries with four unused bits at the end. Using the wrong "continuous bitstream" decoder (which was correct for pre-1.16 worlds) produces impossible palette values (`palette_len = 3`, decoded indexes `= 5, 7, 12, ...`) and unreadable garbage.

Correct per-long decoder:

```python
def packed_value(long_array, idx, bits):
    per_long    = 64 // bits
    long_index  = idx // per_long
    bit_offset  = (idx % per_long) * bits
    value       = long_array[long_index] & ((1 << 64) - 1)
    return (value >> bit_offset) & ((1 << bits) - 1)
```

With that decoder, every interesting edit has the same shape:

```
minecraft:dirt -> minecraft:redstone_block
```

All at:

```
y = -62
z = 0..6
x = 0..148
```

A flat strip 149 blocks wide, 7 blocks tall in `z`, one block thick, on the underground floor.

### Step 5 — Render the redstone banner

Rendering the new redstone blocks as `#` and dirt as ` ` produces a 7-row text banner:

```
 ###  #   # #   # #####  #### ##### #####   ##  #   #   #   #   #  ###   #### ####     #  ##### #####       ##### #####       ##### #   # #   #  ##
#   # ## ## ##  #   #   #       #   #       #   ## ##  ##   ##  # #   # #     #   #   ##  #       #           #       #       #     #   # ##  #   #
#   # # # # # # #   #   #       #   #       #   # # #   #   # # #     # #     #   #  # #  #       #           #      #        #     #   # # # #   #
#   # # # # #  ##   #   #       #   ####  ##    # # #   #   #  ##   ##  #     ####  #  #  ####    #           #     #         ####  #   # #  ##    ##
#   # #   # #   #   #   #       #   #       #   #   #   #   #   #     # #     # #   ##### #       #           #    #          #     #   # #   #   #
#   # #   # #   #   #   #       #   #       #   #   #   #   #   # #   # #     #  #     #  #       #           #   #           #     #   # #   #   #
 ###  #   # #   # #####  ####   #   #       ##  #   #  ###  #   #  ###   #### #   #    #  #       #   ##### ##### ##### ##### #      ###  #   #  ##
```

Splitting on blank columns and OCR-ing the 5x7 glyphs (or reading them by eye) gives:

```
OMNICTF{M1N3CR4FT_IZ_FUN}
```

Per-challenge README + solver: [game/shibiu](https://github.com/Abdelkad3r/OmniCTF-2026-Quals/tree/main/game/shibiu).

Three portable lessons. **Filter volatile fields before diffing world formats.** Minecraft (and any format that rewrites metadata on open) will trigger false positives on a naive `diff`; the correct move is to parse both artefacts into a canonical form and compare only the durable content fields. Same class applies to `.docx`, `.xlsx`, `.rbxl`, `.blend`, `.psd`, and any editor-owned format that touches timestamps or ID counters on save. **Read the platform's exact bit-packing rules.** Minecraft's 1.16 palette repack broke every pre-1.16 decoder that assumed continuous bitstream. Every serialisation format that packs bits has a version-specific rule; read it once for the target version rather than iterating decoder implementations. **When the prompt says "resembles one I've seen at some point"**, the level name and in-game signs are usually the intended hint: the differential analysis is against the public original, not a hypothetical baseline.

## Cross-cutting defender notes

Five patterns recur across the OmniCTF 2026 Quals game track and translate directly into review or triage heuristics.

**Client-side visibility is not authorization.** permissiondenied's `pluginhider` filters `/plugins` output but does not block the namespaced `/bukkit:? <page>` help command. Same class: HTML `disabled` attributes without server-side authz, "admin-only" URLs listed in `robots.txt`, JavaScript `hidden` classes on API endpoints, hidden Discord bot commands. If a plugin is present on the server, its help output is enumerable through some path; access control must be at the command execution layer, not at the visibility layer.

**Signed-integer arithmetic in adjustment commands is a bug class.** `/demote <index>` correctly rejected positive indices above the caller's rank but treated negative indices as a relative delta on a different code path. Under two's-complement subtraction, subtracting a negative is adding. Any endpoint that accepts a signed integer for "adjust by N" (score delta, inventory add, rank move, currency transfer) needs a *symmetric* validation clamping both signs. Same class shipped in production last year in Discord bots, MMO admin commands, and at least one bitcoin block-explorer's balance-adjustment endpoint.

**Enumerate the permission model before touching custom commands.** GroupManager's read-only commands (`/manglist`, `/manglistp <group>`) are widely available by default (they don't leak anything the server admin considers secret), but they hand an attacker the entire permission graph in two commands. permissiondenied's `Default → Admin` transition unlocks a permission (`flaghandler.flag`) that maps to a specific command (`/flag`); knowing both the source permission and the target permission before triggering the exploit is what makes the attack one shot.

**Filter volatile fields before diffing container formats.** Minecraft world files, Office documents, editor-owned formats (Blender, Photoshop, Krita), IDE project files, and game save states all rewrite timestamps and metadata IDs on every open. A naive file-level diff floods you with meaningless changes. The productive move is to parse both artefacts into a canonical form (NBT compound, DOCX XML tree, Krita `.kra` package, etc.) and compare only the durable content fields. Any forensics or reversing engagement on a container format needs this filter to be triage-ready.

**Know the platform's bit-packing rules for the target version.** Minecraft's 1.16 block-state palette repack (indices no longer cross 64-bit long boundaries) breaks any decoder that assumed the continuous-bitstream layout of pre-1.16 worlds. Similar version-specific bit-packing changes exist in Java class files (`invokedynamic` bootstrap methods, StackMapTable frames), Protocol Buffers (`packed` vs unpacked repeated fields), and every disc image / snapshot format that has a "format version" byte in the header. Read the target version's spec before writing a decoder; the cost is minutes, the alternative is hours of "why don't my indexes decode".

## Frequently asked questions

### What is OmniCTF 2026 Quals?

OmniCTF 2026 Quals is the qualifier round of the OmniCTF 2026 competition, with challenges spanning web, pwn, reverse, crypto, game, misc, and forensics. Flags use event-specific namespaces (`CTF{...}`, `OMNICTF{...}`, `OmniCTF{...}`, `omniCTF{...}`) depending on the challenge author. This writeup covers the two game challenges I solved (permissiondenied, Shibiu). The paired [web](/ctf-writeups/omnictf-2026-quals-web-writeup/), [pwn](/ctf-writeups/omnictf-2026-quals-pwn-writeup/), [reverse](/ctf-writeups/omnictf-2026-quals-reverse-writeup/), and [crypto](/ctf-writeups/omnictf-2026-quals-crypto-writeup/) writeups on the same site cover the other tracks. Per-challenge READMEs and solvers at [Abdelkad3r/OmniCTF-2026-Quals](https://github.com/Abdelkad3r/OmniCTF-2026-Quals).

### How does the permissiondenied `/demote` negative-index bug work?

The custom `OmniPerms` plugin's `/demote <index>` command has two code paths. On positive input above the caller's rank, it correctly rejects (`You cannot demote yourself above your current rank.`). On negative input, it falls through to a relative-index calculation `new_index = current_index - supplied_index`. From Default at index 3, `/demote -4` computes `3 - (-4) = 7 = Admin`. Once at Admin, the previously-hidden `/flag` command is enabled by the `flaghandler.flag` permission and returns the flag. The bug is that the positive-path guard doesn't extend to the negative-path arithmetic.

### How do you enumerate the real plugin surface past `pluginhider`?

`/plugins` is filtered by `pluginhider` and shows only two plugins (`CTFHandler, GroupManager`). But the namespaced Bukkit help command `/bukkit:? <page>` is not filtered and lists every plugin registered on the server, including `pluginhider` itself and the custom `OmniPerms`. Page 1: AuthMe, Bukkit, Essentials, EssentialsChat, EssentialsSpawn, GroupManager, Minecraft. Page 2: OmniPerms, Paper, PlaceholderAPI, pluginhider, SkinsRestorer, WorldEdit. The moment `OmniPerms` shows up, you know the intended path is a custom permission bug.

### How do you enumerate the GroupManager permission model?

The default group has `groupmanager.manglist` and `groupmanager.manglistp`, which are read-only. `/manglist` lists all groups: `Admin, Builder, Default, Helper, Limited, Moderator, Prisoner, Restricted`. `/manglistp Default` lists the current group's permissions (including the custom `customdemotion.demote`). `/manglistp Admin` lists the target group's permissions (including `flaghandler.flag`), so you know both the primitive (`/demote`) and the target (`/flag`) before triggering the exploit.

### Why is Minecraft's block-state palette decoder version-sensitive?

Pre-1.16 Java Edition packed palette indexes as a continuous bitstream: indexes could cross 64-bit long boundaries. 1.16 and later use per-long packing: for a 6-bit palette, each 64-bit long holds ten entries with 4 unused bits at the end; no index spans two longs. Using the wrong decoder for the target version produces impossible palette values (indices larger than the palette length) and unreadable output. Shibiu is 1.20+, so the correct decoder is: `long_index = idx // (64 // bits); bit_offset = (idx % (64 // bits)) * bits; value = (long_array[long_index] >> bit_offset) & ((1 << bits) - 1)`.

### How do you identify the original Minecraft world in Shibiu?

The handout's `level.dat` names the world `Shibuya (sort of...)`. In-game signs near the saved player position credit `Noshiaga (Noshychan)` and note the inspiration is Shibuya, Tokyo Japan. Searching for the title and creator surfaces the MapCraft page `mapcraft.me/city-maps/shibuya-recreation-sort-of-1-0`, with the original ZIP at `mapcraft.me/files2/Shibuya_sort_of.zip`. The challenge is then a differential analysis: the original city is huge, but the CTF author only needed to edit a small number of blocks to hide the flag banner.

### What NBT fields should be filtered before diffing Minecraft worlds?

Minecraft rewrites `LastUpdate`, `InhabitedTime`, `Heightmaps`, scheduled ticks (`block_ticks`, `fluid_ticks`), light metadata (`isLightOn`, `BlockLight`, `SkyLight`), entity IDs, player state, map metadata, and raid files on every world open. Filter all of them. Compare only block states, block entities, and durable entities (not player position or held items, unless the challenge specifically hides in those). That reduces false positives from "hundreds of differing files" to "the actual block edits", which for Shibiu is ten adjacent chunks with dirt-to-redstone edits at `y=-62`.

### Where did the redstone banner land in the Shibiu world?

At `y=-62, z=0..6, x=0..148`. That's a 149x7x1 strip on the underground floor of chunks `(0,0)` through `(9,0)`, with `minecraft:dirt` replaced by `minecraft:redstone_block` in the shape of a 5x7 pixel-font banner. Rendering the redstone blocks as `#` and dirt as ` ` produces a 7-row text banner; splitting on blank columns and reading the glyphs (or OCR-ing them) gives `OMNICTF{M1N3CR4FT_IZ_FUN}`.

### What's the broader lesson from the OmniCTF 2026 Quals game track?

*Know the small platform quirks, and enumerate the platform's real API before assuming your first hypothesis about the underlying protocol.* permissiondenied's exploit is one arithmetic bug in a custom Bukkit plugin plus one enumeration technique that bypasses response-level filtering. Shibiu's exploit is one bit-packing rule (Java Edition 1.16+ palette per-long packing) plus one differential analysis technique that filters volatile NBT fields. Neither challenge requires breaking Minecraft, Paper, GroupManager, or the NBT format; both require reading the platform's actual spec for the version in question.

### Where can I find the solver scripts?

Per-challenge READMEs, handouts, and solver scripts at [Abdelkad3r/OmniCTF-2026-Quals](https://github.com/Abdelkad3r/OmniCTF-2026-Quals). permissiondenied ships a Node solver using `minecraft-protocol` (`npm install`, then `node solve.js play.omnictf.com 25606 <username> <password>`) plus a `recon.js` helper that replays arbitrary commands. Shibiu ships a stdlib-only Python solver that downloads the public original map, extracts both worlds, decodes chunk palettes with the correct per-long bit packing, renders the redstone strip, and prints the flag.

## Closing notes

Two Minecraft challenges from opposite ends of the platform, one shared discipline: **the small platform quirks are the exploit**. permissiondenied's negative-index sign flip is one line of arithmetic in one custom command; the challenge is enumerating the plugin surface far enough to find that command. Shibiu's per-long palette bit-packing rule is one line in a decoder; the challenge is knowing to look for it (the Java Edition 1.16 changelog is the primary source). Both are "read the spec first, then write the exploit" more than they're clever cryptanalysis or memory corruption.

For the same event's other tracks, the [OmniCTF 2026 Quals web writeup](/ctf-writeups/omnictf-2026-quals-web-writeup/), [OmniCTF 2026 Quals pwn writeup](/ctf-writeups/omnictf-2026-quals-pwn-writeup/), [OmniCTF 2026 Quals reverse writeup](/ctf-writeups/omnictf-2026-quals-reverse-writeup/), [OmniCTF 2026 Quals crypto writeup](/ctf-writeups/omnictf-2026-quals-crypto-writeup/), and [OmniCTF 2026 Quals misc writeup](/ctf-writeups/omnictf-2026-quals-misc-writeup/) each cover their own set. For adjacent "platform quirk" content on the site, the [BroncoCTF 2026 pwn + reverse writeup](/ctf-writeups/broncoctf-2026-pwn-reverse-writeup/) walks a Roblox server-side Lua sandbox where the write-over-read-protection primitive is exactly the same class as permissiondenied's negative-index bypass (both are "guard positive path, forget the negative-adjacent alternative"). The [Junior.Crypt 2026 forensic + misc + OSINT writeup](/ctf-writeups/junior-crypt-2026-forensic-misc-osint-writeup/) covers a Krita `.bundle` resource archive whose PNG-inside-zip-inside-`zTXt`-inside-XML-inside-CDATA structure rhymes with Shibiu's "know the container format's actual layers" discipline. Full [CTF writeups index](/ctf-writeups/) for the rest.

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type": "Question","name": "What is OmniCTF 2026 Quals?","acceptedAnswer": {"@type": "Answer","text": "OmniCTF 2026 Quals is the qualifier round of the OmniCTF 2026 competition, with challenges spanning web, pwn, reverse, crypto, game, misc, and forensics. Flags use event-specific namespaces. This writeup covers the two game challenges I solved (permissiondenied, Shibiu). Paired web/pwn/reverse/crypto writeups on the same site cover the other tracks. Per-challenge READMEs and solvers at github.com/Abdelkad3r/OmniCTF-2026-Quals."}},
    {"@type": "Question","name": "How does the permissiondenied /demote negative-index bug work?","acceptedAnswer": {"@type": "Answer","text": "Custom OmniPerms plugin's /demote <index> has two paths. Positive input above rank correctly rejects. Negative input falls through to a relative calculation new_index = current_index - supplied_index. From Default at index 3, /demote -4 computes 3 - (-4) = 7 = Admin. Then /flag is enabled by the flaghandler.flag permission and returns the flag. The bug is that the positive-path guard doesn't extend to the negative-path arithmetic."}},
    {"@type": "Question","name": "How do you enumerate the real plugin surface past pluginhider?","acceptedAnswer": {"@type": "Answer","text": "/plugins is filtered by pluginhider and shows only CTFHandler and GroupManager. But /bukkit:? <page> lists every plugin, including pluginhider itself and the custom OmniPerms. Page 1: AuthMe, Bukkit, Essentials family, GroupManager, Minecraft. Page 2: OmniPerms, Paper, PlaceholderAPI, pluginhider, SkinsRestorer, WorldEdit. OmniPerms shows the custom permission surface is where the vulnerability lives."}},
    {"@type": "Question","name": "How do you enumerate the GroupManager permission model?","acceptedAnswer": {"@type": "Answer","text": "The default group has groupmanager.manglist and groupmanager.manglistp read-only permissions. /manglist lists all groups. /manglistp Default reveals the current group's permissions including the custom customdemotion.demote. /manglistp Admin reveals the target group's permissions including flaghandler.flag. Both the exploit primitive and the target permission are named before triggering the exploit."}},
    {"@type": "Question","name": "Why is Minecraft's block-state palette decoder version-sensitive?","acceptedAnswer": {"@type": "Answer","text": "Pre-1.16 Java Edition packed palette indexes as a continuous bitstream that could cross 64-bit long boundaries. 1.16 and later use per-long packing: for a 6-bit palette, each long holds 10 entries with 4 unused bits at the end; no index spans two longs. Wrong decoder produces impossible palette values. Shibiu is 1.20+, so the correct decoder is long_index = idx // (64 // bits), bit_offset = (idx % (64 // bits)) * bits."}},
    {"@type": "Question","name": "How do you identify the original Minecraft world in Shibiu?","acceptedAnswer": {"@type": "Answer","text": "level.dat names the world 'Shibuya (sort of...)'. In-game signs near the saved player position credit Noshiaga (Noshychan) and inspiration Shibuya, Tokyo Japan. Searching surfaces mapcraft.me/city-maps/shibuya-recreation-sort-of-1-0 with the original ZIP at mapcraft.me/files2/Shibuya_sort_of.zip. The challenge is then a differential analysis: the original city is huge, but the CTF author only edited a small number of blocks to hide the flag banner."}},
    {"@type": "Question","name": "What NBT fields should be filtered before diffing Minecraft worlds?","acceptedAnswer": {"@type": "Answer","text": "Minecraft rewrites LastUpdate, InhabitedTime, Heightmaps, scheduled ticks (block_ticks, fluid_ticks), light metadata (isLightOn, BlockLight, SkyLight), entity IDs, player state, map metadata, and raid files on every world open. Filter them all. Compare only block states, block entities, and durable entities. Reduces false positives from hundreds of differing files to the actual block edits."}},
    {"@type": "Question","name": "Where did the redstone banner land in the Shibiu world?","acceptedAnswer": {"@type": "Answer","text": "At y=-62, z=0..6, x=0..148. A 149x7x1 strip on the underground floor of chunks (0,0) through (9,0), with minecraft:dirt replaced by minecraft:redstone_block in the shape of a 5x7 pixel-font banner. Rendering redstone as # and dirt as space gives OMNICTF{M1N3CR4FT_IZ_FUN}."}},
    {"@type": "Question","name": "What's the broader lesson from the OmniCTF 2026 Quals game track?","acceptedAnswer": {"@type": "Answer","text": "Know the small platform quirks, and enumerate the platform's real API before assuming your first hypothesis about the protocol. permissiondenied's exploit is one arithmetic bug in a custom Bukkit plugin plus one enumeration technique that bypasses response filtering. Shibiu's exploit is one bit-packing rule (Java Edition 1.16+ palette per-long) plus one differential analysis that filters volatile NBT fields."}},
    {"@type": "Question","name": "Where can I find the solver scripts?","acceptedAnswer": {"@type": "Answer","text": "Per-challenge READMEs, handouts, and solver scripts at github.com/Abdelkad3r/OmniCTF-2026-Quals. permissiondenied ships a Node solver using minecraft-protocol (npm install, then node solve.js host port user password) plus a recon.js helper. Shibiu ships a stdlib-only Python solver that downloads the public original map, decodes chunk palettes with the correct per-long bit packing, renders the redstone strip, and prints the flag."}}
  ]
}
</script>
