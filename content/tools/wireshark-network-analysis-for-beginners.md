---
title: "Wireshark Network Analysis for Beginners (And Intermediate Users)"
slug: "wireshark-network-analysis-for-beginners"
description: "Catch attackers in a packet capture using Wireshark — the display filters that matter, TLS decryption setup, and the analysis workflow real analysts use."
date: 2026-04-02T11:00:00Z
lastmod: 2026-04-02T11:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["Tools"]
tags: ["wireshark", "network analysis", "packet capture", "pcap"]
keywords: ["wireshark tutorial", "wireshark filters", "pcap analysis"]
toc: true
cover:
  image: "/images/og-default.svg"
  alt: "Wireshark tutorial"
---

Wireshark is the most powerful free network tool ever made — and arguably the most underused. Most users live in the first 20% of its features. This tutorial pushes you into the productive middle 60%.

## Capture Setup

### Choose the Right Interface

On Linux/macOS: `tcpdump -D` lists interfaces. On Windows: the Npcap install adds them to Wireshark's UI.

For full visibility:

- **SPAN/mirror port** on a switch — best for production analysis
- **TAP** — passive splitter; gold standard for forensics
- **Promiscuous mode + monitor mode** on Wi-Fi — captures other clients on the same channel

### Capture Filters vs Display Filters

This is the #1 confusion. They use *different syntaxes*:

```text
# Capture filter (BPF — applied before storage)
host 10.0.0.5 and port 443

# Display filter (Wireshark syntax — applied to loaded pcap)
ip.addr == 10.0.0.5 && tcp.port == 443
```

Rule: use capture filters to keep file sizes manageable. Use display filters for analysis.

## The Display Filters That Matter

```text
# HTTP requests only
http.request

# All DNS queries
dns.flags.response == 0

# TCP retransmissions (network health)
tcp.analysis.retransmission

# Suspicious user-agent
http.user_agent contains "sqlmap"

# Failed TLS handshakes
tls.alert_message

# Specific HTTP response codes
http.response.code == 500

# Beaconing patterns — exact-interval traffic
tcp.flags.syn == 1 && tcp.flags.ack == 0

# Exfiltration candidates — large uploads
tcp.len > 1400 && ip.src == 10.0.0.5

# Cleartext credentials
http.authorization || ftp.request.command == "USER" || telnet
```

Memorize the first ten. The rest are one Google search away.

## TLS Decryption

You cannot break TLS, but you can decrypt **your own** sessions if you control either endpoint:

### Option A: Pre-Master Secret Log

Set `SSLKEYLOGFILE=/path/to/keys.log` before launching Chrome or Firefox. Both browsers write per-session keys to that file. In Wireshark: `Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename`.

Now your captures show plaintext HTTP inside the TLS streams.

### Option B: Server Private Key (TLS 1.2 only)

For RSA-key-exchange ciphers, supply the server private key in the same preference pane. Useless against modern TLS 1.3, which mandates forward secrecy.

## Following Conversations

Right-click a packet → **Follow → TCP Stream** (or HTTP, HTTP/2, QUIC). This reassembles the bidirectional conversation into a readable view. The most useful single right-click in the tool.

## Statistics Panels

`Statistics → Conversations` and `Statistics → Endpoints` show talkers ranked by bytes. Useful for:

- Finding noisy clients on a slow network
- Spotting data exfiltration (one host with disproportionate upload bytes)
- Confirming the actual top destinations on a busy server

`Statistics → I/O Graphs` plots bandwidth over time. Spike at 03:00 every night? Likely a scheduled task — or a beacon.

## Hunt Patterns for Defenders

### DNS Tunneling

```text
dns.qry.name.len > 50 || (dns and frame.len > 200)
```

Long DNS labels in TXT or AAAA queries are a classic tunnel signature.

### Plaintext Protocols

```text
ftp || telnet || http.authorization
```

Any HTTP-Basic, FTP USER, or telnet on a corporate network deserves a ticket.

### Reverse Shells

Reverse shells often look like normal outbound TCP to a high port. The fingerprint:

- Outbound to an unusual ASN
- Long-lived idle TCP
- Small periodic packets (heartbeats)

Use `tcp.stream eq X` to follow specific suspect flows.

## Performance Triage

When the network "feels slow":

1. `tcp.analysis.flags` — surfaces every TCP anomaly
2. `tcp.analysis.retransmission` count > 1% of all packets indicates loss
3. `tcp.analysis.duplicate_ack` clusters mean asymmetric routing or reordering
4. `Expert Information` (Analyze menu) — Wireshark's built-in heuristics

## Useful Extensions

- **Zeek (formerly Bro)** — parses pcaps into structured logs at scale
- **Suricata** — ruleset-driven IDS reading the same pcaps
- **Brim** — UI on top of Zeek logs; great for large captures Wireshark struggles with

## Practice Pcaps

- [Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/) — captures from real infections with explainers
- [PacketTotal](https://packettotal.com) — public pcap analysis service

## References

- [Wireshark User's Guide](https://www.wireshark.org/docs/wsug_html_chunked/)
- [Wireshark Display Filter Reference](https://www.wireshark.org/docs/dfref/)
