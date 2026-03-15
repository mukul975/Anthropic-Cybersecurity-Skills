# API Reference: MITM Attack Simulation Agent

## Overview

Simulates man-in-the-middle attacks using Scapy for ARP spoofing, detects cleartext protocol usage, and checks HSTS enforcement. For authorized penetration testing and lab environments only.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| scapy | >=2.5 | ARP spoofing, packet sniffing, host discovery |
| requests | >=2.28 | HSTS and SSL stripping checks |

## CLI Usage

```bash
# Host discovery and cleartext detection
python agent.py --network 192.168.1.0/24 --interface eth0 --duration 60

# Full MITM simulation
python agent.py --target 192.168.1.100 --gateway 192.168.1.1 --interface eth0
```

## Key Functions

### `get_mac(ip_address)`
Resolves MAC address for a given IP using ARP request via Scapy.

### `discover_hosts(network_cidr)`
Discovers live hosts on a network segment using ARP broadcast scan.

### `arp_spoof(target_ip, spoof_ip, target_mac)`
Sends a spoofed ARP reply to redirect traffic through the attacker machine.

### `arp_restore(target_ip, gateway_ip, target_mac, gateway_mac)`
Restores original ARP tables by sending correct ARP replies after testing.

### `detect_cleartext_protocols(interface, duration)`
Sniffs network traffic for cleartext protocols: HTTP (80), FTP (21), Telnet (23), SMTP (25), POP3 (110), IMAP (143).

### `check_hsts_enforcement(target_url)`
Checks HTTP responses for Strict-Transport-Security headers.

### `run_mitm_simulation(target_ip, gateway_ip, interface, duration)`
Executes a controlled ARP spoofing MITM simulation with automatic ARP restoration on completion.

## Scapy Functions Used

| Function | Purpose |
|----------|---------|
| `ARP()` | Create ARP request/reply packets |
| `Ether()` | Create Ethernet frames |
| `srp()` | Send and receive layer 2 packets |
| `send()` | Send packets at layer 3 |
| `sniff()` | Capture network traffic |

## Cleartext Protocols Detected

| Port | Protocol | Risk |
|------|----------|------|
| 80 | HTTP | Credential interception |
| 21 | FTP | Cleartext authentication |
| 23 | Telnet | Full session hijacking |
| 25 | SMTP | Email interception |
| 110 | POP3 | Email credential theft |
| 143 | IMAP | Email credential theft |
