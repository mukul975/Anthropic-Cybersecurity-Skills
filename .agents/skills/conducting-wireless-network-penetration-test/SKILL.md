---
name: conducting-wireless-network-penetration-test
description: >
  Conducts authorized wireless network penetration tests to assess the security of WiFi
  infrastructure by testing for weak encryption protocols, captive portal bypasses, evil twin
  attacks, WPA2/WPA3 handshake capture, rogue access point detection, and client-side attacks.
  The tester evaluates wireless authentication, network segmentation, and the effectiveness of
  wireless intrusion detection systems. Activates for requests involving wireless pentest, WiFi
  security assessment, WPA2/WPA3 testing, or rogue access point detection.
domain: cybersecurity
subdomain: penetration-testing
tags: [wireless-pentest, WiFi-security, WPA2, WPA3, evil-twin]
version: 1.0.0
author: mahipal
license: Apache-2.0
---
# Conducting Wireless Network Penetration Test

## When to Use

- Assessing the security of enterprise wireless networks including guest, corporate, and IoT WiFi segments
- Testing whether attackers within physical proximity can compromise wireless authentication and access internal networks
- Validating wireless intrusion detection/prevention system (WIDS/WIPS) capabilities against known attack techniques
- Evaluating the effectiveness of WPA3 migration and transition mode configurations
- Testing network segmentation between wireless and wired networks after a wireless network compromise

**Do not use** against wireless networks without written authorization from the network owner, for jamming or denial-of-service attacks against wireless infrastructure unless explicitly authorized, or in environments where wireless disruption could affect life-safety systems.

## Prerequisites

- Written authorization specifying target SSIDs, BSSIDs, and physical testing locations
- External WiFi adapter supporting monitor mode and packet injection (Alfa AWUS036ACH, TP-Link TL-WN722N v1)
- Kali Linux or equivalent with up-to-date wireless tools (aircrack-ng suite, hostapd, bettercap)
- Physical access to the testing location during authorized testing hours
- Knowledge of the target's wireless architecture (SSIDs, authentication types, RADIUS infrastructure)

## Workflow

### Step 1: Wireless Reconnaissance

Discover and map all wireless networks in the target environment:

- Enable monitor mode: `airmon-ng start wlan0`
- Capture wireless traffic: `airodump-ng wlan0mon -w recon --output-format csv,pcap` to discover all SSIDs, BSSIDs, channels, encryption types, and connected clients
- Identify target networks from the authorized scope and note their security configurations (WEP, WPA2-Personal, WPA2-Enterprise, WPA3-SAE, WPA3-Transition)
- Enumerate connected clients and their signal strengths to understand client distribution
- Check for hidden SSIDs by capturing probe requests from clients: `airodump-ng wlan0mon --essid-regex ".*" -c <channel>`
- Identify rogue access points by comparing discovered BSSIDs against the client's authorized AP inventory

### Step 2: WPA2-Personal Handshake Capture and Cracking

For WPA2-PSK networks, capture the 4-way handshake and attempt offline cracking:

- Target the specific AP: `airodump-ng wlan0mon -c <channel> --bssid <bssid> -w capture`
- Deauthenticate a connected client to force re-authentication: `aireplay-ng -0 5 -a <bssid> -c <client_mac> wlan0mon`
- Verify handshake capture in airodump-ng (WPA handshake indicator appears)
- Crack the captured handshake:
  - Dictionary attack: `aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap`
  - GPU-accelerated: `hashcat -m 22000 capture.hc22000 /usr/share/wordlists/rockyou.txt`
  - Rule-based: `hashcat -m 22000 capture.hc22000 wordlist.txt -r /usr/share/hashcat/rules/best64.rule`
- For PMKID capture (clientless): `hcxdumptool -i wlan0mon --enable_status=1 -o pmkid.pcapng --filtermode=2 --filterlist_ap=<bssid>`

### Step 3: WPA2-Enterprise Attack

For 802.1X/EAP networks, attempt credential capture through rogue RADIUS:

- Identify the EAP type in use (PEAP-MSCHAPv2, EAP-TLS, EAP-TTLS) by capturing association requests
- Set up a rogue AP mimicking the enterprise SSID using `hostapd-mana` with a rogue RADIUS server
- Configure hostapd-mana to accept all EAP authentication attempts and capture RADIUS handshakes
- When clients connect to the rogue AP, capture MSCHAPv2 challenge-response pairs
- Crack captured credentials with `asleap` or convert to hashcat format: `hashcat -m 5500 captured_ntlm.txt wordlist.txt`
- If EAP-TLS is in use (certificate-based), document that credential capture is not feasible and the organization has implemented strong wireless authentication

### Step 4: Evil Twin Attack

Deploy a rogue access point to intercept client connections:

- Create an evil twin AP matching the target SSID: configure `hostapd` with the same SSID and channel
- Set up a captive portal using `dnsmasq` for DHCP and DNS, and a web server presenting a fake login page
- Deauthenticate clients from the legitimate AP to force reconnection to the evil twin
- Capture credentials submitted through the captive portal
- For WPA3-Transition mode networks: exploit the downgrade vulnerability by creating a WPA2-only evil twin that transition-mode clients will connect to
- Document all captured credentials and the attack path from wireless access to internal network

### Step 5: Post-Compromise Network Assessment

After gaining wireless network access, assess network segmentation:

- Connect to the compromised wireless network using captured credentials
- Scan the network segment for accessible hosts and services: `nmap -sn <wireless_subnet>`
- Test if wireless clients can reach internal servers, databases, or management interfaces
- Verify that VLAN segmentation properly isolates guest, corporate, and IoT wireless networks
- Test if wireless-to-wired segmentation is enforced by attempting to access servers on the wired network
- Document all accessible resources from the wireless network to demonstrate segmentation failures

## Key Concepts

| Term | Definition |
|------|------------|
| **Evil Twin** | A rogue access point that mimics a legitimate SSID to trick clients into connecting, enabling man-in-the-middle attacks and credential capture |
| **4-Way Handshake** | The WPA2 authentication exchange between client and AP that establishes encryption keys; captured handshakes can be cracked offline |
| **WPA3-SAE** | Simultaneous Authentication of Equals; WPA3's key exchange protocol that resists offline dictionary attacks and provides forward secrecy |
| **Transition Mode** | WPA3 backward compatibility mode that supports both WPA2 and WPA3 clients, potentially vulnerable to downgrade attacks |
| **PMKID Attack** | A clientless attack that captures the Pairwise Master Key Identifier from the AP's first EAPOL frame, allowing offline cracking without capturing a full handshake |
| **802.1X/EAP** | Enterprise wireless authentication using RADIUS and Extensible Authentication Protocol, providing per-user credentials instead of a shared pre-shared key |
| **Deauthentication Attack** | Sending spoofed deauthentication frames to disconnect clients from an AP, forcing them to reconnect and enabling handshake capture or evil twin attacks |

## Tools & Systems

- **Aircrack-ng Suite**: Comprehensive wireless auditing toolkit including airodump-ng (capture), aireplay-ng (injection), and aircrack-ng (cracking)
- **Hostapd-mana**: Modified hostapd for creating rogue access points with EAP credential capture capability
- **Bettercap**: Network attack framework with WiFi modules for deauthentication, handshake capture, and evil twin deployment
- **Hashcat**: GPU-accelerated password cracking supporting WPA2 (mode 22000), MSCHAPv2 (mode 5500), and PMKID formats
- **Kismet**: Wireless network detector, sniffer, and intrusion detection system for passive monitoring

## Common Scenarios

### Scenario: Wireless Security Assessment for a Corporate Office

**Context**: A financial services company has 3 SSIDs: CorpWiFi (WPA2-Enterprise for employees), GuestWiFi (captive portal), and IoT-Net (WPA2-PSK for printers and conferencing systems). The tester is authorized to test all three networks from the lobby and conference rooms.

**Approach**:
1. Wireless reconnaissance identifies all 3 SSIDs across 12 access points with 87 connected clients
2. IoT-Net WPA2-PSK handshake captured and cracked in 3 minutes (password: Company2024!)
3. From IoT-Net, scan reveals the subnet can reach internal servers including the print server and file shares, demonstrating inadequate segmentation
4. Evil twin attack against CorpWiFi captures 4 employee MSCHAPv2 hashes via hostapd-mana; 2 are cracked revealing passwords
5. GuestWiFi captive portal bypass achieved using MAC address spoofing of an already-authenticated device
6. Document that IoT-Net provides a direct path to the internal network bypassing WPA2-Enterprise authentication

**Pitfalls**:
- Conducting deauthentication attacks during business hours without coordinating with the client, causing visible WiFi disruptions
- Not testing WPA3 transition mode for downgrade vulnerabilities when the organization has begun WPA3 migration
- Focusing only on password cracking and missing network segmentation issues that are often the higher-risk finding
- Testing from a single location and missing rogue APs deployed in other areas of the facility

## Output Format

```
## Finding: Weak WPA2-PSK on IoT Network with Inadequate Segmentation

**ID**: WIFI-001
**Severity**: Critical (CVSS 9.4)
**Affected SSID**: IoT-Net (BSSID: AA:BB:CC:DD:EE:FF)
**Encryption**: WPA2-Personal (PSK)

**Description**:
The IoT wireless network uses a weak pre-shared key that was cracked in 3 minutes
using a standard dictionary attack. Once connected to IoT-Net, the tester discovered
that the wireless VLAN is not properly segmented from the internal corporate network,
providing unrestricted access to file servers, the Active Directory domain controller,
and the internal database server.

**Proof of Concept**:
1. Captured WPA2 handshake: airodump-ng wlan0mon -c 6 --bssid AA:BB:CC:DD:EE:FF -w iot
2. Cracked PSK in 3 minutes: aircrack-ng -w rockyou.txt iot-01.cap -> Key: Company2024!
3. Connected to IoT-Net and scanned: nmap -sn 10.20.0.0/24
4. Accessible from IoT-Net: DC01 (10.20.0.5:445), FILESVR (10.20.0.10:445), DBSVR (10.20.0.15:3306)

**Impact**:
An attacker within wireless range (tested from the public lobby) can join the IoT
network and gain direct network access to the corporate infrastructure, bypassing
the WPA2-Enterprise authentication required for employee access.

**Remediation**:
1. Implement a complex 20+ character PSK for IoT-Net, rotated quarterly
2. Deploy VLAN segmentation to isolate IoT-Net from the corporate network
3. Implement firewall rules allowing IoT devices to reach only their required services
4. Migrate IoT devices to 802.1X authentication with device certificates where supported
5. Deploy WIDS to detect deauthentication attacks and rogue access points
```
