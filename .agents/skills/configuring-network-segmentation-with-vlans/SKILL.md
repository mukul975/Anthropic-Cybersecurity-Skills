---
name: configuring-network-segmentation-with-vlans
description: >
  Designs and implements VLAN-based network segmentation on managed switches to isolate
  network zones, enforce access control between segments, and reduce the attack surface
  by limiting lateral movement paths in enterprise network environments.
domain: cybersecurity
subdomain: network-security
tags: [network-security, vlan, network-segmentation, switch-security, 802.1q]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Configuring Network Segmentation with VLANs

## When to Use

- Segmenting an enterprise network into isolated security zones (corporate, servers, DMZ, guest, IoT)
- Meeting compliance requirements (PCI-DSS, HIPAA, SOC 2) that mandate network isolation for sensitive data
- Reducing blast radius of security incidents by preventing lateral movement between network segments
- Isolating high-risk devices (IoT, BYOD, legacy systems) from critical infrastructure
- Implementing defense-in-depth by combining VLANs with firewall rules and access control lists

**Do not use** VLANs as the sole security control without Layer 3 filtering, for isolating networks that require air-gapping, or without proper switch hardening against VLAN hopping attacks.

## Prerequisites

- Managed switches supporting 802.1Q VLAN trunking (Cisco Catalyst, HP Aruba, Juniper EX, etc.)
- Layer 3 switch or firewall for inter-VLAN routing and access control
- Network design document specifying VLAN assignments, IP subnets, and traffic flow requirements
- Console or SSH access to switches with privileged configuration mode
- Understanding of 802.1Q trunking, STP, and inter-VLAN routing concepts

## Workflow

### Step 1: Design the VLAN Architecture

```
# Define VLANs based on security zones and function

VLAN Plan:
  VLAN 10  - CORPORATE    (10.10.10.0/24)  - Employee workstations
  VLAN 20  - SERVERS      (10.10.20.0/24)  - Internal servers
  VLAN 30  - DMZ          (10.10.30.0/24)  - Internet-facing servers
  VLAN 40  - GUEST        (10.10.40.0/24)  - Guest WiFi
  VLAN 50  - IOT          (10.10.50.0/24)  - IoT/OT devices
  VLAN 60  - VOIP         (10.10.60.0/24)  - VoIP phones
  VLAN 100 - MANAGEMENT   (10.10.100.0/24) - Switch/AP management
  VLAN 999 - QUARANTINE   (10.10.99.0/24)  - Isolated/compromised hosts
  VLAN 998 - NATIVE_UNUSED                  - Native VLAN (no traffic)

# Traffic flow matrix:
# CORPORATE -> SERVERS: Allowed (specific ports)
# CORPORATE -> DMZ: Allowed (HTTP/HTTPS only)
# CORPORATE -> GUEST: Denied
# CORPORATE -> IOT: Denied
# GUEST -> Any Internal: Denied
# IOT -> SERVERS: Allowed (specific ports to specific hosts only)
# DMZ -> SERVERS: Allowed (database ports only)
# MANAGEMENT -> All: Allowed (from management stations only)
```

### Step 2: Configure VLANs on Cisco Catalyst Switch

```
! Enter configuration mode
enable
configure terminal

! Create VLANs
vlan 10
  name CORPORATE
  exit
vlan 20
  name SERVERS
  exit
vlan 30
  name DMZ
  exit
vlan 40
  name GUEST
  exit
vlan 50
  name IOT
  exit
vlan 60
  name VOIP
  exit
vlan 100
  name MANAGEMENT
  exit
vlan 998
  name NATIVE_UNUSED
  exit
vlan 999
  name QUARANTINE
  exit

! Configure access ports for workstations (VLAN 10)
interface range GigabitEthernet1/0/1-24
  switchport mode access
  switchport access vlan 10
  switchport nonegotiate
  spanning-tree portfast
  spanning-tree bpduguard enable
  no shutdown
  exit

! Configure access ports for servers (VLAN 20)
interface range GigabitEthernet1/0/25-36
  switchport mode access
  switchport access vlan 20
  switchport nonegotiate
  spanning-tree portfast
  spanning-tree bpduguard enable
  no shutdown
  exit

! Configure trunk ports to other switches
interface GigabitEthernet1/0/48
  switchport mode trunk
  switchport trunk encapsulation dot1q
  switchport trunk native vlan 998
  switchport trunk allowed vlan 10,20,30,40,50,60,100
  switchport nonegotiate
  no shutdown
  exit

! Configure trunk to firewall/router
interface GigabitEthernet1/0/47
  switchport mode trunk
  switchport trunk encapsulation dot1q
  switchport trunk native vlan 998
  switchport trunk allowed vlan 10,20,30,40,50,60,100
  switchport nonegotiate
  no shutdown
  exit

! Shutdown unused ports
interface range GigabitEthernet1/0/37-46
  shutdown
  switchport mode access
  switchport access vlan 999
  exit
```

### Step 3: Harden Switch Against VLAN Hopping

```
! Disable DTP on all ports (prevents switch spoofing)
interface range GigabitEthernet1/0/1-46
  switchport nonegotiate
  exit

! Set native VLAN to unused VLAN on all trunks
interface range GigabitEthernet1/0/47-48
  switchport trunk native vlan 998
  exit

! Enable DHCP Snooping
ip dhcp snooping
ip dhcp snooping vlan 10,20,30,40,50,60
interface GigabitEthernet1/0/47
  ip dhcp snooping trust
  exit

! Enable Dynamic ARP Inspection
ip arp inspection vlan 10,20,30,40,50,60
interface GigabitEthernet1/0/47
  ip arp inspection trust
  exit

! Enable IP Source Guard (prevents IP spoofing)
interface range GigabitEthernet1/0/1-36
  ip verify source
  exit

! Enable Port Security
interface range GigabitEthernet1/0/1-24
  switchport port-security
  switchport port-security maximum 2
  switchport port-security violation restrict
  switchport port-security aging time 60
  exit

! Set VTP to transparent mode (prevents VTP attacks)
vtp mode transparent

! Enable BPDU Guard globally
spanning-tree portfast bpduguard default

! Enable Storm Control
interface range GigabitEthernet1/0/1-36
  storm-control broadcast level 10
  storm-control multicast level 10
  storm-control action shutdown
  exit
```

### Step 4: Configure Inter-VLAN Routing with ACLs

```
! On the Layer 3 switch or firewall, configure SVIs
interface Vlan10
  ip address 10.10.10.1 255.255.255.0
  no shutdown
  exit
interface Vlan20
  ip address 10.10.20.1 255.255.255.0
  no shutdown
  exit
interface Vlan30
  ip address 10.10.30.1 255.255.255.0
  no shutdown
  exit
interface Vlan40
  ip address 10.10.40.1 255.255.255.0
  no shutdown
  exit
interface Vlan50
  ip address 10.10.50.1 255.255.255.0
  no shutdown
  exit

! ACL: Corporate to Servers (allow specific services)
ip access-list extended CORP-TO-SERVERS
  permit tcp 10.10.10.0 0.0.0.255 10.10.20.0 0.0.0.255 eq 80
  permit tcp 10.10.10.0 0.0.0.255 10.10.20.0 0.0.0.255 eq 443
  permit tcp 10.10.10.0 0.0.0.255 10.10.20.0 0.0.0.255 eq 445
  permit udp 10.10.10.0 0.0.0.255 10.10.20.0 0.0.0.255 eq 53
  permit icmp 10.10.10.0 0.0.0.255 10.10.20.0 0.0.0.255 echo
  deny ip any any log
  exit

! ACL: Guest to Internet only (deny all internal)
ip access-list extended GUEST-OUTBOUND
  deny ip 10.10.40.0 0.0.0.255 10.0.0.0 0.255.255.255
  deny ip 10.10.40.0 0.0.0.255 172.16.0.0 0.15.255.255
  deny ip 10.10.40.0 0.0.0.255 192.168.0.0 0.0.255.255
  permit tcp 10.10.40.0 0.0.0.255 any eq 80
  permit tcp 10.10.40.0 0.0.0.255 any eq 443
  permit udp 10.10.40.0 0.0.0.255 any eq 53
  deny ip any any log
  exit

! ACL: IoT limited access
ip access-list extended IOT-OUTBOUND
  permit tcp 10.10.50.0 0.0.0.255 host 10.10.20.10 eq 443
  permit tcp 10.10.50.0 0.0.0.255 any eq 443
  permit udp 10.10.50.0 0.0.0.255 host 10.10.20.1 eq 53
  deny ip 10.10.50.0 0.0.0.255 10.10.50.0 0.0.0.255 log
  deny ip any any log
  exit

! Apply ACLs to VLAN interfaces
interface Vlan10
  ip access-group CORP-TO-SERVERS out
  exit
interface Vlan40
  ip access-group GUEST-OUTBOUND in
  exit
interface Vlan50
  ip access-group IOT-OUTBOUND in
  exit
```

### Step 5: Configure DHCP and DNS per VLAN

```
! DHCP pools for each VLAN
ip dhcp pool CORPORATE
  network 10.10.10.0 255.255.255.0
  default-router 10.10.10.1
  dns-server 10.10.20.10
  domain-name corp.example.com
  lease 1
  exit

ip dhcp pool GUEST
  network 10.10.40.0 255.255.255.0
  default-router 10.10.40.1
  dns-server 1.1.1.1 8.8.8.8
  lease 0 4
  exit

ip dhcp pool IOT
  network 10.10.50.0 255.255.255.0
  default-router 10.10.50.1
  dns-server 10.10.20.10
  lease 7
  exit

! Exclude gateway and server IPs from DHCP pools
ip dhcp excluded-address 10.10.10.1 10.10.10.10
ip dhcp excluded-address 10.10.40.1 10.10.40.10
ip dhcp excluded-address 10.10.50.1 10.10.50.10
```

### Step 6: Verify and Test Segmentation

```bash
# From a workstation on VLAN 10 (Corporate):
# Should succeed:
ping 10.10.20.10          # Server access
curl https://10.10.20.10  # HTTPS to server

# Should fail:
ping 10.10.40.100         # Guest VLAN - should be blocked
ping 10.10.50.100         # IoT VLAN - should be blocked

# From a device on VLAN 40 (Guest):
# Should succeed:
ping 8.8.8.8              # Internet access
curl https://www.google.com

# Should fail:
ping 10.10.10.1           # Corporate gateway - blocked
ping 10.10.20.10          # Server - blocked

# Verify switch configuration
show vlan brief
show interfaces trunk
show ip arp inspection statistics
show ip dhcp snooping binding
show port-security
show ip access-lists

# Run VLAN hopping tests (from authorized pentest)
# These should all fail if hardening is correct:
# 1. DTP negotiation - should fail (nonegotiate)
# 2. Double tagging - should fail (native VLAN 998)
# 3. ARP spoofing - should fail (DAI enabled)
```

## Key Concepts

| Term | Definition |
|------|------------|
| **VLAN (Virtual LAN)** | Logical network partition at Layer 2 that groups switch ports into isolated broadcast domains, regardless of physical location |
| **802.1Q Trunking** | IEEE standard for VLAN tagging that adds a 4-byte header to Ethernet frames, identifying which VLAN a frame belongs to across trunk links |
| **Inter-VLAN Routing** | Layer 3 forwarding of traffic between VLANs using a router, Layer 3 switch, or firewall with access control lists |
| **Native VLAN** | VLAN assigned to untagged frames on trunk ports; should be set to an unused VLAN to prevent VLAN hopping attacks |
| **DHCP Snooping** | Switch feature that validates DHCP messages and builds a binding table of IP-MAC-port mappings, preventing rogue DHCP servers |
| **Port Security** | Switch feature that limits the number of MAC addresses per port and takes action (shutdown, restrict) when violated |

## Tools & Systems

- **Cisco Catalyst/Nexus**: Enterprise managed switches with comprehensive VLAN, trunking, and security feature support
- **HP Aruba CX**: Enterprise switches with REST API management and VLAN segmentation capabilities
- **pfSense/OPNsense**: Open-source firewalls for inter-VLAN routing with stateful access control
- **NetBox**: Open-source IPAM and DCIM tool for documenting VLAN assignments, IP addressing, and network topology
- **Nmap**: Network scanner for verifying segmentation effectiveness by testing reachability across VLAN boundaries

## Common Scenarios

### Scenario: Implementing PCI-DSS Compliant Network Segmentation for Retail

**Context**: A retail chain must isolate their payment card processing systems from the general corporate network to meet PCI-DSS requirements. The current flat network has point-of-sale terminals, employee workstations, inventory servers, and guest WiFi on a single VLAN. The environment uses Cisco Catalyst 9300 switches.

**Approach**:
1. Design VLAN architecture: POS terminals on VLAN 50 (CDE), corporate on VLAN 10, servers on VLAN 20, guest on VLAN 40
2. Create VLANs on all access-layer switches and configure access ports by function
3. Configure trunk links between switches with explicit VLAN allowed lists (no "all" trunks)
4. Set native VLAN to 998 (unused) on all trunks and disable DTP on every port
5. Configure ACLs on the Layer 3 switch: CDE VLAN can only reach the payment processor's IP on port 443; no other inter-VLAN traffic to/from CDE
6. Enable DHCP snooping, DAI, and port security on all access ports
7. Verify segmentation with penetration testing from each VLAN, confirming CDE is fully isolated

**Pitfalls**:
- Leaving DTP enabled on access ports, allowing VLAN hopping to reach the CDE
- Using VLAN 1 as the native VLAN, enabling double-tagging attacks
- Not restricting trunk allowed VLANs, carrying all VLANs including CDE to non-essential switches
- Creating ACLs that allow "any" source to reach CDE servers instead of specific POS terminal IPs

## Output Format

```
## Network Segmentation Implementation Report

**Network**: Retail Store #42
**Switch Platform**: Cisco Catalyst 9300
**VLANs Configured**: 8

### VLAN Summary

| VLAN ID | Name | Subnet | Ports | Purpose |
|---------|------|--------|-------|---------|
| 10 | CORPORATE | 10.10.10.0/24 | Gi1/0/1-24 | Employee workstations |
| 20 | SERVERS | 10.10.20.0/24 | Gi1/0/25-36 | Internal servers |
| 30 | DMZ | 10.10.30.0/24 | Gi2/0/1-4 | Internet-facing |
| 40 | GUEST | 10.10.40.0/24 | WiFi AP trunk | Guest WiFi |
| 50 | CDE | 10.10.50.0/24 | Gi2/0/5-12 | POS terminals |
| 100 | MGMT | 10.10.100.0/24 | Gi1/0/48 | Switch management |
| 998 | NATIVE | N/A | Trunks only | Unused native |
| 999 | QUARANTINE | 10.10.99.0/24 | Unused ports | Isolation |

### Security Hardening Status

| Control | Status |
|---------|--------|
| DTP Disabled (nonegotiate) | All ports |
| Native VLAN (998) | All trunks |
| DHCP Snooping | VLANs 10,20,40,50 |
| Dynamic ARP Inspection | VLANs 10,20,40,50 |
| Port Security | Access ports |
| BPDU Guard | Access ports |
| Unused Ports Shutdown | 10 ports in VLAN 999 |
| VTP Transparent Mode | Enabled |
```
