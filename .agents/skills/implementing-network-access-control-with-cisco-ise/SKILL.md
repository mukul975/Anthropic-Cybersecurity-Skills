---
name: implementing-network-access-control-with-cisco-ise
description: Deploy Cisco Identity Services Engine for 802.1X wired and wireless authentication, MAC Authentication Bypass, posture assessment, and dynamic VLAN assignment for network access control.
domain: cybersecurity
subdomain: network-security
tags: [cisco-ise, 802.1x, nac, radius, network-access-control, posture-assessment, mab, dynamic-vlan, eap-tls]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Implementing Network Access Control with Cisco ISE

## Overview

Cisco Identity Services Engine (ISE) provides centralized network access control through 802.1X authentication, MAC Authentication Bypass (MAB), posture assessment, and guest access management. ISE acts as a RADIUS policy server that evaluates authentication requests from network devices (switches, wireless controllers) and returns authorization policies including VLAN assignments, downloadable ACLs (dACLs), and Security Group Tags (SGTs). This skill covers deploying ISE for enterprise wired 802.1X authentication with Active Directory integration, MAB fallback, posture compliance enforcement, and TrustSec segmentation.

## Prerequisites

- Cisco ISE 3.1+ appliance or virtual machine (16 CPU cores, 64GB RAM minimum for production)
- Cisco switches with 802.1X support (Catalyst 9000 series recommended)
- Active Directory domain with user and computer accounts
- PKI infrastructure for EAP-TLS certificate-based authentication
- DNS and NTP configured consistently across ISE nodes and network devices
- Supplicant software on endpoints (Windows native, AnyConnect NAM, or SecureW2)

## Core Concepts

### 802.1X Architecture

The 802.1X framework involves three components:

| Component | Role | Example |
|-----------|------|---------|
| **Supplicant** | Client requesting network access | Windows 802.1X client, AnyConnect NAM |
| **Authenticator** | Network device controlling port access | Cisco Catalyst switch |
| **Authentication Server** | Policy decision engine | Cisco ISE (RADIUS) |

### Authentication Flow

```
1. Endpoint connects to switch port
2. Switch sends EAP-Request/Identity to endpoint
3. Endpoint responds with EAP-Response/Identity
4. Switch forwards credentials to ISE via RADIUS Access-Request
5. ISE authenticates against AD/LDAP/internal store
6. ISE evaluates authorization policy
7. ISE returns RADIUS Access-Accept with attributes (VLAN, dACL, SGT)
8. Switch enforces authorization on the port
```

### Authentication Methods

| Method | Use Case | Security Level |
|--------|----------|---------------|
| EAP-TLS | Certificate-based, highest security | High |
| PEAP-MSCHAPv2 | Username/password via AD | Medium |
| EAP-FAST | Cisco proprietary, fast reauthentication | Medium |
| MAB | Non-802.1X devices (printers, IP phones) | Low |

## Implementation Steps

### Step 1: Configure ISE for Active Directory Integration

Navigate to **Administration > Identity Management > External Identity Sources > Active Directory**:

1. Add AD join point with domain name (e.g., `corp.example.com`)
2. Provide domain admin credentials for ISE machine account
3. Join ISE to the domain
4. Select AD groups for authorization policies:
   - `Domain Users` - Standard employee access
   - `Domain Computers` - Machine authentication
   - `IT-Admins` - Privileged access
   - `BYOD-Users` - Personal device access

### Step 2: Configure Network Devices in ISE

Navigate to **Administration > Network Resources > Network Devices**:

```
Name: SW-ACCESS-01
IP Address: 10.0.1.1/32
RADIUS Shared Secret: C0mpl3x$3cretKey!
SNMP Settings: v2c, community string
Device Type: Cisco Switches
Location: Building-A-Floor-1
```

Create a Network Device Group hierarchy:
```
Device Type:
  ├── Cisco Switches
  │   ├── Access Layer
  │   └── Distribution Layer
  └── Wireless Controllers
Location:
  ├── Building-A
  └── Building-B
```

### Step 3: Configure Switch for 802.1X

Apply this configuration to the access switch:

```
! Enable AAA
aaa new-model
aaa authentication dot1x default group radius
aaa authorization network default group radius
aaa accounting dot1x default start-stop group radius
aaa accounting update newinfo periodic 2880

! Configure RADIUS server
radius server ISE-PRIMARY
 address ipv4 10.0.5.10 auth-port 1812 acct-port 1813
 key 0 C0mpl3x$3cretKey!
 automate-tester username radius-test probe-on

radius server ISE-SECONDARY
 address ipv4 10.0.5.11 auth-port 1812 acct-port 1813
 key 0 C0mpl3x$3cretKey!
 automate-tester username radius-test probe-on

aaa group server radius ISE-GROUP
 server name ISE-PRIMARY
 server name ISE-SECONDARY
 deadtime 15
 ip radius source-interface Loopback0

! Enable 802.1X globally
dot1x system-auth-control

! Enable RADIUS CoA (Change of Authorization)
aaa server radius dynamic-author
 client 10.0.5.10 server-key C0mpl3x$3cretKey!
 client 10.0.5.11 server-key C0mpl3x$3cretKey!

! Enable device tracking for IP-to-MAC mapping
device-tracking tracking auto-source

! Configure access port template
interface range GigabitEthernet1/0/1-48
 description 802.1X Access Port
 switchport mode access
 switchport access vlan 100

 ! Authentication settings
 authentication host-mode multi-auth
 authentication order dot1x mab
 authentication priority dot1x mab
 authentication port-control auto
 authentication periodic
 authentication timer reauthenticate server
 authentication timer inactivity server dynamic
 authentication violation restrict

 ! 802.1X settings
 dot1x pae authenticator
 dot1x timeout tx-period 10
 dot1x max-reauth-req 2

 ! MAB fallback
 mab

 ! Enable spanning-tree portfast (required for timely auth)
 spanning-tree portfast

 ! Apply pre-auth ACL
 ip access-group PRE-AUTH-ACL in

! Pre-authentication ACL (allow DHCP, DNS, ISE portal)
ip access-list extended PRE-AUTH-ACL
 permit udp any any eq 67
 permit udp any any eq 68
 permit udp any any eq 53
 permit tcp any host 10.0.5.10 eq 8443
 permit tcp any host 10.0.5.11 eq 8443
 deny ip any any
```

### Step 4: Configure ISE Authentication Policy

Navigate to **Policy > Policy Sets**:

**Authentication Policy:**

| Rule Name | Condition | Allowed Protocols | Identity Source |
|-----------|-----------|-------------------|-----------------|
| Dot1X-EAP-TLS | Radius:EAP-Type EQUALS EAP-TLS | EAP-TLS | AD with Certificate |
| Dot1X-PEAP | Radius:EAP-Type EQUALS PEAP | PEAP-MSCHAPv2 | Active Directory |
| MAB | Radius:Service-Type EQUALS Call-Check | MAB Lookup | Internal Endpoints |
| Default | Default | Default | Deny Access |

### Step 5: Configure ISE Authorization Policy

**Authorization Policy:**

| Rule Name | Condition | Authorization Profile |
|-----------|-----------|----------------------|
| IT-Admin-Wired | AD:Group EQUALS IT-Admins AND Dot1X | VLAN10-FullAccess |
| Employee-Compliant | AD:Group EQUALS Domain Users AND Posture:Compliant | VLAN100-Corporate |
| Employee-NonCompliant | AD:Group EQUALS Domain Users AND Posture:NonCompliant | VLAN200-Remediation |
| Printer-MAB | EndpointIdentityGroup EQUALS Printers | VLAN150-Printers |
| IP-Phone-MAB | EndpointIdentityGroup EQUALS IP-Phones | VLAN50-Voice |
| BYOD-Onboarding | AD:Group EQUALS BYOD-Users AND !Registered | BYOD-Portal-Redirect |
| Guest-Access | GuestEndpointGroup EQUALS GuestEndpoints | VLAN300-Guest |
| Default | Default | DenyAccess |

**Authorization Profiles:**

```
Profile: VLAN100-Corporate
  VLAN: 100
  dACL: PERMIT_ALL
  SGT: Employees (0x0005)
  Reauthentication Timer: 28800

Profile: VLAN200-Remediation
  VLAN: 200
  dACL: REMEDIATION-ACL (allow only remediation server access)
  Web Redirection: Posture Discovery
  Reauthentication Timer: 300

Profile: DenyAccess
  Access Type: ACCESS_REJECT
```

### Step 6: Configure Posture Assessment

Navigate to **Work Centers > Posture**:

**Posture Conditions:**
```
- Windows Firewall Enabled (Registry check)
- Antivirus Running and Updated (AV compound condition)
- OS Patch Level Current (Windows Update check)
- Disk Encryption Enabled (BitLocker check)
```

**Posture Requirements:**
```
Requirement: Corporate-Windows-Compliance
  OS: Windows All
  Conditions: Windows Firewall AND Antivirus AND OS Patches
  Remediation: Auto-remediate with AnyConnect ISE Posture Module
```

**Posture Policy:**
```
Rule: Windows-Endpoints
  Identity Group: Any
  OS: Windows All
  Requirement: Corporate-Windows-Compliance
```

### Step 7: Configure TrustSec Segmentation

Enable SGT-based segmentation:

```
! On switch - enable CTS
cts credentials id SW-ACCESS-01 password CtsP@ss
cts role-based enforcement
cts role-based sgt-map 10.0.100.0/24 sgt 5

! Download SGT policy from ISE
cts role-based permissions
```

ISE TrustSec Matrix (SGACL):

| Source SGT | Destination SGT | Policy |
|------------|----------------|--------|
| Employees (5) | Servers (10) | Permit_HTTP_HTTPS |
| Employees (5) | PCI_Zone (15) | Deny_All |
| IT-Admins (3) | Servers (10) | Permit_All |
| Guest (7) | Internet (99) | Permit_HTTP_HTTPS |
| Guest (7) | Servers (10) | Deny_All |

## Troubleshooting

```bash
# On switch - verify authentication status
show authentication sessions
show authentication sessions interface Gi1/0/1 details
show dot1x all

# Check RADIUS connectivity
test aaa server radius ISE-PRIMARY username testuser password testpass

# On ISE - check live logs
# Navigate to Operations > RADIUS > Live Logs
# Filter by MAC address or username
# Review Authentication Details for failure reason

# Common failure reasons:
# 12514 - EAP-TLS handshake failed (certificate issue)
# 22056 - Subject not found in identity store
# 24408 - User not found in Active Directory
# 24454 - User password expired
```

## Best Practices

- **Monitor Mode First** - Deploy in monitor mode (open authentication) before closed mode enforcement
- **Low-Impact Mode** - Use `authentication open` with pre-auth dACLs for gradual rollout
- **MAB Database** - Pre-populate endpoint database with known MAC addresses for printers, phones
- **Profiling** - Enable ISE profiling to automatically classify endpoints by type
- **CoA Support** - Ensure Change of Authorization is configured for dynamic policy updates
- **High Availability** - Deploy ISE in a Primary/Secondary node pair with PAN failover
- **Certificate Infrastructure** - Use machine certificates for EAP-TLS for strongest authentication

## References

- [Cisco ISE Admin Guide 3.1](https://www.cisco.com/c/en/us/td/docs/security/ise/3-1/admin_guide/b_ise_admin_3_1.html)
- [Cisco 802.1X Design Guide](https://www.cisco.com/c/en/us/support/docs/lan-switching/8021x/214843-guide-ieee-802-1x-deployment-with-cisco.html)
- [CiscoLive ISE Deployment Guide 2025](https://www.ciscolive.com/c/dam/r/ciscolive/emea/docs/2025/pdf/BRKSEC-2660.pdf)
- [Cisco ISE Wired 802.1X Configuration](https://www.networkcomputing.com/network-security/cisco-ise-wired-802-1x-configuration)
