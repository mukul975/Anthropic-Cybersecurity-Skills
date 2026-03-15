---
name: implementing-network-access-control
description: >
  Implements 802.1X port-based network access control using RADIUS authentication,
  PacketFence NAC, and switch configurations to enforce identity-based access policies,
  posture assessment, and automatic VLAN assignment for authorized devices.
domain: cybersecurity
subdomain: network-security
tags: [network-security, nac, 802.1x, radius, packetfence]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Implementing Network Access Control

## When to Use

- Enforcing identity-based network access where only authenticated and compliant devices connect to the network
- Implementing zero-trust networking at the access layer with dynamic VLAN assignment based on user role
- Quarantining non-compliant devices that fail endpoint posture checks (missing patches, disabled AV)
- Meeting compliance requirements (PCI-DSS, HIPAA, SOC 2) for network access controls
- Onboarding BYOD devices with automated provisioning and limited network access

**Do not use** as a standalone security solution without complementary controls, for networks with devices that do not support 802.1X supplicants, or without proper fallback mechanisms for critical infrastructure.

## Prerequisites

- RADIUS server (FreeRADIUS, Microsoft NPS, or Cisco ISE) configured with user/device authentication
- Managed switches supporting 802.1X port-based authentication
- Certificate Authority for EAP-TLS certificate distribution (optional but recommended)
- PacketFence or similar NAC platform for posture assessment and remediation
- Active Directory or LDAP directory for centralized user authentication
- DHCP server integration for dynamic IP assignment per VLAN

## Workflow

### Step 1: Install and Configure FreeRADIUS

```bash
# Install FreeRADIUS
sudo apt install -y freeradius freeradius-utils freeradius-ldap

# Configure RADIUS clients (switches that authenticate against RADIUS)
sudo tee /etc/freeradius/3.0/clients.conf << 'EOF'
client switch-core-01 {
    ipaddr = 10.10.100.1
    secret = R4d1u5_S3cr3t_K3y!
    shortname = core-switch
    nastype = cisco
}

client switch-access-01 {
    ipaddr = 10.10.100.10
    secret = R4d1u5_S3cr3t_K3y!
    shortname = access-switch-01
    nastype = cisco
}

client switch-access-02 {
    ipaddr = 10.10.100.11
    secret = R4d1u5_S3cr3t_K3y!
    shortname = access-switch-02
    nastype = cisco
}
EOF

# Configure LDAP module for Active Directory integration
sudo tee /etc/freeradius/3.0/mods-available/ldap << 'EOF'
ldap {
    server = 'ldap://dc01.corp.example.com'
    identity = 'CN=radius-svc,OU=Service Accounts,DC=corp,DC=example,DC=com'
    password = 'ServiceAccountPassword123!'
    base_dn = 'DC=corp,DC=example,DC=com'

    user {
        base_dn = "${..base_dn}"
        filter = "(sAMAccountName=%{%{Stripped-User-Name}:-%{User-Name}})"
    }

    group {
        base_dn = "${..base_dn}"
        filter = "(objectClass=group)"
        membership_attribute = 'memberOf'
    }
}
EOF

sudo ln -s /etc/freeradius/3.0/mods-available/ldap /etc/freeradius/3.0/mods-enabled/ldap
```

### Step 2: Configure VLAN Assignment Policies

```bash
# Configure authorization policies for dynamic VLAN assignment
sudo tee /etc/freeradius/3.0/policy.d/vlan-assignment << 'EOF'
# VLAN assignment based on group membership
vlan_assignment {
    if (&LDAP-Group[*] == "CN=IT-Staff,OU=Groups,DC=corp,DC=example,DC=com") {
        update reply {
            Tunnel-Type = VLAN
            Tunnel-Medium-Type = IEEE-802
            Tunnel-Private-Group-ID = "10"
        }
    }
    elsif (&LDAP-Group[*] == "CN=Developers,OU=Groups,DC=corp,DC=example,DC=com") {
        update reply {
            Tunnel-Type = VLAN
            Tunnel-Medium-Type = IEEE-802
            Tunnel-Private-Group-ID = "15"
        }
    }
    elsif (&LDAP-Group[*] == "CN=Finance,OU=Groups,DC=corp,DC=example,DC=com") {
        update reply {
            Tunnel-Type = VLAN
            Tunnel-Medium-Type = IEEE-802
            Tunnel-Private-Group-ID = "20"
        }
    }
    else {
        # Default: Guest VLAN for unknown users
        update reply {
            Tunnel-Type = VLAN
            Tunnel-Medium-Type = IEEE-802
            Tunnel-Private-Group-ID = "40"
        }
    }
}
EOF

# Add vlan_assignment to the authorize section
# Edit /etc/freeradius/3.0/sites-enabled/default
# In the authorize section, add: vlan_assignment

# Configure EAP for 802.1X authentication
sudo tee /etc/freeradius/3.0/mods-available/eap << 'EAPEOF'
eap {
    default_eap_type = peap
    timer_expire = 60
    max_sessions = 4096

    tls-config tls-common {
        private_key_file = /etc/freeradius/3.0/certs/server.key
        certificate_file = /etc/freeradius/3.0/certs/server.pem
        ca_file = /etc/freeradius/3.0/certs/ca.pem
        dh_file = /etc/freeradius/3.0/certs/dh
        cipher_list = "HIGH:!aNULL:!MD5"
        tls_min_version = "1.2"
    }

    peap {
        tls = tls-common
        default_eap_type = mschapv2
        virtual_server = inner-tunnel
    }

    tls {
        tls = tls-common
    }
}
EAPEOF

# Start FreeRADIUS in debug mode for testing
sudo freeradius -X

# Test authentication
radtest testuser TestPassword123 localhost 0 testing123
```

### Step 3: Configure 802.1X on Cisco Switches

```
! Enable AAA on the switch
enable
configure terminal

aaa new-model
aaa authentication dot1x default group radius
aaa authorization network default group radius
aaa accounting dot1x default start-stop group radius

! Configure RADIUS server
radius server FREERADIUS
  address ipv4 10.10.100.200 auth-port 1812 acct-port 1813
  key R4d1u5_S3cr3t_K3y!
  exit

! Enable 802.1X globally
dot1x system-auth-control

! Configure access ports for 802.1X
interface range GigabitEthernet1/0/1-24
  switchport mode access
  switchport access vlan 999
  authentication port-control auto
  authentication order dot1x mab
  authentication priority dot1x mab
  dot1x pae authenticator
  dot1x timeout tx-period 10
  mab
  authentication event fail action authorize vlan 999
  authentication event no-response action authorize vlan 40
  authentication host-mode multi-auth
  spanning-tree portfast
  exit

! Configure MAB (MAC Authentication Bypass) for devices without 802.1X
! Devices like printers, IP phones that cannot run a supplicant
interface range GigabitEthernet1/0/25-36
  switchport mode access
  switchport access vlan 999
  authentication port-control auto
  authentication order mab
  mab
  authentication event fail action authorize vlan 999
  authentication host-mode single-host
  spanning-tree portfast
  exit

! Configure guest VLAN for unauthenticated devices
interface range GigabitEthernet1/0/1-24
  authentication event no-response action authorize vlan 40
  authentication event fail action authorize vlan 999
  exit

! Configure critical VLAN for RADIUS server unavailability
interface range GigabitEthernet1/0/1-36
  authentication event server dead action authorize vlan 10
  authentication event server alive action reinitialize
  exit
```

### Step 4: Deploy PacketFence NAC for Posture Assessment

```bash
# Install PacketFence
curl -fsSL https://inverse.ca/downloads/GPG_PUBLIC_KEY | sudo gpg --dearmor -o /etc/apt/keyrings/inverse.gpg
echo "deb [signed-by=/etc/apt/keyrings/inverse.gpg] https://inverse.ca/downloads/PacketFence/debian bookworm bookworm" | \
  sudo tee /etc/apt/sources.list.d/packetfence.list
sudo apt update && sudo apt install -y packetfence

# Run the PacketFence configurator
sudo /usr/local/pf/bin/pfcmd configreload

# Access web admin: https://<packetfence-ip>:1443

# Configure PacketFence connection profiles
# Admin UI: Configuration > Policies and Access Control > Connection Profiles

# Create compliance check (Windows Update status)
# Admin UI: Configuration > Compliance > Scan Engines
# Add: Windows Update compliance check
# Remediation VLAN: 999 (quarantine)

# Configure RADIUS integration
# PacketFence acts as a RADIUS proxy, receiving requests from switches
# and enforcing posture-based VLAN assignment

# Edit /usr/local/pf/conf/switches.conf
sudo tee -a /usr/local/pf/conf/switches.conf << 'EOF'
[10.10.100.10]
description=Access Switch 01
type=Cisco::Catalyst_2960
mode=production
radiusSecret=R4d1u5_S3cr3t_K3y!
SNMPVersion=2c
SNMPCommunityRead=public
SNMPCommunityWrite=private
VlanMap=Y
registrationVlan=40
isolationVlan=999
normalVlan=10
EOF
```

### Step 5: Configure Supplicant on Endpoints

```bash
# Windows Group Policy for 802.1X configuration
# Computer Configuration > Policies > Windows Settings > Security Settings
# > System Services > Wired AutoConfig: Automatic
# > Network Policies:
#   Authentication method: Microsoft: Protected EAP (PEAP)
#   Inner method: EAP-MSCHAPv2
#   Trusted Root CA: Corporate CA

# Linux 802.1X configuration with wpa_supplicant
sudo tee /etc/wpa_supplicant/wpa_supplicant-wired.conf << 'EOF'
ctrl_interface=/var/run/wpa_supplicant
ap_scan=0

network={
    key_mgmt=IEEE8021X
    eap=PEAP
    identity="testuser@corp.example.com"
    password="UserPassword123"
    ca_cert="/etc/ssl/certs/corporate-ca.pem"
    phase2="auth=MSCHAPV2"
}
EOF

# Start wpa_supplicant for wired 802.1X
sudo wpa_supplicant -i eth0 -D wired -c /etc/wpa_supplicant/wpa_supplicant-wired.conf -B

# Verify authentication status
wpa_cli -i eth0 status

# macOS: System Preferences > Network > Ethernet > 802.1X
# Configure with PEAP and corporate credentials
```

### Step 6: Test and Validate NAC Deployment

```bash
# Test 1: Authenticated device gets correct VLAN
# Connect a corporate laptop with 802.1X configured
# Verify VLAN assignment on the switch:
# show authentication sessions interface Gi1/0/1

# Expected:
# Session ID: 0A0A0A01000000010001
# Status: Authorized
# Domain: DATA
# Oper host mode: multi-auth
# Oper control dir: both
# Authorized By: Authentication Server
# Vlan Policy: 10

# Test 2: Unauthenticated device goes to guest VLAN
# Connect a device without 802.1X supplicant
# show authentication sessions interface Gi1/0/2
# Expected: Vlan Policy: 40 (Guest)

# Test 3: Failed authentication goes to quarantine
# Attempt authentication with wrong credentials
# Expected: Vlan Policy: 999 (Quarantine)

# Test 4: RADIUS server failure - critical VLAN
# Stop FreeRADIUS temporarily
# Connect a new device
# Expected: Vlan Policy: 10 (Critical/failover)

# Test 5: MAC Authentication Bypass
# Connect a printer (no supplicant)
# MAB should authenticate based on MAC address in RADIUS
# show authentication sessions interface Gi1/0/25

# Generate authentication report
# show authentication sessions | include Auth
# show dot1x all summary
```

## Key Concepts

| Term | Definition |
|------|------------|
| **802.1X** | IEEE standard for port-based network access control that authenticates devices before granting network access via EAP and RADIUS |
| **RADIUS** | Remote Authentication Dial-In User Service protocol used by network devices to authenticate users and receive authorization attributes (VLAN, ACL) |
| **MAB (MAC Authentication Bypass)** | Fallback authentication method that uses a device's MAC address as credentials for devices that cannot run an 802.1X supplicant |
| **EAP-PEAP** | Protected Extensible Authentication Protocol that wraps EAP in a TLS tunnel, commonly used with MSCHAPv2 for username/password authentication |
| **Posture Assessment** | Evaluation of endpoint compliance status (OS patches, antivirus, encryption) before granting full network access |
| **Dynamic VLAN Assignment** | RADIUS-driven automatic VLAN placement based on user identity, group membership, or device type, eliminating static port-based VLAN configuration |

## Tools & Systems

- **FreeRADIUS**: Open-source RADIUS server supporting EAP-TLS, PEAP, LDAP integration, and dynamic VLAN assignment
- **PacketFence**: Open-source NAC solution providing 802.1X integration, posture assessment, captive portal, and device registration
- **Cisco ISE**: Enterprise NAC platform with profiling, posture, guest management, and TrustSec integration
- **wpa_supplicant**: Open-source 802.1X supplicant for Linux and embedded systems supporting EAP-TLS, PEAP, and TTLS
- **Microsoft NPS**: Windows Server RADIUS implementation integrating natively with Active Directory for 802.1X authentication

## Common Scenarios

### Scenario: Deploying 802.1X NAC in a Hospital Network

**Context**: A hospital needs to enforce network access control to meet HIPAA requirements. The network includes clinical workstations (domain-joined), medical devices (no 802.1X support), physician BYOD devices, and guest WiFi. The deployment must not disrupt patient care if the RADIUS server becomes unavailable.

**Approach**:
1. Deploy FreeRADIUS integrated with Active Directory for user authentication and group-based VLAN assignment
2. Configure domain-joined workstations for EAP-PEAP via Group Policy with auto-enrollment
3. Register medical devices (infusion pumps, monitors) for MAB authentication using their MAC addresses in the RADIUS database
4. Configure switches with authentication order dot1x then mab, with critical VLAN fallback to the clinical VLAN if RADIUS is unreachable
5. Deploy PacketFence captive portal for physician BYOD onboarding with limited-access VLAN
6. Configure posture checks requiring Windows Update compliance and BitLocker encryption for full access
7. Test failover scenarios by stopping RADIUS and verifying devices remain on critical VLAN without disruption

**Pitfalls**:
- Not configuring critical VLAN fallback, causing devices to lose network access when RADIUS is unavailable
- MAB MAC address databases becoming stale as medical devices are replaced or moved
- 802.1X timeouts causing delays at workstation login, especially with slow RADIUS responses
- Not testing multi-host mode on ports with IP phones and workstations daisy-chained

## Output Format

```
## NAC Deployment Report

**RADIUS Server**: freeradius-01 (10.10.100.200)
**NAC Platform**: PacketFence 13.1
**Switches Configured**: 12 access switches
**Total Ports**: 576 access ports

### Authentication Summary (24-hour)

| Auth Type | Success | Failure | Total |
|-----------|---------|---------|-------|
| 802.1X (PEAP) | 342 | 12 | 354 |
| MAB | 87 | 3 | 90 |
| Guest Portal | 23 | 5 | 28 |

### VLAN Assignment Distribution

| VLAN | Name | Assigned Devices |
|------|------|------------------|
| 10 | Corporate | 245 |
| 15 | Development | 67 |
| 20 | Finance | 30 |
| 40 | Guest | 23 |
| 50 | Medical Devices | 87 |
| 999 | Quarantine | 15 (posture fail) |

### Compliance Status
- 802.1X coverage: 100% of access ports
- Posture pass rate: 95.8% (15 devices quarantined for missing patches)
- RADIUS failover tested: Successful (critical VLAN activated in 3 seconds)
```
