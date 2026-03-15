# API Reference: Implementing Network Segmentation with Firewall Zones

## Zone Trust Levels

| Zone | Trust Level | Typical VLANs | Default Policy |
|------|-------------|---------------|----------------|
| Internet | 0 (Untrusted) | N/A | Deny all inbound |
| DMZ | 1 (Low) | 10-19 | Permit specific inbound services |
| Guest | 1 (Low) | 50-59 | Internet-only, deny internal |
| Corporate | 3 (Medium) | 100-199 | Permit outbound, restricted inbound |
| Server/DC | 4 (High) | 200-299 | Strict ACL, limited admin |
| PCI CDE | 5 (Critical) | 300-309 | PCI DSS compliant isolation |
| Management | 5 (Critical) | 900-909 | Jump box only |
| OT/SCADA | 5 (Critical) | 400-409 | Air-gapped or strictly firewalled |

## Palo Alto Zone-Based CLI

```bash
# Create security zone
set network zone trust network layer3 ethernet1/2
set network zone untrust network layer3 ethernet1/1
set network zone dmz network layer3 ethernet1/3

# Inter-zone security policy
set rulebase security rules Allow-Corp-to-DMZ from trust to dmz \
  application web-browsing action allow log-end yes

# Default deny rule
set rulebase security rules Deny-All from any to any application any action deny log-start yes
```

## Cisco ASA Zone Commands

```bash
# Define nameif and security level
interface GigabitEthernet0/0
  nameif outside
  security-level 0
interface GigabitEthernet0/1
  nameif inside
  security-level 100
interface GigabitEthernet0/2
  nameif dmz
  security-level 50

# ACL for inter-zone traffic
access-list OUTSIDE_IN extended permit tcp any host 192.168.10.5 eq 443
access-group OUTSIDE_IN in interface outside
```

## PCI DSS Segmentation Requirements

| Requirement | Control |
|-------------|---------|
| Req 1.2 | Restrict connections between untrusted and CDE |
| Req 1.3 | Prohibit direct public access to CDE |
| Req 1.4 | Personal firewall on portable devices |
| Req 11.3.4 | Penetration testing validates segmentation |

## VLAN Trunking (802.1Q)

```bash
# Cisco switch VLAN configuration
vlan 100
  name Corporate
vlan 200
  name Servers
vlan 300
  name PCI_CDE

interface GigabitEthernet0/1
  switchport mode trunk
  switchport trunk allowed vlan 100,200,300
```

### References

- NIST SP 800-41: https://csrc.nist.gov/publications/detail/sp/800-41/rev-1/final
- PCI DSS v4.0 Network Segmentation: https://www.pcisecuritystandards.org/
- CIS Controls v8 Control 12: https://www.cisecurity.org/controls/v8
