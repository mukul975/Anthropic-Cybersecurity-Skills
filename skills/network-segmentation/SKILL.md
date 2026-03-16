---
name: network-segmentation
description:
  Designs network segmentation and Zero Trust network access. Use when designing microsegmentation, ZTNA architecture,
  or network security controls. Expert in Zero Trust networks pillar.
domain: cybersecurity
subdomain: network-security
tags: [microsegmentation, ztna, zero-trust, network-architecture]
version: "1.0"
author: HRD-Security
license: Apache-2.0
---

# Network Segmentation Skill

## Overview

You are a network security architect specializing in Zero Trust network design and microsegmentation.
This skill covers ZTNA architecture, cloud network segmentation, encryption strategies, and
east-west/north-south traffic control aligned with Zero Trust principles.

## Prerequisites

- Understanding of cloud networking (AWS VPC, Azure VNet, security groups)
- Familiarity with ZTNA concepts and software-defined perimeter
- Knowledge of TLS/mTLS and certificate management

## Key Concepts

### Core Expertise

- **ZTNA**: Software-defined perimeter, identity-aware proxies
- **Microsegmentation**: Workload isolation, east-west traffic control
- **Cloud Networks**: AWS VPC, Azure VNet, security groups
- **Encryption**: TLS 1.3, mTLS, certificate management

### Zero Trust Network Principles

#### 1. No Implicit Trust

- Network location does not grant trust
- All traffic is potentially hostile
- Verify before allowing any connection

#### 2. Least Privilege Network Access

- Application-level access, not network-level
- Only necessary ports and protocols
- Time-bound access where possible

#### 3. Encryption Everywhere

- All traffic encrypted (north-south and east-west)
- TLS 1.3 minimum
- Certificate-based authentication

## Practical Steps

### Network Architecture Patterns

#### 1. ZTNA Architecture

```text
User → Edge Proxy → Identity-Aware Access → Application
              ↓
        Identity Check
        Device Posture Check
        Location Check
        Risk Assessment
              ↓
        Application-level tunnel
        (no network exposure)
```

#### 2. Cloud Network Segmentation

```text
Cloud VPC
├── Production Account
│   ├── Web Tier (public subnet)
│   │   └── ALB, WAF
│   ├── Application Tier (private subnet)
│   │   └── Container services
│   └── Data Tier (isolated subnet)
│       └── Database, Cache
├── Non-Production Account
│   └── Similar structure
└── Shared Services Account
    ├── Transit Gateway
    ├── DNS
    └── Logging
```

#### 3. Security Group Strategy

```text
Tier-based Security Groups
├── Web-SG
│   ├── Inbound: 443 from ALB
│   └── Outbound: App-SG only
├── App-SG
│   ├── Inbound: 8080 from Web-SG
│   └── Outbound: Data-SG only
└── Data-SG
    ├── Inbound: 5432 from App-SG
    └── Outbound: None
```

### Segmentation Strategies

#### 1. Network Perimeter

| Control        | Implementation  | Purpose                |
| -------------- | --------------- | ---------------------- |
| WAF            | Edge provider   | Application protection |
| DDoS           | Edge provider   | Availability           |
| Bot Management | Edge provider   | API protection         |
| Edge DNS       | Edge provider   | DNS security           |

#### 2. North-South Traffic

| Traffic Type        | Control                  |
| ------------------- | ------------------------ |
| Inbound (internet)  | WAF, CDN, load balancer  |
| Outbound (internet) | Egress filtering, proxy  |
| Remote access       | ZTNA                     |

#### 3. East-West Traffic

| Traffic Type         | Control                 |
| -------------------- | ----------------------- |
| Between tiers        | Security groups, NACLs  |
| Between services     | Service mesh, mTLS      |
| Between environments | VPC isolation, firewall |

#### 4. Workload Microsegmentation

```text
Application Workloads
├── Each service has own security group
├── Connections explicitly allowed
├── Default deny all
└── Logging enabled
```

### Encryption Requirements

#### TLS Configuration

| Setting                | Requirement       |
| ---------------------- | ----------------- |
| Minimum version        | TLS 1.3           |
| Cipher suites          | AEAD only         |
| Certificate management | Automated renewal |
| HSTS                   | Enabled           |

#### mTLS for Services

- Service-to-service authentication
- Certificate-based identity
- Automated rotation
- Revocation handling

### ZTNA Policy Structure

```yaml
Application: Internal Admin
Rules:
  - Allow if:
      - User in authorized group
      - Device is corporate managed
      - Device passes posture checks
      - Location in allowed countries
      - Session < 12 hours
```

### Device Posture Checks

- Disk encryption enabled
- Firewall enabled
- OS up to date
- EDR running
- Serial number in inventory

## Verification

### Network Architecture Design Output

```markdown
# Network Security Architecture

## 1. Network Topology
[High-level network diagram description]

## 2. Segmentation Strategy
[How networks are segmented]

## 3. Security Controls
[Firewalls, security groups, WAF]

## 4. ZTNA Design
[Identity-aware access configuration]

## 5. Encryption
[TLS, mTLS requirements]

## 6. Monitoring
[Network visibility, logging]

## 7. Zero Trust Alignment
[Network pillar maturity]
```
