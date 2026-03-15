---
name: deploying-palo-alto-prisma-access-zero-trust
description: >
  Deploying Palo Alto Networks Prisma Access for SASE-based zero trust network access
  using GlobalProtect agents, ZTNA Connectors, security policy enforcement, and
  integration with Strata Cloud Manager for unified security management.
domain: cybersecurity
subdomain: zero-trust-architecture
tags: [prisma-access, palo-alto, ztna, sase, globalprotect, strata-cloud-manager, zero-trust]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Deploying Palo Alto Prisma Access Zero Trust

## When to Use

- When implementing enterprise-grade SASE with integrated ZTNA, SWG, CASB, and FWaaS
- When replacing both VPN and branch office firewalls with cloud-delivered security
- When needing advanced threat prevention (WildFire, DNS Security) for remote access traffic
- When deploying zero trust for both mobile users and remote network (branch) connections
- When integrating ZTNA with existing Palo Alto NGFW infrastructure via Strata Cloud Manager

**Do not use** for small organizations (< 200 users) where simpler ZTNA solutions suffice, for environments requiring only web application access without full network security, or when budget constraints preclude enterprise SASE licensing.

## Prerequisites

- Prisma Access license (Business Premium or equivalent)
- Strata Cloud Manager (SCM) tenant configured
- GlobalProtect agent for endpoint deployment
- ZTNA Connector VM: 4 vCPU, 8GB RAM, 128GB disk (VMware, AWS, Azure, or GCP)
- Identity provider: Okta, Entra ID, Ping Identity (SAML 2.0)
- Palo Alto Cortex Data Lake for log storage

## Workflow

### Step 1: Configure Prisma Access Infrastructure in Strata Cloud Manager

Set up the cloud infrastructure for mobile user and remote network connections.

```text
Strata Cloud Manager > Prisma Access > Infrastructure Settings:

Mobile Users Configuration:
  - Service Connection: Auto-selected based on user location
  - DNS Servers: 10.1.1.10, 10.1.1.11 (corporate DNS)
  - IP Pool for Mobile Users: 10.100.0.0/16
  - Authentication: SAML with Okta (Primary), Entra ID (Secondary)
  - GlobalProtect Portal: portal.company.com
  - GlobalProtect Gateway: Auto (nearest Prisma Access location)

Infrastructure Subnet:
  - Range: 172.16.0.0/16
  - Allocation: /24 per Prisma Access location
```

### Step 2: Deploy ZTNA Connectors for Private Application Access

Install ZTNA Connectors to provide secure access to internal applications.

```bash
# Deploy ZTNA Connector on VMware (OVA)
# Download OVA from Strata Cloud Manager > Prisma Access > ZTNA Connectors

# AWS deployment via CloudFormation
aws cloudformation create-stack \
  --stack-name prisma-ztna-connector \
  --template-url https://prisma-access-connector-templates.s3.amazonaws.com/ztna-connector-aws.yaml \
  --parameters \
    ParameterKey=VpcId,ParameterValue=vpc-PROD \
    ParameterKey=SubnetId,ParameterValue=subnet-PRIVATE \
    ParameterKey=InstanceType,ParameterValue=m5.xlarge \
    ParameterKey=TenantServiceGroup,ParameterValue=TSG_ID \
    ParameterKey=ConnectorName,ParameterValue=dc-east-connector-01

# Verify connector registration
# Strata Cloud Manager > Prisma Access > ZTNA Connectors
# Status should show "Connected" with nearest Prisma Access location

# Deploy second connector for HA
# ZTNA Connector auto-discovers nearest Prisma Access location
# IPSec tunnel uses: ecp384/aes256/sha512 for IKE and ESP
# Bandwidth: up to 2 Gbps per connector
```

### Step 3: Define Application Definitions and Access Policies

Create application definitions pointing to internal applications via ZTNA Connectors.

```text
Strata Cloud Manager > Prisma Access > Applications:

Application 1: Internal Wiki
  - FQDN: wiki.internal.corp
  - Port: TCP 443
  - ZTNA Connector: dc-east-connector-01
  - Protocol: HTTPS
  - Health Check: Enabled (HTTP GET /health)

Application 2: Source Code Repository
  - FQDN: git.internal.corp
  - Ports: TCP 22, 443
  - ZTNA Connector: dc-east-connector-01, dc-east-connector-02
  - Protocol: HTTPS, SSH

Application 3: Finance ERP
  - FQDN: erp.internal.corp
  - Port: TCP 443
  - ZTNA Connector: dc-east-connector-01
  - Protocol: HTTPS
  - User Authentication: Required (re-auth every 2h)

Strata Cloud Manager > Policies > Security Policy:

Rule 1: Engineering Access to Dev Tools
  Source: User Group "Engineering" (from Okta SAML)
  Destination: Application "Source Code Repository", "Internal Wiki"
  HIP Profile: "Managed Device with CrowdStrike"
  Action: Allow
  Logging: Enabled
  Threat Prevention: Best Practice profile

Rule 2: Finance Access to ERP
  Source: User Group "Finance"
  Destination: Application "Finance ERP"
  HIP Profile: "Compliant Device - High Security"
  Action: Allow
  SSL Decryption: Forward Proxy
  DLP Profile: "Financial Data Protection"

Rule 3: Default Deny Private Apps
  Source: Any
  Destination: Any Private App
  Action: Deny
  Logging: Enabled
```

### Step 4: Configure Host Information Profile (HIP) for Device Posture

Define device posture requirements using HIP checks.

```text
Strata Cloud Manager > Objects > GlobalProtect > HIP Objects:

HIP Object: "CrowdStrike Running"
  - Vendor: CrowdStrike
  - Product: Falcon Sensor
  - Is Running: Yes
  - Minimum Version: 7.10

HIP Object: "Disk Encryption Enabled"
  - Windows: BitLocker = Encrypted
  - macOS: FileVault = Encrypted

HIP Object: "OS Patch Level"
  - Windows: >= 10.0.22631
  - macOS: >= 14.0

HIP Profile: "Managed Device with CrowdStrike"
  - Match: "CrowdStrike Running" AND "Disk Encryption Enabled"

HIP Profile: "Compliant Device - High Security"
  - Match: "CrowdStrike Running" AND "Disk Encryption Enabled" AND "OS Patch Level"
```

### Step 5: Deploy GlobalProtect Agent to Endpoints

Roll out the GlobalProtect agent for secure connectivity.

```bash
# Deploy GlobalProtect via Intune (Windows)
# MSI download from Strata Cloud Manager > GlobalProtect > Agent Downloads

# GlobalProtect pre-deployment configuration
# pre-deploy.xml for automated portal connection:
cat > pre-deploy.xml << 'EOF'
<GlobalProtect>
  <Settings>
    <portal>portal.company.com</portal>
    <connect-method>pre-logon</connect-method>
    <authentication-override>
      <generate-cookie>yes</generate-cookie>
      <cookie-lifetime>24</cookie-lifetime>
    </authentication-override>
  </Settings>
</GlobalProtect>
EOF

# Verify GlobalProtect connection status
# GlobalProtect system tray > Settings > Connection Details
# Should show: Connected to nearest Prisma Access gateway
# IPSec tunnel established with full threat prevention
```

### Step 6: Configure Logging and Monitoring

Set up Cortex Data Lake integration and monitoring dashboards.

```text
Strata Cloud Manager > Prisma Access > Monitoring:

Log Forwarding:
  - Cortex Data Lake: Enabled (all log types)
  - SIEM Forwarding: Splunk HEC (https://splunk-hec.company.com:8088)
  - Log Types: Traffic, Threat, URL, WildFire, GlobalProtect, HIP Match

Dashboard Monitoring:
  - Mobile Users: Active connections, locations, bandwidth
  - ZTNA Connectors: Health, latency, tunnel status
  - Security Events: Threats blocked, DLP violations, HIP failures
  - Application Usage: Top apps, top users, denied access attempts

Alerting:
  - ZTNA Connector down: Email + PagerDuty
  - HIP failure rate > 10%: Email to IT
  - Threat detected on mobile user: SOC alert
```

## Key Concepts

| Term | Definition |
|------|------------|
| Prisma Access | Palo Alto's cloud-delivered SASE platform providing FWaaS, SWG, CASB, DLP, and ZTNA from a single architecture |
| ZTNA Connector | VM-based connector establishing IPSec tunnels from internal networks to Prisma Access for private application access |
| GlobalProtect | Endpoint agent providing secure connectivity to Prisma Access with HIP checks and always-on VPN |
| Host Information Profile (HIP) | Device posture checks evaluating endpoint security state (EDR, encryption, patches) before granting access |
| Strata Cloud Manager | Unified management console for Prisma Access, NGFW, and Prisma Cloud security policy |
| Cortex Data Lake | Cloud-based log storage and analytics platform for Palo Alto security telemetry |

## Tools & Systems

- **Prisma Access**: Cloud-delivered SASE with integrated ZTNA, SWG, CASB, DLP, FWaaS
- **Strata Cloud Manager (SCM)**: Unified policy management across Palo Alto security products
- **GlobalProtect Agent**: Endpoint connectivity agent with HIP data collection
- **ZTNA Connector**: Outbound-only tunnel connector for internal application access
- **Cortex Data Lake**: Centralized log storage with analytics and threat detection
- **WildFire**: Cloud-based malware analysis and prevention integrated with Prisma Access

## Common Scenarios

### Scenario: Enterprise SASE Migration for 5,000-User Organization

**Context**: A manufacturing company with 5,000 users across 15 offices is consolidating VPN, SWG, and branch firewalls into Prisma Access SASE. Users access 50+ internal applications and need consistent security regardless of location.

**Approach**:
1. Deploy ZTNA Connectors at 3 data centers (2 per DC for HA) for internal application access
2. Configure GlobalProtect with pre-logon connection for always-on security
3. Define 50+ application definitions in SCM with FQDN and port mappings
4. Create HIP profiles: Standard (encryption + AV), Enhanced (+ CrowdStrike + patches)
5. Build security policies mapping user groups to applications with HIP requirements
6. Enable threat prevention profiles (Anti-Spyware, Anti-Virus, WildFire, URL Filtering)
7. Deploy GlobalProtect agent via SCCM to all 5,000 endpoints in phases
8. Configure Cortex Data Lake forwarding to Splunk for SOC monitoring
9. Decommission VPN concentrators and branch firewall appliances

**Pitfalls**: ZTNA Connector requires minimum 4 vCPU and 8GB RAM; under-provisioning causes latency. GlobalProtect pre-logon requires machine certificates for authentication before user login. HIP check intervals should be 60 seconds minimum to avoid performance impact. Plan for a 4-6 week pilot before full deployment.

## Output Format

```
Prisma Access ZTNA Deployment Report
==================================================
Organization: ManufactureCorp
Deployment Date: 2026-02-23

INFRASTRUCTURE:
  ZTNA Connectors: 6 (2x DC-East, 2x DC-West, 2x DC-EU)
  Prisma Access Locations: 8 (auto-selected)
  GlobalProtect Portal: portal.manufacturecorp.com

APPLICATION ACCESS:
  Defined Applications: 52
  Active ZTNA Connections: 3,247
  Average Latency: 12ms

ENDPOINT DEPLOYMENT:
  GlobalProtect Deployed: 4,812 / 5,000 (96.2%)
  HIP Compliant: 4,567 / 4,812 (94.9%)
  HIP Failures: 245 (top: missing patches 120, encryption 85)

SECURITY (last 30 days):
  Threats Blocked: 1,234
  DLP Violations: 89
  URL Blocked: 45,678
  WildFire Submissions: 2,345
```
