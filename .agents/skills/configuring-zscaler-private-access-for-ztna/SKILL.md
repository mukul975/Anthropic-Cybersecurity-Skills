---
name: configuring-zscaler-private-access-for-ztna
description: >
  Configuring Zscaler Private Access (ZPA) to replace traditional VPN with zero trust
  network access by deploying App Connectors, defining application segments, configuring
  access policies based on user identity and device posture, and integrating with IdPs.
domain: cybersecurity
subdomain: zero-trust-architecture
tags: [zscaler, zpa, ztna, zero-trust, app-connector, access-policy, sase]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Configuring Zscaler Private Access for ZTNA

## When to Use

- When replacing traditional VPN concentrators with application-level zero trust access
- When providing remote users secure access to internal applications without network-level connectivity
- When implementing least-privilege access where users only see authorized applications
- When needing to make internal applications invisible to unauthorized users and the internet
- When integrating ZTNA with existing SASE architecture using Zscaler Internet Access (ZIA)

**Do not use** for applications requiring raw UDP access (ZPA primarily supports TCP), for providing full network-level access equivalent to site-to-site VPN (use ZPA AppProtection or branch connector instead), or when the organization requires on-premises-only access control without cloud dependency.

## Prerequisites

- Zscaler Private Access subscription (Business or Transformation edition)
- Identity provider configured: Okta, Microsoft Entra ID, Ping Identity, or SAML 2.0 IdP
- App Connector VM requirements: Linux VM (CentOS 7/8, RHEL 7/8, Ubuntu 18.04+, Amazon Linux 2) with 2 vCPU, 4GB RAM minimum
- Outbound connectivity from App Connector to ZPA cloud on port 443 (no inbound ports required)
- DNS resolution from App Connector to internal application FQDNs
- Zscaler Client Connector deployed on user endpoints

## Workflow

### Step 1: Deploy App Connectors in Application Network

App Connectors establish outbound-only tunnels to the ZPA cloud, providing access to internal applications.

```bash
# Download and install App Connector on Linux VM
# Obtain provisioning key from ZPA Admin Portal > Administration > App Connectors

# For RHEL/CentOS
sudo yum install -y https://yum.private.zscaler.com/yum/el7/zpa-connector-latest.rpm

# For Ubuntu/Debian
curl -sS https://dist.private.zscaler.com/apt/pubkey.gpg | sudo apt-key add -
echo "deb https://dist.private.zscaler.com/apt stable main" | sudo tee /etc/apt/sources.list.d/zpa.list
sudo apt update && sudo apt install -y zpa-connector

# Configure the connector with provisioning key
sudo /opt/zscaler/bin/zpa-connector configure \
  --provision-key "PROVISIONING_KEY_FROM_PORTAL"

# Start the connector service
sudo systemctl enable zpa-connector
sudo systemctl start zpa-connector

# Verify connector status
sudo systemctl status zpa-connector
sudo /opt/zscaler/bin/zpa-connector status

# Deploy second connector for HA (minimum 2 per site)
# Repeat on second VM with same App Connector Group provisioning key
```

### Step 2: Define Server Groups and Application Segments

Map internal applications to server groups and create application segments.

```text
ZPA Admin Portal Configuration:

1. Server Groups:
   Navigate to: Administration > App Connectors > Server Groups
   - Name: "DC-East-Servers"
   - App Connector Group: "DC-East-Connectors"
   - Servers:
     - hr-portal.internal.corp (10.1.1.50, TCP 443)
     - finance-app.internal.corp (10.1.1.51, TCP 443)
     - git.internal.corp (10.1.2.10, TCP 22, 443)

2. Application Segments:
   Navigate to: Resources > Application Segments > Add Application Segment
   - Name: "HR Applications"
   - Domain/URL: hr-portal.internal.corp
   - TCP Ports: 443
   - Server Group: DC-East-Servers
   - Health Reporting: Continuous
   - Bypass Type: Never (force all traffic through ZPA)

   - Name: "Engineering Tools"
   - Domain/URL: git.internal.corp, ci.internal.corp, wiki.internal.corp
   - TCP Ports: 22, 80, 443
   - Server Group: DC-East-Servers
   - Segment Group: "Engineering Segment Group"
```

### Step 3: Configure Access Policies

Define who can access which application segments based on identity and device posture.

```text
ZPA Admin Portal > Policies > Access Policy:

Rule 1: HR Team Access
  - Name: "HR Portal Access"
  - Action: ALLOW
  - Criteria:
    - User Groups: "HR-Department" (from IdP)
    - Application Segment: "HR Applications"
    - Device Posture Profile: "Corporate Managed Device"
    - Client Type: Zscaler Client Connector
  - Conditions:
    - SAML Attribute: department = "Human Resources"
    - Device Trust Level: "HIGH" (CrowdStrike ZTA score > 70)

Rule 2: Engineering Access
  - Name: "Engineering Tools Access"
  - Action: ALLOW
  - Criteria:
    - User Groups: "Engineering-Team", "DevOps-Team"
    - Application Segment: "Engineering Tools"
    - Device Posture Profile: "Developer Workstation"
  - Conditions:
    - Machine Group: "Engineering Laptops"

Rule 3: Contractor Limited Access
  - Name: "Contractor Wiki Access"
  - Action: ALLOW
  - Criteria:
    - User Groups: "External-Contractors"
    - Application Segment: "Wiki Only"
    - Client Type: Zscaler Client Connector OR Browser Access
  - Conditions:
    - Time Window: Mon-Fri 08:00-18:00 EST

Rule 4: Default Deny
  - Name: "Block All Other Access"
  - Action: DENY
  - Criteria: All Users, All Applications
  - Log: Enabled
```

### Step 4: Configure Device Posture Profiles

Integrate device posture signals from endpoint security tools.

```text
ZPA Admin Portal > Administration > Device Posture:

Profile 1: Corporate Managed Device
  - CrowdStrike Falcon: Running, ZTA Score >= 60
  - OS: Windows 10 21H2+, macOS 13+, Ubuntu 22.04+
  - Disk Encryption: Enabled (BitLocker/FileVault)
  - Firewall: Enabled
  - Screen Lock: Enabled

Profile 2: Developer Workstation
  - Inherits: Corporate Managed Device
  - CrowdStrike Falcon: ZTA Score >= 70
  - Patch Level: Within 30 days of latest
  - Certificate: Valid corporate certificate present

Profile 3: BYOD Device
  - OS: Latest minus 1 version
  - Browser: Chrome 120+ or Edge 120+
  - Antivirus: Any recognized AV running
```

### Step 5: Enable Browser Access for Clientless ZTNA

Configure Browser Access for users without Zscaler Client Connector installed.

```text
ZPA Admin Portal > Resources > Application Segments:

For "HR Applications" segment:
  - Enable Browser Access: Yes
  - Browser Access Type: HTTPS
  - Custom Domain: hr.access.company.com
  - Certificate: Upload TLS certificate for custom domain
  - Authentication: SAML via corporate IdP
  - Session Timeout: 4 hours
  - Clipboard Control: Disabled for sensitive apps
  - File Upload/Download: Restricted

For Browser Access Portal:
  - Portal URL: access.company.com
  - IdP: Microsoft Entra ID (SAML 2.0)
  - MFA: Required
  - Applications shown: Only authorized per user group
```

### Step 6: Configure Logging and Monitoring

Set up log streaming for SIEM integration and continuous monitoring.

```text
ZPA Admin Portal > Administration > Log Streaming Service:

Log Receiver Configuration:
  - Name: "Splunk-SIEM"
  - Type: Splunk (HEC)
  - Destination: https://splunk-hec.company.com:8088
  - HEC Token: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  - Log Types:
    - User Activity: Enabled
    - App Connector Status: Enabled
    - Audit Logs: Enabled
    - Browser Access: Enabled

# Splunk search for ZPA access anomalies
index=zscaler_zpa sourcetype=zpa:useractivity
| where action="denied"
| stats count by user, application, policy_name
| where count > 10
| sort -count
```

## Key Concepts

| Term | Definition |
|------|------------|
| App Connector | Lightweight Linux service that creates outbound-only encrypted tunnels from internal networks to ZPA cloud, providing access to applications without inbound ports |
| Application Segment | Logical grouping of internal applications defined by FQDN/IP and ports, mapped to server groups for access policy enforcement |
| Server Group | Collection of application servers associated with App Connector groups that can serve requests for application segments |
| Access Policy | Rules defining which users/groups can access which application segments under what conditions (device posture, time, location) |
| Zscaler Client Connector | Endpoint agent installed on user devices that routes traffic to ZPA cloud for policy enforcement and application access |
| Browser Access | Clientless ZTNA option allowing application access through a web browser without requiring Zscaler Client Connector installation |

## Tools & Systems

- **Zscaler Private Access (ZPA)**: Cloud-native ZTNA platform replacing VPN with identity-based application access
- **Zscaler Client Connector**: Cross-platform endpoint agent routing traffic through ZPA for policy enforcement
- **ZPA App Connector**: Outbound-only tunnel endpoint deployed in application networks
- **ZPA Admin Portal**: Web-based management console for policy, segment, and connector configuration
- **ZPA Log Streaming Service (LSS)**: Real-time log export to SIEM platforms (Splunk, Sentinel, QRadar)
- **CrowdStrike ZTA Integration**: Device posture scoring for conditional access policy enforcement

## Common Scenarios

### Scenario: Migrating 500-User Organization from Cisco AnyConnect VPN to ZPA

**Context**: A financial services firm with 500 employees uses Cisco AnyConnect for remote access. VPN split-tunnel configuration creates security gaps, and full-tunnel mode causes performance issues. The firm needs application-level access control for SOX compliance.

**Approach**:
1. Deploy 4 App Connectors (2 per data center) with HA configuration
2. Define application segments for 20 internal applications grouped by business function
3. Configure access policies mapping AD groups to application segments with device posture requirements
4. Integrate CrowdStrike ZTA scores as device posture input (minimum score 60 for standard, 80 for financial apps)
5. Enable Browser Access for contractors accessing the vendor portal
6. Configure LSS to stream access logs to Splunk for SOX audit trail
7. Run parallel operation for 3 weeks: VPN and ZPA side by side
8. Phase out VPN connections after validating all application access through ZPA

**Pitfalls**: App Connector DNS must resolve all internal FQDNs used in application segments. Wildcard domain segments can cause performance issues if too broad. Browser Access does not support all web application frameworks (WebSocket-heavy apps may require Client Connector). CrowdStrike ZTA integration requires Falcon sensor deployment on all endpoints before enforcing posture policies.

## Output Format

```
ZPA ZTNA Deployment Report
==================================================
Organization: FinanceCorp
Deployment Date: 2026-02-23

INFRASTRUCTURE:
  App Connectors: 4 (2x DC-East, 2x DC-West)
  Connector Status: All healthy
  Connector Version: 24.1.2

APPLICATION COVERAGE:
  Application Segments: 20
  Total Applications: 45
  Server Groups: 4
  Segment Groups: 6

ACCESS POLICIES:
  Total Rules: 12
  Allow Rules: 11
  Deny Rules: 1 (default deny)
  Device Posture Profiles: 3

USER ACCESS (last 30 days):
  Active Users: 487 / 500
  Total Sessions: 124,567
  Allowed Sessions: 123,890 (99.5%)
  Denied Sessions: 677 (0.5%)
  Browser Access Sessions: 2,341

VPN MIGRATION:
  Users migrated to ZPA: 487 / 500
  VPN decommission date: 2026-03-15
```
