---
name: implementing-rapid7-insightvm-for-scanning
description: Deploy and configure Rapid7 InsightVM Security Console and Scan Engines for authenticated and unauthenticated vulnerability scanning across enterprise environments.
domain: cybersecurity
subdomain: vulnerability-management
tags: [rapid7, insightvm, vulnerability-scanning, nexpose, scan-engine, asset-discovery, authenticated-scanning]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Implementing Rapid7 InsightVM for Scanning

## Overview
Rapid7 InsightVM (formerly Nexpose) is an enterprise vulnerability management platform that combines on-premises scanning via Security Console and Scan Engines with cloud-based analytics through the Insight Platform. InsightVM leverages Rapid7's vulnerability research library, Metasploit exploit knowledge, global attacker behavior data, internet-wide scanning telemetry, and real-time reporting to provide comprehensive vulnerability visibility. This skill covers deploying the Security Console, configuring Scan Engines, setting up scan templates, credentialed scanning, and integrating with the Insight Agent for continuous assessment.

## Prerequisites
- Server meeting minimum requirements: 16 GB RAM, 4 CPU cores, 500 GB disk (Security Console)
- Scan Engine: 8 GB RAM, 4 CPU cores, 100 GB disk
- Network access to target subnets (ports vary by scan type)
- Administrative credentials for authenticated scanning (SSH, WMI, SNMP)
- Rapid7 InsightVM license and Insight Platform account
- PostgreSQL database (bundled with Security Console)

## Core Concepts

### InsightVM Architecture Components

#### Security Console
The central management server that:
- Hosts the web-based management interface (default port 3780)
- Stores scan results in an embedded PostgreSQL database
- Manages Scan Engine deployments and scan schedules
- Generates reports and dashboards
- Connects to Rapid7 Insight Platform for cloud analytics

Note: Security Console is NOT supported in containerized environments.

#### Scan Engines
Distributed scanning components that:
- Perform active network scanning against target assets
- Can be deployed across network segments for segmented environments
- Available as container images on Docker Hub for flexible deployment
- Report results back to the Security Console

#### Insight Agent
Lightweight endpoint agent providing:
- Continuous vulnerability assessment without network scans
- Assessment of remote/roaming endpoints
- Complement to engine-based scanning for comprehensive coverage
- Real-time asset inventory updates

### Scan Template Types

| Template | Use Case | Depth |
|----------|----------|-------|
| Discovery Scan | Asset inventory, host enumeration | Low |
| Full Audit without Web Spider | Standard vulnerability assessment | Medium |
| Full Audit Enhanced Logging | Deep assessment with verbose logging | High |
| HIPAA Compliance | Healthcare regulatory compliance | High |
| PCI ASV Audit | PCI DSS external scanning requirement | High |
| CIS Policy Compliance | Configuration benchmarking | Medium |
| Web Spider | Web application discovery and assessment | Medium |

## Implementation Steps

### Step 1: Install Security Console

```bash
# Download InsightVM installer (Linux)
chmod +x Rapid7Setup-Linux64.bin
./Rapid7Setup-Linux64.bin -c

# Verify service is running
systemctl status nexposeconsole.service

# Access web interface
# https://<console-ip>:3780
```

Initial configuration:
1. Navigate to https://localhost:3780
2. Complete the setup wizard with license key
3. Configure database settings (embedded PostgreSQL recommended)
4. Set administrator credentials
5. Activate Insight Platform connection for cloud analytics

### Step 2: Deploy Distributed Scan Engines

```bash
# Install Scan Engine on remote server
./Rapid7Setup-Linux64.bin -c

# During installation, select "Scan Engine only"
# Pair with Security Console using shared secret

# Docker-based Scan Engine deployment
docker pull rapid7/insightvm-scan-engine
docker run -d \
  --name scan-engine \
  -p 40814:40814 \
  -e CONSOLE_HOST=<console-ip> \
  -e CONSOLE_PORT=3780 \
  -e ENGINE_NAME=DMZ-Scanner \
  -e SHARED_SECRET=<pairing-secret> \
  rapid7/insightvm-scan-engine
```

Pair engines in Security Console:
1. Administration > Scan Engines > New Scan Engine
2. Enter engine hostname/IP and port (default 40814)
3. Use shared secret for authentication
4. Verify connectivity status shows "Active"

### Step 3: Configure Asset Discovery Sites

```
Site Configuration:
  Name:           Production-Network
  Scan Engine:    Primary-Engine-01
  Scan Template:  Full Audit without Web Spider

  Included Assets:
    - 10.0.0.0/8     (Internal network)
    - 172.16.0.0/12   (DMZ network)

  Excluded Assets:
    - 10.0.0.1        (Core router - fragile)
    - 10.0.100.0/24   (ICS/SCADA segment)

  Schedule:
    Frequency:    Weekly
    Day:          Sunday
    Time:         02:00 AM
    Max Duration: 8 hours
```

### Step 4: Configure Authenticated Scanning

#### Windows Credentials (WMI)
```
Credential Type:    Microsoft Windows/Samba (SMB/CIFS)
Domain:             CORP.EXAMPLE.COM
Username:           svc_insightvm_scan
Password:           <service-account-password>
Authentication:     NTLM

Privilege Elevation:
  Type:   None (use domain admin or local admin)
```

#### Linux/Unix Credentials (SSH)
```
Credential Type:    Secure Shell (SSH)
Username:           insightvm_scan
Authentication:     SSH Key (preferred) or Password
SSH Private Key:    /opt/rapid7/.ssh/scan_key
Port:               22

Privilege Elevation:
  Type:             sudo
  sudo User:        root
  sudo Password:    <sudo-password>
```

#### Database Credentials
```
Credential Type:    Microsoft SQL Server
Instance:           MSSQLSERVER
Domain:             CORP
Username:           insightvm_db_scan
Authentication:     Windows Authentication

Credential Type:    Oracle
Port:               1521
SID:                ORCL
Username:           insightvm_scan
```

### Step 5: Configure Scan Templates

Custom scan template for balanced scanning:
```
Template Name:      Enterprise-Standard-Scan

Service Discovery:
  TCP Ports:        Well-known (1-1024) + common services
  UDP Ports:        DNS(53), SNMP(161), NTP(123), TFTP(69)
  Method:           SYN scan (stealth)

Vulnerability Checks:
  Safe checks only: Enabled
  Skip potential:   Disabled
  Web spidering:    Disabled (separate template)
  Policy checks:    Enabled (CIS benchmarks)

Performance:
  Max parallel assets:     10
  Max requests per second: 100
  Timeout per asset:       30 minutes
  Retries:                 2
```

### Step 6: Set Up Insight Agent Deployment

```powershell
# Windows Agent Installation (via GPO or SCCM)
msiexec /i agentInstaller-x86_64.msi /quiet /norestart `
  CUSTOMTOKEN=<platform-token> `
  CUSTOMCONFIG=<agent-config>

# Linux Agent Installation
chmod +x agent_installer.sh
./agent_installer.sh install_start \
  --token <platform-token>

# Verify agent connectivity
# Check InsightVM console: Assets > Agent Management
```

### Step 7: Configure Remediation Workflows

```
Remediation Project:
  Name:             Q1-2025-Critical-Remediation

  Scope:
    Severity:       Critical + High
    CVSS Score:     >= 7.0
    Assets:         Production-Network site

  Assignment:
    Team:           Infrastructure-Ops
    Due Date:       2025-03-31

  Tracking:
    Auto-verify:    Enabled (re-scan on next scheduled scan)
    Notification:   Email on overdue items
    Escalation:     Manager notification at 75% SLA
```

### Step 8: API Integration for Automation

```python
import requests
import json

class InsightVMClient:
    """Rapid7 InsightVM API v3 client for automation."""

    def __init__(self, console_url, api_key):
        self.base_url = f"{console_url}/api/3"
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        })
        self.session.verify = False  # Self-signed cert on console

    def get_sites(self):
        """List all configured scan sites."""
        response = self.session.get(f"{self.base_url}/sites")
        response.raise_for_status()
        return response.json().get("resources", [])

    def start_scan(self, site_id, engine_id=None, template_id=None):
        """Trigger an ad-hoc scan for a site."""
        payload = {}
        if engine_id:
            payload["engineId"] = engine_id
        if template_id:
            payload["templateId"] = template_id

        response = self.session.post(
            f"{self.base_url}/sites/{site_id}/scans",
            json=payload
        )
        response.raise_for_status()
        return response.json()

    def get_asset_vulnerabilities(self, asset_id):
        """Retrieve vulnerabilities for a specific asset."""
        response = self.session.get(
            f"{self.base_url}/assets/{asset_id}/vulnerabilities"
        )
        response.raise_for_status()
        return response.json().get("resources", [])

    def get_scan_status(self, scan_id):
        """Check the status of a running scan."""
        response = self.session.get(f"{self.base_url}/scans/{scan_id}")
        response.raise_for_status()
        return response.json()

    def create_remediation_project(self, name, description, assets, vulns):
        """Create a remediation tracking project."""
        payload = {
            "name": name,
            "description": description,
            "assets": {"includedTargets": {"addresses": assets}},
            "vulnerabilities": {"includedVulnerabilities": vulns}
        }
        response = self.session.post(
            f"{self.base_url}/remediations",
            json=payload
        )
        response.raise_for_status()
        return response.json()


# Usage
client = InsightVMClient("https://insightvm-console:3780", "api-key-here")
sites = client.get_sites()
for site in sites:
    print(f"Site: {site['name']} - Assets: {site.get('assets', 0)}")
```

## Best Practices
1. Deploy Scan Engines close to target networks to minimize scan traffic traversing firewalls
2. Use Insight Agents for roaming laptops and remote workers that are not always reachable by network scans
3. Combine agent-based and engine-based scanning for the most accurate vulnerability view
4. Configure scan blackout windows during business-critical hours to avoid operational impact
5. Use credential testing before full scans to validate authentication works
6. Enable safe checks to prevent accidental denial of service on production systems
7. Separate scan sites by network segment, business unit, or compliance scope
8. Leverage tag-based asset groups for dynamic reporting and remediation tracking

## Common Pitfalls
- Running full scans during business hours causing network congestion or service degradation
- Using unauthenticated scans only, missing 60-80% of local vulnerabilities
- Not excluding fragile devices (printers, ICS/SCADA, medical devices) from aggressive scan templates
- Failing to distribute Scan Engines across network segments, causing firewall bottlenecks
- Ignoring scan engine resource utilization leading to incomplete scans
- Not configuring scan duration limits, allowing runaway scans to consume resources indefinitely

## Related Skills
- performing-agentless-vulnerability-scanning
- building-vulnerability-data-pipeline-with-api
- implementing-wazuh-for-vulnerability-detection
- performing-remediation-validation-scanning
