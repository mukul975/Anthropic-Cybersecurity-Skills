---
name: scanning-infrastructure-with-nessus
description: Tenable Nessus is the industry-leading vulnerability scanner used to identify security weaknesses across network infrastructure including servers, workstations, network devices, and operating systems.
domain: cybersecurity
subdomain: vulnerability-management
tags: [vulnerability-management, cve, nessus, tenable, infrastructure-scanning, risk]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Scanning Infrastructure with Nessus

## Overview
Tenable Nessus is the industry-leading vulnerability scanner used to identify security weaknesses across network infrastructure including servers, workstations, network devices, and operating systems. This skill covers configuring scan policies, running authenticated and unauthenticated scans, interpreting results, and integrating Nessus into continuous vulnerability management workflows.

## Prerequisites
- Nessus Professional or Essentials license installed and activated
- Network access to target systems (firewall rules allowing scanner IP)
- Administrative credentials for authenticated scanning
- Understanding of TCP/IP networking and common services
- Written authorization for scanning target environments

## Core Concepts

### Nessus Architecture
Nessus operates as a client-server application where the Nessus scanner engine runs as a service (nessusd) on the host system. It uses a plugin-based architecture with over 200,000 plugins updated weekly by Tenable's research team. Each plugin tests for a specific vulnerability, misconfiguration, or compliance check.

### Scan Types
1. **Host Discovery** - Identifies live hosts using ICMP, TCP, UDP, and ARP
2. **Basic Network Scan** - Default policy covering common vulnerabilities
3. **Advanced Scan** - Custom policy with granular plugin selection
4. **Credentialed Patch Audit** - Authenticated scan checking installed patches
5. **Web Application Tests** - Scans for web-specific vulnerabilities
6. **Compliance Audit** - Checks against CIS, DISA STIG, PCI DSS benchmarks

### Plugin Families
Nessus organizes plugins into families including:
- **Operating Systems**: Windows, Linux, macOS, Solaris
- **Network Devices**: Cisco, Juniper, Palo Alto, Fortinet
- **Web Servers**: Apache, Nginx, IIS, Tomcat
- **Databases**: Oracle, MySQL, PostgreSQL, MSSQL
- **Services**: DNS, SMTP, FTP, SSH, SNMP

## Implementation Steps

### Step 1: Initial Configuration
```bash
# Start Nessus service
sudo systemctl start nessusd
sudo systemctl enable nessusd

# CLI management with nessuscli
/opt/nessus/sbin/nessuscli update --all
/opt/nessus/sbin/nessuscli fix --list

# Verify plugin count
/opt/nessus/sbin/nessuscli update --plugins-only
```

### Step 2: Create Scan Policy
Configure a custom scan policy through the Nessus web UI at https://localhost:8834:

1. Navigate to Policies > New Policy > Advanced Scan
2. Configure General settings: name, description, targets
3. Set Discovery settings:
   - Host Discovery: Ping methods (ICMP, TCP SYN on ports 22,80,443)
   - Port Scanning: SYN scan on common ports or all 65535 ports
   - Service Discovery: Probe all ports for services
4. Configure Assessment settings:
   - Accuracy: Override normal accuracy (reduce false positives)
   - Web Applications: Enable if scanning web servers
5. Select Plugin families relevant to target environment

### Step 3: Configure Credentials
For authenticated scanning, configure credentials under the Credentials tab:
- **SSH**: Username/password or SSH key pair
- **Windows**: Domain credentials via SMB, WMI
- **SNMP**: Community strings (v1/v2c) or USM credentials (v3)
- **Database**: Oracle, MySQL, PostgreSQL connection strings
- **VMware**: vCenter or ESXi credentials

### Step 4: Run the Scan
```
# Using Nessus REST API via curl
# Authenticate and get token
curl -k -X POST https://localhost:8834/session \
  -d '{"username":"admin","password":"password"}' \
  -H "Content-Type: application/json"

# Create scan
curl -k -X POST https://localhost:8834/scans \
  -H "X-Cookie: token=<TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "uuid": "<TEMPLATE_UUID>",
    "settings": {
      "name": "Infrastructure Scan Q1",
      "text_targets": "192.168.1.0/24",
      "enabled": true,
      "launch": "ON_DEMAND"
    }
  }'

# Launch scan
curl -k -X POST https://localhost:8834/scans/<SCAN_ID>/launch \
  -H "X-Cookie: token=<TOKEN>"

# Check scan status
curl -k -X GET https://localhost:8834/scans/<SCAN_ID> \
  -H "X-Cookie: token=<TOKEN>"
```

### Step 5: Analyze Results
Nessus categorizes findings by severity:
- **Critical (CVSS 9.0-10.0)**: Immediate remediation required
- **High (CVSS 7.0-8.9)**: Remediate within 7-14 days
- **Medium (CVSS 4.0-6.9)**: Remediate within 30 days
- **Low (CVSS 0.1-3.9)**: Remediate during next maintenance window
- **Informational**: No immediate action required

### Step 6: Export and Report
```bash
# Export via REST API
curl -k -X POST "https://localhost:8834/scans/<SCAN_ID>/export" \
  -H "X-Cookie: token=<TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"format":"nessus"}'

# Supported formats: nessus (XML), csv, html, pdf
```

## Best Practices
1. Schedule scans during maintenance windows to minimize production impact
2. Use authenticated scanning for 45-60% more vulnerability detection
3. Exclude fragile systems (medical devices, legacy SCADA) from aggressive scans
4. Maintain separate scan policies for different network segments
5. Update plugins before every scan to catch recently disclosed CVEs
6. Validate critical findings manually before escalating to remediation teams
7. Implement scan result trending to track remediation progress over time
8. Store scan results in Tenable.sc or Tenable.io for centralized management

## Common Pitfalls
- Running unauthenticated scans only (misses 45-60% of vulnerabilities)
- Scanning without written authorization (legal and ethical violations)
- Ignoring scan performance impact on production systems
- Failing to tune plugins leading to excessive false positives
- Not validating scanner network connectivity before launching scans
- Using default scan policies without customization for the environment

## Related Skills
- performing-authenticated-vulnerability-scan
- prioritizing-vulnerabilities-with-cvss-scoring
- implementing-continuous-vulnerability-monitoring
- performing-network-vulnerability-assessment
