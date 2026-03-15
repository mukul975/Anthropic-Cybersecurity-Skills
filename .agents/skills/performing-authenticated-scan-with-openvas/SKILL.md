---
name: performing-authenticated-scan-with-openvas
description: Configure and execute authenticated vulnerability scans using OpenVAS/Greenbone Vulnerability Management with SSH and SMB credentials for comprehensive host-level assessment.
domain: cybersecurity
subdomain: vulnerability-management
tags: [openvas, gvm, authenticated-scan, vulnerability-scanning, greenbone, network-security, credentialed-scan]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing Authenticated Scan with OpenVAS

## Overview

OpenVAS (Open Vulnerability Assessment Scanner) is the scanner component of the Greenbone Vulnerability Management (GVM) framework. Authenticated scans use valid credentials (SSH for Linux, SMB for Windows, ESXi for VMware) to log into target systems, enabling detection of local vulnerabilities, missing patches, and misconfigurations that unauthenticated scans cannot identify. Authenticated scans typically find 10-50x more vulnerabilities than unauthenticated scans.

## Prerequisites

- GVM 22.x+ installed (gvmd, openvas-scanner, gsad, ospd-openvas)
- PostgreSQL database configured for gvmd
- Redis configured for openvas-scanner
- NVT feed synchronized (greenbone-nvt-sync or greenbone-feed-sync)
- SSH credentials for Linux targets or SMB credentials for Windows targets
- Network access to target hosts on scan ports

## Installation

### Install GVM on Kali Linux / Debian
```bash
# Install GVM package
sudo apt update && sudo apt install -y gvm

# Run initial setup (creates admin account, syncs feeds)
sudo gvm-setup

# Check installation status
sudo gvm-check-setup

# Start all GVM services
sudo gvm-start

# Access Greenbone Security Assistant at https://127.0.0.1:9392
```

### Install via Docker (Recommended for Production)
```bash
# Pull Greenbone Community Edition containers
docker pull greenbone/gvm:stable

# Run with docker-compose
curl -fsSL https://greenbone.github.io/docs/latest/_static/docker-compose-22.4.yml \
  -o docker-compose.yml

# Start the stack
docker compose -f docker-compose.yml -p greenbone-community-edition up -d

# Wait for feed sync (initial sync takes 15-30 minutes)
docker compose -f docker-compose.yml -p greenbone-community-edition \
  logs -f gvmd 2>&1 | grep -i "feed"
```

## Configuring Credentials

### SSH Credentials for Linux Targets
```bash
# Using gvm-cli to create SSH credential with key-based auth
gvm-cli socket --socketpath /run/gvmd/gvmd.sock --gmp-username admin --gmp-password <password> --xml \
  '<create_credential>
    <name>Linux SSH Key</name>
    <type>usk</type>
    <login>scan_user</login>
    <key>
      <private><![CDATA['"$(cat /home/scan_user/.ssh/id_rsa)"']]></private>
      <phrase>key_passphrase</phrase>
    </key>
  </create_credential>'

# SSH credential with password authentication
gvm-cli socket --socketpath /run/gvmd/gvmd.sock --gmp-username admin --gmp-password <password> --xml \
  '<create_credential>
    <name>Linux SSH Password</name>
    <type>up</type>
    <login>scan_user</login>
    <password>scan_password_here</password>
  </create_credential>'
```

### SMB Credentials for Windows Targets
```bash
# Create SMB credential for Windows authenticated scanning
gvm-cli socket --socketpath /run/gvmd/gvmd.sock --gmp-username admin --gmp-password <password> --xml \
  '<create_credential>
    <name>Windows SMB Cred</name>
    <type>up</type>
    <login>DOMAIN\scan_account</login>
    <password>smb_password_here</password>
  </create_credential>'
```

### ESXi Credentials
```bash
# Create ESXi credential for VMware host scanning
gvm-cli socket --socketpath /run/gvmd/gvmd.sock --gmp-username admin --gmp-password <password> --xml \
  '<create_credential>
    <name>ESXi Root</name>
    <type>up</type>
    <login>root</login>
    <password>esxi_password_here</password>
  </create_credential>'
```

## Creating Scan Targets

```bash
# Create target with SSH credential (Linux hosts)
gvm-cli socket --socketpath /run/gvmd/gvmd.sock --gmp-username admin --gmp-password <password> --xml \
  '<create_target>
    <name>Linux Production Servers</name>
    <hosts>192.168.1.10,192.168.1.11,192.168.1.12</hosts>
    <port_list id="33d0cd82-57c6-11e1-8ed1-406186ea4fc5"/>
    <ssh_credential id="CREDENTIAL_UUID_HERE">
      <port>22</port>
    </ssh_credential>
    <alive_test>ICMP, TCP-ACK Service and ARP Ping</alive_test>
  </create_target>'

# Create target with SMB credential (Windows hosts)
gvm-cli socket --socketpath /run/gvmd/gvmd.sock --gmp-username admin --gmp-password <password> --xml \
  '<create_target>
    <name>Windows Domain Controllers</name>
    <hosts>192.168.1.20,192.168.1.21</hosts>
    <port_list id="33d0cd82-57c6-11e1-8ed1-406186ea4fc5"/>
    <smb_credential id="SMB_CREDENTIAL_UUID_HERE"/>
    <alive_test>ICMP, TCP-ACK Service and ARP Ping</alive_test>
  </create_target>'
```

## Scan Configuration

### Built-in Scan Configs
| Config Name | OID | Use Case |
|------------|-----|----------|
| Full and fast | daba56c8-73ec-11df-a475-002264764cea | Standard production scan |
| Full and deep | 708f25c4-7489-11df-8094-002264764cea | Thorough scan, may be disruptive |
| System Discovery | 8715c877-47a0-438d-98a3-27c7a6ab2196 | Host and service enumeration |

### Create Custom Scan Config for Authenticated Scan
```bash
# Clone "Full and fast" config and customize
gvm-cli socket --socketpath /run/gvmd/gvmd.sock --gmp-username admin --gmp-password <password> --xml \
  '<create_config>
    <copy>daba56c8-73ec-11df-a475-002264764cea</copy>
    <name>Authenticated Full Scan</name>
  </create_config>'
```

## Running the Scan

### Create and Start Scan Task
```bash
# Create scan task
gvm-cli socket --socketpath /run/gvmd/gvmd.sock --gmp-username admin --gmp-password <password> --xml \
  '<create_task>
    <name>Weekly Authenticated Scan - Linux Prod</name>
    <config id="CONFIG_UUID"/>
    <target id="TARGET_UUID"/>
    <scanner id="08b69003-5fc2-4037-a479-93b440211c73"/>
  </create_task>'

# Start the scan task
gvm-cli socket --socketpath /run/gvmd/gvmd.sock --gmp-username admin --gmp-password <password> --xml \
  '<start_task task_id="TASK_UUID"/>'

# Check scan progress
gvm-cli socket --socketpath /run/gvmd/gvmd.sock --gmp-username admin --gmp-password <password> --xml \
  '<get_tasks task_id="TASK_UUID"/>'
```

### Schedule Recurring Scans
```bash
# Create weekly schedule (every Sunday at 2:00 AM UTC)
gvm-cli socket --socketpath /run/gvmd/gvmd.sock --gmp-username admin --gmp-password <password> --xml \
  '<create_schedule>
    <name>Weekly Sunday 2AM</name>
    <icalendar>
BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
DTSTART:20240101T020000Z
RRULE:FREQ=WEEKLY;BYDAY=SU
DURATION:PT12H
END:VEVENT
END:VCALENDAR
    </icalendar>
    <timezone>UTC</timezone>
  </create_schedule>'
```

## Exporting Results

```bash
# Export scan report as XML
gvm-cli socket --socketpath /run/gvmd/gvmd.sock --gmp-username admin --gmp-password <password> --xml \
  '<get_reports report_id="REPORT_UUID" format_id="a994b278-1f62-11e1-96ac-406186ea4fc5"/>'

# Export as CSV
gvm-cli socket --socketpath /run/gvmd/gvmd.sock --gmp-username admin --gmp-password <password> --xml \
  '<get_reports report_id="REPORT_UUID" format_id="c1645568-627a-11e3-a660-406186ea4fc5"/>'

# Use python-gvm for programmatic access
python3 -c "
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform

connection = UnixSocketConnection(path='/run/gvmd/gvmd.sock')
transform = EtreeCheckCommandTransform()
with Gmp(connection=connection, transform=transform) as gmp:
    gmp.authenticate('admin', 'password')
    reports = gmp.get_reports()
    print(f'Total reports: {len(reports)}')
"
```

## Validating Authentication Success

```bash
# Check if credentials were accepted during scan
# In the scan report, look for NVT "Authentication tests" results:
# - OID 1.3.6.1.4.1.25623.1.0.103591 (SSH authentication successful)
# - OID 1.3.6.1.4.1.25623.1.0.90023 (SMB authentication successful)

# Verify via gvm-cli
gvm-cli socket --socketpath /run/gvmd/gvmd.sock --gmp-username admin --gmp-password <password> --xml \
  '<get_results filter="name=SSH rows=10 sort-reverse=severity"/>'
```

## References

- [OpenVAS Official Site](https://www.openvas.org/)
- [Greenbone Community Edition Docs](https://greenbone.github.io/docs/latest/)
- [GVM GitHub Repository](https://github.com/greenbone/openvas-scanner)
- [python-gvm Library](https://github.com/greenbone/python-gvm)
- [GVM Docker Deployment](https://greenbone.github.io/docs/latest/22.4/container/)
