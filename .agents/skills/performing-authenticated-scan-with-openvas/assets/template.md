# OpenVAS Authenticated Scan - Configuration Template

## Scan Service Account Requirements

### Linux SSH Scan Account
```bash
# Create dedicated scan user on target hosts
sudo useradd -r -s /bin/bash -m -c "OpenVAS Scan Account" openvas_scan
sudo usermod -aG sudo openvas_scan  # Or grant specific sudoers entries

# Minimal sudoers entry for authenticated scanning
# /etc/sudoers.d/openvas_scan
openvas_scan ALL=(ALL) NOPASSWD: /usr/bin/dpkg -l
openvas_scan ALL=(ALL) NOPASSWD: /usr/bin/rpm -qa
openvas_scan ALL=(ALL) NOPASSWD: /bin/cat /etc/shadow
openvas_scan ALL=(ALL) NOPASSWD: /usr/sbin/dmidecode
openvas_scan ALL=(ALL) NOPASSWD: /sbin/ip addr
```

### Windows SMB Scan Account
```
Domain: CORP
Account: svc_openvas_scan
Groups: Domain Users, Local Administrators (on targets)
Password Policy: 32+ character randomly generated
Account Type: Service account (no interactive login)
Logon Hours: Restricted to scan window (e.g., Sunday 2-6 AM)
```

## Target Group Definitions

| Target Group | Hosts | Credential Type | Scan Schedule |
|-------------|-------|----------------|---------------|
| Linux Production | 10.1.0.0/24 | SSH Key | Weekly Sunday 2 AM |
| Linux Development | 10.2.0.0/24 | SSH Key | Monthly 1st Sunday |
| Windows Servers | 10.1.1.0/24 | SMB Domain | Weekly Sunday 3 AM |
| Windows Workstations | 10.3.0.0/16 | SMB Domain | Monthly 1st Sunday |
| ESXi Hosts | 10.1.2.10-20 | ESXi Root | Monthly 1st Sunday |

## Scan Configuration Selection Guide

| Scenario | Recommended Config | Max Concurrent NVTs | Notes |
|----------|-------------------|--------------------|----|
| Production (low impact) | Full and fast | 4 | Safe checks only |
| Staging/QA | Full and deep | 10 | May trigger IDS alerts |
| PCI Compliance | Full and fast + PCI NVTs | 4 | Map findings to PCI requirements |
| Post-Patch Validation | System Discovery + targeted | 20 | Quick verification scan |

## Pre-Scan Checklist

- [ ] Feed synchronization completed within last 24 hours
- [ ] Scan credentials tested and verified on sample hosts
- [ ] Change management ticket approved for scan window
- [ ] IDS/IPS exceptions configured for scanner IP
- [ ] Notification sent to system owners about scan window
- [ ] Previous scan results archived
- [ ] Sufficient disk space for report storage (>10GB)
- [ ] Scanner system health verified (CPU, memory, disk)
