---
name: implementing-patch-management-workflow
description: Patch management is the systematic process of identifying, testing, deploying, and verifying software updates to remediate vulnerabilities across an organization's IT infrastructure. An effective patc
domain: cybersecurity
subdomain: vulnerability-management
tags: [vulnerability-management, patch-management, wsus, sccm, ansible, risk]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Implementing Patch Management Workflow

## Overview
Patch management is the systematic process of identifying, testing, deploying, and verifying software updates to remediate vulnerabilities across an organization's IT infrastructure. An effective patch management workflow reduces the attack surface while minimizing operational disruption through structured testing, approval gates, and phased rollouts.

## Prerequisites
- Vulnerability scan results identifying missing patches
- Patch management tools (WSUS, SCCM/MECM, Ansible, Intune, Jamf)
- Test environment mirroring production
- Change management process (ITIL or equivalent)
- Asset inventory with OS and application versions

## Core Concepts

### Patch Lifecycle Phases
1. **Discovery**: Identify available patches from vendors and vulnerability scans
2. **Assessment**: Evaluate patch applicability and risk
3. **Prioritization**: Rank patches by severity, exploitability, and asset criticality
4. **Testing**: Validate patches in non-production environment
5. **Approval**: Change advisory board (CAB) review and approval
6. **Deployment**: Phased rollout to production systems
7. **Verification**: Confirm successful installation and no regressions
8. **Reporting**: Document compliance metrics and exceptions

### Patch Categories
- **Security Patches**: Address CVEs and security vulnerabilities
- **Critical Updates**: Non-security bug fixes affecting stability
- **Service Packs**: Cumulative update collections
- **Feature Updates**: New functionality (Windows feature updates, etc.)
- **Firmware Updates**: BIOS/UEFI, NIC, storage controller firmware
- **Third-Party Patches**: Adobe, Java, Chrome, Firefox, etc.

### Deployment Rings (Phased Rollout)
| Ring | Environment | % of Fleet | Soak Time | Purpose |
|------|------------|------------|-----------|---------|
| Ring 0 | Lab/Test | N/A | 24-48 hrs | Functional validation |
| Ring 1 | IT Early Adopters | 5% | 48-72 hrs | Real-world pilot |
| Ring 2 | Business Pilot | 15% | 5-7 days | Broader compatibility |
| Ring 3 | General Deployment | 50% | 7-14 days | Main rollout |
| Ring 4 | Mission Critical | 30% | After Ring 3 | Final deployment |

## Implementation Steps

### Step 1: Configure Patch Sources

```bash
# WSUS (Windows Server Update Services)
# Configure WSUS server to sync with Microsoft Update
# Via PowerShell on WSUS server:
Install-WindowsFeature -Name UpdateServices -IncludeManagementTools
& "C:\Program Files\Update Services\Tools\WsusUtil.exe" postinstall CONTENT_DIR=D:\WSUS

# Configure GPO for WSUS clients
# Computer Configuration > Administrative Templates > Windows Components > Windows Update
# Specify intranet Microsoft update service location: http://wsus-server:8530
```

```yaml
# Ansible: Configure patch repositories for Linux
# roles/patch-management/tasks/configure_repos.yml
---
- name: Configure RHEL patch repository
  yum_repository:
    name: rhel-patches
    description: RHEL Security Patches
    baseurl: https://satellite.corp.local/pulp/repos/patches
    gpgcheck: yes
    gpgkey: file:///etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release
    enabled: yes

- name: Configure Ubuntu patch sources
  apt_repository:
    repo: "deb https://apt-mirror.corp.local/ubuntu {{ ansible_distribution_release }}-security main"
    state: present
  when: ansible_os_family == "Debian"
```

### Step 2: Automated Patch Assessment

```python
# patch_assessment.py - Correlate vulnerability scans with available patches
import subprocess
import platform
import json

def get_windows_pending_patches():
    """Query Windows Update for pending patches via PowerShell."""
    ps_cmd = """
    $Session = New-Object -ComObject Microsoft.Update.Session
    $Searcher = $Session.CreateUpdateSearcher()
    $Results = $Searcher.Search("IsInstalled=0 AND Type='Software'")
    $Results.Updates | ForEach-Object {
        [PSCustomObject]@{
            Title = $_.Title
            KB = ($_.KBArticleIDs -join ',')
            Severity = $_.MsrcSeverity
            Size = [math]::Round($_.MaxDownloadSize / 1MB, 2)
            Published = $_.LastDeploymentChangeTime.ToString('yyyy-MM-dd')
            CVE = ($_.CveIDs -join ',')
        }
    } | ConvertTo-Json
    """
    result = subprocess.run(
        ["powershell", "-Command", ps_cmd],
        capture_output=True, text=True, timeout=120
    )
    return json.loads(result.stdout) if result.stdout.strip() else []

def get_linux_pending_patches():
    """Query package manager for available security updates."""
    if platform.system() != "Linux":
        return []

    # Try apt (Debian/Ubuntu)
    try:
        result = subprocess.run(
            ["apt", "list", "--upgradable"],
            capture_output=True, text=True, timeout=60
        )
        packages = []
        for line in result.stdout.strip().split("\n")[1:]:
            if line:
                parts = line.split("/")
                packages.append({
                    "package": parts[0],
                    "available_version": parts[1].split()[0] if len(parts) > 1 else "",
                    "source": "apt"
                })
        return packages
    except FileNotFoundError:
        pass

    # Try yum/dnf (RHEL/CentOS)
    try:
        result = subprocess.run(
            ["dnf", "updateinfo", "list", "security", "--available"],
            capture_output=True, text=True, timeout=60
        )
        packages = []
        for line in result.stdout.strip().split("\n"):
            parts = line.split()
            if len(parts) >= 3:
                packages.append({
                    "advisory": parts[0],
                    "severity": parts[1],
                    "package": parts[2],
                    "source": "dnf"
                })
        return packages
    except FileNotFoundError:
        return []
```

### Step 3: Patch Testing Automation

```yaml
# Ansible playbook: test_patches.yml
---
- name: Test Patches in Lab Environment
  hosts: test_servers
  become: yes
  vars:
    rollback_snapshot: "pre-patch-{{ ansible_date_time.date }}"

  tasks:
    - name: Create VM snapshot before patching
      community.vmware.vmware_guest_snapshot:
        hostname: "{{ vcenter_host }}"
        username: "{{ vcenter_user }}"
        password: "{{ vcenter_pass }}"
        datacenter: "{{ datacenter }}"
        name: "{{ inventory_hostname }}"
        snapshot_name: "{{ rollback_snapshot }}"
        state: present
      delegate_to: localhost

    - name: Apply security patches (RHEL/CentOS)
      dnf:
        name: "*"
        state: latest
        security: yes
        update_cache: yes
      when: ansible_os_family == "RedHat"
      register: patch_result

    - name: Apply security patches (Ubuntu/Debian)
      apt:
        upgrade: dist
        update_cache: yes
        only_upgrade: yes
      when: ansible_os_family == "Debian"
      register: patch_result

    - name: Reboot if required
      reboot:
        reboot_timeout: 600
        msg: "Rebooting for patch installation"
      when: patch_result.changed

    - name: Run post-patch validation
      include_tasks: validate_services.yml

    - name: Report patch results
      debug:
        msg: "Patching {{ 'succeeded' if patch_result.changed else 'no updates' }} on {{ inventory_hostname }}"
```

### Step 4: Production Deployment

```yaml
# deploy_patches.yml - Phased production rollout
---
- name: Ring 1 - IT Early Adopters
  hosts: ring1_hosts
  serial: "25%"
  max_fail_percentage: 10
  become: yes
  tasks:
    - import_tasks: apply_patches.yml
    - import_tasks: validate_services.yml
    - name: Wait for soak period
      pause:
        hours: 48
      run_once: true

- name: Ring 2 - Business Pilot
  hosts: ring2_hosts
  serial: "20%"
  max_fail_percentage: 5
  become: yes
  tasks:
    - import_tasks: apply_patches.yml
    - import_tasks: validate_services.yml

- name: Ring 3 - General Deployment
  hosts: ring3_hosts
  serial: "10%"
  max_fail_percentage: 3
  become: yes
  tasks:
    - import_tasks: apply_patches.yml
    - import_tasks: validate_services.yml
```

### Step 5: Verification and Reporting

Run a post-patch vulnerability scan to confirm patch installation:
```bash
# Trigger post-patch verification scan
curl -k -X POST "https://nessus:8834/scans/$VERIFY_SCAN_ID/launch" \
  -H "X-Cookie: token=$TOKEN"

# Compare pre-patch and post-patch results
# Expecting reduction in vulnerabilities matching deployed patches
```

## Patch Management SLAs
| Severity | SLA (Internet-Facing) | SLA (Internal) | SLA (Air-Gapped) |
|----------|----------------------|----------------|-------------------|
| Critical (CVSS 9+) | 48 hours | 7 days | 14 days |
| High (CVSS 7-8.9) | 7 days | 14 days | 30 days |
| Medium (CVSS 4-6.9) | 30 days | 30 days | 60 days |
| Low (CVSS 0.1-3.9) | 90 days | 90 days | 90 days |

## Best Practices
1. Maintain current asset inventory to ensure complete patch coverage
2. Test all patches in a non-production environment before deployment
3. Use phased rollouts with automatic rollback capabilities
4. Coordinate patch windows with change management process
5. Track patch compliance metrics and report to leadership
6. Automate where possible to reduce manual effort and human error
7. Maintain exception documentation for systems that cannot be patched
8. Include third-party application patching (not just OS patches)

## Common Pitfalls
- Patching only operating systems and ignoring third-party applications
- No rollback plan if patches cause service disruption
- Treating all patches with equal urgency (no risk-based prioritization)
- Manual patch processes that cannot scale
- No post-patch verification to confirm successful installation
- Ignoring firmware and BIOS updates

## Related Skills
- prioritizing-vulnerabilities-with-cvss-scoring
- implementing-vulnerability-remediation-sla
- implementing-continuous-vulnerability-monitoring
