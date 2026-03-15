---
name: configuring-host-based-intrusion-detection
description: >
  Configures host-based intrusion detection systems (HIDS) to monitor endpoint file integrity,
  system calls, and configuration changes for security violations. Use when deploying OSSEC,
  Wazuh, or AIDE for endpoint monitoring, building file integrity monitoring (FIM) policies, or
  meeting compliance requirements for change detection. Activates for requests involving HIDS
  configuration, file integrity monitoring, OSSEC/Wazuh deployment, or host-based detection.
domain: cybersecurity
subdomain: endpoint-security
tags: [endpoint, HIDS, Wazuh, OSSEC, file-integrity-monitoring, intrusion-detection]
version: 1.0.0
author: mahipal
license: Apache-2.0
---
# Configuring Host-Based Intrusion Detection

## When to Use

Use this skill when:
- Deploying HIDS agents (Wazuh, OSSEC, AIDE) across Windows and Linux endpoints
- Configuring file integrity monitoring (FIM) for compliance (PCI DSS 11.5, NIST SI-7)
- Monitoring system configuration changes, rootkit detection, and security policy violations
- Integrating HIDS alerts with SIEM platforms for centralized monitoring

**Do not use** this skill for network-based IDS (Suricata, Snort) or for EDR deployment.

## Prerequisites

- Wazuh server (manager) deployed and accessible from endpoints
- Administrative access to target endpoints
- Network connectivity: agents to Wazuh manager on port 1514 (TCP/UDP) and 1515 (TCP enrollment)
- Wazuh dashboard (OpenSearch Dashboards) for alert visualization
- Understanding of critical files/directories to monitor per OS

## Workflow

### Step 1: Install Wazuh Agent

**Windows**:
```powershell
# Download and install Wazuh agent
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.0-1.msi" `
  -OutFile "wazuh-agent.msi"
msiexec /i wazuh-agent.msi /q WAZUH_MANAGER="wazuh-manager.corp.com" `
  WAZUH_REGISTRATION_SERVER="wazuh-manager.corp.com" WAZUH_AGENT_GROUP="windows-workstations"
net start WazuhSvc
```

**Linux (Debian/Ubuntu)**:
```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  > /etc/apt/sources.list.d/wazuh.list
apt-get update && apt-get install wazuh-agent -y
sed -i 's/MANAGER_IP/wazuh-manager.corp.com/' /var/ossec/etc/ossec.conf
systemctl daemon-reload && systemctl enable --now wazuh-agent
```

### Step 2: Configure File Integrity Monitoring (FIM)

Edit agent configuration (`/var/ossec/etc/ossec.conf` or `C:\Program Files (x86)\ossec-agent\ossec.conf`):

```xml
<syscheck>
  <!-- Scan frequency: every 12 hours -->
  <frequency>43200</frequency>
  <scan_on_start>yes</scan_on_start>
  <alert_new_files>yes</alert_new_files>

  <!-- Linux critical directories -->
  <directories check_all="yes" realtime="yes">/etc</directories>
  <directories check_all="yes" realtime="yes">/usr/bin</directories>
  <directories check_all="yes" realtime="yes">/usr/sbin</directories>
  <directories check_all="yes" realtime="yes">/bin</directories>
  <directories check_all="yes" realtime="yes">/sbin</directories>
  <directories check_all="yes">/boot</directories>

  <!-- Windows critical directories -->
  <directories check_all="yes" realtime="yes">C:\Windows\System32</directories>
  <directories check_all="yes" realtime="yes">C:\Windows\SysWOW64</directories>
  <directories check_all="yes" realtime="yes">%PROGRAMFILES%</directories>

  <!-- Windows registry monitoring -->
  <windows_registry>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run</windows_registry>
  <windows_registry>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce</windows_registry>
  <windows_registry>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services</windows_registry>

  <!-- Ignore frequently changing files -->
  <ignore>/etc/mtab</ignore>
  <ignore>/etc/resolv.conf</ignore>
  <ignore type="sregex">.log$</ignore>
</syscheck>
```

### Step 3: Configure Rootkit Detection

```xml
<rootcheck>
  <disabled>no</disabled>
  <frequency>43200</frequency>
  <rootkit_files>/var/ossec/etc/shared/rootkit_files.txt</rootkit_files>
  <rootkit_trojans>/var/ossec/etc/shared/rootkit_trojans.txt</rootkit_trojans>
  <system_audit>/var/ossec/etc/shared/system_audit_rcl.txt</system_audit>
  <check_dev>yes</check_dev>
  <check_files>yes</check_files>
  <check_if>yes</check_if>
  <check_pids>yes</check_pids>
  <check_ports>yes</check_ports>
  <check_sys>yes</check_sys>
  <check_trojans>yes</check_trojans>
  <check_unixaudit>yes</check_unixaudit>
</rootcheck>
```

### Step 4: Configure Log Analysis Rules

```xml
<!-- Custom rules in /var/ossec/etc/rules/local_rules.xml -->
<group name="local,syscheck,">
  <!-- Alert on critical binary modifications -->
  <rule id="100001" level="12">
    <if_sid>550</if_sid>
    <match>/usr/bin/|/usr/sbin/|/bin/|/sbin/</match>
    <description>Critical system binary modified: $(file)</description>
    <group>syscheck,pci_dss_11.5,</group>
  </rule>

  <!-- Alert on new executable in temp directories -->
  <rule id="100002" level="10">
    <if_sid>554</if_sid>
    <match>/tmp/|/var/tmp/</match>
    <description>New file created in temp directory: $(file)</description>
    <group>syscheck,malware,</group>
  </rule>

  <!-- Alert on SSH configuration changes -->
  <rule id="100003" level="10">
    <if_sid>550</if_sid>
    <match>/etc/ssh/sshd_config</match>
    <description>SSH configuration modified</description>
    <group>syscheck,authentication,</group>
  </rule>
</group>
```

### Step 5: Configure Active Response

```xml
<!-- Auto-block IP after repeated authentication failures -->
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>5712</rules_id>
  <timeout>600</timeout>
</active-response>

<!-- Disable account after brute force detection -->
<active-response>
  <disabled>no</disabled>
  <command>disable-account</command>
  <location>local</location>
  <rules_id>100100</rules_id>
  <timeout>3600</timeout>
</active-response>
```

### Step 6: Integrate with SIEM

```
# Wazuh to Splunk via Filebeat
# Edit /etc/filebeat/filebeat.yml:
filebeat.inputs:
  - type: log
    paths:
      - /var/ossec/logs/alerts/alerts.json
    json.keys_under_root: true
output.elasticsearch:
  hosts: ["https://splunk-hec:8088"]

# Wazuh to Elastic via direct integration
# Wazuh indexer feeds directly into OpenSearch/Elasticsearch
# Dashboard: https://wazuh-dashboard:5601
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **HIDS** | Host-based Intrusion Detection System; monitors individual endpoints for malicious activity |
| **FIM** | File Integrity Monitoring; detects unauthorized changes to files by comparing cryptographic hashes |
| **Syscheck** | Wazuh/OSSEC module for file integrity monitoring and registry monitoring |
| **Rootcheck** | Wazuh/OSSEC module for rootkit and malware detection |
| **Active Response** | Automated defensive action triggered by HIDS alert (IP block, account disable) |
| **CDB List** | Constant Database list used for custom lookups in Wazuh rules |

## Tools & Systems

- **Wazuh**: Open-source HIDS platform (fork of OSSEC) with manager, agent, and dashboard
- **OSSEC**: Original open-source HIDS (predecessor to Wazuh)
- **AIDE (Advanced Intrusion Detection Environment)**: Standalone file integrity checker for Linux
- **Tripwire**: Commercial file integrity monitoring solution
- **Samhain**: Open-source HIDS focused on file integrity and log monitoring

## Common Pitfalls

- **Monitoring too many directories**: FIM on entire filesystems generates excessive alerts. Focus on critical system binaries, configuration files, and web roots.
- **Not excluding noisy files**: Frequently changing files (logs, temp, caches) generate false positive FIM alerts. Maintain exclusion lists.
- **Ignoring baseline establishment**: First FIM scan creates a baseline. Changes detected before baseline stabilization are noise, not threats. Allow 48 hours for baseline.
- **Active response without testing**: Auto-blocking IPs or disabling accounts can cause outages. Test active response rules in a non-production environment first.
- **Agent enrollment failures**: Agents must successfully enroll with the manager before monitoring begins. Verify firewall rules allow port 1514 and 1515 traffic.
