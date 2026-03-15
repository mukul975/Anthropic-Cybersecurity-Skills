---
name: detecting-lateral-movement-in-network
description: >
  Identifies lateral movement techniques in enterprise networks by analyzing
  authentication logs, network flows, SMB traffic, and RDP sessions using Zeek,
  Velociraptor, and SIEM correlation rules to detect attackers moving between systems.
domain: cybersecurity
subdomain: network-security
tags: [network-security, lateral-movement, threat-detection, siem, pass-the-hash]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Detecting Lateral Movement in Network

## When to Use

- Monitoring enterprise networks for post-compromise lateral movement patterns (pass-the-hash, RDP hopping, PSExec)
- Building SIEM detection rules and alerts for common MITRE ATT&CK lateral movement techniques (T1021, T1570)
- Investigating suspected breaches by analyzing authentication patterns and network connections between internal hosts
- Hunting for anomalous east-west traffic patterns that indicate an attacker pivoting through the network
- Validating that network segmentation and access controls effectively limit lateral movement paths

**Do not use** as a substitute for endpoint detection and response (EDR) tools, for monitoring only north-south traffic while ignoring internal traffic flows, or without baseline knowledge of normal internal communication patterns.

## Prerequisites

- Network security monitoring deployed at internal choke points (Zeek, Suricata, or network TAPs)
- SIEM platform (Splunk, Elastic, Microsoft Sentinel) collecting Windows Security Event Logs, DNS, and flow data
- Windows Event Log forwarding configured for Security events (4624, 4625, 4648, 4672, 4768, 4769)
- Baseline of normal internal authentication and connection patterns
- Understanding of MITRE ATT&CK Lateral Movement tactics (TA0008)

## Workflow

### Step 1: Configure Log Collection for Lateral Movement Detection

```bash
# Windows Event Logs to collect (via WEF or agent):
# Security Log:
#   4624 - Successful logon (Type 3=Network, Type 10=RemoteInteractive)
#   4625 - Failed logon
#   4648 - Logon using explicit credentials (RunAs, PsExec)
#   4672 - Special privileges assigned (admin logon)
#   4768 - Kerberos TGT request
#   4769 - Kerberos service ticket request
#   4776 - NTLM authentication (credential validation)
# System Log:
#   7045 - New service installed (PsExec indicator)
#   7036 - Service started/stopped

# Configure Windows Event Forwarding (WEF) subscription
# On the collector server (PowerShell):
# wecutil cs lateral-movement-subscription.xml

# Filebeat configuration for Windows Event Log shipping
cat > /etc/filebeat/modules.d/security.yml << 'EOF'
- module: system
  auth:
    enabled: true
    var.paths: ["/var/log/auth.log"]
  syslog:
    enabled: true

- module: zeek
  connection:
    enabled: true
    var.paths: ["/opt/zeek/logs/current/conn.log"]
  dns:
    enabled: true
    var.paths: ["/opt/zeek/logs/current/dns.log"]
  smb_mapping:
    enabled: true
    var.paths: ["/opt/zeek/logs/current/smb_mapping.log"]
  dce_rpc:
    enabled: true
    var.paths: ["/opt/zeek/logs/current/dce_rpc.log"]
EOF

# Zeek configuration for lateral movement detection
# Enable SMB, DCE-RPC, and Kerberos logging
cat >> /opt/zeek/share/zeek/site/local.zeek << 'EOF'
@load policy/protocols/smb
@load policy/protocols/conn/known-hosts
@load policy/protocols/conn/known-services
@load frameworks/intel/seen
EOF

sudo zeekctl deploy
```

### Step 2: Build Detection Rules for Common Lateral Movement Techniques

```yaml
# Splunk SPL queries for lateral movement detection

# 1. Detect PsExec usage (new service creation on remote hosts)
# index=wineventlog EventCode=7045 ServiceName="PSEXESVC" OR ServiceName="*psexec*"
# | stats count by ComputerName, ServiceName, ImagePath
# | where count > 0

# 2. Detect Pass-the-Hash (Type 3 logon with NTLM)
# index=wineventlog EventCode=4624 LogonType=3 AuthenticationPackageName="NTLM"
# | where TargetUserName!="ANONYMOUS LOGON" AND TargetUserName!="$"
# | stats count dc(ComputerName) as unique_hosts by TargetUserName, IpAddress
# | where unique_hosts > 3

# 3. Detect RDP lateral movement (Type 10 logon from internal IPs)
# index=wineventlog EventCode=4624 LogonType=10
# | where cidrmatch("10.0.0.0/8", IpAddress) OR cidrmatch("192.168.0.0/16", IpAddress)
# | stats count dc(ComputerName) as rdp_hosts by TargetUserName, IpAddress
# | where rdp_hosts > 2

# Elastic SIEM detection rules (KQL)
# event.code: "4624" and winlog.event_data.LogonType: "3"
#   and winlog.event_data.AuthenticationPackageName: "NTLM"
#   and not winlog.event_data.TargetUserName: *$
#   and source.ip: (10.0.0.0/8 or 172.16.0.0/12 or 192.168.0.0/16)
```

```bash
# Sigma rules for lateral movement detection
# Install sigma and convert to target SIEM format
pip3 install sigma-cli

cat > lateral_movement_pth.yml << 'EOF'
title: Pass-the-Hash Lateral Movement Detection
id: f8d98d6c-7a07-4d74-b064-dd4a3c244528
status: experimental
description: Detects network logon with NTLM authentication to multiple hosts
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 3
        AuthenticationPackageName: NTLM
    filter:
        TargetUserName|endswith: '$'
    condition: selection and not filter
    timeframe: 15m
    count:
        field: ComputerName
        min: 3
        group-by: TargetUserName
level: high
tags:
    - attack.lateral_movement
    - attack.t1550.002
EOF

# Convert Sigma rule to Splunk SPL
sigma convert -t splunk lateral_movement_pth.yml

# Convert to Elastic query
sigma convert -t elasticsearch lateral_movement_pth.yml
```

### Step 3: Network-Level Detection with Zeek

```bash
# Detect SMB lateral movement (admin$ and c$ share access)
cat /opt/zeek/logs/current/smb_mapping.log | \
  zeek-cut ts id.orig_h id.resp_h path | \
  grep -iE "(admin\$|c\$|ipc\$)" | \
  sort -t$'\t' -k2 | uniq -c | sort -rn

# Detect hosts connecting to many internal hosts on port 445 (SMB spreading)
cat /opt/zeek/logs/current/conn.log | \
  zeek-cut ts id.orig_h id.resp_h id.resp_p | \
  awk '$4 == 445' | \
  awk '{print $2}' | sort | uniq -c | sort -rn | head -10

# Detect WMI lateral movement (DCE-RPC to IWbemServices)
cat /opt/zeek/logs/current/dce_rpc.log | \
  zeek-cut ts id.orig_h id.resp_h operation | \
  grep -i "wbem\|wmi" | sort | uniq -c | sort -rn

# Detect RDP connections between internal hosts
cat /opt/zeek/logs/current/conn.log | \
  zeek-cut ts id.orig_h id.resp_h id.resp_p duration | \
  awk '$4 == 3389 && $5 > 60' | \
  sort -t$'\t' -k2 | head -20

# Detect Kerberos ticket-granting anomalies
cat /opt/zeek/logs/current/kerberos.log | \
  zeek-cut ts id.orig_h id.resp_h client service success error_msg | \
  grep -v "true" | head -20

# Custom Zeek script for lateral movement detection
sudo tee /opt/zeek/share/zeek/site/custom-detections/lateral-movement.zeek << 'ZEEKEOF'
@load base/frameworks/notice
@load base/frameworks/sumstats

module LateralMovement;

export {
    redef enum Notice::Type += {
        SMB_Lateral_Spread,
        RDP_Lateral_Chain
    };
    const smb_host_threshold: count = 5 &redef;
    const smb_time_window: interval = 15min &redef;
}

event zeek_init()
{
    local r1 = SumStats::Reducer(
        $stream="lateral.smb",
        $apply=set(SumStats::UNIQUE)
    );

    SumStats::create([
        $name="detect-smb-lateral",
        $epoch=smb_time_window,
        $reducers=set(r1),
        $threshold_val(key: SumStats::Key, result: SumStats::Result) = {
            return result["lateral.smb"]$unique + 0.0;
        },
        $threshold=smb_host_threshold + 0.0,
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = {
            NOTICE([
                $note=SMB_Lateral_Spread,
                $msg=fmt("Host %s connected to %d SMB hosts in %s",
                         key$str, result["lateral.smb"]$unique, smb_time_window),
                $identifier=key$str
            ]);
        }
    ]);
}

event connection_state_remove(c: connection)
{
    if ( c$id$resp_p == 445/tcp && c$id$resp_h in Site::local_nets )
    {
        SumStats::observe("lateral.smb",
            [$str=cat(c$id$orig_h)],
            [$str=cat(c$id$resp_h)]
        );
    }
}
ZEEKEOF

sudo zeekctl deploy
```

### Step 4: Threat Hunting for Lateral Movement Indicators

```bash
# Hunt for authentication anomalies in Windows logs
# Splunk query: Users authenticating from unusual source hosts
# index=wineventlog EventCode=4624 LogonType=3
# | stats values(IpAddress) as source_ips dc(IpAddress) as source_count by TargetUserName
# | where source_count > 5
# | sort -source_count

# Hunt for service accounts used interactively
# index=wineventlog EventCode=4624 (LogonType=2 OR LogonType=10)
# | where match(TargetUserName, "^svc-.*")
# | table _time ComputerName TargetUserName IpAddress LogonType

# Network flow analysis for lateral movement patterns
# Look for hosts that suddenly start communicating with many internal hosts
cat /opt/zeek/logs/current/conn.log | \
  zeek-cut ts id.orig_h id.resp_h | \
  awk '{
    key = $2
    targets[key][$3] = 1
  }
  END {
    for (src in targets) {
      count = 0
      for (dst in targets[src]) count++
      if (count > 20) print src, count
    }
  }' | sort -k2 -rn

# Detect credential dumping artifacts (large LSASS reads)
# Look for connections from hosts that suddenly pivot
cat /opt/zeek/logs/current/conn.log | \
  zeek-cut ts id.orig_h id.resp_h id.resp_p orig_bytes | \
  awk '$4 == 445 && $5 > 10000000' | sort -t$'\t' -k5 -rn

# Timeline analysis: map the attack path
# index=wineventlog (EventCode=4624 OR EventCode=7045)
# | eval stage=case(
#     EventCode=4624 AND LogonType=3, "Network Logon",
#     EventCode=4624 AND LogonType=10, "RDP Logon",
#     EventCode=7045, "Service Creation"
#   )
# | timechart span=5m count by stage
```

### Step 5: Automated Response and Containment

```bash
# SOAR playbook for lateral movement response (pseudocode)
# When lateral movement alert triggers:

# 1. Enrich the alert with context
# - Query AD for user group membership and role
# - Check if source IP is a known admin workstation
# - Look up recent vulnerability scan results for affected hosts

# 2. Automated containment actions
# Option A: Isolate the host via switch port shutdown
# ssh admin@switch "conf t; interface Gi1/0/5; shutdown"

# Option B: Quarantine via VLAN change (less disruptive)
# ssh admin@switch "conf t; interface Gi1/0/5; switchport access vlan 999"

# Option C: Block at firewall
sudo iptables -I FORWARD -s 10.10.5.23 -j DROP

# 3. Disable the compromised account
# PowerShell: Disable-ADAccount -Identity compromised_user

# 4. Force password reset
# PowerShell: Set-ADAccountPassword -Identity compromised_user -Reset

# 5. Collect forensic evidence before full containment
# velociraptor artifact collect Windows.KapeFiles.Targets --target BasicCollection
```

### Step 6: Build Detection Dashboard

```bash
# Elastic Kibana dashboard queries for lateral movement monitoring

# Panel 1: Authentication heatmap (source vs destination)
# Aggregation: Terms on source.ip (rows) and destination.ip (columns)
# Metric: Count of event.code:4624

# Panel 2: SMB connections between internal hosts
# Filter: destination.port:445 and source.ip:10.0.0.0/8
# Aggregation: Top 20 source IPs by unique destination count

# Panel 3: RDP sessions timeline
# Filter: destination.port:3389 and event.code:4624 and winlog.event_data.LogonType:10
# Visualization: Timeline by source.ip

# Panel 4: New service installations
# Filter: event.code:7045
# Aggregation: Terms on winlog.event_data.ServiceName

# Panel 5: Failed authentication spike detection
# Filter: event.code:4625
# Aggregation: Date histogram with anomaly detection

# Export Kibana dashboard
# curl -X GET "elastic-siem:5601/api/saved_objects/_export" \
#   -H "kbn-xsrf: true" \
#   -d '{"type":"dashboard","objects":[{"id":"lateral-movement-dashboard","type":"dashboard"}]}' \
#   > lateral_movement_dashboard.ndjson
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Lateral Movement** | MITRE ATT&CK tactic (TA0008) describing techniques attackers use to move through a network from one compromised system to another |
| **Pass-the-Hash (T1550.002)** | Using captured NTLM password hashes to authenticate to remote systems without knowing the plaintext password |
| **PsExec (T1569.002)** | Remote service execution tool that creates a temporary service on the target system, detectable by Event ID 7045 |
| **East-West Traffic** | Network communication between internal systems (as opposed to north-south traffic between internal and external networks) |
| **Authentication Anomaly** | Deviation from baseline authentication patterns such as a user logging into systems they never accessed before |
| **Kerberoasting (T1558.003)** | Requesting Kerberos service tickets for service accounts and cracking them offline, detectable via Event ID 4769 anomalies |

## Tools & Systems

- **Zeek**: Network security monitor generating SMB, Kerberos, DCE-RPC, and connection logs for lateral movement analysis
- **Splunk/Elastic SIEM**: Log aggregation platforms for correlating authentication events, network flows, and service creation across the enterprise
- **Sigma**: Vendor-agnostic detection rule format for writing portable lateral movement detection rules across SIEM platforms
- **Velociraptor**: Endpoint forensics tool for collecting evidence from hosts involved in lateral movement chains
- **BloodHound**: Active Directory attack path analysis tool for identifying potential lateral movement routes before attackers exploit them

## Common Scenarios

### Scenario: Detecting a Ransomware Operator's Lateral Movement

**Context**: The SOC receives an alert for PsExec service creation on a file server (10.10.20.15) at 2:00 AM. The alert triggers a lateral movement investigation. The organization has Zeek network monitoring and Windows Event Log forwarding to Splunk.

**Approach**:
1. Query Splunk for Event ID 7045 (service creation) on 10.10.20.15 to confirm PsExec execution and identify the source IP (10.10.5.23)
2. Trace authentication history for 10.10.5.23: find Event ID 4624 Type 3 logons, discovering the host authenticated to 8 servers in the past hour using NTLM (pass-the-hash pattern)
3. Check Zeek conn.log for 10.10.5.23: identify SMB connections (port 445) to 12 internal hosts and large file transfers to an external IP
4. Build the attack timeline: initial compromise via phishing at 1:15 AM, credential dumping at 1:25 AM, lateral movement to 8 servers between 1:30-2:00 AM
5. Identify all compromised hosts by tracing authentication chains: 10.10.5.23 -> 10.10.20.15 -> 10.10.20.16 -> 10.10.20.17
6. Contain by quarantining all identified hosts to VLAN 999, disabling the compromised account, and blocking the external C2 IP
7. Report the complete attack chain with timeline, affected hosts, and detection gaps

**Pitfalls**:
- Only investigating the single alert instead of tracing the full lateral movement chain across all hosts
- Not checking for persistence mechanisms on each compromised host before declaring containment
- Relying solely on Windows Event Logs without correlating network flow data, missing lateral movement via tools that do not generate Windows events
- Not establishing a baseline of normal internal authentication patterns, making anomaly detection impossible

## Output Format

```
## Lateral Movement Investigation Report

**Case ID**: IR-2024-0312
**Initial Alert**: PsExec on 10.10.20.15 at 02:00 UTC
**Investigation Period**: 2024-03-15 01:00 to 03:00 UTC

### Attack Timeline

| Time (UTC) | Source | Destination | Technique | Evidence |
|------------|--------|-------------|-----------|----------|
| 01:15 | External | 10.10.5.23 | Initial Access (Phishing) | Email log + HTTP download |
| 01:25 | 10.10.5.23 | Local | Credential Dumping | LSASS access (Sysmon EID 10) |
| 01:32 | 10.10.5.23 | 10.10.20.15 | Pass-the-Hash (SMB) | EID 4624 Type 3 NTLM |
| 01:38 | 10.10.5.23 | 10.10.20.16 | PsExec | EID 7045 + Zeek SMB |
| 01:45 | 10.10.20.16 | 10.10.20.17 | RDP | EID 4624 Type 10 |
| 02:00 | 10.10.20.17 | 10.10.20.15 | PsExec (triggered alert) | EID 7045 |
| 02:10 | 10.10.5.23 | 203.0.113.50 | Data Exfiltration | Zeek conn.log 2.3 GB |

### Affected Systems
- 10.10.5.23 (workstation-045) - Initial compromise
- 10.10.20.15 (file-server-01) - Data accessed
- 10.10.20.16 (app-server-02) - Pivoted through
- 10.10.20.17 (db-server-01) - Final target

### Detection Gaps
1. Initial phishing email not blocked by email gateway
2. Credential dumping not detected (no LSASS monitoring)
3. 30-minute gap between first lateral movement and alert
```
