---
name: containing-active-security-breach
description: Rapidly contain an active security breach by isolating compromised systems, blocking attacker communications, and preserving evidence while minimizing business disruption.
domain: cybersecurity
subdomain: incident-response
tags: [incident-response, containment, breach-response, network-isolation, dfir]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Containing an Active Security Breach

## When to Use
- Active unauthorized access detected on network or systems
- IDS/IPS alerts indicate ongoing exploitation or data exfiltration
- SOC analysts confirm a true positive security incident requiring immediate containment
- Lateral movement or privilege escalation observed in real time
- Ransomware encryption activity detected before full deployment

## Prerequisites
- Incident Response Plan with defined containment procedures
- Network access to firewalls, switches, and endpoint management consoles
- EDR/XDR platform deployed across endpoints (CrowdStrike, SentinelOne, Microsoft Defender for Endpoint)
- SIEM access with real-time log correlation (Splunk, Elastic, QRadar)
- Pre-approved authority to isolate systems (documented in IR plan)
- Forensic imaging tools ready for evidence preservation

## Workflow

### Step 1: Validate and Classify the Incident
```bash
# Check SIEM for correlated alerts - Splunk example
index=security sourcetype=ids_alerts severity=critical
| stats count by src_ip, dest_ip, signature
| where count > 5
| sort -count

# Verify endpoint alerts via CrowdStrike Falcon API
curl -X GET "https://api.crowdstrike.com/detects/queries/detects/v1?filter=status:'new'+max_severity_displayname:'Critical'" \
  -H "Authorization: Bearer $FALCON_TOKEN"
```

### Step 2: Identify Scope of Compromise
```bash
# Identify all systems communicating with attacker C2
# Using Zeek connection logs
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p duration orig_bytes resp_bytes \
  | awk '$3 == 443 && $5 > 1000000' | sort -t$'\t' -k5 -rn | head -20

# Check for lateral movement in Windows Event Logs
wevtutil qe Security /q:"*[System[(EventID=4624)] and EventData[Data[@Name='LogonType']='3']]" /f:text /c:50

# Query Active Directory for recent authentication anomalies
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625} -MaxEvents 100 |
  Group-Object -Property {$_.Properties[5].Value} | Sort-Object Count -Descending
```

### Step 3: Execute Network Containment
```bash
# Block attacker IP at perimeter firewall (Palo Alto example)
set cli pager off
configure
set rulebase security rules emergency-block from any to any source [attacker_ip] action deny
set rulebase security rules emergency-block from any to any destination [attacker_ip] action deny
commit force

# Isolate compromised VLAN at switch level (Cisco)
configure terminal
interface vlan 100
  shutdown
end
write memory

# Block C2 domains at DNS level
# Add to DNS sinkhole or RPZ
echo "attacker-c2-domain.com CNAME ." >> /etc/bind/rpz.local
rndc reload
```

### Step 4: Isolate Compromised Endpoints
```bash
# CrowdStrike - Network contain host via API
curl -X POST "https://api.crowdstrike.com/devices/entities/devices-actions/v2?action_name=contain" \
  -H "Authorization: Bearer $FALCON_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ids": ["device_id_1", "device_id_2"]}'

# Microsoft Defender for Endpoint - Isolate machine
curl -X POST "https://api.securitycenter.microsoft.com/api/machines/{machineId}/isolate" \
  -H "Authorization: Bearer $MDE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"Comment": "IR-2024-001: Active breach containment", "IsolationType": "Full"}'

# SentinelOne - Disconnect from network
curl -X POST "https://usea1.sentinelone.net/web/api/v2.1/agents/actions/disconnect" \
  -H "Authorization: ApiToken $S1_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"filter": {"ids": ["agent_id"]}, "data": {}}'
```

### Step 5: Preserve Volatile Evidence Before Full Isolation
```bash
# Capture live memory from compromised Windows host
winpmem_mini_x64.exe memdump_hostname_$(date +%Y%m%d).raw

# Capture network connections and running processes
netstat -anob > netstat_capture_$(date +%Y%m%d_%H%M).txt
tasklist /V /FO CSV > process_list_$(date +%Y%m%d_%H%M).csv
wmic process list full > process_detail_$(date +%Y%m%d_%H%M).txt

# Linux volatile evidence collection
dd if=/proc/kcore of=/mnt/forensics/memory_$(hostname)_$(date +%Y%m%d).raw bs=1M
ss -tulnp > /mnt/forensics/network_$(hostname).txt
ps auxwwf > /mnt/forensics/processes_$(hostname).txt
```

### Step 6: Disable Compromised Accounts
```bash
# Disable compromised Active Directory accounts
Import-Module ActiveDirectory
Disable-ADAccount -Identity "compromised_user"
Set-ADUser -Identity "compromised_user" -Description "Disabled - IR-2024-001 $(Get-Date)"

# Revoke all active sessions
Revoke-AzureADUserAllRefreshToken -ObjectId "user_object_id"

# Reset service account credentials
Set-ADAccountPassword -Identity "svc_compromised" -Reset -NewPassword (ConvertTo-SecureString "TempP@ss$(Get-Random)" -AsPlainText -Force)
```

### Step 7: Validate Containment Effectiveness
```bash
# Verify no active C2 communications
tcpdump -i eth0 host attacker_ip -c 100 -w verification_capture.pcap

# Check for new lateral movement attempts
index=security sourcetype=wineventlog EventCode=4624 LogonType=3
  earliest=-15m
| stats count by src_ip, dest_ip
| where src_ip IN ("compromised_hosts")

# Validate endpoint isolation status
curl -X GET "https://api.crowdstrike.com/devices/entities/devices/v2?ids=device_id" \
  -H "Authorization: Bearer $FALCON_TOKEN" | jq '.resources[].status'
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| Short-term Containment | Immediate actions to stop active damage (network isolation, account disable) |
| Long-term Containment | Sustainable measures while investigation continues (VLAN segmentation, enhanced monitoring) |
| Evidence Preservation | Capturing volatile data before containment actions destroy forensic artifacts |
| Blast Radius | Total scope of systems, accounts, and data affected by the breach |
| Containment Boundary | Network and logical perimeter established to prevent further spread |
| Kill Chain Disruption | Breaking the attacker's operational chain at the earliest possible stage |
| Business Continuity | Maintaining critical operations while containing the threat |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| CrowdStrike Falcon | Endpoint detection, network containment of hosts |
| Microsoft Defender for Endpoint | Endpoint isolation and automated investigation |
| Palo Alto NGFW | Perimeter firewall rules for IP/domain blocking |
| Splunk/Elastic SIEM | Real-time alert correlation and scope analysis |
| Zeek (Bro) | Network traffic analysis for C2 identification |
| Velociraptor | Remote forensic collection and endpoint querying |
| Active Directory | Account management and authentication control |

## Common Scenarios

1. **Ransomware Pre-Encryption**: Attacker has deployed ransomware binary but encryption hasn't started. Isolate patient zero, block C2, and prevent lateral deployment.
2. **Active Data Exfiltration**: Data is being exfiltrated to external server. Block egress to C2, capture network evidence, isolate affected systems.
3. **Compromised Domain Controller**: Attacker has DC access. Isolate DC from network, reset KRBTGT twice, rotate all privileged credentials.
4. **Supply Chain Compromise**: Malicious update deployed across environment. Block update server, isolate systems that received the update, assess scope.
5. **Insider Threat - Active Exfil**: Employee actively copying sensitive data. Disable account, block USB access, preserve evidence chain.

## Output Format
- Containment action log with timestamps (who, what, when)
- Network isolation verification report
- List of compromised/isolated systems with justification
- Evidence preservation checksums and chain of custody records
- Containment effectiveness validation results
- Stakeholder notification with current status and next steps
