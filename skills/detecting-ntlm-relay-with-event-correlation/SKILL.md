---
name: detecting-ntlm-relay-with-event-correlation
description: Detect NTLM relay attacks (T1557.001) by correlating Windows Event 4624 LogonType 3 for IP-to-hostname mismatches, identifying Responder/LLMNR poisoning artifacts, auditing SMB/LDAP signing, and flagging NTLMv2-to-NTLMv1 downgrades across Splunk SPL, Sentinel KQL, Sigma rules, and PowerShell audits. Use when building multi-platform SIEM correlation rules and dashboards for credential relay in NTLM-enabled AD or responding to PetitPotam/DFSCoerce/PrinterBug alerts. Do not use for the lightweight Python-script hunt emitting a JSON relay report - use hunting-for-ntlm-relay-attacks.
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- NTLM-relay
- event-correlation
- T1557.001
- Event-4624
- Responder
- SMB-signing
- LDAP-signing
- NTLM-downgrade
- PetitPotam
- Active-Directory
version: '1.0'
author: mukul975
license: Apache-2.0
atlas_techniques:
- AML.T0051
- AML.T0054
- AML.T0056
- AML.T0020
d3fend_techniques:
- Application Protocol Command Analysis
- Network Isolation
- Network Traffic Analysis
- Client-server Payload Profiling
- Network Traffic Community Deviation
nist_ai_rmf:
- MEASURE-2.7
- MEASURE-2.5
- GOVERN-6.1
- MAP-5.1
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
mitre_attack:
- T1046
- T1057
- T1082
- T1083
- T1069
---

# Detecting NTLM Relay with Event Correlation

> **Authorized Testing Disclaimer**: The offensive techniques and attack simulations described in this skill are intended exclusively for authorized penetration testing, red team engagements, purple team exercises, and security research conducted with explicit written permission from the system owner. Unauthorized use of these techniques against systems you do not own or have permission to test is illegal and unethical. Always operate within the scope of your engagement and comply with applicable laws and regulations.

## Overview

NTLM relay attacks intercept NTLM authentication messages and forward them to a target service to gain unauthorized access. Attackers use tools like Responder for LLMNR/NBT-NS/mDNS poisoning, ntlmrelayx (Fox-IT/Impacket) for multi-protocol relay, and coercion techniques like PetitPotam (MS-EFSRPC) and DFSCoerce to force authentication from high-value targets like domain controllers. This skill provides a comprehensive event correlation framework using Windows Security Event 4624 LogonType 3 analysis, IP-to-hostname mismatch detection, Responder traffic identification, SMB/LDAP signing audit, and NTLM downgrade detection to identify relay attacks across Active Directory environments.

## When to Use

- Hunting for credential relay activity in Active Directory environments where NTLM authentication is still in use
- Investigating alerts for authentication anomalies where the source IP does not match the expected workstation
- Auditing SMB signing and LDAP signing enforcement to assess exposure to relay attacks
- Detecting NTLM downgrade attacks where NTLMv2 is forced to NTLMv1 for easier offline cracking or relay
- Building SIEM correlation rules for MITRE ATT&CK T1557.001 (LLMNR/NBT-NS Poisoning and SMB Relay)
- Responding to PetitPotam, DFSCoerce, or PrinterBug coercion alerts that may precede relay attacks
- During purple team exercises validating NTLM relay detection and SMB signing enforcement

**Do not use** without centralized Windows Security Event Log collection, as a substitute for enforcing SMB signing and Extended Protection for Authentication (EPA) which prevent relay attacks at the protocol level, or without an IP-to-hostname inventory for correlation.

## Prerequisites

- Windows Advanced Audit Policy configured to capture Event IDs 4624, 4625, 4648, 4776, and 8004
- Centralized log collection via Windows Event Forwarding (WEF) or agent-based shipping to SIEM
- SIEM platform (Splunk, Elastic, Microsoft Sentinel) with correlation and alerting capability
- IP address to hostname mapping inventory (DHCP logs, DNS records, or CMDB)
- Network monitoring for LLMNR (UDP 5355), NBT-NS (UDP 137), and mDNS (UDP 5353) traffic
- Understanding of MITRE ATT&CK T1557.001 and T1187 (Forced Authentication)

## Workflow

### Step 1: Understand NTLM Relay Attack Flow

The NTLM relay attack follows a three-phase pattern: coercion/poisoning, interception, and relay.

**Phase 1 -- Coercion or Poisoning**: The attacker forces or tricks a victim into initiating NTLM authentication. Methods include LLMNR/NBT-NS poisoning (Responder), PetitPotam (MS-EFSRPC abuse), PrinterBug (SpoolService), and DFSCoerce.

**Phase 2 -- Interception**: The attacker captures the NTLM Type 1 (Negotiate) and Type 3 (Authenticate) messages from the victim.

**Phase 3 -- Relay**: The attacker forwards the captured NTLM messages to a target service (SMB, LDAP, HTTP, MSSQL) to authenticate as the victim. This succeeds only when message signing is not enforced.

```
Victim ──NTLM Negotiate──> Attacker ──NTLM Negotiate──> Target
Victim <──NTLM Challenge── Attacker <──NTLM Challenge── Target
Victim ──NTLM Authenticate──> Attacker ──NTLM Authenticate──> Target
                                                         ↓
                                              Attacker authenticated
                                              as Victim on Target
```

**Key Detection Insight**: In a relay attack, Event 4624 on the target will show the victim's username but the attacker's IP address. The WorkstationName field may still reflect the victim's machine. This IP-to-hostname mismatch is the primary detection signal.

### Step 2: Event 4624 LogonType 3 Analysis for Relay Detection

```spl
# Splunk: Detect IP-to-Hostname Mismatches in Network Logons
# Core NTLM relay detection -- correlates WorkstationName with IpAddress

index=wineventlog EventCode=4624 LogonType=3
    AuthenticationPackageName="NTLM" LmPackageName="NTLM V2"
| where TargetUserName != "ANONYMOUS LOGON"
    AND TargetUserName != "-"
    AND NOT match(TargetUserName, ".*\\$$")
| eval workstation_lower=lower(WorkstationName)
| lookup dns_inventory.csv hostname AS workstation_lower OUTPUT expected_ip
| where isnotnull(expected_ip) AND IpAddress != expected_ip
| table _time ComputerName TargetUserName WorkstationName IpAddress expected_ip
    LogonProcessName AuthenticationPackageName
| sort -_time
| rename ComputerName as TargetHost, IpAddress as ActualSourceIP,
    expected_ip as ExpectedSourceIP
```

```spl
# Splunk: Detect Rapid Multi-Host Authentication (Relay Spraying)
# Attackers relay captured credentials to multiple targets quickly

index=wineventlog EventCode=4624 LogonType=3
    AuthenticationPackageName="NTLM"
| where TargetUserName != "ANONYMOUS LOGON"
    AND NOT match(TargetUserName, ".*\\$$")
| bin _time span=2m
| stats dc(ComputerName) as target_count values(ComputerName) as targets
    values(IpAddress) as source_ips by _time TargetUserName
| where target_count > 3
| table _time TargetUserName source_ips target_count targets
| sort -target_count
```

```spl
# Splunk: Detect NTLM Authentication from Non-Workstation IPs
# Relay tools often run from Linux attack boxes not in DNS/DHCP inventory

index=wineventlog EventCode=4624 LogonType=3
    AuthenticationPackageName="NTLM"
| where TargetUserName != "ANONYMOUS LOGON"
    AND NOT match(TargetUserName, ".*\\$$")
| lookup dhcp_leases.csv ip AS IpAddress OUTPUT mac_address hostname
| where isnull(hostname)
| stats count dc(ComputerName) as targets_hit values(ComputerName) as target_hosts
    by IpAddress TargetUserName WorkstationName
| where count > 1
| table IpAddress TargetUserName WorkstationName targets_hit target_hosts count
| sort -targets_hit
```

```kql
-- Microsoft Sentinel KQL: NTLM Relay Detection via IP-Hostname Mismatch

let known_hosts = datatable(WorkstationName:string, ExpectedIP:string)
[
    // Populate from CMDB or use DeviceNetworkInfo table
];
SecurityEvent
| where EventID == 4624 and LogonType == 3
| where AuthenticationPackageName == "NTLM"
| where TargetUserName !endswith "$"
| where TargetUserName != "ANONYMOUS LOGON"
| where IpAddress != "-" and IpAddress != "::1" and IpAddress != "127.0.0.1"
| extend WorkstationClean = toupper(trim_end(@"\s+", WorkstationName))
| join kind=inner (known_hosts) on WorkstationName
| where IpAddress != ExpectedIP
| project TimeGenerated, Computer, TargetUserName, WorkstationName,
    IpAddress, ExpectedIP, LogonProcessName, AuthenticationPackageName,
    LmPackageName
| sort by TimeGenerated desc
```

```kql
-- Microsoft Sentinel KQL: Rapid NTLM Authentication to Multiple Targets

SecurityEvent
| where EventID == 4624 and LogonType == 3
| where AuthenticationPackageName == "NTLM"
| where TargetUserName !endswith "$"
| where TargetUserName != "ANONYMOUS LOGON"
| summarize TargetCount=dcount(Computer),
    Targets=make_set(Computer),
    SourceIPs=make_set(IpAddress),
    AuthCount=count()
    by TargetUserName, bin(TimeGenerated, 2m)
| where TargetCount > 3
| project TimeGenerated, TargetUserName, SourceIPs, TargetCount, Targets, AuthCount
| sort by TargetCount desc
```

### Step 3: Responder Detection via Network and Event Analysis

```spl
# Splunk: Detect Responder LLMNR/NBT-NS Poisoning via Network Logs
# Responder answers LLMNR (UDP 5355) and NBT-NS (UDP 137) queries

index=network sourcetype=zeek_dns
| where query_type IN ("LLMNR", "NBNS")
    OR id.resp_p IN (5355, 137)
| stats dc(id.orig_h) as victims count by id.resp_h answers
| where count > 10
| rename id.resp_h as responder_ip
| table responder_ip victims answers count
| sort -count
```

```spl
# Splunk: Detect LLMNR/NBT-NS Response from Non-DNS Servers
# Legitimate DNS servers respond to these; Responder impersonates them

index=network sourcetype="bro:dns:json" OR sourcetype="zeek:conn:json"
| where id_resp_p=5355 OR id_resp_p=137
| where NOT cidrmatch("10.10.0.0/24", id_resp_h)
| stats count dc(id_orig_h) as unique_victims by id_resp_h
| where unique_victims > 3
| table id_resp_h unique_victims count
| rename id_resp_h as suspicious_responder
```

```powershell
# PowerShell: Detect LLMNR and NBT-NS activity on local network
# Run on a monitoring host to identify Responder-like behavior

# Check if LLMNR is disabled (should be disabled to prevent poisoning)
$llmnr = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
    -Name "EnableMulticast" -ErrorAction SilentlyContinue
Write-Host "[*] LLMNR Status: $(if ($llmnr.EnableMulticast -eq 0) { 'DISABLED (Good)' } else { 'ENABLED (Vulnerable to Responder)' })"

# Check if NBT-NS is disabled
$adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
foreach ($adapter in $adapters) {
    $nbtns = $adapter.TcpipNetbios
    $status = switch ($nbtns) {
        0 { "Default (Enabled)" }
        1 { "Enabled" }
        2 { "Disabled (Good)" }
    }
    Write-Host "[*] Adapter '$($adapter.Description)' NBT-NS: $status"
}

# Query Windows Firewall logs for LLMNR/NBT-NS traffic
Get-WinEvent -LogName "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" `
    -MaxEvents 1000 -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Message -match "5355|137" -and $_.Message -match "UDP"
    } |
    Select-Object TimeCreated, @{N='Detail';E={$_.Message.Substring(0,200)}} |
    Format-Table -AutoSize
```

```yaml
# Sigma Rule: Responder LLMNR/NBT-NS Poisoning Detection
title: Potential Responder LLMNR/NBT-NS Poisoning Activity
id: 7a8b9c0d-e1f2-3a4b-5c6d-7e8f9a0b1c2d
status: stable
description: >
  Detects a single host responding to LLMNR (UDP 5355) or NBT-NS (UDP 137)
  queries from multiple unique sources, indicating possible Responder poisoning.
references:
    - https://www.hackthebox.com/blog/ntlm-relay-attack-detection
    - https://blog.fox-it.com/2017/05/09/relaying-credentials-everywhere-with-ntlmrelayx/
logsource:
    category: firewall
detection:
    selection:
        dst_port:
            - 5355
            - 137
        action: allow
    condition: selection | count(src_ip) by dst_ip > 5
    timeframe: 5m
level: high
tags:
    - attack.credential_access
    - attack.t1557.001
falsepositives:
    - Legitimate WINS servers or DNS servers responding to broadcast queries
    - Network discovery tools performing name resolution
```

### Step 4: SMB Signing Enforcement Audit

SMB signing prevents NTLM relay to SMB services and must be set to "Required" (not
just "Enabled"). LDAP signing and channel binding provide the equivalent protection
for LDAP/LDAPS on domain controllers. Audit both across the domain and treat any host
where `RequireSecuritySignature` is False as vulnerable. Full PowerShell audit scripts
(local + domain-wide SMB, LDAP signing/channel binding on DCs) and the Zeek-based
Splunk unsigned-SMB monitor: see [references/signing-audit-scripts.md](references/signing-audit-scripts.md).

### Step 5: NTLM Downgrade Detection

NTLMv1 is weaker and easier to relay/crack than NTLMv2 and should not be in use.
Watch for `LmPackageName="NTLM V1"` on Event 4624 LogonType 3, and for NTLMv1 appearing
after a period of only NTLMv2 (active downgrade). Also audit `LmCompatibilityLevel`
(target 5 = NTLMv2 only, refuse LM & NTLM). Splunk, Sentinel KQL, and local PowerShell
downgrade-detection queries: see [references/downgrade-coercion-dashboard-queries.md](references/downgrade-coercion-dashboard-queries.md).

### Step 6: NTLM Audit and Restriction Policy Configuration

Before restricting NTLM, enable auditing domain-wide (GPO: Restrict NTLM: Audit NTLM
authentication in this domain = Enable all) so all NTLM pass-through is logged as
Event 8004 in the NTLM/Operational log. Review that baseline to find every service
still depending on NTLM before enforcing restrictions. GPO/registry settings and the
PowerShell + Splunk 8004 audit queries: see [references/signing-audit-scripts.md](references/signing-audit-scripts.md).

### Step 7: PetitPotam and Coercion Attack Detection

Coercion techniques (PetitPotam/MS-EFSRPC, DFSCoerce, PrinterBug) force a machine
account -- often a domain controller -- to authenticate to the attacker for relay. The
signal is a machine account (`TargetUserName` ending in `$`) authenticating via NTLM
LogonType 3 from an IP that does not match its own host, especially relayed to AD CS or
LDAP. Splunk, Sentinel KQL, and the Sigma rule for coerced machine-account relay: see
[references/downgrade-coercion-dashboard-queries.md](references/downgrade-coercion-dashboard-queries.md).

### Step 8: Build Comprehensive Correlation Dashboard

Combine the detections above into one dashboard: IP-hostname mismatches (core indicator),
NTLMv1 downgrade events, machine-account relay (PetitPotam), NTLM volume anomalies, and
SMB signing status from the audit CSV. The full multi-panel Splunk dashboard query: see
[references/downgrade-coercion-dashboard-queries.md](references/downgrade-coercion-dashboard-queries.md).

## Key Concepts

| Term | Definition |
|------|------------|
| **NTLM Relay (T1557.001)** | Attack that intercepts NTLM authentication messages and forwards them to a target service, authenticating as the victim without knowing their password |
| **Event 4624 LogonType 3** | Windows Security Event for successful network logon -- the primary event generated on relay targets; source IP field reveals the relay attacker's address |
| **IP-Hostname Mismatch** | When Event 4624 WorkstationName field does not correspond to the IpAddress field, indicating the authentication was relayed through a third party |
| **Responder** | Attack tool that poisons LLMNR (UDP 5355), NBT-NS (UDP 137), and mDNS (UDP 5353) responses to capture NTLM authentication from victims on the local network |
| **ntlmrelayx** | Fox-IT/Impacket tool that relays captured NTLM authentication to SMB, LDAP, HTTP, MSSQL, and other protocols to gain unauthorized access |
| **SMB Signing** | Cryptographic signing of SMB packets that prevents relay attacks against SMB services; must be set to "Required" (not just "Enabled") for protection |
| **LDAP Signing** | Cryptographic signing of LDAP operations that prevents relay attacks against LDAP services on domain controllers; controlled by LDAPServerIntegrity registry value |
| **LDAP Channel Binding** | Extended Protection for Authentication (EPA) that binds the NTLM authentication to the TLS channel, preventing relay to LDAPS |
| **NTLMv1 Downgrade** | Attack forcing authentication from NTLMv2 to the weaker NTLMv1 protocol, which is easier to crack offline and has weaker relay protections |
| **PetitPotam** | Coercion technique abusing MS-EFSRPC to force a domain controller to authenticate to an attacker-controlled host, enabling relay to AD CS or LDAP |
| **LmCompatibilityLevel** | Registry setting controlling which NTLM version is used; value of 5 (Send NTLMv2 only, refuse LM and NTLM) provides strongest protection |
| **Event 8004** | NTLM operational log event on domain controllers showing all NTLM authentication pass-through, critical for auditing NTLM usage before restriction |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **Splunk / Elastic SIEM** | Log aggregation and correlation for Event 4624 analysis, IP-hostname mismatch detection, and NTLM downgrade monitoring |
| **Microsoft Sentinel** | Cloud SIEM with KQL queries for NTLM relay detection and built-in analytics rules for PetitPotam |
| **CrowdStrike Falcon Identity Protection** | Detects NTLM relay attacks against domain controller accounts regardless of coercion method used |
| **Responder** | LLMNR/NBT-NS/mDNS poisoning tool used by attackers -- understanding its behavior is essential for detection |
| **ntlmrelayx (Impacket)** | Multi-protocol NTLM relay tool developed by Fox-IT -- used in testing and by adversaries |
| **PingCastle** | Active Directory security assessment tool that audits SMB signing, LDAP signing, and NTLM configuration |
| **Zeek** | Network security monitor for capturing SMB signing negotiation, LLMNR traffic, and DCE-RPC activity |
| **Sigma** | Vendor-agnostic detection rule format for portable NTLM relay detection rules |

## Common Scenarios

### Scenario 1: Responder Poisoning with NTLM Relay to File Server

**Context**: A SOC analyst observes multiple Event 4624 LogonType 3 entries on a file server (10.10.20.100) where the WorkstationName field shows different workstation names but the IpAddress field consistently shows 10.10.5.50, a host not in the IT asset inventory.

**Approach**:
1. Query Event 4624 on 10.10.20.100 filtered for IpAddress=10.10.5.50: find 15 successful NTLM logons in 30 minutes from 8 different user accounts
2. Cross-reference 10.10.5.50 with DHCP logs and DNS: host is not a registered domain member, MAC address shows a Linux-based NIC
3. Query Zeek network logs for 10.10.5.50: identify LLMNR responses (UDP 5355) to multiple workstations and SMB connections to 10.10.20.100
4. Confirm IP-hostname mismatch: WorkstationName values (WS-FINANCE01, WS-HR03, etc.) all resolve to different IPs in DNS, not 10.10.5.50
5. Check SMB signing on 10.10.20.100: RequireSecuritySignature is False, enabling the relay attack
6. Contain: block 10.10.5.50 at the switch, force password reset for all 8 affected accounts, enable SMB signing on the file server
7. Remediate: disable LLMNR and NBT-NS via GPO, enforce SMB signing domain-wide

**Pitfalls**:
- Dismissing the multiple logons as normal network activity without checking the IP-hostname correlation
- Not checking SMB signing status on the target server to understand why the relay succeeded
- Only resetting the password for one user instead of all accounts that were relayed

### Scenario 2: PetitPotam Relay to AD Certificate Services

**Context**: During a threat hunt, an analyst finds Event 4624 LogonType 3 on the AD CS server (ADCS01) showing the domain controller machine account (DC01$) authenticating via NTLM from IP 10.10.5.50, which is not the DC's IP address (10.10.1.10).

**Approach**:
1. Confirm the anomaly: DC01$ should only authenticate from 10.10.1.10, but Event 4624 shows authentication from 10.10.5.50 via NTLM (not Kerberos)
2. Check for certificate enrollment: query AD CS logs for certificate requests from DC01$ around the same timestamp -- find a certificate issued for DC01$
3. Identify the attack: PetitPotam coerced DC01 to authenticate to 10.10.5.50, which relayed the authentication to ADCS01 to request a certificate for DC01$
4. Assess impact: with a DC certificate, the attacker can authenticate as DC01$ and perform DCSync to extract all domain credentials
5. Revoke the fraudulently issued certificate immediately
6. Check for DCSync activity: query Event 4662 for directory replication from non-DC sources
7. Contain: isolate 10.10.5.50, revoke certificate, patch EFS (MS-EFSRPC), enforce EPA on AD CS, require LDAP signing on all DCs

**Pitfalls**:
- Not recognizing that machine account NTLM authentication from an unexpected IP is a critical indicator of coercion + relay
- Failing to check AD CS for fraudulent certificate issuance, which represents the actual objective of the attack
- Not auditing LDAP signing and EPA on AD CS servers, which would have prevented the relay

## Output Format

```
Hunt ID: TH-NTLM-RELAY-[DATE]-[SEQ]
Alert Severity: Critical
MITRE Technique: T1557.001 (LLMNR/NBT-NS Poisoning and SMB Relay)

Relay Indicators:
  Victim Account: [Domain\Username or Machine$]
  WorkstationName: [Victim hostname from Event 4624]
  Expected Source IP: [IP matching WorkstationName in DNS/DHCP]
  Actual Source IP: [Attacker/relay IP from Event 4624 IpAddress field]
  Target Host: [Server receiving the relayed authentication]

Authentication Details:
  Event ID: 4624
  LogonType: 3 (Network)
  AuthenticationPackage: NTLM
  LmPackageName: [NTLM V1 or NTLM V2]
  LogonProcess: [NtLmSsp]
  Timestamp: [Event time]

Signing Status:
  Target SMB Signing: [Required/Not Required]
  Target LDAP Signing: [Required/Not Required]
  LDAP Channel Binding: [Required/Not Required]

Poisoning Evidence:
  LLMNR Activity: [Detected/Not Detected from relay IP]
  NBT-NS Activity: [Detected/Not Detected from relay IP]
  Coercion Method: [PetitPotam/DFSCoerce/PrinterBug/Unknown]

Risk Assessment: [Critical - relay from DC / High - relay from user account]
Recommended Actions:
  - Immediate: [Block relay IP, reset affected credentials]
  - Short-term: [Enable SMB/LDAP signing, disable LLMNR/NBT-NS]
  - Long-term: [Migrate to Kerberos, enforce EPA, restrict NTLM via GPO]
```
