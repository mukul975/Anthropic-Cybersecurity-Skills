---
name: detecting-ransomware-precursors-in-network
description: >
  Detects early-stage ransomware indicators in network traffic before encryption begins,
  including initial access broker activity, command-and-control beaconing, credential
  harvesting, reconnaissance scanning, and staging behavior. Uses network detection tools
  (Zeek, Suricata, Arkime), SIEM correlation rules, and threat intelligence feeds to
  identify ransomware precursor patterns such as Cobalt Strike beacons, Mimikatz network
  signatures, and RDP brute-force attempts. Activates for requests involving pre-ransomware
  detection, network-based ransomware indicators, or early warning ransomware monitoring.
domain: cybersecurity
subdomain: ransomware-defense
tags: [ransomware, detection, network-security, incident-response, defense]
version: 1.0.0
author: mahipal
license: Apache-2.0
---
# Detecting Ransomware Precursors in Network Traffic

## When to Use

- Building detection rules for pre-ransomware network activity (the average time from Cobalt Strike deployment to encryption is 17 minutes)
- Monitoring for initial access broker (IAB) indicators that precede ransomware deployment
- Creating SIEM correlation rules that chain multiple precursor events into high-confidence alerts
- Tuning network detection systems to distinguish ransomware staging from normal administrative activity
- Investigating suspicious network patterns that may indicate ransomware operators have established a foothold

**Do not use** for post-encryption response (see recovering-from-ransomware-attack). This skill focuses on the pre-encryption detection window where containment can prevent data loss.

## Prerequisites

- Network detection platform (Zeek/Bro, Suricata, or Arkime/Moloch) deployed on network TAP or SPAN ports
- SIEM platform (Splunk, Elastic Security, Microsoft Sentinel, or QRadar) ingesting network logs
- Threat intelligence feeds covering ransomware IOCs (CISA, abuse.ch, OTX, MISP)
- Network flow data (NetFlow/IPFIX) from core routers and firewalls
- DNS query logging from internal resolvers
- Full packet capture capability for incident investigation

## Workflow

### Step 1: Identify Ransomware Kill Chain Phases in Network Traffic

Map network-observable indicators to each pre-encryption phase:

| Kill Chain Phase | Network Indicators | Detection Source |
|------------------|--------------------|------------------|
| Initial Access | RDP brute force, VPN credential stuffing, phishing callback | Firewall logs, IDS, proxy logs |
| C2 Establishment | Cobalt Strike beacons (HTTPS/DNS), Sliver/Brute Ratel callbacks | Zeek SSL/HTTP logs, DNS logs |
| Credential Harvesting | NTLM relay, Kerberoasting, DCSync traffic | Zeek Kerberos/NTLM logs, DC logs |
| Reconnaissance | Internal port scanning, AD enumeration (LDAP/SMB) | Zeek conn.log, flow data |
| Lateral Movement | PsExec/WMI/WinRM traffic, RDP pivoting, SMB file copies | Zeek SMB/DCE-RPC logs |
| Staging | Data aggregation, archive creation, cloud upload prep | Proxy logs, DNS logs, DLP |

### Step 2: Deploy Network Detection Rules

**Suricata rules for common ransomware precursors:**

```yaml
# Cobalt Strike default HTTPS beacon profile detection
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"RANSOMWARE PRECURSOR - Cobalt Strike Default TLS Certificate"; tls.cert_subject; content:"Major Cobalt Strike"; sid:3000001; rev:1;)

# Cobalt Strike DNS beacon
alert dns $HOME_NET any -> any 53 (msg:"RANSOMWARE PRECURSOR - Cobalt Strike DNS Beacon Pattern"; dns.query; pcre:"/^[a-z0-9]{3}\.[a-z]{4,8}\./"; threshold:type both, track by_src, count 50, seconds 60; sid:3000002; rev:1;)

# Mimikatz network signature (DCSync - DRS GetNCChanges)
alert tcp $HOME_NET any -> $HOME_NET 135 (msg:"RANSOMWARE PRECURSOR - Possible DCSync/Mimikatz"; content:"|05 00 0b|"; offset:0; depth:3; content:"|e3 51 4d 2b 4b 47 15 d2|"; sid:3000003; rev:1;)

# Internal network scanning (many connections, few bytes)
alert tcp $HOME_NET any -> $HOME_NET any (msg:"RANSOMWARE PRECURSOR - Internal Port Scan"; flags:S; threshold:type both, track by_src, count 100, seconds 10; sid:3000004; rev:1;)

# PsExec service installation over SMB
alert tcp $HOME_NET any -> $HOME_NET 445 (msg:"RANSOMWARE PRECURSOR - PsExec Service Install"; content:"|ff|SMB"; content:"PSEXESVC"; nocase; sid:3000005; rev:1;)

# RDP brute force from internal host (lateral movement)
alert tcp $HOME_NET any -> $HOME_NET 3389 (msg:"RANSOMWARE PRECURSOR - Internal RDP Brute Force"; flow:to_server,established; threshold:type both, track by_src, count 20, seconds 60; sid:3000006; rev:1;)

# Large SMB file transfer (data staging)
alert tcp $HOME_NET any -> $HOME_NET 445 (msg:"RANSOMWARE PRECURSOR - Large SMB Transfer Possible Staging"; flow:to_server,established; dsize:>60000; threshold:type both, track by_src, count 100, seconds 300; sid:3000007; rev:1;)
```

**Zeek scripts for behavioral detection:**

```zeek
# detect_ransomware_precursors.zeek
# Detect high volume of failed SMB connections (credential testing)

@load base/protocols/smb

module RansomwarePrecursor;

export {
    redef enum Notice::Type += {
        SMB_Brute_Force,
        Suspicious_Internal_Scan,
        Excessive_DNS_Queries,
        SMB_Admin_Share_Access,
    };

    const smb_fail_threshold = 10 &redef;
    const scan_threshold = 50 &redef;
    const dns_query_threshold = 200 &redef;
}

global smb_fail_count: table[addr] of count &default=0 &create_expire=5min;
global conn_count: table[addr] of set[addr] &create_expire=1min;

event smb2_message(c: connection, hdr: SMB2::Header, is_orig: bool) {
    if (hdr$status != 0) {
        ++smb_fail_count[c$id$orig_h];
        if (smb_fail_count[c$id$orig_h] >= smb_fail_threshold) {
            NOTICE([$note=SMB_Brute_Force,
                    $msg=fmt("Host %s has %d failed SMB attempts", c$id$orig_h, smb_fail_count[c$id$orig_h]),
                    $src=c$id$orig_h,
                    $identifier=cat(c$id$orig_h)]);
        }
    }
}

event new_connection(c: connection) {
    if (c$id$orig_h in Site::local_nets && c$id$resp_h in Site::local_nets) {
        if (c$id$orig_h !in conn_count)
            conn_count[c$id$orig_h] = set();
        add conn_count[c$id$orig_h][c$id$resp_h];
        if (|conn_count[c$id$orig_h]| >= scan_threshold) {
            NOTICE([$note=Suspicious_Internal_Scan,
                    $msg=fmt("Host %s connected to %d internal hosts in 1 min", c$id$orig_h, |conn_count[c$id$orig_h]|),
                    $src=c$id$orig_h,
                    $identifier=cat(c$id$orig_h)]);
        }
    }
}
```

### Step 3: Create SIEM Correlation Rules

**Splunk correlation for ransomware precursor chain:**

```spl
| tstats count FROM datamodel=Network_Traffic
  WHERE earliest=-24h All_Traffic.dest_port IN (445, 135, 139, 3389, 5985, 5986)
    AND All_Traffic.src_ip IN 10.0.0.0/8
    AND All_Traffic.dest_ip IN 10.0.0.0/8
  BY All_Traffic.src_ip, All_Traffic.dest_port, _time span=1h
| stats dc(All_Traffic.dest_port) as port_count,
        values(All_Traffic.dest_port) as ports,
        count as total_conns
  BY All_Traffic.src_ip
| where port_count >= 3 AND total_conns > 50
| rename All_Traffic.src_ip as src_ip
| lookup threat_intel_ioc ip as src_ip OUTPUT threat_type
| eval risk_score = case(
    port_count >= 5 AND total_conns > 200, "CRITICAL",
    port_count >= 3 AND total_conns > 50, "HIGH",
    1=1, "MEDIUM")
| table src_ip, ports, port_count, total_conns, risk_score, threat_type
```

**Microsoft Sentinel KQL - Ransomware precursor correlation:**

```kql
let timeframe = 24h;
let RDPBruteForce = SecurityEvent
| where TimeGenerated > ago(timeframe)
| where EventID == 4625
| where LogonType == 10
| summarize FailedRDP = count() by TargetAccount, IpAddress, bin(TimeGenerated, 1h)
| where FailedRDP > 10;
let SuspiciousSMB = SecurityEvent
| where TimeGenerated > ago(timeframe)
| where EventID == 5145
| where ShareName has "ADMIN$" or ShareName has "C$" or ShareName has "IPC$"
| summarize AdminShareAccess = count() by SubjectUserName, IpAddress, bin(TimeGenerated, 1h)
| where AdminShareAccess > 5;
let ServiceInstalls = SecurityEvent
| where TimeGenerated > ago(timeframe)
| where EventID == 7045
| where ServiceName has_any ("PSEXESVC", "meterpreter", "beacon");
RDPBruteForce
| join kind=inner SuspiciousSMB on IpAddress
| project TimeGenerated, IpAddress, TargetAccount, FailedRDP, SubjectUserName, AdminShareAccess
| extend AlertTitle = "Ransomware Precursor: RDP Brute Force + Admin Share Access"
```

### Step 4: Integrate Threat Intelligence

Configure automated IOC feeds for known ransomware infrastructure:

```bash
# Download and update ransomware C2 blocklists
# abuse.ch Feodo Tracker (Cobalt Strike, TrickBot, BazarLoader C2s)
curl -s https://feodotracker.abuse.ch/downloads/ipblocklist.csv | \
  grep -v "^#" | cut -d, -f2 > /opt/threat-intel/feodo_ips.txt

# abuse.ch URLhaus (malware distribution URLs)
curl -s https://urlhaus.abuse.ch/downloads/csv_recent/ | \
  grep -v "^#" | cut -d, -f3 > /opt/threat-intel/urlhaus_urls.txt

# abuse.ch ThreatFox (ransomware IOCs)
curl -s https://threatfox.abuse.ch/export/csv/recent/ | \
  grep -i "ransomware" | cut -d, -f3 > /opt/threat-intel/ransomware_iocs.txt

# CISA Known Exploited Vulnerabilities (initial access vectors)
curl -s https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | \
  python3 -c "import json,sys; data=json.load(sys.stdin); [print(v['cveID'],v['vendorProject'],v['product']) for v in data['vulnerabilities'] if 'ransomware' in v.get('knownRansomwareCampaignUse','').lower()]"
```

### Step 5: Establish Alert Triage and Escalation

Define triage procedures based on precursor confidence level:

| Alert Type | Confidence | Response Time | Action |
|------------|-----------|---------------|--------|
| Confirmed Cobalt Strike beacon | High | 15 minutes | Isolate host immediately, trigger IR |
| DCSync/Kerberoasting from non-DC | High | 15 minutes | Disable account, isolate host, trigger IR |
| Internal port scan + admin share access | Medium-High | 30 minutes | Investigate source host, check EDR telemetry |
| RDP brute force from internal host | Medium | 1 hour | Verify if legitimate admin activity, check host |
| Unusual DNS query volume | Low-Medium | 4 hours | Check for DNS tunneling, correlate with other alerts |

## Key Concepts

| Term | Definition |
|------|------------|
| **Ransomware Precursor** | Network activity that precedes ransomware encryption, including C2 communication, lateral movement, and data staging |
| **Dwell Time** | Time between initial compromise and ransomware deployment, averaging 21 days but sometimes as short as 17 minutes |
| **Initial Access Broker (IAB)** | Threat actors who sell compromised network access to ransomware operators on dark web markets |
| **Beaconing** | Periodic C2 callbacks from implants (Cobalt Strike, Sliver) that can be detected by analyzing connection timing patterns |
| **Kerberoasting** | Credential harvesting technique requesting Kerberos service tickets for offline cracking, detectable via unusual TGS-REQ patterns |
| **DCSync** | Technique using Directory Replication Service to extract password hashes from domain controllers, critical ransomware precursor |

## Tools & Systems

- **Zeek (formerly Bro)**: Network analysis framework generating structured logs for SMB, Kerberos, DNS, HTTP, and TLS connections
- **Suricata**: High-performance IDS/IPS with protocol analysis and multi-threading support for ransomware signature detection
- **Arkime (formerly Moloch)**: Full packet capture and search platform for deep forensic investigation of network events
- **RITA (Real Intelligence Threat Analytics)**: Open-source tool for detecting beaconing, DNS tunneling, and long connections in Zeek logs
- **AC-Hunter**: Network threat hunting platform from Active Countermeasures for beacon detection and C2 identification

## Common Scenarios

### Scenario: Detecting LockBit Precursors in a Manufacturing Network

**Context**: A manufacturing company's SOC receives an alert for unusual SMB traffic from a workstation (10.1.5.42) in the engineering department. The workstation connected to 47 internal hosts on port 445 within 5 minutes at 2:00 AM.

**Approach**:
1. Zeek conn.log analysis shows 10.1.5.42 initiated connections to 47 unique internal IPs on port 445, 135, and 3389 between 01:55-02:05
2. Zeek ssl.log reveals an outbound HTTPS connection to 185.x.x.x every 60 seconds with consistent 48-byte payloads (Cobalt Strike beacon pattern)
3. RITA beacon analysis confirms high beacon score (0.96) for the external IP with 60-second jitter
4. Zeek kerberos.log shows TGS-REQ for multiple SPN accounts from 10.1.5.42 (Kerberoasting)
5. SMB tree_connect events show access to ADMIN$ shares on 12 hosts (lateral movement staging)
6. Containment: Host isolated, credentials for engineering user reset, blocking rule for C2 IP deployed
7. Full IR initiated before ransomware deployment could begin

**Pitfalls**:
- Dismissing internal port scans as vulnerability scanner activity without verifying the source is an authorized scanner
- Not correlating individual low-severity alerts (DNS anomaly + SMB access + failed logins) into a high-severity chain
- Setting detection thresholds too high to avoid false positives, missing low-and-slow reconnaissance
- Ignoring encrypted traffic analysis (JA3/JA4 fingerprinting) that can identify Cobalt Strike even in TLS tunnels

## Output Format

```
## Ransomware Precursor Detection Alert

**Alert ID**: [SIEM-generated ID]
**Detection Time**: [Timestamp]
**Source Host**: [IP / Hostname]
**Confidence**: [High / Medium / Low]
**Kill Chain Phase**: [Initial Access / C2 / Credential Harvest / Recon / Lateral Movement / Staging]

### Indicators Detected
| Indicator | Source | Detail | MITRE ATT&CK |
|-----------|--------|--------|--------------|
| [Type] | [Zeek/Suricata/SIEM] | [Description] | [T-ID] |

### Correlation Chain
1. [Timestamp] - [Event 1]
2. [Timestamp] - [Event 2]
3. [Timestamp] - [Event 3]

### Recommended Actions
- [ ] Isolate source host from network
- [ ] Check EDR telemetry for host-based indicators
- [ ] Reset credentials for affected user accounts
- [ ] Block identified C2 infrastructure
- [ ] Escalate to incident response team
```
