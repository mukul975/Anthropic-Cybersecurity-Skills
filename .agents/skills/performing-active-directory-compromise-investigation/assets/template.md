# Active Directory Compromise Investigation Report Template

## Case Information

| Field | Details |
|-------|---------|
| Case ID | IR-AD-YYYY-XXX |
| Investigator | |
| Date Initiated | |
| Organization | |
| Domain(s) Affected | |
| Domain Controllers | |
| Estimated Compromise Date | |

## Executive Summary

[Brief description of the AD compromise, scope, and critical findings]

## Scope of Investigation

### Domain Controllers Examined
| DC Name | OS Version | IP Address | Role | Status |
|---------|-----------|------------|------|--------|
| | | | | |

### Log Sources Collected
- [ ] Security Event Logs (all DCs)
- [ ] System Event Logs
- [ ] Directory Service Logs
- [ ] DNS Server Logs
- [ ] PowerShell Transcription Logs
- [ ] Replication Metadata
- [ ] GPO Configuration Export
- [ ] Privileged Group Membership Export

## Attack Timeline

| Timestamp | Event | Source | Severity |
|-----------|-------|--------|----------|
| | Initial access | | |
| | Privilege escalation | | |
| | Lateral movement | | |
| | Domain compromise | | |
| | Data access/exfiltration | | |

## Findings

### Finding 1: [Attack Category]
- **Severity:** CRITICAL / HIGH / MEDIUM / LOW
- **Evidence:** [Event IDs, log entries, artifacts]
- **Impact:** [Accounts, systems, data affected]
- **MITRE ATT&CK:** [Technique ID and name]

### Finding 2: [Attack Category]
- **Severity:**
- **Evidence:**
- **Impact:**
- **MITRE ATT&CK:**

## Compromised Accounts

| Account | Type | Privileges | Compromise Method | Status |
|---------|------|------------|-------------------|--------|
| | Domain Admin | | DCSync | Disabled |
| | Service Account | | Kerberoasting | Reset |

## Kerberos Analysis

### Golden Ticket Assessment
- [ ] krbtgt password age: _____ days
- [ ] TGTs with abnormal lifetimes detected: Yes / No
- [ ] RC4 encryption on tickets detected: Yes / No
- [ ] Service tickets without TGT requests: Yes / No

### Kerberoasting Assessment
- [ ] Bulk TGS requests from single source: Yes / No
- [ ] Service accounts with weak passwords: Yes / No
- [ ] Service accounts targeted: _____ accounts

## Lateral Movement Map

```
[Source] --> [Hop 1] --> [Hop 2] --> [Domain Controller]
   |
   +--> [Hop 1b] --> [File Server]
```

## Persistence Mechanisms Found

- [ ] AdminSDHolder ACL modifications
- [ ] SID History injection
- [ ] Rogue GPO policies
- [ ] Skeleton Key malware
- [ ] DCShadow objects
- [ ] Rogue AD CS certificates
- [ ] Scheduled tasks via GPO
- [ ] Modified login scripts
- [ ] Custom WMI subscriptions

## Remediation Actions

### Immediate (0-24 hours)
- [ ] Disable all compromised accounts
- [ ] Isolate compromised systems
- [ ] Block attacker IP addresses at firewall
- [ ] Double-rotate krbtgt password
- [ ] Revoke all active sessions

### Short-term (24-72 hours)
- [ ] Reset all privileged account passwords
- [ ] Reset all service account passwords
- [ ] Remove unauthorized group memberships
- [ ] Revert malicious GPO changes
- [ ] Remove persistence mechanisms

### Long-term (1-4 weeks)
- [ ] Force all user password changes
- [ ] Implement tiered administration model
- [ ] Deploy Privileged Access Workstations
- [ ] Enable Microsoft Defender for Identity
- [ ] Implement LAPS for local admin passwords
- [ ] Configure advanced audit policies
- [ ] Add critical accounts to Protected Users group

## Indicators of Compromise

### Accounts
| Account | Type | Activity |
|---------|------|----------|
| | | |

### IP Addresses
| IP | Activity | First Seen | Last Seen |
|----|----------|------------|-----------|
| | | | |

### Tools Detected
| Tool | Hash | Location | Purpose |
|------|------|----------|---------|
| | | | |

## Appendix

### Event Log Analysis Summary
### BloodHound Attack Path Diagrams
### GPO Change Detail
### Network Diagram with Lateral Movement Overlay
