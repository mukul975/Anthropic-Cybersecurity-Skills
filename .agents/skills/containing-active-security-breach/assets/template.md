# Breach Containment Action Report

## Incident Information
| Field | Value |
|-------|-------|
| Incident ID | IR-YYYY-NNN |
| Date/Time Detected | YYYY-MM-DD HH:MM UTC |
| Containment Started | YYYY-MM-DD HH:MM UTC |
| Containment Completed | YYYY-MM-DD HH:MM UTC |
| Incident Commander | [Name] |
| Severity Level | [Critical/High/Medium/Low] |

## Incident Summary
[Brief description of the breach - what was detected, initial indicators, how the breach was discovered]

## Scope of Compromise

### Affected Systems
| Hostname | IP Address | Role | Compromise Evidence | Containment Action |
|----------|-----------|------|--------------------|--------------------|
| | | | | |

### Compromised Accounts
| Account Name | Account Type | Last Logon | Containment Action | Status |
|-------------|-------------|------------|-------------------|--------|
| | | | | |

### Affected Data
| Data Classification | Data Type | Volume | Exfiltration Confirmed | Evidence |
|--------------------|-----------|--------|----------------------|----------|
| | | | | |

## Attack Timeline
| Time (UTC) | Event | Source | Details |
|-----------|-------|--------|---------|
| | Initial access detected | | |
| | Lateral movement observed | | |
| | Containment initiated | | |
| | Containment verified | | |

## Containment Actions Taken

### Network Containment
- [ ] Attacker IPs blocked at perimeter firewall
  - IPs blocked: [list]
  - Firewall rule name/ID: [reference]
- [ ] C2 domains sinkholed
  - Domains: [list]
  - Method: [DNS sinkhole/RPZ/hosts file]
- [ ] Compromised network segments isolated
  - VLANs/subnets: [list]
  - Method: [ACL/VLAN shutdown/firewall rule]

### Endpoint Containment
- [ ] Compromised hosts network-contained via EDR
  - EDR platform: [CrowdStrike/SentinelOne/MDE]
  - Hosts isolated: [list]
- [ ] Malicious processes terminated
  - Processes: [list with PIDs]
- [ ] Unauthorized software quarantined
  - Files: [list with hashes]

### Identity Containment
- [ ] Compromised user accounts disabled
  - Accounts: [list]
- [ ] Active sessions revoked
  - Method: [Azure AD/On-prem AD]
- [ ] Service account credentials rotated
  - Accounts: [list]
- [ ] MFA tokens reset
  - Users: [list]

### DNS/Web Containment
- [ ] Malicious domains blocked at DNS
- [ ] Web proxy rules updated
- [ ] SSL certificates revoked (if applicable)

## Evidence Preserved

### Volatile Evidence (Collected Before Isolation)
| Evidence Type | Host | Collection Time | SHA256 Hash | Collector |
|--------------|------|-----------------|-------------|-----------|
| Memory dump | | | | |
| Network connections | | | | |
| Process list | | | | |
| DNS cache | | | | |

### Network Evidence
| Capture Type | Source | Time Range | File Size | SHA256 Hash |
|-------------|--------|------------|-----------|-------------|
| PCAP | | | | |
| NetFlow | | | | |

## Containment Verification

### Verification Checks
- [ ] No active C2 communications detected post-containment
- [ ] No new lateral movement attempts observed
- [ ] All compromised accounts confirmed disabled
- [ ] Isolated systems confirmed unreachable from network
- [ ] Business-critical services tested and operational
- [ ] Enhanced monitoring deployed on adjacent systems

### Monitoring Status
| Monitor Type | Scope | Status | Alert Threshold |
|-------------|-------|--------|----------------|
| Network traffic | Compromised segments | Active/Pending | |
| EDR alerts | All endpoints | Active/Pending | |
| Authentication logs | Domain-wide | Active/Pending | |
| Data loss prevention | Sensitive repositories | Active/Pending | |

## Business Impact Assessment
| Service/System | Impact Level | Workaround Available | Estimated Restore |
|---------------|-------------|---------------------|-------------------|
| | | | |

## Next Steps
1. [ ] Complete forensic imaging of all compromised systems
2. [ ] Begin eradication phase - remove attacker persistence
3. [ ] Conduct root cause analysis
4. [ ] Prepare for recovery phase
5. [ ] Schedule stakeholder briefing

## Approvals
| Role | Name | Signature | Date |
|------|------|-----------|------|
| Incident Commander | | | |
| CISO | | | |
| IT Director | | | |
| Legal Counsel | | | |
