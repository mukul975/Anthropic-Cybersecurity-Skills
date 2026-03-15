---
name: containing-active-breach
description: >
  Executes containment strategies to stop active adversary operations and prevent
  lateral movement during a confirmed security breach. Implements short-term and
  long-term containment using network segmentation, endpoint isolation, credential
  revocation, and access control modifications. Activates for requests involving
  breach containment, lateral movement prevention, network isolation, active
  threat containment, or live incident response.
domain: cybersecurity
subdomain: incident-response
tags: [breach-containment, lateral-movement, network-isolation, credential-revocation, live-response]
version: 1.0.0
author: mahipal
license: Apache-2.0
---

# Containing Active Breaches

## When to Use

- A confirmed intrusion is in progress with an active adversary on the network
- Malware is spreading laterally across endpoints or servers
- A compromised account is being used for unauthorized access to systems
- Ransomware encryption has been detected and is actively propagating
- An attacker has established command-and-control communications from internal hosts

**Do not use** for post-incident cleanup when the adversary is no longer active; use eradication procedures instead.

## Prerequisites

- Confirmed incident classification with P1 or P2 severity from triage
- EDR console access with host isolation capabilities (CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne)
- Network firewall and switch management access for segmentation
- Active Directory or identity provider administrative access for credential actions
- Pre-approved containment authority documented in the incident response plan
- Evidence preservation plan to avoid destroying forensic artifacts during containment

## Workflow

### Step 1: Assess Containment Scope

Before taking containment actions, map the full scope of compromise to avoid partial containment that alerts the adversary:

- Identify all confirmed compromised hosts via EDR telemetry and SIEM correlation
- Map lateral movement paths using authentication logs (Windows Event ID 4624 Type 3 and Type 10)
- Identify all compromised credentials (check for pass-the-hash, Kerberoasting, DCSync activity)
- Determine C2 channels (beacon intervals, domains, IPs, protocols)
- Assess whether the adversary has domain admin or equivalent privileges

```
Containment Scope Assessment:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Compromised Hosts:     5 (WKSTN-042, WKSTN-087, SRV-FILE01, SRV-DC02, WKSTN-103)
Compromised Accounts:  3 (jsmith, svc-backup, admin-tier0)
C2 Channels:           HTTPS beacon to 185.220.x.x every 60s ± 15% jitter
Lateral Movement:      PsExec via svc-backup, RDP via admin-tier0
Adversary Privilege:   Domain Admin (admin-tier0 compromised)
Data at Risk:          Finance share (\\SRV-FILE01\finance$) accessed
```

### Step 2: Execute Short-Term Containment

Implement immediate actions to stop adversary operations without destroying evidence:

**Network Containment:**
- Isolate confirmed compromised endpoints via EDR network containment (maintains agent communication)
- Block C2 IP addresses and domains at perimeter firewall and internal DNS
- Implement microsegmentation rules to prevent communication between compromised hosts
- Sinkhole C2 domains at internal DNS to capture connection attempts from undiscovered implants

**Identity Containment:**
- Disable compromised user accounts in Active Directory (do not delete; preserve audit trail)
- Reset passwords for all compromised accounts
- Revoke active sessions and tokens (Azure AD: `Revoke-AzureADUserAllRefreshToken`)
- Disable the compromised service account and rotate its credentials
- If Domain Admin is compromised: double-reset the KRBTGT password (reset twice, 12 hours apart)

**Endpoint Containment:**
- Use EDR to terminate malicious processes on contained hosts
- Block known malicious hashes in EDR prevention policy
- Quarantine identified malware samples
- Disable remote services (WinRM, RDP, SMB) on critical servers not yet compromised

### Step 3: Execute Long-Term Containment

Implement sustainable containment while the investigation continues:

- Create network ACLs isolating the compromised VLAN/subnet while allowing business-critical traffic
- Deploy temporary jump hosts for administrators to access contained systems for investigation
- Implement enhanced monitoring (full packet capture) on network segments adjacent to compromised hosts
- Enable advanced audit policies on all domain controllers (4768, 4769, 4771 for Kerberos attacks)
- Deploy canary tokens and honeypot accounts to detect adversary attempts to expand from containment

### Step 4: Validate Containment Effectiveness

Confirm that containment measures have stopped adversary operations:

- Monitor for new C2 callbacks from any internal host to known adversary infrastructure
- Check for new lateral movement attempts (failed authentication from disabled accounts)
- Verify that contained hosts cannot reach the internet except through the EDR agent
- Confirm that compromised credentials produce authentication failures
- Review SIEM for any new alerts matching the adversary's known TTPs

```
Containment Validation Checklist:
[x] C2 beacon traffic ceased from all known compromised hosts
[x] Disabled accounts producing expected 4625 failure events (no new successes)
[x] Contained hosts unreachable via network scan from adjacent subnets
[x] No new hosts exhibiting IOCs from the initial compromise
[x] Honeypot account has not been accessed (adversary may be dormant)
[ ] Full packet capture running on finance VLAN (pending switch config)
```

### Step 5: Preserve Evidence During Containment

Containment must not destroy forensic evidence:

- Capture memory dumps from compromised hosts before any remediation (use WinPmem or Magnet RAM Capture)
- Collect volatile data: running processes, network connections, logged-on users, scheduled tasks
- Export relevant event logs before they rotate (Security, System, PowerShell, Sysmon)
- Capture network traffic between compromised hosts and C2 infrastructure
- Document all containment actions with timestamps for the incident timeline

### Step 6: Communicate Containment Status

Provide structured status updates to incident commander and stakeholders:

- Current containment effectiveness (percentage of adversary activity stopped)
- Remaining risks (undiscovered implants, persistence mechanisms not yet identified)
- Business impact of containment actions (which systems are offline, user impact)
- Estimated timeline for eradication phase
- Escalation needs (law enforcement notification, external IR retainer activation)

## Key Concepts

| Term | Definition |
|------|------------|
| **Short-Term Containment** | Immediate actions to stop active adversary operations; typically network isolation and credential disablement |
| **Long-Term Containment** | Sustainable measures allowing continued investigation while preventing adversary re-access |
| **KRBTGT Double Reset** | Resetting the KRBTGT password twice to invalidate all existing Kerberos tickets including golden tickets |
| **Network Containment** | EDR feature that isolates an endpoint from all network communication except the EDR management channel |
| **Lateral Movement** | Adversary technique of moving from one compromised system to another within a network using stolen credentials or exploits |
| **C2 Sinkholing** | Redirecting DNS queries for C2 domains to an internal server to prevent adversary communication and detect additional victims |
| **Microsegmentation** | Granular network access controls between workloads that limit lateral communication paths |

## Tools & Systems

- **CrowdStrike Falcon**: Endpoint containment with one-click network isolation preserving agent connectivity
- **Microsoft Defender for Endpoint**: Live response console for remote containment actions and evidence collection
- **Palo Alto Networks NGFW**: Application-aware firewall rules for C2 traffic blocking and microsegmentation
- **Velociraptor**: Open-source endpoint monitoring and response tool for artifact collection during containment
- **BloodHound**: Active Directory attack path mapping to identify potential lateral movement routes the adversary may exploit

## Common Scenarios

### Scenario: Ransomware Lateral Propagation via SMB

**Context**: EDR alerts on three file servers showing rapid file encryption. The ransomware is spreading via SMB using a compromised domain service account.

**Approach**:
1. Immediately isolate all three file servers via EDR network containment
2. Disable the compromised service account in Active Directory
3. Block SMB (TCP 445) between all server VLANs at the network switch layer
4. Deploy an emergency GPO disabling the SMB server service on non-critical endpoints
5. Capture memory from one encrypted server before it reboots
6. Search for the ransomware binary hash across all endpoints using EDR threat hunting

**Pitfalls**:
- Shutting down servers immediately, destroying volatile memory evidence
- Only disabling the known compromised account without checking for other persistence mechanisms
- Restoring from backup before confirming the adversary's access has been fully revoked

## Output Format

```
CONTAINMENT STATUS REPORT
=========================
Incident:        INC-2025-1547
Status:          CONTAINED (Short-Term)
Timestamp:       2025-11-15T15:47:00Z
Containment Lead: [Name]

ACTIONS TAKEN
Network:
- [x] 5 hosts isolated via CrowdStrike containment
- [x] C2 IP 185.220.x.x blocked at perimeter FW (rule #4521)
- [x] C2 domain evil.example[.]com sinkholed to 10.0.0.99

Identity:
- [x] jsmith account disabled
- [x] svc-backup account disabled, password rotated
- [x] admin-tier0 account disabled
- [x] KRBTGT first reset completed at 15:30 UTC

Endpoint:
- [x] Malicious hash blocked in EDR prevention policy
- [x] Malware processes terminated on all contained hosts

EVIDENCE PRESERVED
- Memory dumps: 3 of 5 hosts completed
- Event logs exported: all 5 hosts
- Network capture: running on finance VLAN

REMAINING RISKS
- Possible undiscovered implants on non-EDR endpoints (15 legacy hosts)
- KRBTGT second reset pending (scheduled 03:30 UTC +1 day)
- Adversary may have exfiltrated data before containment

BUSINESS IMPACT
- Finance file share offline (affects 42 users)
- 3 user workstations isolated (users reassigned to loaners)
- Estimated restoration: pending eradication completion
```
