# Lateral Movement Investigation Checklist

Use this checklist when responding to a lateral movement alert from Zeek.

## Incident Information

| Field | Value |
|---|---|
| **Alert ID** | |
| **Alert Time (UTC)** | |
| **Analyst** | |
| **Severity** | ☐ Critical ☐ High ☐ Medium ☐ Low |
| **Alert Category** | ☐ SMB Admin Share ☐ PsExec ☐ RDP Pivot ☐ PtH ☐ DCSync |
| **Source IP** | |
| **Destination IP(s)** | |
| **MITRE Technique** | |

---

## Phase 1: Initial Triage (15 min)

- [ ] Review the alert details and source/destination IPs
- [ ] Check if source IP is a known admin workstation or IT asset
- [ ] Check if this is a known false positive (scanner, backup, SCCM)
- [ ] Verify the user account associated with the activity
- [ ] Determine if the activity occurred during business hours
- [ ] Check for related alerts in the same time window

**Triage Decision**: ☐ Escalate ☐ False Positive ☐ Needs More Analysis

---

## Phase 2: Scope Assessment (30 min)

### Network Activity

- [ ] Query conn.log for all connections from the source IP in the past 24h
  ```bash
  cat conn.log | zeek-cut ts uid id.orig_h id.resp_h id.resp_p service | grep "SOURCE_IP"
  ```
- [ ] Identify all destination hosts contacted on ports 445, 3389, 135, 5985
- [ ] Check for data exfiltration indicators (large outbound transfers)
- [ ] Map the full chain of lateral movement (A → B → C → ...)

### SMB Activity

- [ ] Check smb_mapping.log for all share access from the source
  ```bash
  cat smb_mapping.log | zeek-cut ts uid id.orig_h id.resp_h path | grep "SOURCE_IP"
  ```
- [ ] Check smb_files.log for file writes (especially .exe, .dll, .bat, .ps1)
  ```bash
  cat smb_files.log | zeek-cut ts uid id.orig_h id.resp_h name action | grep "SOURCE_IP"
  ```

### Authentication Activity

- [ ] Check ntlm.log for authentication attempts
  ```bash
  cat ntlm.log | zeek-cut ts uid id.orig_h id.resp_h username domainname | grep "SOURCE_IP"
  ```
- [ ] Check kerberos.log for ticket requests
  ```bash
  cat kerberos.log | zeek-cut ts uid id.orig_h id.resp_h client service | grep "SOURCE_IP"
  ```
- [ ] Note all user accounts used across the movement chain

### RPC Activity

- [ ] Check dce_rpc.log for service creation, remote execution
  ```bash
  cat dce_rpc.log | zeek-cut ts uid id.orig_h id.resp_h endpoint operation | grep "SOURCE_IP"
  ```

---

## Phase 3: Host Investigation

### Source Host

- [ ] Identify the host (hostname, OS, owner, role)
- [ ] Check endpoint logs (EDR) for process execution
- [ ] Look for initial compromise indicators (phishing, exploit)
- [ ] Check for persistence mechanisms installed
- [ ] Review recent user logon activity

### Destination Host(s)

For each destination in the lateral movement chain:

| Destination IP | Hostname | Compromised? | Actions Taken |
|---|---|---|---|
| | | ☐ Yes ☐ No ☐ Unknown | |
| | | ☐ Yes ☐ No ☐ Unknown | |
| | | ☐ Yes ☐ No ☐ Unknown | |

---

## Phase 4: Containment

- [ ] Isolate confirmed compromised hosts (network quarantine)
- [ ] Disable compromised user accounts
- [ ] Block source IP at internal firewall (if active threat)
- [ ] Enable enhanced monitoring on affected network segments
- [ ] Notify affected system owners

---

## Phase 5: Remediation

- [ ] Reimage confirmed compromised hosts
- [ ] Reset passwords for all affected accounts
- [ ] Reset Kerberos KRBTGT password (if DCSync confirmed — twice, 12h apart)
- [ ] Review and revoke any persistent access (scheduled tasks, services)
- [ ] Patch vulnerabilities that enabled initial access
- [ ] Review network segmentation between workstation and server VLANs

---

## Phase 6: Post-Incident

- [ ] Update Zeek detection allowlists (admin_hosts, jump_hosts, domain_controllers)
- [ ] Tune detection thresholds based on this incident
- [ ] Document the full attack timeline
- [ ] Create IOCs for threat intelligence sharing
- [ ] Write incident report
- [ ] Schedule lessons-learned meeting
- [ ] Update this checklist with any new steps identified

---

## Timeline

| Time (UTC) | Source | Destination | Activity | Notes |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |

---

## Notes

_Free-form investigation notes:_
