# Lateral Movement Investigation Checklist

## Incident Details

| Field | Value |
|---|---|
| **Incident ID** | |
| **Date/Time Detected** | |
| **Analyst** | |
| **Detection Source** | Zeek — lateral movement detection |
| **Severity** | ☐ Critical ☐ High ☐ Medium ☐ Low |

## Initial Triage

- [ ] Review Zeek notice.log for lateral movement alerts
- [ ] Identify the suspected source host (patient zero)
- [ ] Determine the timeframe of suspicious activity
- [ ] Check if activity correlates with known maintenance/change windows
- [ ] Verify source host is not a known admin workstation

## SMB Admin Share Analysis (T1021.002)

- [ ] Query `smb_mapping.log` for admin share access (`C$`, `ADMIN$`, `IPC$`)
  ```bash
  cat smb_mapping.log | zeek-cut ts id.orig_h id.resp_h path | grep -iE '(ADMIN\$|C\$|IPC\$)'
  ```
- [ ] Identify the user account used for SMB authentication
- [ ] Check `dce_rpc.log` for `svcctl` service creation (PsExec indicator)
  ```bash
  cat dce_rpc.log | zeek-cut ts id.orig_h id.resp_h endpoint operation | grep -i svcctl
  ```
- [ ] List all hosts accessed via admin shares from the source
- [ ] Document share paths and timestamps

## RDP Pivot Analysis (T1021.001)

- [ ] Query `conn.log` for internal RDP connections
  ```bash
  cat conn.log | zeek-cut ts id.orig_h id.resp_h id.resp_p duration | awk '$4 == 3389'
  ```
- [ ] Identify hosts acting as both RDP client and server (pivot nodes)
- [ ] Map the full RDP pivot chain
- [ ] Check RDP session durations for anomalies
- [ ] Verify if RDP is authorized for identified hosts

## Pass-the-Hash Analysis (T1550.002)

- [ ] Query `ntlm.log` for multi-source authentication per user
  ```bash
  cat ntlm.log | zeek-cut ts id.orig_h username domainname success | sort -k3
  ```
- [ ] Identify accounts authenticating from 3+ distinct sources
- [ ] Check if flagged accounts are service accounts (expected multi-source)
- [ ] Determine if source hosts are authorized for the flagged accounts
- [ ] Cross-reference with Active Directory logon events

## DCSync Analysis (T1003.006)

- [ ] Query `dce_rpc.log` for `drsuapi` endpoint calls
  ```bash
  cat dce_rpc.log | zeek-cut ts id.orig_h id.resp_h endpoint operation | grep -i drsuapi
  ```
- [ ] Verify if source hosts are legitimate domain controllers
- [ ] If non-DC source detected: **ESCALATE IMMEDIATELY**
- [ ] Document source IP, destination DC, and timestamp
- [ ] Check if krbtgt or privileged accounts may be compromised

## Lateral Tool Transfer Analysis (T1570)

- [ ] Query `files.log` for executable transfers between internal hosts
  ```bash
  cat files.log | zeek-cut ts tx_hosts rx_hosts filename mime_type total_bytes | \
      grep -E 'x-dosexec|x-executable'
  ```
- [ ] Identify transferred filenames and sizes
- [ ] Extract file hashes from `files.log` for threat intelligence lookup
- [ ] Check if files were subsequently executed (correlate with endpoint logs)

## Scope Assessment

- [ ] Total number of affected hosts: ____
- [ ] Total number of compromised accounts: ____
- [ ] Earliest indicator timestamp: ____
- [ ] Latest indicator timestamp: ____
- [ ] Network segments affected: ____
- [ ] Any evidence of data exfiltration: ☐ Yes ☐ No ☐ Unknown

## Evidence Collection

- [ ] Preserve relevant Zeek logs (copy, do not modify originals)
- [ ] Capture full PCAPs for key timeframes if available
- [ ] Export timeline from `scripts/process.py` output
- [ ] Screenshot/export SIEM correlation results
- [ ] Document chain of custody

## Containment Actions

- [ ] Isolate confirmed compromised hosts from network
- [ ] Disable compromised user accounts
- [ ] Block lateral movement paths (firewall rules)
- [ ] If DCSync detected: initiate credential rotation
- [ ] If PtH detected: force password reset for affected accounts
- [ ] Restrict RDP access to authorized admin workstations only

## Post-Incident

- [ ] Update Zeek detection thresholds based on findings
- [ ] Add legitimate admin share usage to allowlists
- [ ] Document lessons learned
- [ ] Update incident response playbook
- [ ] Schedule follow-up threat hunt in 30 days
- [ ] Brief stakeholders on findings and remediation

## Notes

_Use this space for free-form investigation notes, timeline reconstruction, and analyst observations._

---

**Template version:** 1.0
**Last updated:** 2025-03-17
**MITRE ATT&CK references:** TA0008, T1021.001, T1021.002, T1550.002, T1570, T1003.006
