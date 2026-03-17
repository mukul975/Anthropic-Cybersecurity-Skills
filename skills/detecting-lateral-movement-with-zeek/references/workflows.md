# Lateral Movement Detection Workflow

## Overview

This document describes the end-to-end workflow for detecting, triaging, and
investigating lateral movement using Zeek network data.

## Phase 1: Data Collection

### Required Zeek Logs

Ensure Zeek is configured to generate all relevant logs:

```bash
# Verify required scripts are loaded in local.zeek
@load base/protocols/smb
@load base/protocols/dce-rpc
@load base/protocols/rdp
@load base/protocols/ntlm
@load base/protocols/krb

# Load lateral movement detection scripts
@load ./lateral-movement/smb-admin-shares.zeek
@load ./lateral-movement/psexec-detect.zeek
@load ./lateral-movement/rdp-pivot.zeek
@load ./lateral-movement/pass-the-hash.zeek
@load ./lateral-movement/dcsync-detect.zeek
```

### Log Rotation and Retention

- Keep at least 30 days of Zeek logs for investigation
- Ensure `conn.log` rotation handles high-volume environments
- Forward `notice.log` to SIEM in real-time

## Phase 2: Detection

### Real-Time Detection (Zeek Scripts)

The Zeek scripts in this skill generate notices for:

1. **SMB_Admin_Share_Access** — Non-admin host accessing C$, ADMIN$, IPC$
2. **SMB_Suspicious_File_Write** — File written to ADMIN$ share
3. **PsExec_Service_Install** — Remote service creation via SVCCTL
4. **RDP_Workstation_to_Workstation** — RDP between non-server hosts
5. **RDP_Lateral_Movement** — Single host with RDP to 3+ destinations
6. **Pass_The_Hash_Suspected** — NTLM authentication burst from single source
7. **DCSync_Detected** — Directory replication request from non-DC host

### Batch Analysis (Python Script)

Run `scripts/process.py` periodically or on-demand:

```
┌─────────────────────────────────────────────────┐
│              Zeek Log Directory                   │
│  conn.log │ smb_mapping.log │ dce_rpc.log │ ... │
└─────────────────┬───────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────┐
│             process.py                            │
│                                                   │
│  1. Parse conn.log → internal connections         │
│  2. Parse smb_mapping.log → admin share access    │
│  3. Parse dce_rpc.log → suspicious RPC calls      │
│  4. Correlate across logs by connection UID        │
│  5. Score and rank findings                       │
│  6. Output JSON report                            │
└─────────────────┬───────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────┐
│              report.json                          │
│  High-severity findings for investigation         │
└─────────────────────────────────────────────────┘
```

## Phase 3: Triage

### Severity Classification

| Severity | Indicators | Action |
|---|---|---|
| **Critical** | DCSync from non-DC; PsExec + admin share write from unknown host | Immediate incident response |
| **High** | Admin share access from non-admin host; workstation-to-workstation RDP chain | Investigate within 1 hour |
| **Medium** | NTLM auth burst; single unusual RDP session | Investigate within 4 hours |
| **Low** | Admin share access from known-but-unusual admin host | Review during daily triage |

### False Positive Reduction

Common false positives and how to handle them:

1. **IT admin tools** (SCCM, PDQ Deploy) → Add to `admin_hosts` allowlist
2. **Vulnerability scanners** → Add scanner IPs to exclusion list
3. **Backup software** (Veeam, Commvault) → Exclude backup server IPs
4. **Domain controller replication** → Ensure all DCs are in `domain_controllers` set
5. **Help desk remote support** → Add help desk tools to `jump_hosts`

## Phase 4: Investigation

### Investigation Steps

For each high-severity alert:

1. **Identify the source host**
   ```bash
   # Get all connections from the suspicious source in the time window
   cat conn.log | zeek-cut ts uid id.orig_h id.resp_h id.resp_p proto service \
     | grep "SOURCE_IP"
   ```

2. **Map the movement chain**
   ```bash
   # Find all SMB connections from the source
   cat smb_mapping.log | zeek-cut ts uid id.orig_h id.resp_h path \
     | grep "SOURCE_IP"
   
   # Find all RDP connections
   cat rdp.log | zeek-cut ts uid id.orig_h id.resp_h cookie \
     | grep "SOURCE_IP"
   ```

3. **Check authentication logs**
   ```bash
   # NTLM auth from the source
   cat ntlm.log | zeek-cut ts uid id.orig_h id.resp_h username domainname \
     | grep "SOURCE_IP"
   
   # Kerberos activity
   cat kerberos.log | zeek-cut ts uid id.orig_h id.resp_h client service \
     | grep "SOURCE_IP"
   ```

4. **Correlate with conn.log for full picture**
   ```bash
   # All internal connections from the source, sorted by time
   cat conn.log | zeek-cut ts uid id.orig_h id.resp_h id.resp_p service \
     | grep "SOURCE_IP" | sort -t$'\t' -k1
   ```

5. **Build timeline** — Combine all findings into a chronological sequence

### Pivot Points

From a confirmed compromised host, investigate:

- All hosts it connected to (potential further compromise)
- All hosts that connected to it (potential initial access vector)
- Credentials used (check ntlm.log, kerberos.log for usernames)
- Files transferred (check smb_files.log, files.log)

## Phase 5: Response

### Containment

1. Isolate confirmed compromised hosts at the network level
2. Disable compromised accounts
3. Block lateral movement ports between workstation segments (if not already segmented)

### Remediation

1. Reimage compromised hosts
2. Reset credentials for affected accounts
3. Review and enhance network segmentation
4. Deploy additional monitoring on affected segments

### Post-Incident

1. Update Zeek allowlists/blocklists based on findings
2. Tune detection thresholds
3. Document new TTPs observed
4. Update `assets/template.md` investigation checklist
