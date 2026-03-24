# Detection Workflow — Lateral Movement with Zeek

## Overview

This document describes the end-to-end workflow for detecting lateral movement using Zeek network logs, from data collection through investigation and response.

## Workflow Stages

### Stage 1: Data Collection

```
Network Traffic (Span/TAP)
         │
         ▼
    Zeek Sensor
         │
         ├── conn.log          (all connections)
         ├── smb_mapping.log   (SMB share access)
         ├── dce_rpc.log       (DCE/RPC calls)
         ├── ntlm.log          (NTLM authentication)
         ├── files.log          (file transfers)
         └── notice.log        (Zeek-generated alerts)
```

**Requirements:**
- Zeek deployed on network tap/span port covering internal segments
- Protocol analyzers loaded: SMB, DCE/RPC, NTLM, RDP
- Log rotation configured (recommended: daily rotation, 90-day retention)

### Stage 2: Detection Rules

Apply detection logic via Zeek scripts and/or post-processing:

| Detection | Input Logs | Method |
|---|---|---|
| Admin Share Access | smb_mapping.log | Pattern match on `C$`, `ADMIN$`, `IPC$` |
| PsExec Execution | dce_rpc.log | Match `svcctl` endpoint + `CreateServiceW` |
| RDP Pivoting | conn.log | Graph analysis: host is both RDP client and server |
| NTLM Account Spray | ntlm.log | Same user from N+ distinct sources in time window |
| DCSync | dce_rpc.log | `drsuapi` endpoint + opnum 3 from non-DC |
| Tool Transfer | files.log | PE MIME type between internal hosts |

### Stage 3: Alert Triage

```
Detection Fires
      │
      ▼
┌─────────────────┐
│  Initial Triage  │
│                   │
│ 1. Is source a    │
│    known admin    │──Yes──▶ Log & reduce priority
│    workstation?   │
│                   │
│ 2. Is activity    │
│    during change  │──Yes──▶ Verify change ticket
│    window?        │
│                   │
│ 3. Multiple       │
│    indicators?    │──Yes──▶ ESCALATE immediately
└─────────────────┘
         │
         No match
         │
         ▼
   Standard investigation
```

### Stage 4: Investigation

For each confirmed alert, follow the investigation checklist (see `assets/template.md`):

1. **Identify the source host**
   - Query `conn.log` for all connections from the source in the alert timeframe
   - Check `ntlm.log` for authentication patterns
   - Look for preceding inbound connections (initial access vector)

2. **Map the movement chain**
   ```bash
   # Build connection graph for suspect host
   cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p | \
       awk '$1 == "SUSPECT_IP" || $2 == "SUSPECT_IP"' | sort -u
   ```

3. **Identify transferred payloads**
   ```bash
   # Find files transferred by suspect
   cat files.log | zeek-cut tx_hosts rx_hosts filename mime_type total_bytes | \
       grep "SUSPECT_IP"
   ```

4. **Check authentication anomalies**
   ```bash
   # NTLM auth from suspect host
   cat ntlm.log | zeek-cut ts id.orig_h username domainname success | \
       grep "SUSPECT_IP"
   ```

5. **Timeline reconstruction**
   - Correlate all log entries by timestamp
   - Build a chronological sequence of events
   - Identify initial compromise, lateral movement, and objectives

### Stage 5: Response

| Finding | Response Action |
|---|---|
| Confirmed lateral movement | Isolate affected hosts from network |
| NTLM Account Spray detected | Force password reset for compromised accounts |
| DCSync detected | Rotate krbtgt and affected credentials, audit DC access |
| Tool transfer identified | Extract and analyze transferred files |
| RDP pivot chain | Disable RDP on non-essential hosts, enforce NLA |

### Stage 6: Post-Incident

1. **Update baselines** — Add legitimate admin share usage to allowlists
2. **Tune detections** — Adjust thresholds based on false positive analysis
3. **Document findings** — Update incident report with Zeek evidence
4. **Improve coverage** — Deploy additional Zeek scripts for newly discovered TTPs

## Automation Integration

### SIEM Forwarding

```bash
# Forward Zeek logs to SIEM via syslog
# Add to local.zeek:
@load policy/tuning/json-logs.zeek

# Configure rsyslog/filebeat to ship JSON logs to SIEM
```

### SOAR Playbook Triggers

- Admin share access from non-admin workstation → Auto-isolate + ticket
- DCSync from non-DC → Emergency alert + auto-isolate
- NTLM Account Spray threshold exceeded → Auto-disable account + alert

## Continuous Improvement

- Review detection efficacy monthly
- Test with red team exercises quarterly
- Update MITRE ATT&CK mappings as new sub-techniques emerge
- Correlate Zeek findings with endpoint telemetry (EDR) for higher fidelity
