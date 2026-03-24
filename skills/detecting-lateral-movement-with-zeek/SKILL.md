---
name: detecting-lateral-movement-with-zeek
description: >
  Detect lateral movement in network traffic using Zeek (formerly Bro) log
  analysis. Parses conn.log, smb_mapping.log, smb_files.log, dce_rpc.log,
  kerberos.log, and ntlm.log to identify SMB file transfers, NTLM account
  spray activity, remote service execution, and anomalous internal connections.
domain: cybersecurity
subdomain: network-security
tags: [zeek, lateral-movement, smb, dce-rpc, ntlm-spray, network-forensics]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Detecting Lateral Movement with Zeek

Analyze Zeek network logs to identify lateral movement techniques including
SMB admin share access, DCE/RPC remote service creation, NTLM account spray,
Kerberos ticket anomalies, and large internal data transfers indicative
of staging or exfiltration between hosts.

## When to Use

- Hunting for lateral movement after an initial compromise indicator is found on one endpoint
- Investigating suspected NTLM account spray or Pass-the-Ticket attacks across the internal network
- Monitoring SMB traffic for unauthorized file transfers to admin shares (C$, ADMIN$, IPC$)
- Detecting remote service execution via DCE/RPC (PsExec, schtasks, WMI lateral patterns)
- Building alerting rules for internal network anomalies in a Zeek-based NSMP deployment
- Performing post-incident timeline reconstruction using Zeek logs as a network-level evidence source

**Do not use** as a standalone detection mechanism. Zeek sees network traffic only; combine with endpoint telemetry (Sysmon, EDR) for full visibility. Encrypted SMB3 traffic may limit Zeek's visibility into file-level details.

## Prerequisites

- Zeek 6.0+ deployed on a network tap or SPAN port monitoring internal VLAN traffic
- Zeek SMB analyzer enabled (loaded by default: `@load base/protocols/smb`)
- Zeek DCE/RPC analyzer enabled (`@load base/protocols/dce-rpc`)
- Zeek Kerberos analyzer enabled (`@load base/protocols/krb`)
- Python 3.8+ (standard library only)
- Access to Zeek log directory (default: `/opt/zeek/logs/current/`)
- Familiarity with Zeek TSV log format (fields separated by `\t`, header lines prefixed with `#`)

## Workflow

### Step 1: Verify Zeek Log Collection

Confirm that Zeek is producing the required log files for lateral movement detection:

```bash
# Check that all required analyzers are producing logs
ls -la /opt/zeek/logs/current/conn.log
ls -la /opt/zeek/logs/current/smb_mapping.log
ls -la /opt/zeek/logs/current/smb_files.log
ls -la /opt/zeek/logs/current/dce_rpc.log
ls -la /opt/zeek/logs/current/kerberos.log
ls -la /opt/zeek/logs/current/ntlm.log

# Quick field check on conn.log
zeek-cut id.orig_h id.resp_h id.resp_p proto service < /opt/zeek/logs/current/conn.log | head -20
```

### Step 2: Parse conn.log for Internal Lateral Patterns

Identify connections between internal hosts on lateral-movement-associated ports:

```bash
# Extract SMB connections (port 445) between internal hosts
zeek-cut ts id.orig_h id.orig_p id.resp_h id.resp_p proto service duration orig_bytes resp_bytes \
  < /opt/zeek/logs/current/conn.log \
  | awk '$5 == 445 && $7 == "smb"'

# Extract DCE/RPC connections (port 135)
zeek-cut ts id.orig_h id.resp_h id.resp_p service \
  < /opt/zeek/logs/current/conn.log \
  | awk '$4 == 135'

# Extract WinRM connections (port 5985/5986)
zeek-cut ts id.orig_h id.resp_h id.resp_p service \
  < /opt/zeek/logs/current/conn.log \
  | awk '$4 == 5985 || $4 == 5986'
```

### Step 3: Analyze SMB Admin Share Access

Detect access to administrative shares (C$, ADMIN$, IPC$) which is the primary vector for tools like PsExec:

```bash
# Check smb_mapping.log for admin share access
zeek-cut ts id.orig_h id.resp_h path share_type \
  < /opt/zeek/logs/current/smb_mapping.log \
  | grep -iE '(C\$|ADMIN\$|IPC\$)'

# Check smb_files.log for file writes to admin shares
zeek-cut ts id.orig_h id.resp_h action path name size \
  < /opt/zeek/logs/current/smb_files.log \
  | grep -i 'SMB::FILE_WRITE'
```

Deploy the following Zeek script to generate `notice.log` alerts on admin share access:

```zeek
@load base/protocols/smb
@load base/frameworks/notice

redef enum Notice::Type += {
    Admin_Share_Access
};

event smb1_tree_connect_andx_request(c: connection, hdr: SMB1::Header, path: string, service: string) {
    if ( /\$/ in path )
        NOTICE([$note=Admin_Share_Access,
                $msg=fmt("Admin share access: %s -> %s (%s)", c$id$orig_h, c$id$resp_h, path),
                $conn=c]);
}
```

### Step 4: Detect DCE/RPC Remote Service Operations

Monitor for remote service creation and scheduled task registration via DCE/RPC:

```bash
# Look for service control manager operations (PsExec pattern)
zeek-cut ts id.orig_h id.resp_h endpoint operation \
  < /opt/zeek/logs/current/dce_rpc.log \
  | grep -iE '(svcctl|atsvc|ITaskSchedulerService)'
```

### Step 5: Detect NTLM Account Spray

Analyze ntlm.log for authentication anomalies indicating credential reuse.
Zeek's ntlm.log does not expose password hashes, so this detection identifies
a single account authenticating to many hosts in a short window — the network
signature of credential spraying tools like CrackMapExec:

```bash
# Extract NTLM authentications
zeek-cut ts id.orig_h id.resp_h username domainname server_nb_computer_name success \
  < /opt/zeek/logs/current/ntlm.log

# Failed NTLM authentications (brute force or credential testing)
zeek-cut ts id.orig_h id.resp_h username success \
  < /opt/zeek/logs/current/ntlm.log \
  | awk '$5 == "F"'

# Sort by timestamp for timeline analysis
zeek-cut ts id.orig_h id.resp_h username success \
  < /opt/zeek/logs/current/ntlm.log \
  | sort -k1,1
```

Deploy the following Zeek script to generate `notice.log` alerts when a single
account touches more hosts than the threshold in a rolling window:

```zeek
@load base/protocols/ntlm
@load base/frameworks/notice

redef enum Notice::Type += {
    NTLM_Account_Spray
};

global ntlm_tracker: table[string] of set[addr] &create_expire=5min;
const spray_threshold = 3 &redef;

event ntlm_log(rec: NTLM::Info) {
    if ( ! rec?$username || rec$username == "-" )
        return;
    if ( rec$username !in ntlm_tracker )
        ntlm_tracker[rec$username] = set();
    add ntlm_tracker[rec$username][rec$id$resp_h];
    if ( |ntlm_tracker[rec$username]| >= spray_threshold )
        NOTICE([$note=NTLM_Account_Spray,
                $msg=fmt("NTLM account spray: %s -> %d hosts", rec$username, |ntlm_tracker[rec$username]|),
                $sub=rec$username,
                $conn=rec$id]);
}
```

### Step 6: Run the Automated Analysis Agent

Use the provided agent.py for comprehensive lateral movement detection:

```bash
python3 agent.py /opt/zeek/logs/current/
python3 agent.py /opt/zeek/logs/2026-03-18/  # Analyze a specific date
```

## Verification

- Confirm conn.log captures internal SMB (port 445) and DCE/RPC (port 135) connections with correct field parsing
- Verify smb_mapping.log correctly logs admin share paths (C$, ADMIN$, IPC$)
- Test with a known PsExec execution in a lab: expect to see SMB FILE_WRITE of the service binary followed by DCE/RPC svcctl CreateService
- Validate NTLM log parsing by performing a test authentication and confirming username, domain, and success fields are captured; verify the NTLM Account Spray Zeek script generates a `notice.log` entry when the spray threshold is exceeded
- Cross-reference Zeek alerts with Sysmon Event ID 1 (Process Creation) on the target host to confirm end-to-end detection
- Verify the agent correctly handles both TSV and JSON Zeek log formats
