---
name: detecting-lateral-movement-with-zeek
description: Detect lateral movement techniques including SMB/RDP pivoting, PsExec execution, pass-the-hash attacks, and lateral tool transfer by analyzing Zeek network logs for anomalous internal east-west traffic patterns.
domain: cybersecurity
subdomain: threat-detection
tags: [zeek, lateral-movement, smb, rdp, network-analysis, threat-hunting, psexec, pass-the-hash, ntlm, dce-rpc]
version: "1.0"
author: juliosuas
license: Apache-2.0
mitre_attack: ["T1021", "T1570", "T1550.002", "T1021.002", "T1021.001"]
---

# Detecting Lateral Movement with Zeek

## Overview

Lateral movement is a critical phase in the attack lifecycle (MITRE ATT&CK TA0008) where adversaries pivot through internal systems after initial compromise. Zeek's deep protocol analysis generates structured logs for SMB, DCE/RPC, NTLM, Kerberos, and RDP sessions, enabling detection of PsExec-style remote execution, pass-the-hash authentication, admin share access, RDP pivoting chains, and lateral tool transfers — all without endpoint agents.

## Prerequisites

- Zeek 5.0+ deployed on network tap or SPAN port capturing east-west traffic
- Python 3.9+ with pandas for log analysis
- Understanding of SMB/CIFS protocol and Windows authentication
- Access to internal network segments (not just perimeter)
- Familiarity with Zeek log formats (conn.log, smb_mapping.log, dce_rpc.log, ntlm.log, kerberos.log)

## Key Concepts

| Concept | Zeek Log | Detection Signal |
|---------|----------|-----------------|
| **PsExec Execution** | smb_mapping.log, dce_rpc.log | SMB map to ADMIN$ or IPC$ followed by DCE/RPC svcctl calls |
| **Pass-the-Hash** | ntlm.log | NTLM auth with same hash across multiple hosts in short timeframe |
| **RDP Pivoting** | conn.log | Sequential RDP (3389) connections from newly compromised hosts |
| **Admin Share Access** | smb_mapping.log | Mapping to C$, ADMIN$, IPC$ shares from non-admin workstations |
| **Lateral Tool Transfer** | smb_files.log | Executable files (.exe, .dll, .ps1) written to remote shares |
| **DCSync** | dce_rpc.log | DrsReplicaAdd/DrsGetNCChanges calls to domain controller |

## Steps

### Step 1: Monitor SMB Admin Share Access

```zeek
# lateral-smb.zeek — Detect admin share mappings
@load base/protocols/smb

event smb1_tree_connect_andx_request(c: connection, hdr: SMB1::Header, path: string, service: string) {
    if (/ADMIN\$|C\$|IPC\$/ in path) {
        local msg = fmt("Admin share access: %s -> %s:%s", c$id$orig_h, c$id$resp_h, path);
        NOTICE([$note=SMB::AdminShareAccess,
                $msg=msg,
                $conn=c,
                $identifier=cat(c$id$orig_h, c$id$resp_h, path)]);
    }
}

event smb2_tree_connect_request(c: connection, hdr: SMB2::Header, path: string) {
    if (/ADMIN\$|C\$|IPC\$/ in path) {
        NOTICE([$note=SMB::AdminShareAccess,
                $msg=fmt("SMB2 admin share: %s -> %s:%s", c$id$orig_h, c$id$resp_h, path),
                $conn=c]);
    }
}
```

### Step 2: Detect PsExec-Style Execution

```zeek
# lateral-psexec.zeek — Detect PsExec via DCE/RPC service control
@load base/protocols/dce-rpc

event dce_rpc_request(c: connection, fid: count, opnum: count, stub_len: count) {
    # svcctl operations: CreateServiceW (0x0c), StartServiceW (0x13)
    if (c$dce_rpc$endpoint == "svcctl" && (opnum == 12 || opnum == 19)) {
        NOTICE([$note=DCE_RPC::PsExecDetected,
                $msg=fmt("PsExec-style service creation: %s -> %s (svcctl opnum %d)",
                         c$id$orig_h, c$id$resp_h, opnum),
                $conn=c]);
    }
}
```

### Step 3: Detect Pass-the-Hash via NTLM

```bash
# Analyze ntlm.log for same NTLM hash used across multiple destinations
zeek-cut ts id.orig_h id.resp_h username server_dns_computer_name < ntlm.log | \
  awk '{print $3, $4, $5}' | sort | uniq -c | sort -rn | head -20
```

### Step 4: Identify RDP Pivot Chains

```bash
# Find sequential RDP connections suggesting pivoting
zeek-cut ts id.orig_h id.resp_h id.resp_p duration < conn.log | \
  awk '$4 == 3389 {print $1, $2, $3}' | \
  sort -k2 | \
  awk '{
    if ($2 == prev_dst) {
      print "PIVOT: " prev_src " -> " $2 " -> " $3 " (via RDP chain)"
    }
    prev_src = $2; prev_dst = $3
  }'
```

### Step 5: Detect Lateral Tool Transfer

```bash
# Find executables transferred via SMB
zeek-cut ts id.orig_h id.resp_h name size < smb_files.log | \
  grep -iE '\.(exe|dll|ps1|bat|vbs|scr|com)$' | \
  sort -k5 -rn
```

## Expected Output

```
# PsExec Detection
[notice] PsExec-style service creation: 10.0.1.50 -> 10.0.1.100 (svcctl opnum 12)
[notice] PsExec-style service creation: 10.0.1.50 -> 10.0.1.101 (svcctl opnum 19)

# Admin Share Access
[notice] SMB2 admin share: 10.0.1.50 -> 10.0.1.100:ADMIN$
[notice] SMB2 admin share: 10.0.1.50 -> 10.0.1.101:C$

# RDP Pivot Chain
PIVOT: 10.0.1.5 -> 10.0.1.50 -> 10.0.1.100 (via RDP chain)
PIVOT: 10.0.1.50 -> 10.0.1.100 -> 10.0.2.20 (via RDP chain)

# Lateral Tool Transfer
2026-03-15T14:32:00  10.0.1.50  10.0.1.100  payload.exe  245760
2026-03-15T14:33:12  10.0.1.50  10.0.1.101  mimikatz.exe  1310720
```

## Verification

1. Deploy Zeek scripts on test network and confirm logs generate for SMB/RDP traffic
2. Run PsExec against test host and verify `dce_rpc.log` captures svcctl operations
3. Validate NTLM analysis script correctly identifies same-hash multi-host authentication
4. Test RDP pivot detection with sequential RDP sessions across 3+ hosts
5. Confirm file transfer detection catches `.exe` and `.dll` files in `smb_files.log`
