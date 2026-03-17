---
name: detecting-lateral-movement-with-zeek
description: >
  Detect lateral movement in enterprise networks using Zeek (formerly Bro) network
  security monitor. Covers SMB-based lateral movement (PsExec, admin shares), RDP
  pivoting, Pass-the-Hash network indicators, and DCSync detection through Zeek log
  analysis and custom scripts.
domain: cybersecurity
subdomain: threat-hunting
tags:
  - zeek
  - lateral-movement
  - smb
  - rdp
  - network-analysis
  - mitre-attack
  - threat-hunting
  - pass-the-hash
  - dcsync
  - psexec
  - incident-response
  - network-forensics
version: "1.0"
mitre_attack:
  tactics:
    - TA0008  # Lateral Movement
  techniques:
    - T1021   # Remote Services
    - T1021.001  # Remote Desktop Protocol
    - T1021.002  # SMB/Windows Admin Shares
    - T1570   # Lateral Tool Transfer
    - T1550.002  # Pass the Hash
    - "T1003.006"  # DCSync
---

# Detecting Lateral Movement with Zeek

## Overview

Lateral movement is one of the most critical phases of an attack lifecycle. After gaining
initial access, adversaries move through the network to reach high-value targets — domain
controllers, file servers, databases. Zeek provides deep protocol-level visibility into
network traffic, making it an excellent tool for detecting these movements.

This skill covers how to use Zeek's built-in log types and custom scripts to identify
lateral movement techniques mapped to **MITRE ATT&CK Tactic TA0008 (Lateral Movement)**,
including:

- **SMB lateral movement** — PsExec, admin share access (`C$`, `ADMIN$`, `IPC$`)
- **RDP pivoting** — Unusual RDP sessions indicating pivot activity
- **Pass-the-Hash (PtH)** — Network-level indicators of NTLM credential reuse
- **DCSync** — Replication requests from non-domain-controller hosts

## Prerequisites

- **Zeek** (v5.0+) installed and capturing network traffic
- Access to Zeek log files (`conn.log`, `smb_mapping.log`, `smb_files.log`, `dce_rpc.log`, `ntlm.log`, `rdp.log`, `kerberos.log`)
- Python 3.8+ (for the analysis script in `scripts/process.py`)
- Basic understanding of Windows networking protocols (SMB, RDP, Kerberos, NTLM)
- Network baseline — know your normal DC-to-DC replication, admin RDP patterns, etc.

## Key Concepts

### Zeek Log Types for Lateral Movement Detection

| Log File | Protocol | Lateral Movement Relevance |
|---|---|---|
| `conn.log` | TCP/UDP | Internal host-to-host connections on key ports (445, 3389, 135) |
| `smb_mapping.log` | SMB | Share access — detects `C$`, `ADMIN$`, `IPC$` access |
| `smb_files.log` | SMB | File operations on shares — detect service binary drops |
| `dce_rpc.log` | DCE/RPC | RPC calls — detect PsExec service creation, DCSync |
| `ntlm.log` | NTLM | NTLM authentication — detect Pass-the-Hash patterns |
| `rdp.log` | RDP | RDP sessions — detect pivoting and unusual sessions |
| `kerberos.log` | Kerberos | Kerberos tickets — detect overpass-the-hash, golden tickets |

### Lateral Movement Indicators

1. **SMB Admin Share Access**: Connections to `\\host\C$`, `\\host\ADMIN$`, or `\\host\IPC$` from non-admin workstations
2. **PsExec Pattern**: IPC$ connection → service creation via SVCCTL → executable dropped to ADMIN$ → SMB execution
3. **RDP from Workstation to Workstation**: Workstations rarely RDP to other workstations; this is a strong lateral movement indicator
4. **NTLM after Kerberos**: In a domain environment, NTLM usage may indicate Pass-the-Hash (legitimate domain auth uses Kerberos)
5. **DCSync Replication**: `DRSGetNCChanges` RPC calls from non-DC hosts indicate credential theft

## Steps

### Step 1: Deploy Zeek with Lateral Movement Detection Scripts

Create a Zeek script to detect SMB admin share access:

```zeek
# lateral-movement/smb-admin-shares.zeek
# Detect access to administrative shares (C$, ADMIN$, IPC$) from non-admin hosts

@load base/protocols/smb

module LateralMovement;

export {
    redef enum Notice::Type += {
        SMB_Admin_Share_Access,
        SMB_Suspicious_File_Write,
    };

    ## Set of known admin/IT workstations allowed to access admin shares
    option admin_hosts: set[subnet] = {} &redef;
}

event smb2_tree_connect_request(c: connection, hdr: SMB2::Header, path: string) &priority=5
{
    local share = to_lower(path);

    if ( /\$/ in share )
    {
        local src = c$id$orig_h;

        if ( src !in admin_hosts )
        {
            NOTICE([
                $note=SMB_Admin_Share_Access,
                $msg=fmt("Non-admin host accessed admin share: %s -> %s", src, path),
                $conn=c,
                $src=src,
                $identifier=cat(src, path)
            ]);
        }
    }
}

event smb2_write_request(c: connection, hdr: SMB2::Header, file_id: SMB2::GUID,
                          offset: count, data_len: count)
{
    if ( c?$smb_state && c$smb_state?$current_tree )
    {
        local tree_path = to_lower(c$smb_state$current_tree$path);
        if ( /admin\$/ in tree_path )
        {
            NOTICE([
                $note=SMB_Suspicious_File_Write,
                $msg=fmt("File written to ADMIN$ share from %s", c$id$orig_h),
                $conn=c,
                $src=c$id$orig_h
            ]);
        }
    }
}
```

### Step 2: Detect PsExec-style Execution

```zeek
# lateral-movement/psexec-detect.zeek
# Detect PsExec-style remote execution via DCE/RPC SVCCTL

@load base/protocols/dce-rpc

module LateralMovement;

export {
    redef enum Notice::Type += {
        PsExec_Service_Install,
    };

    ## Track hosts that accessed IPC$ recently
    global ipc_access: table[addr] of set[addr] &create_expire=5min;
}

event dce_rpc_request(c: connection, fid: count, ctx_id: count,
                       opnum: count, stub_len: count)
{
    # SVCCTL CreateServiceW opnum = 12
    if ( c?$dce_rpc && c$dce_rpc?$endpoint && c$dce_rpc$endpoint == "svcctl" && opnum == 12 )
    {
        local src = c$id$orig_h;
        local dst = c$id$resp_h;

        NOTICE([
            $note=PsExec_Service_Install,
            $msg=fmt("Remote service creation (PsExec pattern): %s -> %s", src, dst),
            $conn=c,
            $src=src
        ]);
    }
}
```

### Step 3: Detect RDP Pivoting

```zeek
# lateral-movement/rdp-pivot.zeek
# Detect unusual RDP patterns indicating lateral movement

@load base/protocols/rdp

module LateralMovement;

export {
    redef enum Notice::Type += {
        RDP_Lateral_Movement,
        RDP_Workstation_to_Workstation,
    };

    ## Subnets containing servers — RDP to these is more expected
    option server_subnets: set[subnet] = {} &redef;

    ## Known jump hosts / bastion hosts
    option jump_hosts: set[addr] = {} &redef;

    ## Track RDP sessions per source
    global rdp_sessions: table[addr] of set[addr] &create_expire=1hr;
}

event rdp_connect_request(c: connection, cookie: string)
{
    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    # Skip known jump hosts
    if ( src in jump_hosts )
        return;

    # Track this session
    if ( src !in rdp_sessions )
        rdp_sessions[src] = set();
    add rdp_sessions[src][dst];

    # Alert: workstation-to-workstation RDP (neither in server subnets)
    if ( src !in server_subnets && dst !in server_subnets )
    {
        NOTICE([
            $note=RDP_Workstation_to_Workstation,
            $msg=fmt("Workstation-to-workstation RDP: %s -> %s (user: %s)", src, dst, cookie),
            $conn=c,
            $src=src,
            $identifier=cat(src, dst)
        ]);
    }

    # Alert: host RDPing to multiple destinations (pivot behavior)
    if ( |rdp_sessions[src]| >= 3 )
    {
        NOTICE([
            $note=RDP_Lateral_Movement,
            $msg=fmt("Host %s has RDP sessions to %d hosts (possible pivoting)", src, |rdp_sessions[src]|),
            $conn=c,
            $src=src,
            $identifier=cat(src, "rdp_pivot")
        ]);
    }
}
```

### Step 4: Detect Pass-the-Hash Network Indicators

```zeek
# lateral-movement/pass-the-hash.zeek
# Detect potential Pass-the-Hash via NTLM usage patterns

@load base/protocols/ntlm

module LateralMovement;

export {
    redef enum Notice::Type += {
        Pass_The_Hash_Suspected,
    };

    ## Track NTLM auth from hosts that normally use Kerberos
    global ntlm_auth_count: table[addr] of count &create_expire=1hr &default=0;

    ## Threshold for NTLM auths before alerting
    option ntlm_threshold: count = 5;
}

event ntlm_authenticate(c: connection, request: NTLM::Authenticate)
{
    local src = c$id$orig_h;
    ntlm_auth_count[src] += 1;

    # Multiple NTLM authentications to different hosts in short period
    # suggests Pass-the-Hash or credential spraying
    if ( ntlm_auth_count[src] >= ntlm_threshold )
    {
        local user = request?$user_name ? request$user_name : "<unknown>";
        local domain = request?$domain_name ? request$domain_name : "<unknown>";

        NOTICE([
            $note=Pass_The_Hash_Suspected,
            $msg=fmt("Possible Pass-the-Hash: %s (%s\\%s) — %d NTLM auths in short window",
                     src, domain, user, ntlm_auth_count[src]),
            $conn=c,
            $src=src,
            $identifier=cat(src, "pth")
        ]);
    }
}
```

### Step 5: Detect DCSync Attacks

```zeek
# lateral-movement/dcsync-detect.zeek
# Detect DCSync — DRSGetNCChanges from non-DC hosts

@load base/protocols/dce-rpc

module LateralMovement;

export {
    redef enum Notice::Type += {
        DCSync_Detected,
    };

    ## Known domain controllers
    option domain_controllers: set[addr] = {} &redef;
}

event dce_rpc_request(c: connection, fid: count, ctx_id: count,
                       opnum: count, stub_len: count)
{
    # DRSUAPI DRSGetNCChanges opnum = 3
    if ( c?$dce_rpc && c$dce_rpc?$endpoint && c$dce_rpc$endpoint == "drsuapi" && opnum == 3 )
    {
        local src = c$id$orig_h;

        if ( src !in domain_controllers )
        {
            NOTICE([
                $note=DCSync_Detected,
                $msg=fmt("DCSync detected: non-DC host %s requesting directory replication", src),
                $conn=c,
                $src=src,
                $identifier=cat(src, "dcsync")
            ]);
        }
    }
}
```

### Step 6: Analyze Zeek Logs with Python

Use the provided `scripts/process.py` script to parse Zeek logs and flag lateral movement indicators:

```bash
# Analyze conn.log for internal lateral movement patterns
python3 scripts/process.py --conn-log /var/log/zeek/current/conn.log

# Analyze SMB logs for admin share access
python3 scripts/process.py --smb-log /var/log/zeek/current/smb_mapping.log

# Full analysis across all relevant logs
python3 scripts/process.py --log-dir /var/log/zeek/current/ --output report.json
```

## Verification

1. **Test with known-good traffic**: Replay a PCAP with known lateral movement (e.g., from a red team exercise) through Zeek and verify detections fire.

2. **Validate notice.log**: After deploying scripts, check `notice.log` for expected alerts:
   ```bash
   cat notice.log | zeek-cut note msg src | grep LateralMovement
   ```

3. **Baseline tuning**: Run for 24–48 hours, review false positives, and tune:
   - Add legitimate admin hosts to `admin_hosts`
   - Add bastion hosts to `jump_hosts`
   - Add DCs to `domain_controllers`
   - Adjust `ntlm_threshold` based on environment

4. **Red team validation**: Execute controlled lateral movement techniques and confirm detection:
   - PsExec to a test host → should trigger `PsExec_Service_Install`
   - Access `\\target\C$` → should trigger `SMB_Admin_Share_Access`
   - RDP pivot chain → should trigger `RDP_Lateral_Movement`

## References

- See `references/standards.md` for MITRE ATT&CK mappings and Zeek documentation
- See `references/workflows.md` for the complete detection workflow
- See `assets/template.md` for an investigation checklist
