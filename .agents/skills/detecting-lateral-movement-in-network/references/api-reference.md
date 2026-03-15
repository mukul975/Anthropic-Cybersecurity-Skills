# Lateral Movement Detection API Reference

## Windows Event IDs for Lateral Movement

| Event ID | Log | Significance |
|----------|-----|-------------|
| 4624 (Type 3) | Security | Network logon (SMB, PsExec) |
| 4624 (Type 10) | Security | RDP logon |
| 4625 | Security | Failed logon attempt |
| 4648 | Security | Explicit credential use (RunAs) |
| 4672 | Security | Admin privileges assigned |
| 4768 | Security | Kerberos TGT request |
| 4769 | Security | Kerberos service ticket |
| 4776 | Security | NTLM credential validation |
| 7045 | System | New service installed (PsExec) |

## Zeek Log Files for Lateral Movement

| Log | Content |
|-----|---------|
| `conn.log` | All connections (filter internal-to-internal) |
| `smb_mapping.log` | SMB share access |
| `smb_files.log` | SMB file operations |
| `dce_rpc.log` | DCE/RPC calls (PsExec, WMI) |
| `kerberos.log` | Kerberos ticket operations |
| `ntlm.log` | NTLM authentication events |
| `rdp.log` | RDP connection metadata |

## Zeek Script - Lateral Movement Detection

```zeek
event connection_established(c: connection) {
    if (Site::is_local_addr(c$id$orig_h) && Site::is_local_addr(c$id$resp_h)) {
        if (c$id$resp_p == 445/tcp || c$id$resp_p == 3389/tcp || c$id$resp_p == 5985/tcp) {
            NOTICE([
                $note=LateralMovement::Suspicious,
                $conn=c,
                $msg=fmt("Lateral: %s -> %s:%s", c$id$orig_h, c$id$resp_h, c$id$resp_p)
            ]);
        }
    }
}
```

## Splunk SPL - Lateral Movement Queries

```spl
# Multiple hosts accessed from single source
index=wineventlog EventCode=4624 LogonType=3
| stats dc(ComputerName) as targets values(ComputerName) as hosts by SourceIP Account_Name
| where targets > 5

# PsExec detection (service install after network logon)
index=wineventlog EventCode=7045 ServiceName="PSEXESVC"
| table _time ComputerName ServiceName ServiceFileName AccountName

# Pass-the-hash (NTLM Type 3 without prior Type 10)
index=wineventlog EventCode=4624 LogonType=3 AuthenticationPackageName=NTLM
| stats count by SourceIP ComputerName Account_Name
```

## python-evtx - Parse EVTX Files

```python
import Evtx.Evtx as evtx

with evtx.Evtx("Security.evtx") as log:
    for record in log.records():
        xml = record.xml()
        if "<EventID>4624</EventID>" in xml:
            print(record.timestamp(), xml)
```

## MITRE ATT&CK Lateral Movement (TA0008)

| Technique | ID | Detection |
|-----------|-------|-----------|
| Remote Services: SMB | T1021.002 | Port 445 + 7045 events |
| Remote Services: RDP | T1021.001 | Port 3389 + 4624 Type 10 |
| Remote Services: WinRM | T1021.006 | Port 5985/5986 |
| Lateral Tool Transfer | T1570 | SMB file operations |
| Pass the Hash | T1550.002 | NTLM Type 3 from workstation |
