# Lateral Movement Investigation Checklist

## Initial Triage
- [ ] Zeek logs available: conn.log, smb_mapping.log, dce_rpc.log, ntlm.log
- [ ] Time window defined for investigation
- [ ] Baseline of normal admin share usage documented

## SMB Analysis
- [ ] Admin share access (ADMIN$, C$, IPC$) from unexpected sources identified
- [ ] SMB file transfers of executables (.exe, .dll, .ps1) detected
- [ ] PsExec pattern confirmed (IPC$ + svcctl DCE/RPC calls)

## Authentication Analysis
- [ ] NTLM pass-the-hash indicators checked (same user, multiple hosts, short window)
- [ ] Kerberoasting indicators reviewed (unusual TGS requests)
- [ ] Service account lateral usage assessed

## Network Pivot Analysis
- [ ] RDP pivot chains mapped (sequential connections through compromised hosts)
- [ ] Unusual east-west traffic volume identified
- [ ] New connections from previously quiet hosts flagged

## Response
- [ ] All compromised hosts identified and isolated
- [ ] Affected credentials reset
- [ ] Lateral movement paths blocked (network segmentation)
- [ ] Persistence mechanisms hunted on all touched systems
- [ ] Timeline of attack documented
