# NTLM Relay Attack Detection Reference

## Windows Event IDs

| Event ID | Log | Description |
|----------|-----|-------------|
| 4624 | Security | Successful logon — primary relay detection event |
| 4625 | Security | Failed logon — may indicate relay attempts |
| 5145 | Security | Network share object access — named pipe monitoring |
| 4776 | Security | NTLM credential validation |

## Event 4624 Fields for Relay Detection

| Field | Suspicious Value | Significance |
|-------|-----------------|--------------|
| LogonType | 3 (Network) | Relay always produces network logon |
| AuthenticationPackageName | NTLMSSP | NTLM used instead of Kerberos |
| LmPackageName | NTLM V1 | Downgraded to NTLMv1 (very suspicious) |
| WorkstationName | Mismatch with IpAddress | Key relay indicator |
| TargetUserSid | S-1-0-0 (NULL SID) | Unauthenticated relay attempt |
| LogonGuid | {00000000-...} | Empty GUID indicates relay |
| ImpersonationLevel | Impersonation | Relay uses impersonation |

## Suspicious Named Pipes (Event 5145)

| Pipe Name | Service | Relay Target |
|-----------|---------|-------------|
| `spoolss` | Print Spooler | PrinterBug/SpoolSample |
| `lsarpc` | LSA | PetitPotam, DFSCoerce |
| `netlogon` | Netlogon | ZeroLogon relay |
| `samr` | SAM | User enumeration |
| `efsrpc` | EFS | PetitPotam |
| `netdfs` | DFS | DFSCoerce |
| `srvsvc` | Server Service | General relay |

## Splunk Detection Query

```spl
index=wineventlog EventCode=4624 Logon_Type=3 Authentication_Package=NTLM
| eval hostname_ip_match=if(Workstation_Name==src_ip OR isnull(Workstation_Name), "match", "mismatch")
| where hostname_ip_match="mismatch"
| stats count values(src_ip) as source_ips values(Workstation_Name) as workstations by Account_Name, Computer
| where count > 3
```

## Elastic EQL Detection (NTLM Relay Against Computer Account)

```eql
sequence by winlog.computer_name with maxspan=5s
  [any where event.code == "5145" and
    winlog.event_data.RelativeTargetName in ("spoolss","netdfs","lsarpc","samr","efsrpc","netlogon") and
    winlog.event_data.SubjectUserName != winlog.computer_name]
  [authentication where event.code in ("4624","4625") and
    winlog.event_data.AuthenticationPackageName == "NTLM" and
    winlog.event_data.LogonType == "3" and
    winlog.event_data.TargetUserName : "*$"]
```

## PowerShell Detection

```powershell
# Query NTLM type 3 logons
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} |
  Where-Object {
    $_.Properties[8].Value -eq 3 -and
    $_.Properties[14].Value -match 'NTLM'
  } | Select-Object TimeCreated,
    @{N='User';E={$_.Properties[5].Value}},
    @{N='Workstation';E={$_.Properties[11].Value}},
    @{N='SourceIP';E={$_.Properties[18].Value}},
    @{N='AuthPkg';E={$_.Properties[14].Value}}

# Check SMB signing
Get-SmbServerConfiguration | Select-Object RequireSecuritySignature, EnableSecuritySignature
```

## SMB Signing Enforcement

```powershell
# Enable SMB signing (require on server)
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force

# Group Policy path
# Computer Configuration > Policies > Windows Settings > Security Settings >
# Local Policies > Security Options >
# Microsoft network server: Digitally sign communications (always): Enabled
```

## Common Relay Tools (Detection Signatures)

| Tool | Network Signature |
|------|------------------|
| Responder | LLMNR/NBT-NS responses from non-authoritative source |
| ntlmrelayx | Rapid sequential NTLM auth from single source IP |
| PetitPotam | EFS RPC calls to \\attacker\share via lsarpc pipe |
| PrinterBug | RPC call to spoolss pipe targeting attacker listener |
| mitm6 | DHCPv6 responses with rogue DNS server |

## MITRE ATT&CK Mapping

- **T1557.001** — Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay
- **T1187** — Forced Authentication
- **T1003.001** — OS Credential Dumping: LSASS Memory
- **TA0006** — Credential Access (Tactic)

## Response Checklist

1. Enable SMB signing on all domain hosts via GPO
2. Disable LLMNR: `Set-DnsClientGlobalSetting -SuffixSearchList @("")`
3. Disable NBT-NS in network adapter advanced settings
4. Enable Extended Protection for Authentication (EPA)
5. Enforce NTLMv2 and deny NTLMv1: `LmCompatibilityLevel = 5`
6. Deploy SMB signing GPO: `RequireSecuritySignature = 1`
