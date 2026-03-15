# API Reference: Zerologon (CVE-2020-1472)

## Vulnerability Overview
- **CVE**: CVE-2020-1472
- **CVSS**: 10.0 (Critical)
- **Protocol**: MS-NRPC (Netlogon Remote Protocol)
- **Port**: 135 (RPC)
- **Impact**: Domain Admin without credentials

## Attack Mechanism
The Netlogon AES-CFB8 implementation uses a static IV of zero bytes.
Sending authentication requests with 256 zero bytes succeeds with
probability 1/256 per attempt.

## Detection Tools

### Nmap
```bash
nmap -p 135,445 --script smb-vuln-cve-2020-1472 <DC_IP>
```

### Impacket zerologon_tester.py
```bash
zerologon_tester.py DC01 10.10.10.1
```

### CrackMapExec
```bash
crackmapexec smb <DC_IP> -u '' -p '' -M zerologon
```

## Patch Information

### Microsoft KBs
| KB | OS Version |
|----|-----------|
| KB4571694 | Windows Server 2016 |
| KB4571703 | Windows Server 2019 |
| KB4571723 | Windows Server 2012 R2 |
| KB4571736 | Windows Server 2012 |

### Registry Key for Enforcement
```
HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters
FullSecureChannelProtection = 1 (DWORD)
```

## MS-NRPC Protocol

### NetrServerAuthenticate3
```
DCERPC call to \PIPE\netlogon
Function: NetrServerAuthenticate3
ClientCredential: 8 zero bytes
NegotiateFlags: 0x212fffff
```

### Authentication Flow
1. Client calls `NetrServerReqChallenge` (sends 8 zero bytes)
2. Server responds with ServerChallenge
3. Client calls `NetrServerAuthenticate3` (ClientCredential = zeros)
4. On success (~1/256), client sets DC machine password to empty

## Event Log Detection

### Event IDs
| Event | Source | Description |
|-------|--------|-------------|
| 5827 | Netlogon | Vulnerable connection denied |
| 5828 | Netlogon | Vulnerable connection allowed |
| 5829 | Netlogon | Vulnerable connection (audit mode) |
| 5830 | Netlogon | Device allowed by GPO exception |
| 5831 | Netlogon | Device denied |

### KQL Detection
```kql
SecurityEvent
| where EventID in (5827, 5828, 5829)
| project TimeGenerated, Computer, EventData
```

## Remediation
1. Apply KB patches immediately
2. Set `FullSecureChannelProtection = 1`
3. Monitor Event IDs 5827-5831
4. Block RPC port 135 from untrusted networks
5. Enable DC enforcement mode
