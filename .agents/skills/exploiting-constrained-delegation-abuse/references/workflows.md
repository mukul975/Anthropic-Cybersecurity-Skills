# Workflows - Constrained Delegation Abuse

## S4U Attack Chain

```
1. Enumerate → findDelegation.py or PowerView
2. Obtain account credentials → password, hash, or TGT
3. S4U2self → Request ticket as target user to compromised service
4. S4U2proxy → Forward ticket to delegated service (CIFS/LDAP/HTTP)
5. Access → Use ticket for privileged access to target service
6. Escalate → DCSync via LDAP or file access via CIFS
```

## Alternate Service Name Workflow

```
1. Delegation configured for: CIFS/DC01.domain.local
2. Request S4U ticket for CIFS as administrator
3. Modify SPN in ticket to LDAP/DC01.domain.local
4. Use modified ticket for DCSync (secretsdump.py -k)
5. Full domain compromise achieved
```
