# Workflows - DCSync Domain Persistence

## DCSync Attack Chain

```
1. Prerequisites
   ├── Domain Admin or account with replication rights
   ├── Network access to Domain Controller (TCP/135, dynamic RPC)
   └── Tool: Mimikatz (Windows) or secretsdump.py (Linux)

2. Credential Extraction
   ├── Extract KRBTGT hash (Golden Ticket capability)
   ├── Extract Administrator hash (immediate DA access)
   ├── Extract all domain hashes (comprehensive dump)
   └── Extract service account hashes (lateral movement)

3. Golden Ticket Persistence
   ├── Forge Golden Ticket with KRBTGT hash
   ├── Set arbitrary user, SID, and group memberships
   ├── Import ticket into current session
   └── Access any resource in the domain

4. DCSync Rights Persistence
   ├── Create low-profile account in AD
   ├── Grant DS-Replication-Get-Changes-All rights
   ├── Verify rights with ACL enumeration
   └── Account can now perform DCSync independently
```

## Golden Ticket Lifecycle

```
Creation: KRBTGT hash + Domain SID → Golden Ticket (10-year validity)
Usage: Import ticket → Access any service in domain
Survival: Persists through password resets (except double KRBTGT reset)
Detection: Anomalous TGT lifetime, non-existent users, impossible SIDs
Cleanup: Double KRBTGT password reset (with 10+ hour gap between resets)
```
