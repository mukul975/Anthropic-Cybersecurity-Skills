# Workflows — Active Directory Penetration Testing

## AD Attack Flow

```
Domain User Credentials
    │
    ├── Enumeration
    │   ├── BloodHound (attack paths)
    │   ├── LDAP queries (users, groups, GPOs)
    │   └── Service account discovery (SPNs)
    │
    ├── Kerberos Attacks
    │   ├── Kerberoasting → Hash cracking
    │   ├── AS-REP Roasting → Hash cracking
    │   └── Delegation abuse (unconstrained/constrained/RBCD)
    │
    ├── ADCS Attacks
    │   ├── ESC1-ESC8 template exploitation
    │   └── Certificate-based auth to DA
    │
    ├── Credential Harvesting
    │   ├── LSASS dump (Mimikatz)
    │   ├── SAM/SYSTEM extraction
    │   └── DPAPI credential decryption
    │
    ├── Domain Escalation
    │   ├── DCSync (krbtgt + all hashes)
    │   ├── Golden Ticket
    │   └── AdminSDHolder persistence
    │
    └── Impact Demonstration
        ├── Full domain hash extraction
        ├── Access to sensitive resources
        └── Cross-forest trust abuse
```
