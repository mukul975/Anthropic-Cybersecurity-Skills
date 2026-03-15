# Workflows — Internal Network Penetration Testing

## Attack Flow

```
Network Access (Ethernet/VPN)
    │
    ├── Network Discovery (Nmap, ARP scan)
    │
    ├── Credential Capture (Responder, mitm6)
    │       │
    │       └── Hash Cracking (Hashcat)
    │
    ├── AD Enumeration (BloodHound, LDAP)
    │       │
    │       ├── Kerberoasting
    │       ├── AS-REP Roasting
    │       └── GPP Password Extraction
    │
    ├── Lateral Movement (PsExec, WMI, WinRM)
    │       │
    │       └── Credential Harvesting (Mimikatz, LSASS dump)
    │
    ├── Privilege Escalation
    │       │
    │       ├── Local (unquoted paths, token impersonation)
    │       └── Domain (DCSync, Golden Ticket, ADCS)
    │
    └── Impact Demonstration
            ├── Sensitive data access
            ├── Domain compromise proof
            └── Attack path documentation
```

## Evidence Collection Workflow

```
evidence/
├── credentials/
│   ├── responder_captures/
│   ├── cracked_hashes/
│   └── dumped_creds/
├── screenshots/
├── bloodhound/
│   └── domain_data.json
├── scan_results/
│   ├── nmap/
│   └── shares/
└── attack_paths/
    └── path_documentation.md
```
