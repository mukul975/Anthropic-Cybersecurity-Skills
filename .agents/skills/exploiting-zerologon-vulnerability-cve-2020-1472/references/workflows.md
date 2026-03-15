# Workflows: Zerologon Exploitation

## Exploitation Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│                ZEROLOGON EXPLOITATION WORKFLOW                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. RECONNAISSANCE                                               │
│     ├── Identify domain controllers (DNS SRV records)            │
│     ├── Verify network access to DC (TCP 135, RPC)               │
│     └── Check patch status with zerologon_tester.py              │
│                                                                  │
│  2. EXPLOITATION                                                 │
│     ├── Run CVE-2020-1472 exploit (~256 attempts, ~3 seconds)    │
│     ├── DC machine account password set to empty                 │
│     └── Verify exploitation success                              │
│                                                                  │
│  3. CREDENTIAL EXTRACTION                                        │
│     ├── DCSync with empty hash (secretsdump.py -no-pass)         │
│     ├── Extract Administrator NTLM hash                          │
│     ├── Extract krbtgt hash (for Golden Ticket)                  │
│     └── Extract all domain user hashes                           │
│                                                                  │
│  4. DOMAIN ACCESS                                                │
│     ├── Pass-the-Hash as Administrator                           │
│     ├── Access any domain system                                 │
│     └── Create Golden Ticket for persistence                     │
│                                                                  │
│  5. RESTORATION (CRITICAL)                                       │
│     ├── Restore DC machine account password immediately          │
│     ├── Verify AD replication is functioning                     │
│     └── Document exploitation and restoration timestamps         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Impact Assessment

```
Zerologon Impact Chain
│
├── DC Machine Account Password Reset to Empty
│   ├── AD Replication BREAKS (secrets no longer sync)
│   ├── DNS may stop functioning
│   ├── Group Policy stops processing
│   └── Kerberos ticket validation fails
│
├── DCSync with Empty Hash
│   ├── ALL domain password hashes extracted
│   ├── krbtgt hash = Golden Ticket capability
│   └── Service account hashes = lateral movement
│
└── Full Domain Compromise
    ├── Administrator access to all systems
    ├── Ability to create/modify any account
    └── Complete control over Active Directory
```

**RED TEAM WARNING**: Always restore the DC machine account password immediately after exploitation. Failing to do so will cause Active Directory to break, potentially causing a production outage.
