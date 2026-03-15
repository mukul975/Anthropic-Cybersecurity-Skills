# Workflows: BloodHound AD Analysis

## BloodHound Analysis Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│              BLOODHOUND ANALYSIS WORKFLOW                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. DATA COLLECTION                                              │
│     ├── Select collector (SharpHound/AzureHound)                 │
│     ├── Choose collection method                                 │
│     │   ├── All (comprehensive, noisy)                           │
│     │   ├── DCOnly (LDAP only, stealthier)                       │
│     │   ├── Session (user sessions on computers)                 │
│     │   └── ACL (permission relationships)                       │
│     ├── Execute collection                                       │
│     └── Exfiltrate ZIP to analysis workstation                   │
│                                                                  │
│  2. DATA IMPORT                                                  │
│     ├── Start BloodHound CE/Neo4j                                │
│     ├── Upload collection ZIP                                    │
│     ├── Verify node counts (Users, Computers, Groups)            │
│     └── Mark owned principals and high-value targets             │
│                                                                  │
│  3. INITIAL ANALYSIS                                             │
│     ├── Run pre-built analytics                                  │
│     │   ├── Find all Domain Admins                               │
│     │   ├── Find Kerberoastable accounts                         │
│     │   ├── Find AS-REP Roastable accounts                       │
│     │   ├── Find unconstrained delegation                        │
│     │   └── Find shortest paths to DA                            │
│     ├── Identify high-value targets                              │
│     └── Document initial findings                                │
│                                                                  │
│  4. ATTACK PATH IDENTIFICATION                                   │
│     ├── Mark owned nodes                                         │
│     ├── Shortest path from owned to DA                           │
│     ├── Analyze ACL abuse paths                                  │
│     │   ├── GenericAll / GenericWrite                             │
│     │   ├── WriteDACL / WriteOwner                               │
│     │   ├── ForceChangePassword                                  │
│     │   └── AddMember                                            │
│     ├── Analyze delegation abuse                                 │
│     ├── Analyze GPO abuse paths                                  │
│     └── Prioritize attack paths by feasibility                   │
│                                                                  │
│  5. EXPLOITATION                                                 │
│     ├── Execute selected attack path                             │
│     ├── Kerberoast service accounts                              │
│     ├── Abuse ACL misconfigurations                              │
│     ├── Leverage delegation settings                             │
│     └── Mark newly owned principals                              │
│                                                                  │
│  6. REPORTING                                                    │
│     ├── Export attack path screenshots                           │
│     ├── Document each hop in attack chain                        │
│     ├── Map to MITRE ATT&CK techniques                          │
│     ├── Provide remediation for each finding                     │
│     └── Generate AD hardening recommendations                    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## SharpHound Collection Method Selection

```
Collection Method Decision
│
├── Need comprehensive data?
│   └── Use -c All (Collects everything)
│       Warning: Noisy, generates LDAP and SMB traffic
│
├── Need stealth?
│   └── Use -c DCOnly (Queries only DCs via LDAP)
│       Limitation: No session or local group data
│
├── Need session data over time?
│   └── Use -c Session --loop
│       Best for: Finding where admins are logged in
│
├── Azure AD environment?
│   └── Use AzureHound
│       Collects: Roles, App Registrations, Service Principals
│
└── Minimal footprint needed?
    └── Use -c Group,ACL
        Collects: Group memberships and ACL relationships only
```

## Attack Path Exploitation Decision Tree

```
BloodHound Shows Path to DA
│
├── Path via Kerberoastable account?
│   ├── Request TGS ticket (Rubeus/GetUserSPNs)
│   ├── Crack with hashcat (-m 13100)
│   └── Use cracked credential to continue path
│
├── Path via ACL abuse?
│   ├── GenericAll on user? → ForceChangePassword
│   ├── GenericAll on group? → Add self to group
│   ├── WriteDACL? → Grant self GenericAll, then abuse
│   ├── WriteOwner? → Change owner, then modify DACL
│   └── AddMember? → Add self to privileged group
│
├── Path via delegation?
│   ├── Unconstrained? → Coerce DC auth + capture TGT
│   ├── Constrained? → S4U2Self + S4U2Proxy abuse
│   └── RBCD? → Configure msDS-AllowedToActOnBehalf
│
├── Path via GPO?
│   ├── GenericWrite on GPO? → Add scheduled task
│   └── GpLink control? → Link malicious GPO to OU
│
└── Path via session?
    ├── Admin on computer with DA session?
    ├── Dump LSASS for DA credentials
    └── Or steal token/ticket
```

## BloodHound Edge Reference

| Edge Type | Meaning | Abuse Method |
|---|---|---|
| MemberOf | Group membership | Inherit group permissions |
| AdminTo | Local admin rights | PsExec, WMI, WinRM |
| HasSession | User logged in | Credential theft |
| GenericAll | Full control | Reset password, modify object |
| GenericWrite | Write properties | Set SPN, modify attributes |
| WriteDacl | Modify permissions | Grant self full control |
| WriteOwner | Change owner | Take ownership then WriteDacl |
| ForceChangePassword | Reset password | Change user password |
| AddMember | Add to group | Add self to privileged group |
| AllowedToDelegate | Constrained delegation | S4U2Proxy abuse |
| AllowedToAct | RBCD | Resource-based constrained delegation |
| CanRDP | RDP access | Remote desktop connection |
| CanPSRemote | WinRM access | PowerShell remoting |
| ExecuteDCOM | DCOM execution | Remote code execution |
| GPLink | GPO linked to OU | Modify GPO for code execution |
