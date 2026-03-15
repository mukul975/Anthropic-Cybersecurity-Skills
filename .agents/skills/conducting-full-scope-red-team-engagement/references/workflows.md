# Workflows: Full-Scope Red Team Engagement

## Engagement Lifecycle Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│                    RED TEAM ENGAGEMENT LIFECYCLE                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. SCOPING & PLANNING                                           │
│     ├── Define Rules of Engagement (RoE)                         │
│     ├── Identify threat actors to emulate                        │
│     ├── Define objectives and success criteria                   │
│     ├── Establish communication channels and emergency stops     │
│     └── Legal authorization and sign-off                         │
│                                                                  │
│  2. RECONNAISSANCE (2-4 weeks)                                   │
│     ├── Passive OSINT collection                                 │
│     │   ├── DNS enumeration (Amass, subfinder)                   │
│     │   ├── Email harvesting (theHarvester)                      │
│     │   ├── Social media profiling (LinkedIn, Twitter)           │
│     │   └── Credential breach searches (DeHashed)                │
│     ├── Active scanning (if in scope)                            │
│     │   ├── Port/service scanning (Nmap)                         │
│     │   ├── Web application discovery (Aquatone)                 │
│     │   └── Vulnerability scanning (Nuclei)                      │
│     └── Target prioritization matrix                             │
│                                                                  │
│  3. WEAPONIZATION (1-2 weeks)                                    │
│     ├── Develop custom payloads                                  │
│     │   ├── Shellcode generation and encryption                  │
│     │   ├── Loader development (C/C++, Rust, Nim)                │
│     │   └── Sandbox evasion techniques                           │
│     ├── Configure C2 infrastructure                              │
│     │   ├── Deploy team server (Havoc/Cobalt Strike)             │
│     │   ├── Set up HTTPS redirectors                             │
│     │   ├── Configure domain fronting or CDN                     │
│     │   └── Test beacon callbacks                                │
│     └── Prepare phishing infrastructure                          │
│         ├── Register look-alike domains                          │
│         ├── Configure SPF/DKIM/DMARC                             │
│         └── Design email templates                               │
│                                                                  │
│  4. INITIAL ACCESS (1-2 weeks)                                   │
│     ├── Execute phishing campaign (T1566)                        │
│     ├── Exploit external services (T1190)                        │
│     ├── Credential stuffing/spraying (T1110)                     │
│     ├── Supply chain vectors (T1195)                             │
│     └── Physical access attempts (if in scope)                   │
│                                                                  │
│  5. POST-EXPLOITATION (2-4 weeks)                                │
│     ├── Establish persistence (T1053, T1547)                     │
│     ├── Privilege escalation                                     │
│     │   ├── Local priv esc (T1068, T1548)                        │
│     │   └── Domain priv esc (Kerberoasting, DCSync)              │
│     ├── Credential harvesting                                    │
│     │   ├── LSASS dump (T1003.001)                               │
│     │   ├── SAM database (T1003.002)                             │
│     │   └── Kerberos tickets (T1558)                             │
│     ├── Lateral movement                                         │
│     │   ├── SMB (T1021.002)                                      │
│     │   ├── WMI (T1047)                                          │
│     │   ├── WinRM (T1021.006)                                    │
│     │   └── RDP (T1021.001)                                      │
│     └── Objective pursuit                                        │
│         ├── Crown jewel identification                           │
│         ├── Data staging (T1074)                                 │
│         └── Exfiltration demonstration (T1041)                   │
│                                                                  │
│  6. REPORTING & DEBRIEF (1-2 weeks)                              │
│     ├── Attack narrative with timeline                           │
│     ├── MITRE ATT&CK heat map                                   │
│     ├── Detection gap analysis                                   │
│     ├── Remediation recommendations                              │
│     ├── Executive debrief presentation                           │
│     └── Purple team follow-up sessions                           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Decision Tree: Initial Access Vector Selection

```
START: Select Initial Access Vector
│
├── Is phishing in scope?
│   ├── YES → Target high-value employees
│   │         ├── C-suite → CEO fraud / whale phishing
│   │         ├── IT Staff → Credential harvesting
│   │         └── HR/Finance → Malicious attachment
│   └── NO → Proceed to external attack surface
│
├── External-facing services found?
│   ├── VPN → Check for CVEs (Fortinet, Pulse Secure, Citrix)
│   ├── Exchange → ProxyShell/ProxyLogon
│   ├── Web Apps → OWASP Top 10, file upload, RCE
│   └── RDP → Brute force / credential stuffing
│
└── Physical access in scope?
    ├── Badge cloning (Proxmark3)
    ├── Tailgating
    └── Rogue device deployment (LAN Turtle)
```

## Operational Security (OPSEC) Checklist

1. **Infrastructure Separation**: Separate attack infrastructure from assessment infrastructure
2. **Redirectors**: Use HTTPS redirectors between C2 and targets
3. **Domain Aging**: Register domains 30+ days before engagement
4. **Categorization**: Categorize phishing domains before use (Bluecoat, Fortiguard)
5. **Payload Testing**: Test payloads against VirusTotal alternatives (antiscan.me)
6. **Log Rotation**: Rotate and encrypt operational logs
7. **Clean-up**: Remove all implants and artifacts post-engagement
8. **Communication**: Use encrypted channels for team coordination (Signal, Keybase)

## TTPs Execution Checklist

| Phase | TTP | Tool | Status |
|---|---|---|---|
| Recon | T1593 - Open Website Search | Amass, Recon-ng | [ ] |
| Recon | T1589 - Victim Identity Info | theHarvester, LinkedIn | [ ] |
| Initial Access | T1566.001 - Spearphishing | GoPhish, custom | [ ] |
| Execution | T1059.001 - PowerShell | Custom stager | [ ] |
| Persistence | T1053.005 - Scheduled Task | schtasks.exe | [ ] |
| Priv Esc | T1558.003 - Kerberoasting | Rubeus | [ ] |
| Defense Evasion | T1055 - Process Injection | Custom loader | [ ] |
| Credential Access | T1003.001 - LSASS Memory | Mimikatz/SafetyKatz | [ ] |
| Discovery | T1087.002 - Domain Account Discovery | BloodHound/SharpHound | [ ] |
| Lateral Movement | T1021.002 - SMB/Admin Shares | PsExec, wmiexec | [ ] |
| Collection | T1560 - Archive Data | 7-Zip, tar | [ ] |
| Exfiltration | T1041 - Exfil Over C2 | Havoc/CS download | [ ] |
