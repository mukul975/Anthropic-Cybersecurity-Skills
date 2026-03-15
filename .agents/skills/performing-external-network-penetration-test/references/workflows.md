# Workflows — External Network Penetration Testing

## End-to-End Workflow

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────────┐
│ Pre-Engagement   │───>│  Reconnaissance   │───>│ Vulnerability        │
│ - Scoping        │    │  - Passive OSINT  │    │ Analysis             │
│ - RoE signing    │    │  - Active scanning│    │ - Automated scans    │
│ - Legal docs     │    │  - Enum subdomains│    │ - Manual validation  │
└─────────────────┘    └──────────────────┘    └─────────────────────┘
                                                          │
┌─────────────────┐    ┌──────────────────┐    ┌──────────▼──────────┐
│   Reporting      │<───│ Post-Exploitation │<───│   Exploitation       │
│ - Findings doc   │    │  - Priv escalation│    │ - Service exploits   │
│ - CVSS scoring   │    │  - Persistence    │    │ - Web app attacks    │
│ - Remediation    │    │  - Pivoting proof  │    │ - Password attacks   │
│ - Executive brief│    │  - Evidence gather │    │ - Credential spray   │
└─────────────────┘    └──────────────────┘    └─────────────────────┘
```

## Daily Testing Workflow

```
Morning:
  1. Review previous day's findings
  2. Update target list with new discoveries
  3. Run updated scans on newly discovered hosts
  4. Verify scan results and triage

Afternoon:
  5. Manual exploitation of high-value targets
  6. Attempt lateral movement from compromised hosts
  7. Document all successful and failed exploitation attempts

Evening:
  8. Compile evidence and screenshots
  9. Update findings tracker
  10. Plan next day's attack vectors
  11. Communicate critical findings to client immediately
```

## Reconnaissance Sub-Workflow

```
Domain Target
    │
    ├── DNS Enumeration ──> Subdomain Discovery ──> IP Resolution
    │                                                    │
    ├── WHOIS/ASN Lookup ──> IP Range Identification ────┤
    │                                                    │
    ├── Certificate Transparency ──> Hidden Subdomains ──┤
    │                                                    │
    ├── Shodan/Censys ──> Service Fingerprinting ────────┤
    │                                                    │
    └── OSINT (GitHub, Pastebin) ──> Credential Leaks    │
                                                         ▼
                                              Master Target List
                                           (IPs, Ports, Services)
```

## Vulnerability Triage Workflow

```
Scan Results
    │
    ├── Critical (CVSS >= 9.0) ──> Immediate exploitation attempt
    │                               ──> Notify client if RCE confirmed
    │
    ├── High (CVSS 7.0-8.9) ──> Validate and exploit within 24h
    │
    ├── Medium (CVSS 4.0-6.9) ──> Validate, exploit if time permits
    │
    └── Low/Info (CVSS < 4.0) ──> Document, include in final report
```

## Evidence Collection Workflow

```
For each successful exploitation:
  1. Screenshot the exploit execution
  2. Record terminal output (script command or asciinema)
  3. Capture network traffic (tcpdump/Wireshark)
  4. Document exact commands/payloads used
  5. Note timestamps (UTC)
  6. Hash any files extracted (SHA-256)
  7. Store evidence in organized folder structure:
     evidence/
     ├── {date}/
     │   ├── {target-ip}/
     │   │   ├── screenshots/
     │   │   ├── terminal_logs/
     │   │   ├── pcaps/
     │   │   └── notes.md
```
