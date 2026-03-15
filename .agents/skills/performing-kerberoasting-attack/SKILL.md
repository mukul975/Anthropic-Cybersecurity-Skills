---
name: performing-kerberoasting-attack
description: Kerberoasting is a post-exploitation technique that targets service accounts in Active Directory by requesting Kerberos TGS (Ticket Granting Service) tickets for accounts with Service Principal Names 
domain: cybersecurity
subdomain: red-teaming
tags: [red-team, adversary-simulation, mitre-attack, exploitation, post-exploitation, kerberoasting, active-directory, credential-access]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Performing Kerberoasting Attack

## Overview

Kerberoasting is a post-exploitation technique that targets service accounts in Active Directory by requesting Kerberos TGS (Ticket Granting Service) tickets for accounts with Service Principal Names (SPNs) set. These tickets are encrypted with the service account's NTLM hash, allowing offline brute-force cracking without generating failed login events. It is one of the most common privilege escalation paths in AD environments because any domain user can request TGS tickets.

## MITRE ATT&CK Mapping

- **T1558.003** - Steal or Forge Kerberos Tickets: Kerberoasting
- **T1087.002** - Account Discovery: Domain Account
- **T1069.002** - Permission Groups Discovery: Domain Groups

## Implementation Steps

### Phase 1: SPN Enumeration
1. Enumerate accounts with SPNs using LDAP queries
2. Filter for user accounts (not computer accounts)
3. Identify accounts with elevated privileges (adminCount=1)
4. Prioritize accounts with weak password policies

### Phase 2: TGS Ticket Request
1. Request TGS tickets for identified SPN accounts
2. Extract ticket data in crackable format (hashcat/john compatible)
3. Ensure RC4 encryption is requested when possible (easier to crack)
4. Document all requested tickets

### Phase 3: Offline Cracking
1. Use hashcat mode 13100 (Kerberos 5 TGS-REP etype 23) for RC4 tickets
2. Use hashcat mode 19700 (Kerberos 5 TGS-REP etype 17) for AES-128
3. Use hashcat mode 19800 (Kerberos 5 TGS-REP etype 18) for AES-256
4. Apply targeted wordlists and rules based on password policy

### Phase 4: Credential Validation
1. Validate cracked credentials against domain
2. Assess access level of compromised accounts
3. Map accounts to BloodHound attack paths
4. Document for engagement report

## Tools and Resources

| Tool | Purpose | Platform |
|------|---------|----------|
| Rubeus | Kerberoasting and ticket manipulation | Windows (.NET) |
| Impacket GetUserSPNs.py | Remote Kerberoasting | Linux/Python |
| PowerView | SPN enumeration | Windows (PowerShell) |
| hashcat | Offline password cracking | Cross-platform |
| John the Ripper | Offline password cracking | Cross-platform |

## Detection Indicators

- Event ID 4769: Kerberos Service Ticket Request with RC4 encryption (0x17)
- Anomalous TGS requests from a single account in short timeframe
- TGS requests for services the user normally does not access
- Honeypot SPN accounts with alerting on ticket requests

## Validation Criteria

- [ ] SPN accounts enumerated and documented
- [ ] TGS tickets extracted in crackable format
- [ ] Offline cracking attempted with appropriate wordlists
- [ ] Cracked credentials validated
- [ ] Access level of compromised accounts assessed
