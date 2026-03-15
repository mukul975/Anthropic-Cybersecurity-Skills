---
name: conducting-pass-the-ticket-attack
description: Pass-the-Ticket (PtT) is a lateral movement technique that uses stolen Kerberos tickets (TGT or TGS) to authenticate to services without knowing the user's password. By extracting Kerberos tickets fro
domain: cybersecurity
subdomain: red-teaming
tags: [red-team, adversary-simulation, mitre-attack, exploitation, post-exploitation, kerberos, pass-the-ticket, lateral-movement]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Conducting Pass-the-Ticket Attack

## Overview

Pass-the-Ticket (PtT) is a lateral movement technique that uses stolen Kerberos tickets (TGT or TGS) to authenticate to services without knowing the user's password. By extracting Kerberos tickets from memory (LSASS) on a compromised host, an attacker can inject those tickets into their own session to impersonate the ticket owner and access resources as that user.

## MITRE ATT&CK Mapping

- **T1550.003** - Use Alternate Authentication Material: Pass the Ticket
- **T1003.001** - OS Credential Dumping: LSASS Memory
- **T1558** - Steal or Forge Kerberos Tickets
- **T1021.002** - Remote Services: SMB/Windows Admin Shares

## Implementation Steps

### Phase 1: Ticket Extraction
1. Gain local admin access on target workstation
2. Dump Kerberos tickets from LSASS memory using Mimikatz or Rubeus
3. Export tickets in .kirbi format (Mimikatz) or base64 (Rubeus)
4. Identify high-value tickets (Domain Admin TGTs, service tickets to critical systems)

### Phase 2: Ticket Injection
1. Purge existing Kerberos tickets from attacker session
2. Import/inject stolen ticket into current session
3. Verify ticket is loaded and valid
4. Access target resources using injected ticket

### Phase 3: Lateral Movement
1. Access remote systems using the stolen ticket identity
2. Perform actions as the impersonated user
3. Collect additional credentials from accessed systems
4. Document evidence of successful lateral movement

## Tools and Resources

| Tool | Purpose | Command |
|------|---------|---------|
| Mimikatz | Ticket export/import | sekurlsa::tickets /export, kerberos::ptt |
| Rubeus | Ticket dumping and injection | dump, ptt, tgtdeleg |
| Impacket ticketConverter | Convert between formats | ticketConverter.py ticket.kirbi ticket.ccache |
| Impacket psexec/smbexec | Remote execution with ticket | KRB5CCNAME=ticket.ccache psexec.py |

## Detection Indicators

- Event ID 4768 with unusual client addresses
- Event ID 4769 service ticket requests from unexpected hosts
- TGT usage from different IP than the TGT was issued to
- Multiple authentications from same ticket across different workstations

## Validation Criteria

- [ ] Kerberos tickets extracted from compromised host
- [ ] Tickets injected into attacker session
- [ ] Lateral movement demonstrated using stolen tickets
- [ ] Evidence captured for reporting
