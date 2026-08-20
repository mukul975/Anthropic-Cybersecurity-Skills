# Standards and Framework Mappings

## NIST Cybersecurity Framework 2.0

### DE.CM: Detection Processes - Continuous Monitoring
- **DE.CM-01**: Networks and network services are monitored to find potentially adverse events
  - **Application**: Honeytoken access generates high-fidelity network/authentication events (Kerberos TGS requests, NTLM auth) indicating compromise

### DE.AE: Detection Processes - Adverse Event Analysis  
- **DE.AE-02**: Potentially adverse events are analyzed to better understand associated activities
  - **Application**: Honeytoken triggers provide context for incident analysis (Kerberoasting, credential theft, lateral movement patterns)

### DE.DP: Detection Processes - Detection Processes
- **DE.DP-04**: Event detection information is communicated
  - **Application**: SIEM alerts on honeytoken access integrate with SOC workflows, ticketing (ServiceNow, Jira), and incident response playbooks

## MITRE ATT&CK Framework v19.1

### T1003: OS Credential Dumping
**Tactic**: Credential Access  
**Description**: Adversaries attempt to dump credentials to obtain account login and credential material

**Sub-Techniques Detected by Honeytokens**:
- **T1003.001**: LSASS Memory (if honeytoken credentials cached)
- **T1003.002**: Security Account Manager (honeytoken in SAM database)
- **T1003.006**: DCSync (honeytoken account used to request replication)

**Detection**: Event ID 4662 (object access) when honeytoken account requests DS-Replication-Get-Changes

---

### T1558: Steal or Forge Kerberos Tickets
**Tactic**: Credential Access  
**Description**: Adversaries may attempt to subvert Kerberos authentication by stealing or forging Kerberos tickets

**Sub-Technique**:
- **T1558.003**: Kerberoasting
  - **Description**: Adversaries request service tickets for accounts with SPNs, crack offline
  - **Detection**: Honeytoken SPNs generate Event ID 4769 when TGS requested; RC4 encryption indicates cracking attempt

**Detection Artifacts**:
```
Event 4769:
  Service Name: MSSQLSvc/honeytoken-sql.corp.local:1433
  Ticket Encryption: 0x17 (RC4-HMAC) ← Attacker prefers RC4 for cracking
  Source: Attacker workstation
```

- **T1558.001**: Golden Ticket
  - **Detection**: Forged TGT for honeytoken account with unusual lifetime (10 years vs. normal 10 hours)
  
- **T1558.002**: Silver Ticket  
  - **Detection**: Forged TGS for honeytoken SPN without corresponding TGT request

---

### T1087: Account Discovery
**Tactic**: Discovery  
**Sub-Technique**: T1087.002 (Domain Account)

**Detection**: Honeytokens appear in LDAP queries, `net user /domain`, PowerView enumeration; access logged via Event ID 4662

---

### T1069: Permission Groups Discovery
**Tactic**: Discovery  
**Sub-Technique**: T1069.002 (Domain Groups)

**Detection**: Honeytoken membership in Domain Admins/Enterprise Admins discovered via `net group "Domain Admins" /domain` or BloodHound

---

### T1078: Valid Accounts
**Tactic**: Defense Evasion, Persistence, Privilege Escalation, Initial Access  
**Sub-Technique**: T1078.002 (Domain Accounts)

**Detection**: Honeytoken accounts used for authentication (Event 4768 TGT, 4776 NTLM) from unauthorized sources

## MITRE D3FEND Framework

### D3-DUC: Decoy User Credential
**Defensive Technique**: Deceive  
**Description**: A credential that is created for the purposes of deceiving an adversary

**Implementation**: Honeytokens deployed as Active Directory user accounts with SPNs and high-privilege group memberships

**Detection Analytics**:
- Authentication attempts using decoy credentials (Event 4768, 4776)
- Kerberos ticket requests for decoy SPNs (Event 4769)
- LDAP queries accessing decoy account attributes (Event 4662)

**Considerations from D3FEND**:
- Decoy credentials should be integrated with larger decoy environment (honeytoken accounts + fake file shares + honeypot systems)
- When decoy credentials compromised, interaction with decoy assets should be monitored for attacker TTP collection

---

### D3-DACH: Decoy Account
**Defensive Technique**: Deceive  
**Description**: Accounts created for the purpose of deceiving adversaries; designed to be discovered during reconnaissance

**Implementation**: Honeytoken accounts placed in Service Accounts OU, added to Domain Admins group, assigned enticing descriptions

**Detection Coverage**:
- Account enumeration (BloodHound, PowerView, AdFind)
- Privilege escalation attempts leveraging decoy ACLs
- Lateral movement using decoy credentials

---

### D3-DNR: Decoy Network Resource
**Defensive Technique**: Deceive  
**Description**: Network resources (files, shares, systems) used to attract and detect adversaries

**Honeytoken Integration**: Decoy SPNs reference non-existent or honeypot services (e.g., MSSQLSvc/fake-sql.corp.local)

## CIS Controls v8.1

### Control 6: Access Control Management
**Safeguard 6.8**: Define and Maintain Role-Based Access Control  
**Application**: Honeytokens test effectiveness of access controls; unauthorized use indicates privilege escalation or stolen credentials

### Control 8: Audit Log Management
**Safeguard 8.2**: Collect Audit Logs  
**Application**: Windows Security Event Log (Event IDs 4768, 4769, 4776) provides audit trail for honeytoken access

**Safeguard 8.11**: Conduct Audit Log Reviews  
**Application**: SIEM correlation rules automatically review logs for honeytoken triggers

## MITRE ATT&CK Mitigations

### M1015: Active Directory Configuration
**Mitigation**: Ensure proper Active Directory permissions and authentication mechanisms
**Honeytoken Role**: Validates that attackers cannot differentiate honeytokens from legitimate accounts; tests AD enumeration detection

### M1027: Password Policies  
**Mitigation**: Set and enforce secure password policies
**Honeytoken Role**: Honeytoken passwords must be complex to prevent accidental compromise via password spray

### M1041: Encrypt Sensitive Information (Kerberos Encryption)
**Mitigation**: Disable RC4 encryption for Kerberos; enforce AES256
**Honeytoken Role**: Detecting RC4 TGS requests for honeytoken SPNs indicates Kerberoasting attempt

## NIST Special Publication 800-53 Rev. 5

### AU-6: Audit Review, Analysis, and Reporting
**Control**: Audit logs are reviewed and analyzed for indications of inappropriate activity
**Implementation**: SIEM rules for Event IDs 4768, 4769, 4776, 4662 targeting honeytoken accounts

### SI-4: System Monitoring  
**Control**: The system is monitored to detect attacks and indicators of potential attacks
**Implementation**: Honeytoken access = high-confidence indicator of compromise requiring immediate response

### SC-26: Decoys
**Control**: Include components designed to be the target of malicious attacks for detecting, deflecting, and analyzing such attacks
**Implementation**: AD honeytokens are decoy components per SC-26 guidance

## Windows Security Event IDs Reference

### Event ID 4768: Kerberos TGT Request
**Logged When**: User/service requests Ticket Granting Ticket from KDC  
**Honeytoken Detection**: TGT requested for honeytoken account from unauthorized workstation

**Key Fields**:
- `TargetUserName`: Honeytoken account name
- `IpAddress`: Source IP (should match authorized admin workstations only)
- `TicketOptions`: Check for unusual flags
- `PreAuthType`: Pre-authentication type (0 = no pre-auth = suspicious)

---

### Event ID 4769: Kerberos Service Ticket Request
**Logged When**: User/service requests TGS for specific SPN  
**Honeytoken Detection**: TGS requested for honeytoken SPN = Kerberoasting

**Key Fields**:
- `ServiceName`: Honeytoken SPN (e.g., MSSQLSvc/honeytoken-sql.corp.local:1433)
- `TicketEncryptionType`: 0x17 (RC4) indicates Kerberoasting attempt
- `IpAddress`: Source IP
- `Status`: 0x0 = success (attacker obtained ticket)

**Normal vs. Malicious**:
- **Normal**: TGS requested by application server for legitimate service authentication
- **Malicious**: TGS requested by user workstation for service account SPN (offline cracking)

---

### Event ID 4776: NTLM Authentication
**Logged When**: Domain controller validates credentials via NTLM  
**Honeytoken Detection**: Authentication attempt using honeytoken credentials

**Key Fields**:
- `TargetUserName`: Honeytoken account
- `Workstation`: Source workstation name
- `Status`: 0xC0000064 = user does not exist, 0xC000006A = wrong password

---

### Event ID 4624: Successful Logon
**Logged When**: Account successfully logs on  
**Honeytoken Detection**: Honeytoken account should NEVER log on; any 4624 = critical alert

**Key Fields**:
- `TargetUserName`: Honeytoken account
- `LogonType`: 3 = network, 10 = RDP, 9 = NewCredentials
- `IpAddress`: Source IP
- `ProcessName`: Process used for logon

---

### Event ID 4662: Operation Performed on Object
**Logged When**: LDAP operation performed (read, write, modify)  
**Honeytoken Detection**: Honeytoken account attributes accessed or privileges modified

**Key Fields**:
- `ObjectName`: DN of object accessed (e.g., CN=Domain Admins,CN=Users,DC=corp,DC=local)
- `Properties`: GUID of properties accessed
  - `{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}`: DS-Replication-Get-Changes (DCSync)
  - `{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}`: DS-Replication-Get-Changes-All (DCSync)
- `SubjectUserName`: Account performing operation (should NOT be honeytoken)

## Industry Standards and Best Practices

### Gartner: Deception Technology Best Practices (2025)
**Recommendation**: Deploy honeytokens as low-cost, high-value detection layer complementing EDR and SIEM

**Key Metrics**:
- **Alert Accuracy**: Honeytokens provide 95%+ alert accuracy (minimal false positives)
- **Mean Time to Detect (MTTD)**: Honeytoken alerts reduce MTTD to <5 minutes for credential theft
- **Coverage**: Minimum 5-10 honeytokens per 1000 users recommended

### SANS: Active Directory Security Best Practices (2026)
**Honeytoken Guidance**:
1. Deploy 1 honeytoken per 100-200 users
2. Place in Service Accounts OU and Admin Accounts OU
3. Monitor Event IDs 4768, 4769, 4776 with <60 second alert SLA
4. Integrate with SOAR for automated containment (disable compromised user, isolate workstation)

### Microsoft: Protecting Privileged Access (2026)
**Honeytoken Integration**:
- Microsoft Defender for Identity (MDI) includes built-in honeytoken capability ("honeytoken accounts" feature)
- MDI auto-generates realistic service account names and monitors for access
- Integration with Microsoft Sentinel for automated incident creation

### MITRE: 11 Strategies of a World-Class Cybersecurity Operations Center
**Strategy 4**: Collect the Right Data  
**Application**: Windows Security Event Logs (4768, 4769, 4776) provide right data for honeytoken detection

**Strategy 7**: Turn Data into Information with Context  
**Application**: Honeytoken access provides context (not just "Kerberos ticket requested" but "Kerberos ticket requested for decoy account = attacker present")

## Real-World Adoption (2026)

### Microsoft Defender for Identity (MDI) Honeytokens
**Feature**: "Configure honeytoken accounts" in MDI portal  
**Capabilities**:
- Auto-generate honeytoken account names from ML model (blend with legitimate accounts)
- Automatic SPN assignment (HTTP, MSSQL, LDAP, CIFS)
- Alert severity: Critical (no false positives)
- Integration: Microsoft Sentinel, Microsoft 365 Defender

**Alert Types**:
- "Honeytoken account Kerberos ticket requested"
- "Suspicious authentication using honeytoken account"
- "Honeytoken account queried (Directory Services enumeration)"

---

### SentinelOne Singularity Identity
**Feature**: "Decoy Credentials" module  
**Capabilities**:
- Deploy honeytokens across AD and Entra ID
- Real-time Kerberos traffic analysis (not just log-based)
- Autonomous response: Auto-disable compromised user, isolate workstation
- Integration: SentinelOne XDR, Storyline correlation

---

### CyberArk Identity Security Platform
**Feature**: "Honeypot Accounts" in CyberArk Vault  
**Capabilities**:
- Honeytoken credentials stored in vault, monitored for retrieval attempts
- Integration with CyberArk EPM (Endpoint Privilege Manager)
- Alert on: Vault retrieval, authentication attempt, DCSync attempt

## Compliance and Regulatory References

### PCI DSS v4.0
**Requirement 10.2.5**: Log and alert on unauthorized access to authentication credentials  
**Honeytoken Mapping**: Honeytoken access = unauthorized access; automated alerting via SIEM

### HIPAA Security Rule
**45 CFR § 164.312(b)**: Audit Controls - implement hardware, software, procedural mechanisms to record and examine access  
**Honeytoken Mapping**: Windows Event Logs + SIEM provide audit trail for honeytoken access

### GDPR Article 32: Security of Processing
**Requirement**: Ability to ensure ongoing confidentiality, integrity, availability, and resilience  
**Honeytoken Mapping**: Detect unauthorized access to AD credentials (personal data controller access)

### CMMC Level 2: Access Control (AC)
**AC.L2-3.1.3**: Control information flow  
**Honeytoken Mapping**: Detect unauthorized information flows (DCSync replication requests from honeytoken accounts)

## References

- NIST Cybersecurity Framework 2.0 (2024)
- MITRE ATT&CK v19.1 (2026)
- MITRE D3FEND Knowledge Base (2026)
- CIS Controls v8.1 (2023)
- NIST SP 800-53 Rev. 5 (2020)
- Microsoft: Best Practices for Securing Active Directory (2026)
- Gartner: Market Guide for Deception Technology (2025)
- SANS: Detecting Kerberoasting Activity (2026)
- Microsoft Defender for Identity Documentation (2026)
- SentinelOne Singularity Identity Guide (2026)
