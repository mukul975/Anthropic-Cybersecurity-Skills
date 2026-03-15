# Red Team Engagement Planning Workflows

## Workflow 1: Scoping and Threat Modeling

### Step 1: Stakeholder Meeting
```
1. Schedule kickoff with CISO, CTO, legal counsel, and engagement sponsor
2. Present red team capabilities and engagement type options
3. Discuss organizational threat landscape and prior incidents
4. Identify crown jewels (DC, financial systems, PII stores, IP repositories)
5. Agree on engagement type: Full-scope / Assumed Breach / Objective-based
6. Document initial scope boundaries
```

### Step 2: Threat Intelligence Review
```
1. Pull industry-specific threat reports (Mandiant M-Trends, CrowdStrike Global Threat Report)
2. Query MITRE ATT&CK for relevant threat groups:
   - Financial: FIN7, FIN12, Carbanak
   - Healthcare: APT41, Lazarus
   - Government: APT29, APT28, Turla
   - Technology: APT10, Hafnium
3. Map threat actor TTPs to ATT&CK Navigator
4. Export ATT&CK Navigator layer as JSON for engagement tracking
5. Identify top 10-15 techniques for emulation
```

### Step 3: Attack Surface Analysis
```
1. Review external attack surface using passive reconnaissance
2. Map network topology from provided documentation
3. Identify remote access points (VPN, RDP, Citrix)
4. Catalog cloud services (AWS, Azure, GCP, SaaS)
5. Review physical locations and access controls
6. Identify human targets for social engineering vectors
```

## Workflow 2: Rules of Engagement Development

### Step 1: Draft ROE Document
```
Sections to include:
1. Executive Summary
2. Engagement Objectives
3. Scope Definition
   - In-scope IP ranges/domains
   - In-scope physical locations
   - In-scope personnel (for social engineering)
   - Out-of-scope systems (production DBs, medical devices, SCADA)
4. Authorized Techniques
   - Approved MITRE ATT&CK techniques
   - Prohibited techniques (e.g., DoS, data destruction)
5. Communication Plan
   - Primary POC: Name, phone, email
   - Secondary POC: Name, phone, email
   - Daily check-in schedule
   - Encrypted communication channel details
6. Emergency Procedures
   - Stop code word: [DEFINED]
   - Escalation matrix
   - Incident response coordination
7. Legal Authorization
   - Get-out-of-jail letter template
   - Signed authorization from executive sponsor
8. Data Handling
   - Sensitive data discovery procedures
   - Data retention and destruction policy
9. Timeline
   - Start date, end date
   - Blackout periods
   - Reporting deadline
```

### Step 2: Legal Review
```
1. Submit ROE to organization's legal counsel
2. Review liability and indemnification clauses
3. Ensure compliance with local laws (CFAA, Computer Misuse Act, etc.)
4. Verify insurance coverage for testing activities
5. Obtain signed legal authorization
```

### Step 3: Distribution and Acknowledgment
```
1. Distribute finalized ROE to all red team operators
2. Require written acknowledgment from each operator
3. Provide emergency contact cards to each operator
4. Brief operators on scope restrictions and prohibited actions
5. Archive signed copies in secure document management system
```

## Workflow 3: Operational Planning

### Step 1: Infrastructure Planning
```
1. Identify C2 framework requirements (Cobalt Strike, Sliver, Mythic)
2. Plan redirector architecture:
   - HTTPS redirectors for web traffic
   - DNS redirectors for DNS tunneling
   - SMTP redirectors for phishing
3. Register domains that match target organization's naming patterns
4. Obtain SSL certificates for phishing and C2 domains
5. Configure domain categorization for web filtering bypass
6. Set up VPN/jump boxes for operator access
```

### Step 2: Phased Attack Plan
```
Phase 1: Reconnaissance (Days 1-3)
- OSINT collection on target organization
- External attack surface enumeration
- Social media profiling of target personnel
- Technology stack identification

Phase 2: Initial Access (Days 4-7)
- Spearphishing campaign delivery
- External service exploitation attempts
- Physical access attempts (if in scope)
- Supply chain attack vectors

Phase 3: Establish Persistence (Days 8-10)
- Deploy persistent implants
- Establish backup C2 channels
- Create local admin accounts
- Install backdoor services

Phase 4: Lateral Movement (Days 11-15)
- Internal network enumeration
- Credential harvesting
- Privilege escalation
- Domain controller targeting

Phase 5: Objective Completion (Days 16-18)
- Access crown jewels
- Demonstrate data exfiltration capability
- Document evidence of access
- Capture screenshots and proof

Phase 6: Cleanup and Reporting (Days 19-20)
- Remove all implants and persistence mechanisms
- Delete created accounts
- Restore modified configurations
- Compile evidence and findings
```

### Step 3: Deconfliction Planning
```
1. Establish deconfliction channel with SOC (separate from normal SOC comms)
2. Define red team IP addresses for SOC whitelisting (trusted agent model only)
3. Create deconfliction log template for real-time tracking
4. Schedule daily deconfliction calls during engagement
5. Define escalation criteria for when SOC must be notified
6. Agree on evidence preservation procedures if real incident overlaps
```

## Workflow 4: Engagement Execution Tracking

### Step 1: Daily Operations
```
1. Morning briefing with red team operators
2. Review previous day's activities and findings
3. Assign daily objectives aligned to attack plan
4. Execute assigned techniques with OPSEC considerations
5. Document all activities in engagement log with timestamps
6. Evening debrief and progress assessment
7. Update attack graph with new access and findings
```

### Step 2: Decision Points
```
Go/No-Go criteria for each phase transition:
- Phase 1 → 2: Sufficient reconnaissance data collected
- Phase 2 → 3: Initial access achieved, no detection alerts
- Phase 3 → 4: Persistence established, C2 communications stable
- Phase 4 → 5: Sufficient privileges and network access obtained
- Phase 5 → 6: Objectives achieved or engagement time expired
```

### Step 3: Metrics Collection
```
Track throughout engagement:
- Time to Initial Access (TTIA)
- Time to Domain Admin (TTDA)
- Time to Objective (TTO)
- Number of detections triggered
- Mean Time to Detect (MTTD) for blue team
- Techniques executed vs. detected ratio
- Number of unique hosts compromised
- Credentials harvested count
```
