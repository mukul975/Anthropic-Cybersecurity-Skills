# Red Team Engagement Plan Template

## Document Control

| Field | Value |
|-------|-------|
| Document Title | Red Team Engagement Plan |
| Organization | [ORGANIZATION NAME] |
| Version | 1.0 |
| Classification | CONFIDENTIAL |
| Author | [RED TEAM LEAD] |
| Date Created | [DATE] |
| Last Modified | [DATE] |
| Engagement ID | RT-[ORG]-[YYYYMMDD] |

---

## 1. Engagement Overview

### 1.1 Purpose
[Describe the purpose of this red team engagement and the business drivers behind it]

### 1.2 Engagement Type
- [ ] Full Scope Red Team
- [ ] Assumed Breach
- [ ] Objective-Based
- [ ] Purple Team Collaborative

### 1.3 Key Stakeholders

| Role | Name | Department | Contact |
|------|------|------------|---------|
| Executive Sponsor | | | |
| Technical POC | | | |
| Legal Counsel | | | |
| SOC Manager | | | |
| Red Team Lead | | | |

---

## 2. Scope Definition

### 2.1 In-Scope Assets

#### Network Ranges
| CIDR Range | Description | Location |
|-----------|-------------|----------|
| | | |

#### Domains
| Domain | Description | Type |
|--------|-------------|------|
| | | External/Internal |

#### Cloud Environments
| Provider | Account/Subscription | Services |
|----------|---------------------|----------|
| | | |

#### Physical Locations
| Address | Building/Floor | Access Type |
|---------|---------------|-------------|
| | | |

### 2.2 Out-of-Scope

| Asset | Reason | Alternative |
|-------|--------|------------|
| | | |

### 2.3 Restrictions
- [ ] No Denial of Service
- [ ] No data destruction
- [ ] No production database access
- [ ] No social engineering of executives
- [ ] Custom: [SPECIFY]

---

## 3. Threat Profile

### 3.1 Selected Threat Actor
**Primary:** [THREAT ACTOR NAME]
**Aliases:** [LIST]
**Motivation:** [Financial/Espionage/Disruption]

### 3.2 Mapped MITRE ATT&CK Techniques

| Tactic | Technique ID | Technique Name | Priority |
|--------|-------------|----------------|----------|
| Initial Access | | | High/Medium/Low |
| Execution | | | |
| Persistence | | | |
| Privilege Escalation | | | |
| Defense Evasion | | | |
| Credential Access | | | |
| Discovery | | | |
| Lateral Movement | | | |
| Collection | | | |
| Exfiltration | | | |
| Command and Control | | | |

### 3.3 ATT&CK Navigator Layer
[Attach exported JSON layer file]

---

## 4. Attack Plan

### Phase 1: Reconnaissance
**Duration:** [X days]
**Objective:** [DESCRIBE]

| Activity | Tool/Method | Expected Outcome | Risk Level |
|----------|------------|-------------------|------------|
| | | | |

### Phase 2: Initial Access
**Duration:** [X days]
**Objective:** [DESCRIBE]

| Activity | Tool/Method | Expected Outcome | Risk Level |
|----------|------------|-------------------|------------|
| | | | |

### Phase 3: Establish Persistence
**Duration:** [X days]
**Objective:** [DESCRIBE]

| Activity | Tool/Method | Expected Outcome | Risk Level |
|----------|------------|-------------------|------------|
| | | | |

### Phase 4: Lateral Movement
**Duration:** [X days]
**Objective:** [DESCRIBE]

| Activity | Tool/Method | Expected Outcome | Risk Level |
|----------|------------|-------------------|------------|
| | | | |

### Phase 5: Privilege Escalation
**Duration:** [X days]
**Objective:** [DESCRIBE]

| Activity | Tool/Method | Expected Outcome | Risk Level |
|----------|------------|-------------------|------------|
| | | | |

### Phase 6: Objective Completion
**Duration:** [X days]
**Objective:** [DESCRIBE]

| Activity | Tool/Method | Expected Outcome | Risk Level |
|----------|------------|-------------------|------------|
| | | | |

### Phase 7: Cleanup and Reporting
**Duration:** [X days]
**Objective:** [DESCRIBE]

| Activity | Tool/Method | Expected Outcome | Risk Level |
|----------|------------|-------------------|------------|
| | | | |

---

## 5. Infrastructure Requirements

### 5.1 C2 Infrastructure
| Component | Provider | Domain/IP | Purpose |
|-----------|---------|-----------|---------|
| C2 Server | | | Primary command and control |
| Redirector | | | Traffic redirection |
| Phishing Server | | | Email delivery |
| Payload Host | | | Stage delivery |

### 5.2 Operator Equipment
| Item | Specification | Assigned To |
|------|-------------|-------------|
| Laptop | | |
| USB Devices | | |
| WiFi Adapter | | |
| Lock Pick Set | | |

---

## 6. Communication Plan

### 6.1 Channels
- **Primary:** [METHOD]
- **Secondary:** [METHOD]
- **Emergency:** [METHOD]

### 6.2 Check-in Schedule
| Frequency | Method | Participants | Time |
|-----------|--------|-------------|------|
| Daily | | | |
| Weekly | | | |

### 6.3 Emergency Stop Procedure
- **Code Word:** [WORD]
- **Activation Method:** [DESCRIBE]
- **Response Time:** [X minutes]

---

## 7. Legal Authorization

### 7.1 Authorization Statement
I hereby authorize [RED TEAM COMPANY/TEAM] to conduct the red team engagement
as described in this document against [ORGANIZATION NAME] assets.

**Signature:** ___________________________
**Name:** ___________________________
**Title:** ___________________________
**Date:** ___________________________

### 7.2 Attached Documents
- [ ] Signed Rules of Engagement
- [ ] Master Services Agreement
- [ ] Non-Disclosure Agreement
- [ ] Get-Out-of-Jail Letters (physical testing)
- [ ] Insurance Certificate

---

## 8. Reporting

### 8.1 Deliverables
| Deliverable | Due Date | Format | Recipients |
|------------|----------|--------|------------|
| Daily Status Update | Daily | Email | Technical POC |
| Interim Report | Mid-engagement | PDF | Sponsor, CISO |
| Final Report | [DATE] | PDF | Full distribution |
| Executive Summary | [DATE] | PDF/PPT | Executive team |
| Technical Debrief | [DATE] | Presentation | Security team |

### 8.2 Report Sections
1. Executive Summary
2. Engagement Overview and Scope
3. Methodology
4. Attack Narrative (Timeline)
5. Findings and Observations
6. Risk Ratings and Impact Assessment
7. Recommendations
8. Appendices (Evidence, Tool List, IOCs)

---

## Appendix A: Engagement Checklist

### Pre-Engagement
- [ ] Scope defined and approved
- [ ] ROE signed by all parties
- [ ] Legal authorization obtained
- [ ] Insurance verified
- [ ] Infrastructure deployed and tested
- [ ] Operators briefed on ROE
- [ ] Emergency contacts distributed
- [ ] Deconfliction channel established
- [ ] Threat profile selected and mapped

### During Engagement
- [ ] Daily check-ins conducted
- [ ] Activity log maintained
- [ ] Evidence collected and secured
- [ ] Deconfliction matrix updated
- [ ] Phase transition approvals obtained

### Post-Engagement
- [ ] All implants and persistence removed
- [ ] Created accounts deleted
- [ ] Modified configurations restored
- [ ] Final report delivered
- [ ] Technical debrief completed
- [ ] Lessons learned session conducted
- [ ] Evidence securely archived
- [ ] Infrastructure decommissioned
