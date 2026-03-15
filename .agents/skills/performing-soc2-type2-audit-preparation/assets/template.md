# SOC 2 Type II Audit Preparation Checklist

## Organization Information
| Field | Value |
|-------|-------|
| Organization Name | |
| Audit Period Start | |
| Audit Period End | |
| Audit Firm | |
| TSC Categories In Scope | Security / Availability / Processing Integrity / Confidentiality / Privacy |
| Preparation Lead | |
| Assessment Date | |

---

## Phase 1: Scoping

### TSC Category Selection
- [ ] Security (Common Criteria) - Mandatory
- [ ] Availability - Include if uptime SLAs exist
- [ ] Processing Integrity - Include if data processing services provided
- [ ] Confidentiality - Include if confidential data handled
- [ ] Privacy - Include if personal information processed

### System Boundaries
- [ ] In-scope services identified
- [ ] Infrastructure components documented (servers, databases, networks)
- [ ] Cloud services and regions listed
- [ ] Data flows mapped (input, processing, storage, output)
- [ ] Subservice organizations identified (e.g., AWS, Azure, GCP)
- [ ] Carve-out vs. inclusive method determined for subservice orgs
- [ ] Out-of-scope systems and justifications documented

### Audit Firm Selection
- [ ] CPA firm selected with SOC 2 experience
- [ ] Engagement letter signed
- [ ] Audit timeline agreed upon
- [ ] Fee structure confirmed
- [ ] Point of contact established

---

## Phase 2: Control Design

### Control Matrix
- [ ] All applicable TSC criteria identified
- [ ] Existing controls inventoried and mapped to criteria
- [ ] Control gaps identified and new controls designed
- [ ] Each control has:
  - [ ] Unique control ID
  - [ ] Clear description of control activity
  - [ ] Mapped TSC criteria
  - [ ] Control type (Preventive/Detective/Corrective)
  - [ ] Frequency (Continuous/Daily/Weekly/Monthly/Quarterly/Annual)
  - [ ] Assigned owner
  - [ ] Defined evidence type
- [ ] Coverage verified: every TSC criterion mapped to at least one control

### Key Controls by Series

#### CC1 - Control Environment
- [ ] Code of conduct/ethics policy published
- [ ] Board/management oversight documented
- [ ] Organizational chart with security roles
- [ ] Background check process for new hires
- [ ] Performance evaluation includes security responsibilities

#### CC2 - Communication and Information
- [ ] Security policies communicated to employees
- [ ] External security commitments documented (SLAs, contracts)
- [ ] Incident notification procedures defined

#### CC3 - Risk Assessment
- [ ] Annual risk assessment completed
- [ ] Risk register maintained
- [ ] Fraud risk assessment performed

#### CC4 - Monitoring Activities
- [ ] Internal control testing programme
- [ ] Control deficiency tracking and remediation

#### CC5 - Control Activities
- [ ] Information security policies approved and current
- [ ] Procedures documented for key processes

#### CC6 - Logical and Physical Access
- [ ] MFA enabled for all production and sensitive systems
- [ ] Role-based access control (RBAC) implemented
- [ ] Quarterly user access reviews performed
- [ ] Access provisioning/deprovisioning process documented
- [ ] Terminated user access removed within 24 hours
- [ ] Physical access restricted to authorized personnel
- [ ] Encryption at rest (AES-256) and in transit (TLS 1.2+)
- [ ] Endpoint protection deployed to all devices
- [ ] Firewall and network segmentation configured

#### CC7 - System Operations
- [ ] SIEM deployed with alerting rules
- [ ] 24/7 monitoring capability (or justified exception)
- [ ] Vulnerability scanning (weekly/monthly)
- [ ] Annual penetration testing by third party
- [ ] Incident response plan documented and tested
- [ ] Security event evaluation procedures

#### CC8 - Change Management
- [ ] Change management policy and process documented
- [ ] Changes require peer review and management approval
- [ ] Separation of duties between development and deployment
- [ ] Emergency change process defined

#### CC9 - Risk Mitigation
- [ ] Vendor management programme implemented
- [ ] Critical vendor SOC reports reviewed annually
- [ ] Vendor security assessments performed
- [ ] Insurance coverage evaluated

---

## Phase 3: Evidence Collection

### Evidence Repository
- [ ] Centralized evidence storage established
- [ ] Folder structure organized by TSC criterion
- [ ] Naming convention defined and communicated
- [ ] Evidence collection calendar created
- [ ] Owners assigned for each evidence type

### Periodic Evidence Checklist

#### Monthly
- [ ] Security metrics report
- [ ] Incident summary report
- [ ] Change management summary
- [ ] Backup verification logs

#### Quarterly
- [ ] User access review completion (all systems)
- [ ] Risk register update
- [ ] Vendor review status
- [ ] Management/board security briefing

#### Annually
- [ ] Penetration test report
- [ ] Security awareness training records
- [ ] Business continuity/DR test results
- [ ] Policy review and approval records
- [ ] Risk assessment report
- [ ] Background check process verification

### Evidence Quality Checks
- [ ] Evidence covers the complete audit period
- [ ] No gaps in periodic control evidence
- [ ] Screenshots include timestamps and system identification
- [ ] Reports are in PDF or export format (not editable)
- [ ] Approval chains clearly visible in tickets

---

## Phase 4: Pre-Audit Readiness

### Documentation
- [ ] System description document completed and reviewed
- [ ] Management assertion letter drafted
- [ ] Subservice organization disclosures accurate
- [ ] CUECs (Complementary User Entity Controls) documented
- [ ] CSOCs (Complementary Subservice Organization Controls) documented

### Walkthrough Testing
- [ ] Sample of each control type tested internally
- [ ] Control operation verified against design
- [ ] Evidence adequacy confirmed
- [ ] Control owners can explain and demonstrate controls

### Gap Remediation
- [ ] All identified gaps documented
- [ ] Remediation plans with owners and timelines
- [ ] Critical gaps resolved before audit starts
- [ ] Compensating controls documented where needed

### Audit Team Preparation
- [ ] Control owners briefed on audit process
- [ ] Interview preparation materials distributed
- [ ] Evidence request list anticipated and pre-staged
- [ ] Auditor access to systems and tools arranged
- [ ] Communication channel with audit firm established

---

## Phase 5: Audit Execution

### Audit Support
- [ ] Kick-off meeting completed
- [ ] Information requests responded to within SLA
- [ ] Population lists provided (users, changes, incidents, vendors)
- [ ] Interviews scheduled and completed
- [ ] Exception responses prepared promptly

### Post-Audit
- [ ] Draft report reviewed for factual accuracy
- [ ] Exception descriptions verified
- [ ] Management responses drafted for exceptions
- [ ] Final report received and distributed
- [ ] Remediation plan created for all exceptions
- [ ] Lessons learned documented
- [ ] Next audit cycle planning initiated

---

## Summary Status

| Phase | Status | Completion % | Notes |
|-------|--------|-------------|-------|
| Scoping | | | |
| Control Design | | | |
| Evidence Collection | | | |
| Pre-Audit Readiness | | | |
| Audit Execution | | | |
| Post-Audit | | | |

## Exception Tracker

| Exception # | Control ID | TSC Criteria | Description | Root Cause | Remediation | Owner | Due Date | Status |
|-------------|-----------|-------------|-------------|------------|-------------|-------|----------|--------|
| | | | | | | | | |

## Sign-off

| Role | Name | Signature | Date |
|------|------|-----------|------|
| SOC 2 Lead | | | |
| CISO | | | |
| CTO | | | |
