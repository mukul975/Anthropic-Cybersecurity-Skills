# SOC 2 Type II Audit Preparation Workflows

## Workflow 1: Scoping and TSC Selection

```
Start
  |
  v
[Analyze Customer Requirements]
  - Review customer security questionnaires
  - Identify frequently requested TSC categories
  - Review contractual obligations
  |
  v
[Define System Boundaries]
  - Identify in-scope services and applications
  - Map infrastructure components
  - Identify data flows and storage locations
  - Determine subservice organizations (e.g., AWS, Azure)
  |
  v
[Select TSC Categories]
  - Security (CC) - Always included
  |
  +--> [SaaS with uptime SLAs?] --> Include Availability (A)
  |
  +--> [Process financial/sensitive data?] --> Include Processing Integrity (PI)
  |
  +--> [Handle confidential customer data?] --> Include Confidentiality (C)
  |
  +--> [Collect/process personal data?] --> Include Privacy (P)
  |
  v
[Document Scope and Boundaries]
  |
  v
[Select Audit Firm]
  - Verify CPA firm qualifications
  - Confirm experience with your industry
  - Agree on audit timeline and fees
  |
  v
End
```

## Workflow 2: Control Design and Mapping

```
Start
  |
  v
[Review TSC Requirements]
  - Identify all applicable criteria and points of focus
  |
  v
[Map Existing Controls to TSC]
  - Inventory current security controls
  - Map each control to TSC criteria
  - Identify coverage gaps
  |
  v
[Design New Controls for Gaps]
  - Define control objective
  - Define control activity
  - Set control frequency
  - Assign control owner
  - Define evidence requirements
  |
  v
[Classify Control Types]
  |
  +--> Preventive: Stops events before they occur
  |     (e.g., MFA, firewall rules, access reviews)
  |
  +--> Detective: Identifies events after they occur
  |     (e.g., SIEM alerts, audit logs, vulnerability scans)
  |
  +--> Corrective: Remedies events after detection
        (e.g., incident response, patching, access revocation)
  |
  v
[Document Control Matrix]
  - TSC Criterion -> Control ID -> Description -> Type ->
    Frequency -> Owner -> Evidence -> Test Procedure
  |
  v
[Implement Controls]
  |
  v
[Validate Control Operation]
  |
  v
End
```

## Workflow 3: Evidence Collection Process

```
Start
  |
  v
[Establish Evidence Repository]
  - Create structured folder hierarchy by TSC category
  - Set naming conventions (YYYY-MM_CC6.1_AccessReview)
  - Assign evidence collection responsibilities
  |
  v
[Continuous Controls (Daily/Real-time)]
  - SIEM log collection and alerting
  - Intrusion detection monitoring
  - Endpoint protection status
  - Encryption enforcement
  |
  v
[Periodic Controls]
  |
  +--> Weekly:
  |     - Vulnerability scan reports
  |     - Backup verification
  |
  +--> Monthly:
  |     - Security metric reports
  |     - Incident summary
  |     - Change management review
  |
  +--> Quarterly:
  |     - User access reviews (CC6.3)
  |     - Risk assessment updates (CC3.2)
  |     - Vendor security reviews (CC9.2)
  |     - Board/management reporting (CC1.2)
  |
  +--> Annually:
        - Penetration testing (CC7.1)
        - Security awareness training (CC1.4)
        - Business continuity testing (A1.3)
        - Policy reviews and updates (CC5.3)
        - Risk assessment (CC3.1)
  |
  v
[Organize and Label Evidence]
  - Screenshot with timestamps
  - Export system reports to PDF
  - Preserve ticket/approval chains
  - Document manual control execution
  |
  v
[Quality Check Evidence]
  - Verify coverage for entire audit period
  - Confirm no gaps in periodic controls
  - Validate evidence matches control description
  |
  v
End
```

## Workflow 4: Readiness Assessment

```
Start
  |
  v
[Perform Walkthrough Testing]
  - Select sample of each control type
  - Trace control from input to evidence
  - Verify control operates as designed
  |
  v
[Identify Gaps and Exceptions]
  |
  +--> [Control Not Operating?]
  |     - Document exception
  |     - Implement remediation
  |     - Restart evidence collection
  |
  +--> [Evidence Missing?]
  |     - Locate alternative evidence
  |     - Implement improved capture
  |
  +--> [Control Design Insufficient?]
        - Redesign control
        - Implement and begin new evidence period
  |
  v
[Prepare System Description]
  - Overview of organization
  - Principal service commitments
  - System components description
  - Subservice organization relationships
  - CUECs and CSOCs
  |
  v
[Prepare Management Assertion]
  - Confirm system description is fairly presented
  - Assert controls were suitably designed
  - Assert controls operated effectively
  |
  v
[Brief Control Owners]
  - Explain audit process
  - Review evidence expectations
  - Prepare for auditor interviews
  |
  v
End
```

## Workflow 5: Audit Execution Support

```
Start
  |
  v
[Kick-off Meeting with Auditor]
  - Confirm scope and timeline
  - Provide system description
  - Share evidence repository access
  - Establish communication cadence
  |
  v
[Respond to Information Requests]
  - Provide requested populations (user lists, change tickets, etc.)
  - Facilitate system access for auditor testing
  - Schedule interviews with control owners
  |
  v
[Auditor Performs Testing]
  - Inquiry (interviews with control owners)
  - Observation (watch control operation)
  - Inspection (review evidence documents)
  - Reperformance (re-execute control steps)
  |
  v
[Address Exceptions]
  |
  +--> [Exception Found]
  |     - Investigate root cause
  |     - Determine if compensating controls exist
  |     - Provide additional context to auditor
  |     - Document remediation plan
  |
  +--> [No Exceptions] --> Continue
  |
  v
[Review Draft Report]
  - Check system description accuracy
  - Verify control descriptions
  - Review exception descriptions
  - Confirm factual accuracy
  |
  v
[Receive Final Report]
  |
  v
[Plan Remediation for Exceptions]
  |
  v
End
```
