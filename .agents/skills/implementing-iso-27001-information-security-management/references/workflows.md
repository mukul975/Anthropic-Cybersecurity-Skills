# ISO 27001 Implementation Workflows

## Workflow 1: ISMS Scoping and Context Analysis

```
Start
  |
  v
[Identify Internal Context]
  - Organization structure
  - Existing policies and processes
  - IT infrastructure and systems
  - Culture and capabilities
  |
  v
[Identify External Context]
  - Legal and regulatory requirements
  - Industry standards and obligations
  - Customer and partner requirements
  - Threat landscape and geopolitical factors
  |
  v
[Identify Interested Parties]
  - Customers and clients
  - Regulators and authorities
  - Employees and contractors
  - Shareholders and board members
  - Suppliers and partners
  |
  v
[Define ISMS Scope]
  - Business units in scope
  - Physical locations
  - Information systems and networks
  - Third-party services
  - Exclusions with justification
  |
  v
[Document ISMS Scope Statement]
  |
  v
[Obtain Top Management Approval]
  |
  v
End
```

## Workflow 2: Risk Assessment Process

```
Start
  |
  v
[Define Risk Criteria]
  - Risk acceptance criteria
  - Likelihood scale (1-5)
  - Impact scale (1-5)
  - Risk matrix thresholds
  |
  v
[Create Asset Inventory]
  - Information assets
  - Software assets
  - Hardware assets
  - People (roles)
  - Services (cloud, third-party)
  - Physical locations
  |
  v
[Identify Threats]
  - Natural threats (fire, flood)
  - Human threats (insider, external attacker)
  - Technical threats (malware, system failure)
  - Supply chain threats
  |
  v
[Identify Vulnerabilities]
  - Technical vulnerabilities
  - Process weaknesses
  - People-related gaps
  - Physical security gaps
  |
  v
[Assess Existing Controls]
  - Document current controls
  - Evaluate control effectiveness
  |
  v
[Calculate Risk Level]
  Risk = Likelihood x Impact
  - Consider existing controls
  - Use defined risk criteria
  |
  v
[Compare Against Risk Acceptance]
  |
  +--> [Risk Acceptable] --> Document and Monitor
  |
  +--> [Risk Not Acceptable]
        |
        v
      [Select Risk Treatment]
        - Mitigate (apply controls)
        - Transfer (insurance, outsource)
        - Avoid (stop activity)
        - Accept (with justification)
        |
        v
      [Map to Annex A Controls]
        |
        v
      [Document in Risk Treatment Plan]
        |
        v
      [Update Statement of Applicability]
        |
        v
      End
```

## Workflow 3: Statement of Applicability (SoA) Creation

```
Start
  |
  v
[List All 93 Annex A Controls]
  |
  v
[For Each Control]
  |
  v
[Is Control Required by Risk Treatment?]
  |
  +--> Yes --> Mark as Applicable
  |             - Link to risk(s)
  |             - Document implementation status
  |             - Assign control owner
  |
  +--> No --> [Is Control Required by Law/Contract?]
               |
               +--> Yes --> Mark as Applicable
               |             - Document legal/contractual basis
               |
               +--> No --> [Is Control Best Practice?]
                            |
                            +--> Yes --> Mark as Applicable
                            |             - Document business justification
                            |
                            +--> No --> Mark as Not Applicable
                                        - Document exclusion justification
  |
  v
[Review SoA Completeness]
  - All 93 controls addressed
  - Every exclusion justified
  - Implementation status documented
  |
  v
[Approve SoA]
  |
  v
End
```

## Workflow 4: Internal Audit Programme

```
Start
  |
  v
[Plan Audit Programme]
  - Define audit scope (clauses and controls)
  - Schedule audits across the year
  - Assign qualified auditors (independent of audited area)
  - Prepare audit criteria and checklists
  |
  v
[Conduct Audit]
  - Opening meeting with auditees
  - Review documented information
  - Interview key personnel
  - Observe processes in action
  - Collect objective evidence
  - Closing meeting with preliminary findings
  |
  v
[Document Findings]
  - Major Nonconformities (systemic failure, absence of control)
  - Minor Nonconformities (isolated failure, partial implementation)
  - Observations (potential for improvement)
  - Opportunities for Improvement (OFIs)
  |
  v
[Issue Audit Report]
  |
  v
[Corrective Action Process]
  - Containment: immediate action to limit impact
  - Root Cause Analysis: identify underlying cause
  - Corrective Action: implement fix to prevent recurrence
  - Verification: confirm effectiveness of correction
  |
  v
[Track to Closure]
  |
  v
[Feed into Management Review]
  |
  v
End
```

## Workflow 5: Management Review

```
Start
  |
  v
[Prepare Review Inputs]
  - Status of actions from previous reviews
  - Changes in external/internal issues
  - Changes in interested party needs
  - Information security performance:
    * Nonconformities and corrective actions
    * Monitoring and measurement results
    * Audit results
    * Fulfilment of objectives
  - Feedback from interested parties
  - Results of risk assessment and treatment plan
  - Opportunities for continual improvement
  |
  v
[Conduct Management Review Meeting]
  - Present ISMS performance data
  - Discuss risk landscape changes
  - Review incident trends
  - Evaluate resource adequacy
  |
  v
[Document Review Outputs]
  - Decisions on continual improvement opportunities
  - Changes needed to the ISMS
  - Resource allocation decisions
  - Updated risk acceptance criteria (if needed)
  |
  v
[Assign Actions with Owners and Deadlines]
  |
  v
[Track Implementation]
  |
  v
End
```

## Workflow 6: Certification Audit Preparation

```
Start
  |
  v
[Pre-Audit Readiness Check]
  - All mandatory documents in place
  - SoA current and approved
  - Risk assessment completed
  - Internal audit completed
  - Management review conducted
  - Corrective actions closed
  |
  v
[Select Certification Body]
  - Verify UKAS/ANAB accreditation
  - Compare audit team experience
  - Review commercial terms
  |
  v
[Stage 1 Audit (Documentation Review)]
  - Auditor reviews ISMS documentation
  - Assesses readiness for Stage 2
  - Identifies any significant gaps
  |
  v
[Address Stage 1 Findings]
  - Resolve documentation gaps
  - Complete any missing processes
  |
  v
[Stage 2 Audit (Certification Audit)]
  - On-site assessment (typically 3-5 days)
  - Evidence-based verification
  - Interviews across the organization
  - Technical control testing
  |
  v
[Audit Outcome]
  |
  +--> [No Major NCRs] --> Certificate Issued
  |
  +--> [Major NCRs Found]
        |
        v
      [Resolve NCRs within 90 days]
        |
        v
      [Follow-up Audit]
        |
        v
      [Certificate Issued]
  |
  v
End
```
