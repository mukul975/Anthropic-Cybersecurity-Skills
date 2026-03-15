# GDPR Data Protection Control Workflows

## Workflow 1: Data Subject Request (DSR) Handling

```
Start
  |
  v
[Receive DSR from Data Subject]
  - Via email, web form, phone, in-person
  - Record receipt timestamp (30-day clock starts)
  |
  v
[Verify Identity of Requestor]
  - Request additional identification if needed
  - Clock pauses until identity verified
  |
  v
[Classify Request Type]
  |
  +--> Access Request (Art. 15) --> Locate all personal data
  +--> Rectification (Art. 16) --> Identify incorrect data
  +--> Erasure (Art. 17) --> Verify grounds for erasure
  +--> Restriction (Art. 18) --> Flag data for restriction
  +--> Portability (Art. 20) --> Export in machine-readable format
  +--> Objection (Art. 21) --> Assess processing basis
  |
  v
[Check for Exemptions]
  - Legal obligation to retain
  - Freedom of expression
  - Public health
  - Archiving in public interest
  - Legal claims
  |
  v
[Execute Request Across All Systems]
  - Production databases
  - Backups and archives
  - Third-party processors
  - Cloud services
  - Analytics platforms
  |
  v
[Document Action Taken]
  |
  v
[Respond to Data Subject within 30 days]
  - Extension to 60 additional days if complex (notify subject)
  |
  v
End
```

## Workflow 2: Data Breach Notification (Art. 33-34)

```
Start
  |
  v
[Breach Detected or Reported]
  - Technical detection (SIEM, DLP, IDS)
  - Employee report
  - External notification
  - Third-party processor notification
  |
  v
[72-hour Clock Starts]
  |
  v
[Assess Breach Severity]
  - Number of data subjects affected
  - Types of personal data compromised
  - Special categories involved?
  - Risk to rights and freedoms
  |
  v
[Determine Notification Requirements]
  |
  +--> [Risk to Rights and Freedoms?]
        |
        +--> No Risk --> Document in breach register only
        |
        +--> Risk exists --> Notify Supervisory Authority (72 hours)
        |                    |
        |                    v
        +--> High Risk --> Notify Supervisory Authority (72 hours)
                           AND notify affected data subjects
  |
  v
[Prepare Supervisory Authority Notification]
  - Nature of the breach
  - Categories and approximate number of data subjects
  - Categories and approximate number of records
  - Name and contact details of DPO
  - Likely consequences of the breach
  - Measures taken or proposed to address the breach
  |
  v
[Submit Notification to Lead Supervisory Authority]
  |
  v
[If High Risk: Notify Data Subjects]
  - Clear and plain language
  - Description of breach
  - DPO contact information
  - Likely consequences
  - Measures taken to mitigate
  |
  v
[Conduct Post-Breach Review]
  - Root cause analysis
  - Control improvements
  - Update breach register
  |
  v
End
```

## Workflow 3: Data Protection Impact Assessment (DPIA)

```
Start
  |
  v
[Identify Processing Activity]
  |
  v
[Screen Against DPIA Criteria]
  - Profiling or automated decision-making?
  - Large-scale special category data?
  - Systematic monitoring of public areas?
  - New technology application?
  - Cross-border data transfer?
  - Vulnerable data subjects?
  |
  +--> [No DPIA triggers] --> Document screening decision --> End
  |
  +--> [DPIA required]
        |
        v
[Describe Processing Operation]
  - Purpose and scope
  - Data elements collected
  - Data subjects categories
  - Recipients and transfers
  - Retention period
  - Technology used
  |
  v
[Assess Necessity and Proportionality]
  - Is processing necessary for the purpose?
  - Could purpose be achieved with less data?
  - Is lawful basis appropriate?
  - Are data subject rights supported?
  |
  v
[Identify and Assess Risks]
  - Risks to confidentiality
  - Risks to integrity
  - Risks to availability
  - Risks to rights and freedoms
  - Likelihood and severity of each risk
  |
  v
[Identify Mitigation Measures]
  - Technical measures (encryption, pseudonymization, access controls)
  - Organizational measures (policies, training, DPO oversight)
  - Contractual measures (DPAs, SCCs)
  |
  v
[Determine Residual Risk]
  |
  +--> [Residual Risk Acceptable] --> Approve and proceed
  |
  +--> [Residual Risk High] --> Consult DPO
  |                             |
  |                             +--> [Can mitigate further] --> Add measures
  |                             |
  |                             +--> [Cannot mitigate] --> Prior consultation
  |                                    with Supervisory Authority (Art. 36)
  |
  v
[Document DPIA]
  - Keep under review
  - Reassess when processing changes
  |
  v
End
```

## Workflow 4: International Data Transfer Assessment

```
Start
  |
  v
[Identify Cross-Border Transfer]
  - Data flowing outside EEA
  - Cloud services in non-EEA regions
  - Group company data sharing
  - Vendor/processor locations
  |
  v
[Check Adequacy Decision]
  - Is destination country on EU adequacy list?
  - (Andorra, Argentina, Canada, Faroe Islands, Guernsey,
     Israel, Isle of Man, Japan, Jersey, New Zealand, Republic
     of Korea, Switzerland, UK, Uruguay, US under DPF)
  |
  +--> [Adequate] --> Document and proceed
  |
  +--> [Not Adequate]
        |
        v
      [Select Transfer Mechanism]
        |
        +--> Standard Contractual Clauses (SCCs)
        +--> Binding Corporate Rules (BCRs)
        +--> Approved Code of Conduct
        +--> Certification Mechanism
        +--> Derogations (Art. 49) - limited circumstances
        |
        v
      [Conduct Transfer Impact Assessment (TIA)]
        - Laws of destination country
        - Government surveillance powers
        - Data protection standards
        - Access by public authorities
        |
        v
      [Identify Supplementary Measures]
        - Technical: encryption with EEA-held keys
        - Contractual: additional processor obligations
        - Organizational: policies limiting access
        |
        v
      [Document Transfer Mechanism]
        - Signed SCCs with correct module
        - TIA findings and conclusions
        - Supplementary measures implemented
  |
  v
End
```

## Workflow 5: Records of Processing Activities (ROPA)

```
Start
  |
  v
[Identify All Processing Activities]
  - Interview business units
  - Review system inventory
  - Analyze data flows
  - Check vendor agreements
  |
  v
[For Each Processing Activity Document:]
  |
  v
[Controller Record (Art. 30(1))]
  - Name and contact details of controller (and DPO)
  - Purposes of processing
  - Categories of data subjects
  - Categories of personal data
  - Categories of recipients
  - Transfers to third countries (safeguards)
  - Retention periods
  - Technical and organizational security measures
  |
  v
[Processor Record (Art. 30(2))]
  - Name and contact details of processor and controller
  - Categories of processing carried out
  - Transfers to third countries (safeguards)
  - Technical and organizational security measures
  |
  v
[Maintain and Update ROPA]
  - Review quarterly or when processing changes
  - Update for new systems, vendors, purposes
  - Make available to supervisory authority on request
  |
  v
End
```
