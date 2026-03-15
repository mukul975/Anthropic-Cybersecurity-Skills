# Standards and Framework References

## MITRE ATT&CK

- **Reconnaissance (TA0043)**: Pre-engagement intelligence gathering
  - T1595 - Active Scanning
  - T1592 - Gather Victim Host Information
  - T1589 - Gather Victim Identity Information
  - T1590 - Gather Victim Network Information
  - T1591 - Gather Victim Org Information
- **Resource Development (TA0042)**: Infrastructure and capability preparation
  - T1583 - Acquire Infrastructure
  - T1584 - Compromise Infrastructure
  - T1587 - Develop Capabilities
  - T1588 - Obtain Capabilities
  - T1608 - Stage Capabilities

## PTES (Penetration Testing Execution Standard)

### Pre-engagement Interactions
- Scope definition and boundaries
- Goals and objectives
- Rules of engagement
- Communication plan
- Emergency contacts
- Timeline and milestones
- Legal considerations
- Authorization documentation

### Intelligence Gathering
- OSINT requirements
- Threat actor identification
- Attack surface mapping
- Technology profiling

## OSSTMM (Open Source Security Testing Methodology Manual)

### Section 3: Rules of Engagement
- Test boundaries and limitations
- Test vectors classification
- Compliance requirements
- Reporting standards

### Section 4: Scope
- Physical security scope
- Wireless scope
- Telecommunications scope
- Data networks scope
- Social engineering scope

## NIST SP 800-115

### Technical Guide to Information Security Testing and Assessment
- Section 3: Review Techniques
- Section 4: Target Identification and Analysis
- Section 5: Target Vulnerability Validation
- Section 6: Security Assessment Planning

## CBEST Framework (Bank of England)

- Threat intelligence-led penetration testing
- Threat actor profile development
- Scenario-based adversary simulation
- Control validation and assessment

## TIBER-EU Framework

- European framework for threat intelligence-based ethical red teaming
- Phase 1: Generic Threat Landscape
- Phase 2: Threat Intelligence
- Phase 3: Red Team Testing
- Phase 4: Closure

## CREST STAR (Simulated Targeted Attack and Response)

- Intelligence-led red team testing standard
- Adversary simulation methodology
- Detection and response validation
- Structured reporting format

## Relevant CVE/CWE References

Not directly applicable for planning phase - CVE/CWE references will be mapped during the attack execution phase based on selected TTPs and target environment.

## Compliance Frameworks Impacting Scope

| Framework | Impact on Red Team Scope |
|-----------|--------------------------|
| PCI DSS | Cardholder data environment must be tested |
| HIPAA | PHI handling requires special data protections |
| SOX | Financial systems require specific authorization |
| GDPR | Personal data handling restrictions apply |
| CMMC | DoD contractor supply chain considerations |
