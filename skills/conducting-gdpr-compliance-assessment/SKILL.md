---
name: conducting-gdpr-compliance-assessment
description: >-
  Conduct comprehensive GDPR compliance assessments by evaluating data processing
  activities against EU Regulation 2016/679, including Article 30 records of processing,
  lawful basis validation, data subject rights implementation, Data Protection Impact
  Assessments (DPIAs) under Article 35, breach notification procedures, international
  transfer safeguards (SCCs, adequacy decisions), and technical/organizational measures
  under Article 32. Use when processing personal data of EU residents, preparing for
  supervisory authority audits, implementing privacy-by-design for new systems, scoping
  compliance gaps for M&A due diligence, assessing third-party processors, or responding
  to data subject access requests at scale. Incorporates 2026 guidance from ICO, EDPB,
  and post-Data (Use and Access) Act 2026 UK-GDPR considerations.
domain: cybersecurity
subdomain: compliance-governance
tags:
- gdpr
- data-protection
- privacy
- compliance
- dpia
- data-subject-rights
- article-30
- controller
- processor
- eu-regulation
- ico
- supervisory-authority
version: "1.0"
author: dakshverma23
license: Apache-2.0
nist_csf:
- GV.OC-02
- GV.PO-01
- GV.RM-04
- PR.DS-01
- PR.DS-02
- ID.AM-05
mitre_attack:
- T1530
- T1567
---

# Conducting GDPR Compliance Assessment

## When to Use

- When an organization **processes personal data of EU residents** (Article 3 territorial scope applies)
- When preparing for a **supervisory authority audit** (ICO, CNIL, BfDI) or responding to formal inquiry
- When implementing **privacy-by-design** requirements (Article 25) for new systems or data flows
- When **scoping compliance gaps** before M&A due diligence or contract negotiations with EU entities
- When responding to **data subject access requests (DSARs)** and discovering gaps in data inventory
- When assessing **third-party processors** for GDPR compliance before signing Data Processing Agreements (DPAs)
- After **data breach incidents** to verify notification procedures meet 72-hour requirement (Article 33)

**Do not use** for non-EU privacy frameworks alone (CCPA, PIPEDA, LGPD); those require separate assessments with jurisdiction-specific criteria.

## Prerequisites

- Understanding of **GDPR Articles 5-32** core requirements and key definitions (controller, processor, personal data, special category data)
- Access to organization's **Article 30 records** of processing activities (mandatory for controllers with 250+ employees or high-risk processing)
- Copies of **Data Processing Agreements (DPAs)** with third-party processors (Article 28 requirements)
- Access to **privacy policies, consent forms, cookie notices** currently in use
- Knowledge of applicable **lawful bases** (Article 6: consent, contract, legal obligation, vital interests, public task, legitimate interest)
- Copy of organization's **data breach response plan** and incident register (Article 33(5))
- List of **international data transfers** (non-EU/EEA destinations) and existing safeguards
- **Data flow diagrams** showing personal data collection, storage, processing, and deletion paths

## Workflow

### Phase 1: Determine Territorial Applicability (Article 3)

GDPR applies if ANY of these conditions are met:
1. Organization has an **establishment in the EU** (office, subsidiary, representative) regardless of where processing occurs
2. Organization **offers goods/services to EU residents** (even if not established in EU) — targeting evidenced by EU pricing, .eu domains, EU languages
3. Organization **monitors behavior of EU residents** (behavioral advertising, tracking, profiling)

```
Applicability Determination Checklist:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
□ EU office, subsidiary, or Article 27 representative designated?
□ Website targets EU users (.eu domains, EUR pricing, EU delivery)?
□ Marketing materials reference GDPR rights or EU data protection?
□ Cookie banners deployed for EU visitors?
□ Behavioral tracking of EU residents (analytics, retargeting)?
□ Processing location (does NOT determine applicability per EDPB guidance)?

If ANY checkbox = YES → Full GDPR compliance required
If all NO but occasional EU resident data → Limited applicability under derogations
```

**Note**: Post-Brexit, UK organizations follow **UK GDPR** (as amended by Data Protection Act 2018 and Data (Use and Access) Act 2026). Requirements are substantially similar but consult ICO for UK-specific guidance.

### Phase 2: Inventory Data Processing Activities (Article 30)

Controllers and processors must maintain **written records of processing activities**. Small companies (<250 employees) are exempt ONLY if processing is occasional, not high-risk, and excludes special categories — this exempts almost no SaaS, e-commerce, or B2C operators.

**For EACH processing activity, document**:
- Name and contact details of **controller** (and DPO if designated under Article 37)
- **Purposes** of processing (be specific: "targeted advertising based on browsing history" not "marketing")
- **Categories of data subjects** (customers, employees, children, vulnerable persons)
- **Categories of personal data** (names, email, IP addresses, location data, device IDs)
- **Special category data** (Article 9: health, biometric, genetic, racial/ethnic, political opinions, religious beliefs, trade union, sex life)
- **Categories of recipients** (who receives the data — CRM vendor Salesforce, payment processor Stripe, analytics provider Google)
- **International transfers** (non-EU/EEA destination countries + safeguards: SCCs, adequacy, BCRs)
- **Retention periods** (specific durations OR criteria to determine them: "until account deletion + 30 days")
- **Technical and organizational security measures** (encryption AES-256, access control MFA, pseudonymization, audit logging)
- **Categories of data subjects** (customers, employees, children, vulnerable persons)
- **Categories of personal data** (names, email, IP addresses, location data, device IDs)
- **Special category data** (Article 9: health, biometric, genetic, racial/ethnic, political opinions, religious beliefs, trade union, sex life)
- **Categories of recipients** (who receives the data — CRM vendor Salesforce, payment processor Stripe, analytics provider Google)
- **International transfers** (non-EU/EEA destination countries + safeguards: SCCs, adequacy, BCRs)
- **Retention periods** (specific durations OR criteria to determine them: "until account deletion + 30 days")
- **Technical and organizational security measures** (encryption AES-256, access control MFA, pseudonymization, audit logging)

**Automation approach**:
```bash
# Example: Parse existing DPAs and privacy policies for Article 30 fields
python scripts/article30_parser.py --input contracts/processors/ --output ropa.json

# Validate completeness against mandatory fields
python scripts/article30_validator.py --ropa ropa.json --check-retention --check-transfers

# Generate Article 30 register in supervisory authority format
python scripts/generate_ropa_report.py --input ropa.json --output Article30_Register.pdf
```

**Common gaps identified in 2026 audits** (per ICO/EDPB enforcement):
- Missing retention periods (found in 68% of SME audits)
- Vague purposes ("business operations" instead of specific use cases)
- Unidentified sub-processors in cloud service chains
- No documentation of international transfer safeguards

### Phase 3: Validate Lawful Basis for Each Activity (Article 6)

Every processing activity MUST have **one lawful basis**. You cannot switch basis after processing begins without valid justification.

| Lawful Basis | Use Cases | Requirements & Pitfalls |
|--------------|-----------|-------------------------|
| **Consent** (6(1)(a)) | Marketing emails, non-essential cookies, profiling | Must be freely given, specific, informed, unambiguous. Withdrawable as easily as given. Pre-ticked boxes INVALID. Bundled consent INVALID (per EDPB Guidelines 05/2020) |
| **Contract** (6(1)(b)) | Process order for delivery, create user account for service | Only for processing **strictly necessary** to perform contract. Cannot be used for analytics or marketing |
| **Legal Obligation** (6(1)(c)) | Tax record retention, employment law compliance | Must cite specific EU/member state law requiring processing |
| **Vital Interests** (6(1)(d)) | Medical emergency data sharing | Only when life is at risk and no other basis available |
| **Public Task** (6(1)(e)) | Government services, public health monitoring | Only for public authorities or those exercising official authority |
| **Legitimate Interest** (6(1)(f)) | Fraud prevention, network security, intra-group transfers | Requires **Legitimate Interest Assessment (LIA)** balancing test. Cannot override data subject rights |

**Verification procedure**:
```
FOR EACH processing activity in Article 30 register:
1. Identify the claimed lawful basis
2. IF "consent" → Verify:
   - Consent mechanism allows granular choice (not bundled)
   - Clear, plain language explanation provided at point of collection
   - Documented proof (consent receipts, timestamps)
   - Withdrawal mechanism equally easy as giving consent
   
3. IF "legitimate interest" → Verify:
   - Legitimate Interest Assessment (LIA) conducted and documented
   - LIA addresses: purpose, necessity, balance test, safeguards
   - Data subjects informed of LI basis in privacy notice
   
4. IF "special category data" (Article 9) → Verify ADDITIONAL condition:
   - Explicit consent, OR
   - Legal claims, OR
   - Substantial public interest (with appropriate basis in law), OR
   - Employment/social security law, etc.

5. Document in Article 30 register alongside each activity
```

**Red flags**:
- Claiming "contract" for marketing (not necessary for contract performance)
- Claiming "legitimate interest" without an LIA
- Multiple bases claimed for same activity (must choose ONE primary basis)



**Automation approach**:
```bash
# Parse existing DPAs and privacy policies for Article 30 fields
python scripts/article30_parser.py --input contracts/processors/ --output ropa.json

# Validate completeness against mandatory fields
python scripts/article30_validator.py --ropa ropa.json --check-retention --check-transfers

# Generate Article 30 register in supervisory authority format
python scripts/generate_ropa_report.py --input ropa.json --output Article30_Register.md
```

**Common gaps identified in 2026 audits** (per ICO/EDPB enforcement):
- Missing retention periods (found in 68% of SME audits)
- Vague purposes ("business operations" instead of specific use cases)
- Unidentified sub-processors in cloud service chains
- No documentation of international transfer safeguards

### Phase 3: Validate Lawful Basis for Each Activity (Article 6)

Every processing activity MUST have **one lawful basis**. You cannot switch basis after processing begins without valid justification.

| Lawful Basis | Use Cases | Requirements & Pitfalls |
|--------------|-----------|-------------------------|
| **Consent** (6(1)(a)) | Marketing emails, non-essential cookies, profiling | Must be freely given, specific, informed, unambiguous. Withdrawable as easily as given. Pre-ticked boxes INVALID. Bundled consent INVALID (per EDPB Guidelines 05/2020) |
| **Contract** (6(1)(b)) | Process order for delivery, create user account for service | Only for processing **strictly necessary** to perform contract. Cannot be used for analytics or marketing |
| **Legal Obligation** (6(1)(c)) | Tax record retention, employment law compliance | Must cite specific EU/member state law requiring processing |
| **Vital Interests** (6(1)(d)) | Medical emergency data sharing | Only when life is at risk and no other basis available |
| **Public Task** (6(1)(e)) | Government services, public health monitoring | Only for public authorities or those exercising official authority |
| **Legitimate Interest** (6(1)(f)) | Fraud prevention, network security, intra-group transfers | Requires **Legitimate Interest Assessment (LIA)** balancing test. Cannot override data subject rights |

**Verification procedure**:
```
FOR EACH processing activity in Article 30 register:
1. Identify the claimed lawful basis
2. IF "consent" → Verify:
   - Consent mechanism allows granular choice (not bundled)
   - Clear, plain language explanation provided at point of collection
   - Documented proof (consent receipts, timestamps)
   - Withdrawal mechanism equally easy as giving consent
   
3. IF "legitimate interest" → Verify:
   - Legitimate Interest Assessment (LIA) conducted and documented
   - LIA addresses: purpose, necessity, balance test, safeguards
   - Data subjects informed of LI basis in privacy notice
   
4. IF "special category data" (Article 9) → Verify ADDITIONAL condition:
   - Explicit consent, OR
   - Legal claims, OR
   - Substantial public interest (with appropriate basis in law), OR
   - Employment/social security law, etc.

5. Document in Article 30 register alongside each activity
```

**Red flags**:
- Claiming "contract" for marketing (not necessary for contract performance)
- Claiming "legitimate interest" without an LIA
- Multiple bases claimed for same activity (must choose ONE primary basis)

### Phase 4: Assess Data Subject Rights Implementation (Articles 12-23)

GDPR grants **eight data subject rights**. Verify technical/procedural capability:

| Right | Article | Organization Must Be Able To |
|-------|---------|------------------------------|
| **Right to be Informed** | Art 13-14 | Provide privacy notice at collection; transparent policies |
| **Right of Access** | Art 15 | Deliver copy of personal data within 1 month (DSAR) |
| **Right to Rectification** | Art 16 | Correct inaccurate data |
| **Right to Erasure** | Art 17 | Delete data when no longer necessary (with exceptions) |
| **Right to Restrict Processing** | Art 18 | Pause processing under certain conditions |
| **Right to Data Portability** | Art 20 | Export data in machine-readable format (CSV, JSON) |
| **Right to Object** | Art 21 | Stop processing for direct marketing or legitimate interest |
| **Rights re Automated Decision-Making** | Art 22 | Human review of algorithmic decisions with legal/significant effect |

**Assessment questions**:
```
□ Can the organization locate ALL personal data for a given data subject across systems?
□ Is there a documented DSAR procedure with <1 month SLA?
□ Can data be exported in structured, machine-readable format (CSV/JSON)?
□ Is there a "delete user" function that cascades across databases?
□ Are deletion requests logged for audit purposes?
□ Is automated decision-making (e.g., credit scoring, hiring algorithms) documented?
□ Do individuals have right to human review for automated decisions?
□ Are privacy notices provided at point of data collection?
```

**Testing procedure**:
```bash
# Test DSAR workflow end-to-end
1. Submit test DSAR for a known user
2. Time the response (must be ≤30 days)
3. Verify ALL personal data is included
4. Check format is machine-readable (CSV/JSON)
5. Confirm no personal data of other users leaked

# Test erasure capability
1. Submit deletion request for test user
2. Verify deletion across ALL systems (databases, backups, logs, analytics)
3. Confirm deletion logged in audit trail
4. Check retention exceptions properly applied (legal holds)
```

**Common implementation gaps** (2026 ICO findings):
- DSAR average response time: 18 days (compliant) but 31% exceed 30-day limit
- 47% of organizations cannot export data in machine-readable format
- 62% lack cascade-delete functionality across all systems
- 41% do not log deletion requests for audit

### Phase 5: Review Data Protection Impact Assessments (Article 35)

A **DPIA is mandatory** when processing is "likely to result in high risk" to rights:
- Systematic/extensive automated processing (profiling with significant effects)
- Large-scale processing of special category data (health, biometric)
- Systematic monitoring of public areas (CCTV, facial recognition)

**DPIA must contain**:
1. Description of processing operations and purposes
2. Assessment of **necessity and proportionality**
3. **Risks to data subject rights** (likelihood + severity)
4. **Mitigation measures** to address risks

```
DPIA Checklist:
━━━━━━━━━━━━━━
□ High-risk processing identified? (profiling, special categories, monitoring)
□ DPIA conducted BEFORE processing started?
□ DPIA reviewed by DPO (if designated)?
□ Supervisory authority consulted (if residual high risk after mitigations)?
□ DPIA updated when processing changes?
□ DPIA documents necessity (could purposes be achieved with less data)?
□ DPIA documents proportionality (is processing excessive)?
□ Risks rated (likelihood: low/medium/high × severity: low/medium/high)?
□ Mitigation measures reduce risk to acceptable level?
```

**Mandatory DPIA triggers** (EDPB Guidelines 09/2020):
1. **Systematic profiling**: Automated processing to evaluate personal aspects (creditworthiness, work performance, location, health)
2. **Large-scale special category data**: Processing health data of >10,000 individuals
3. **Systematic monitoring**: CCTV in public spaces, tracking online behavior, profiling for targeted ads
4. **Sensitive data matching/combining**: Combining datasets from different sources
5. **Vulnerable data subjects**: Children, elderly, employees (power imbalance)
6. **Innovative technology**: AI/ML, biometrics, IoT where risks unknown

**Example DPIA structure**:
```yaml
activity: Behavioral Advertising Platform
date: 2026-03-15
assessor: Privacy Officer

processing_description:
  purpose: Serve targeted ads based on browsing history
  data_categories: browsing URLs, click events, device IDs, location
  data_subjects: website visitors (including children)
  retention: 90 days

necessity_proportionality:
  necessity: Required to fund free service; contextual ads insufficient revenue
  proportionality: Excessive – collecting precise location when city-level sufficient
  
risks:
  - risk_id: R1
    description: Profiling reveals sensitive inferences (health, religion)
    likelihood: HIGH
    severity: HIGH
    risk_level: CRITICAL
    
mitigations:
  - measure_id: M1
    description: Implement sensitive category blocking (health, religion keywords)
    effectiveness: Reduces likelihood HIGH → MEDIUM
    responsibility: Engineering Team
    
residual_risk: MEDIUM (acceptable with ongoing monitoring)
authority_consultation: Not required (risk reduced to medium)

dpo_approval: [Name], 2026-03-16
controller_approval: [Name], 2026-03-17
```

### Phase 6: Audit Data Breach Notification Procedures (Articles 33-34)

**72-hour rule**: Controller must notify supervisory authority within **72 hours** of becoming aware of a personal data breach (unless unlikely to risk rights).

**Breach notification must include** (Article 33(3)):
- Nature of breach (categories/approximate number of data subjects affected)
- Contact details of DPO or contact point
- Likely consequences
- Measures taken/proposed to mitigate

**Assessment**:
```bash
# Test breach detection and notification process
1. Simulate breach scenario (authorized test with legal approval)
2. Time detection → internal escalation → DPO notification → authority draft
3. Verify notification template contains all Article 33(3) requirements
4. Check if breach register exists (Article 33(5) - mandatory)

# Example: Check for breach detection tooling
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetObject \
  --max-items 100 --output json | \
  jq '.Events[] | select(.Resources[].ResourceName | contains("sensitive"))'
```

**Breach notification timeline verification**:
```
Hour 0:   Breach detected (e.g., intrusion alert, data exfiltration alarm)
Hour 1:   Security team confirms breach involves personal data
Hour 2:   DPO notified
Hour 4:   Breach scope assessment begins
Hour 24:  Scope confirmed (X data subjects, Y data categories)
Hour 48:  Notification drafted with all Article 33(3) elements
Hour 70:  Legal review complete
Hour 72:  Notification submitted to supervisory authority ← DEADLINE

If >72 hours: Must include reasons for delay in notification
```

**Data subject notification** (Article 34):
- Required when breach **likely to result in high risk** to rights
- Direct notification "without undue delay"
- Exceptions: Data encrypted/pseudonymized, subsequent measures eliminate high risk, disproportionate effort (public communication acceptable)

**Breach register template** (Article 33(5)):
```json
{
  "breach_id": "BR-2026-001",
  "discovered_date": "2026-03-10T14:30:00Z",
  "notification_date_authority": "2026-03-12T10:00:00Z",
  "72_hour_deadline": "2026-03-13T14:30:00Z",
  "within_deadline": true,
  "affected_data_subjects": 1500,
  "categories_of_data": ["email", "name", "payment_card_last4"],
  "likely_consequences": "Risk of phishing targeting affected users",
  "measures_taken": "Mandatory password reset, MFA enforced, users notified",
  "supervisory_authority": "ICO",
  "notification_reference": "ICO-BR-2026-12345"
}
```

### Phase 7: Verify International Transfer Safeguards (Chapter V)

Transfers to **non-EU/EEA countries** require safeguards unless exemptions apply:

| Mechanism | Description | When to Use |
|-----------|-------------|-------------|
| **Adequacy Decision** | EU Commission deems country has adequate protection | UK, Switzerland, Japan, Canada (commercial), Argentina, Uruguay, Israel, New Zealand, South Korea, Andorra, Faroe Islands, Guernsey, Isle of Man, Jersey |
| **Standard Contractual Clauses (SCCs)** | EU-approved contract templates (2021 version) | Most common for cloud providers (AWS, Google, Microsoft) |
| **Binding Corporate Rules (BCRs)** | Internal data protection policies for multinationals | Large enterprises with intra-group transfers |
| **Derogations** (Art 49) | Explicit consent, contract necessity, legal claims | Rare, limited cases only; cannot be used for repeated/systematic transfers |

**Verification procedure**:
```
FOR EACH third-party processor outside EU/EEA:
1. Identify transfer destination country
2. Check if adequacy country (see list above)
3. IF NOT adequacy → verify SCCs signed (MUST be 2021 version)
4. Verify supplementary measures for high-risk countries (encryption, pseudonymization)
5. Check if Transfer Impact Assessment (TIA) conducted (required post-Schrems II)
6. Document in Article 30 register

# Example: US transfers
- Data Privacy Framework (DPF): Adequacy decision (2023) for certified organizations
- Non-DPF organizations: Require SCCs + supplementary measures
- Government access risk: TIA should address FISA 702, EO 12333
```

**SCCs 2021 version** (mandatory since Sep 27, 2021):
- **Module 1**: Controller to Controller
- **Module 2**: Controller to Processor (most common for SaaS)
- **Module 3**: Processor to Processor (sub-processors)
- **Module 4**: Processor to Controller

**Transfer Impact Assessment (TIA) checklist**:
```
□ Destination country laws reviewed (government access, surveillance)?
□ Encryption in transit and at rest implemented?
□ Data minimization applied (only essential data transferred)?
□ Pseudonymization used where possible?
□ Access controls limit who can decrypt/access data?
□ Contractual obligations exceed SCCs where needed?
□ Regular audits of processor security measures?
□ Exit strategy documented (data return/deletion upon termination)?
```

### Phase 8: Assess Technical & Organizational Measures (Article 32)

"Security appropriate to the risk" including:
- Pseudonymization and encryption
- Confidentiality, integrity, availability, resilience
- Regular testing and evaluation
- Incident response capability

**Security controls checklist**:
```
ENCRYPTION
□ Data-at-rest encrypted? (AES-256 or equivalent)
□ Data-in-transit encrypted? (TLS 1.2+ for all personal data transmission)
□ Encryption keys managed securely? (HSM, KMS, rotation policy)
□ Pseudonymization applied where appropriate?

ACCESS CONTROL
□ Least privilege principle enforced?
□ Multi-factor authentication (MFA) required for admin access?
□ Role-based access control (RBAC) implemented?
□ Access reviews conducted regularly? (quarterly/annually)
□ Segregation of duties for sensitive operations?

MONITORING & LOGGING
□ Audit logging enabled for all personal data access?
□ Logs retained for appropriate period? (6-12 months typical)
□ Logs monitored for anomalous access patterns?
□ SIEM/security monitoring in place?
□ Log integrity protected (tamper-proof)?

RESILIENCE
□ Backup and disaster recovery tested?
□ RPO (Recovery Point Objective) defined and met?
□ RTO (Recovery Time Objective) defined and met?
□ Redundancy for critical systems?

TESTING
□ Penetration testing conducted? (annually minimum for high-risk)
□ Vulnerability scanning? (quarterly minimum)
□ Security awareness training for staff? (annual minimum)
□ Incident response plan tested? (tabletop exercises)
```

**Example security configuration validation**:
```bash
# Check TLS version on web servers
nmap --script ssl-enum-ciphers -p 443 example.com | grep "TLSv1.2\|TLSv1.3"

# Verify encryption-at-rest for S3 buckets
aws s3api get-bucket-encryption --bucket your-bucket-name

# Check database encryption
# PostgreSQL:
psql -c "SHOW ssl;"
psql -c "SELECT * FROM pg_settings WHERE name LIKE '%encrypt%';"

# Check MFA enforcement for AWS IAM users
aws iam get-credential-report | jq '.[] | select(.mfa_active == "false")'
```

### Phase 9: Compile Findings and Remediation Roadmap

Generate comprehensive **GDPR compliance report** with:

1. **Executive summary** (compliance posture, critical gaps, risk level)
2. **Compliance scorecard** (use `assets/compliance-scorecard.md` template)
3. **Article-by-article assessment** (compliant, partial, non-compliant)
4. **Risk-rated findings** (Critical, High, Medium, Low)
5. **Remediation roadmap** with ownership, timelines, and milestones
6. **Next steps** (immediate actions, 30/60/90-day priorities)

**Use the compliance scorecard**:
```bash
# Generate filled compliance scorecard
cp assets/compliance-scorecard.md assessment_results/GDPR_Compliance_Scorecard_2026-03-15.md
# Fill in assessment results for each section
# Calculate weighted score
```

**Remediation prioritization matrix**:

| Risk Level | Timeline | Criteria |
|------------|----------|----------|
| **🔴 Critical** | 0-30 days | Missing Article 30 records, no lawful basis, 72-hour breach notification incapable, international transfers without safeguards |
| **🟡 High** | 1-3 months | Incomplete DSAR capability, missing DPIAs for high-risk, weak encryption (TLS 1.0/1.1), no MFA for admin |
| **🟠 Medium** | 3-6 months | Retention periods not documented, consent mechanisms not granular, no LIAs for legitimate interest, audit logging gaps |
| **🔵 Low** | 6-12 months | Privacy policy updates, staff training expansion, penetration testing frequency increase |

## Key Concepts

| Term | Definition |
|------|------------|
| **Controller** | Entity that determines **purposes and means** of processing (the "decision-maker"); bears primary GDPR compliance responsibility |
| **Processor** | Entity that processes data **on behalf of** the controller (e.g., cloud provider, payroll vendor, email service); must follow controller instructions |
| **Personal Data** | Any information relating to an **identified or identifiable** natural person (Article 4(1)); includes names, IDs, location data, online identifiers |
| **Special Category Data** | Sensitive data requiring extra protection: race, ethnic origin, political opinions, religious/philosophical beliefs, trade union membership, genetic data, biometric data, health data, sex life/sexual orientation (Article 9) |
| **Data Subject** | The individual whose personal data is being processed; has rights under Articles 12-23 |
| **Supervisory Authority** | National data protection authority (e.g., ICO in UK, CNIL in France, BfDI in Germany) responsible for enforcement |
| **DPO (Data Protection Officer)** | Designated person monitoring GDPR compliance; **mandatory** for public authorities, large-scale monitoring, or large-scale special category data (Articles 37-39) |
| **DPIA (Data Protection Impact Assessment)** | Risk assessment required for high-risk processing (Article 35); must include necessity, risks, and mitigations |
| **DSAR (Data Subject Access Request)** | Formal request by individual to access their personal data (Article 15); must be fulfilled within 1 month |
| **Lawful Basis** | Legal justification for processing (Article 6): consent, contract, legal obligation, vital interests, public task, legitimate interest |
| **Consent** | Freely given, specific, informed, unambiguous indication of data subject's wishes by statement or clear affirmative action (Article 4(11)) |
| **Legitimate Interest** | Lawful basis requiring balancing test (Article 6(1)(f)); processing necessary for legitimate interests except where overridden by data subject rights |
| **SCCs (Standard Contractual Clauses)** | EU-approved contract templates for international data transfers (2021 version current); provide adequate safeguards per Article 46 |
| **Adequacy Decision** | EU Commission determination that a non-EU country ensures adequate data protection (Article 45); allows free data flow |
| **Pseudonymization** | Processing data so it can no longer be attributed to a specific data subject without additional information (Article 4(5)); security measure under Article 32 |
| **RoPA (Records of Processing Activities)** | Written register required by Article 30 documenting all processing activities; mandatory for most organizations |

## Tools & Systems

| Tool | Purpose | Category | Source |
|------|---------|----------|--------|
| **OneTrust** | GRC platform for GDPR compliance management, cookie consent, DSAR automation | Commercial | https://onetrust.com |
| **TrustArc** | Privacy management platform, DPIA automation, assessment workflows | Commercial | https://trustarc.com |
| **DataGrail** | Data subject rights automation, DSAR fulfillment across SaaS apps | Commercial | https://datagrail.io |
| **BigID** | Data discovery and classification for GDPR data inventory | Commercial | https://bigid.com |
| **Transcend** | Privacy infrastructure, automated DSAR fulfillment, consent management | Commercial | https://transcend.io |
| **Open Data Rights** | Open-source DSAR automation toolkit | Open Source | https://github.com/opendatarights |
| **Osano** | Cookie consent management, data mapping, vendor risk | Commercial | https://osano.com |
| **Cookiebot** | Cookie consent management, cookie scanning, GDPR-compliant banners | Commercial | https://cookiebot.com |
| **GDPR.eu** | Official GDPR text, guidance, checklists | Reference | https://gdpr.eu |
| **ICO Toolkit** | UK supervisory authority self-assessment tools | Reference | https://ico.org.uk |

## Common Scenarios

### Scenario 1: Third-Party SaaS Processor Compliance Assessment

**Context**: You're a SaaS controller (B2B platform) evaluating a CRM vendor (processor) before signing a Data Processing Agreement. The vendor will process customer contact details (names, emails, company names) for sales pipeline management.

**Approach**:
1. **Request vendor's Article 30 records**: Ask for their processing register showing what personal data they process, for what purposes, retention periods, and sub-processors (e.g., AWS for hosting).

2. **Verify DPA template includes all Article 28 requirements**:
   ```
   □ Processing subject matter, duration, nature, purpose (Article 28(3))
   □ Processor processes only on documented instructions
   □ Confidentiality obligations for processor staff
   □ Security measures appropriate to risk (Article 32)
   □ Sub-processor rules: controller approval, flow-down obligations
   □ Assistance with data subject rights (Art 15-22)
   □ Assistance with security and breach obligations
   □ Deletion or return of data after service termination
   □ Audit rights for controller
   □ Processor liability for damages (Article 82)
   ```

3. **Check sub-processors**: Verify the vendor discloses all sub-processors (e.g., AWS us-east-1 for hosting). Confirm they are covered by either:
   - Adequacy decision (AWS has Data Privacy Framework certification for US), OR
   - Standard Contractual Clauses (SCCs)

4. **Review vendor's security certifications**: Request SOC 2 Type II, ISO 27001, or equivalent. While not GDPR-specific, these demonstrate "appropriate technical and organizational measures" per Article 32.

5. **Assess vendor's breach notification SLA**: Can they notify you within 24-48 hours of discovering a breach? (You need this to meet your own 72-hour deadline to supervisory authority.)

6. **Document in your Article 30 register**:
   ```yaml
   activity: Customer Relationship Management
   controller: [Your Company]
   processor: [CRM Vendor]
   purpose: Sales pipeline tracking, customer communication
   data_categories: names, emails, company names, phone numbers
   recipients: [CRM Vendor (processor), AWS (sub-processor)]
   retention: Until customer relationship ends + 6 years (legal claims)
   transfers: USA (AWS us-east-1, adequacy via Data Privacy Framework)
   security: Processor certified SOC 2 Type II, AES-256 encryption, TLS 1.3
   ```

7. **Sign DPA** before any personal data is shared with vendor.

**Pitfalls to avoid**:
- ❌ Assuming SOC 2 = GDPR compliance (it covers security but not all GDPR requirements)
- ❌ Failing to get written sub-processor list (you need to know ALL parties touching data)
- ❌ Not verifying international transfer safeguards (even within US, check Data Privacy Framework)
- ❌ Signing DPA with 2010 SCCs (must be 2021 version as of Sept 27, 2021)

---

### Scenario 2: Responding to Supervisory Authority Audit (ICO Inquiry)

**Context**: Your organization received a preliminary inquiry letter from the ICO (UK supervisory authority) following a data subject complaint. The ICO requests evidence of GDPR compliance within 30 days.

**Approach**:
1. **Engage legal counsel immediately** (responses are legally binding and can be used in enforcement proceedings).

2. **Compile Article 30 records**:
   ```bash
   python scripts/generate_ropa_report.py --input ropa.json \
     --output ICO_Article30_Register.pdf --format pdf
   ```
   Ensure all mandatory fields complete (purposes, data categories, retention, transfers, security).

3. **Gather lawful basis documentation**:
   - If **consent**: Consent receipts, timestamps, withdrawal mechanism evidence
   - If **legitimate interest**: Legitimate Interest Assessments (LIAs) for each activity
   - If **contract**: Contract templates showing processing is necessary for performance
   - If **special category data**: Document additional Article 9 legal basis (explicit consent, legal claims, etc.)

4. **Prepare DPIA reports** for high-risk processing:
   - Collect all completed DPIAs
   - Verify DPO reviewed and signed each DPIA
   - If any high-risk processing has NO DPIA → immediate remediation required (critical gap)

5. **Document data subject rights fulfillment**:
   ```
   DSAR Statistics (Last 12 Months):
   - Total requests received: 47
   - Average response time: 18 days (compliant: <30 days)
   - Requests fulfilled: 45
   - Requests refused (with justification): 2
   - Complaints escalated to ICO: 0
   ```

6. **Provide evidence of technical measures** (Article 32):
   - Encryption configurations (TLS 1.3 for transit, AES-256 for rest)
   - Access control policies (RBAC, MFA rollout percentage)
   - Audit logging retention policy
   - Backup and disaster recovery procedures
   - Most recent penetration test report (summary)
   - Security awareness training records

7. **Demonstrate DPO involvement** (if designated per Article 37):
   - DPO contact details published in privacy policy
   - Evidence of DPO consultation on high-risk processing
   - DPO independence (not reporting to senior management on data processing matters)

8. **Address the specific complaint** (if inquiry stemmed from data subject complaint):
   - Timeline of events
   - Actions taken to remediate
   - Steps to prevent recurrence
   - Compensation offered to data subject (if applicable)

9. **Submit response within deadline** (typically 30 days):
   - Cover letter summarizing compliance posture
   - Appendices with evidence (Article 30 register, DPIAs, policies, certifications)
   - Legal review before submission

**Pitfalls to avoid**:
- ❌ Incomplete Article 30 records (missing retention periods is #1 ICO finding)
- ❌ Claiming "legitimate interest" without an LIA (automatic non-compliance finding)
- ❌ Missing DPIA for high-risk processing (e.g., large-scale profiling)
- ❌ Overstating compliance maturity (ICO will verify claims; dishonesty escalates enforcement)
- ❌ Missing the 30-day response deadline (extends investigation, increases penalties)

**Likely outcome**:
- ✅ **No further action**: If compliance demonstrated (minor gaps acceptable if remediation plan provided)
- ⚠️ **Advisory notice**: ICO identifies gaps, requires remediation within specified timeframe (no fine)
- 🔴 **Enforcement notice**: Formal order to take specific actions; failure = criminal offense
- 🔴 **Monetary penalty**: Up to €20M or 4% of global turnover for serious violations

## Output Format

```
GDPR COMPLIANCE ASSESSMENT REPORT
==================================
Organization:          Acme SaaS Inc.
Assessment Period:     2026-02-01 to 2026-03-15
Assessor:              Security & Privacy Team
Supervisory Authority: ICO (Information Commissioner's Office, UK)
Scope:                 All processing activities involving EU/UK residents

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

EXECUTIVE SUMMARY
─────────────────
Overall Compliance Score:  73/100 (PARTIALLY COMPLIANT)
Risk Level:                MEDIUM-HIGH
Critical Findings:         3
High Priority Findings:    7
Medium Priority Findings:  12

Compliance Status: 🟡 PARTIALLY COMPLIANT
Action Required:   Immediate remediation of 3 critical findings within 30 days

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

COMPLIANCE SCORECARD BY AREA
┌─────────────────────────────┬────────┬────────┬─────────┐
│ Area                        │ Score  │ Target │ Status  │
├─────────────────────────────┼────────┼────────┼─────────┤
│ Territorial Applicability   │ 4/4    │ 100%   │ ✓ PASS  │
│ Article 30 Records (RoPA)   │ 41/55  │ 75%    │ ~ PART  │
│ Lawful Basis Validation     │ 7/10   │ 70%    │ ~ PART  │
│ Data Subject Rights         │ 6/8    │ 75%    │ ~ PART  │
│ DPIAs                       │ 3/7    │ 43%    │ ✗ FAIL  │
│ Breach Notification         │ 4/6    │ 67%    │ ~ PART  │
│ International Transfers     │ 5/10   │ 50%    │ ✗ FAIL  │
│ Security Measures (Art 32)  │ 8/10   │ 80%    │ ✓ PASS  │
│ Processor Management        │ 3/6    │ 50%    │ ✗ FAIL  │
│ DPO (if required)           │ N/A    │ N/A    │ N/A     │
└─────────────────────────────┴────────┴────────┴─────────┘

OVERALL WEIGHTED SCORE: 73/100

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

CRITICAL FINDINGS (Immediate Action - 0-30 Days)
════════════════════════════════════════════════

[F-001] 🔴 Missing DPIAs for High-Risk Processing
Article:       35 (Data Protection Impact Assessment)
Risk Level:    CRITICAL
Current State: No DPIAs conducted for behavioral advertising platform
               processing 500K+ user profiles with sensitive inferences
Requirement:   Article 35 mandates DPIA for systematic large-scale profiling
Impact:        Non-compliance with mandatory GDPR requirement; potential
               supervisory authority enforcement action
Remediation:   1. Conduct DPIA for advertising platform within 14 days
               2. DPO review and sign-off required
               3. If residual high risk, consult ICO before proceeding
Owner:         Privacy Officer
Due Date:      2026-04-05 (21 days)

[F-002] 🔴 International Transfers Without Safeguards
Article:       44-50 (International Transfers)
Risk Level:    CRITICAL
Current State: Personal data transferred to US-based analytics provider
               (Segment) without Standard Contractual Clauses
Requirement:   Chapter V requires adequacy decision OR SCCs for non-EU transfers
Impact:        Unlawful data transfers; immediate suspension required
Remediation:   1. Verify Segment Data Privacy Framework certification, OR
               2. Sign 2021 SCCs with Segment within 7 days, OR
               3. Suspend data transfers until safeguards in place
Owner:         Legal + Procurement
Due Date:      2026-03-22 (7 days)

[F-003] 🔴 Article 30 Records Incomplete
Article:       30 (Records of Processing Activities)
Risk Level:    CRITICAL
Current State: 14 of 27 processing activities lack documented retention periods
Requirement:   Article 30(1)(f) requires retention periods for all activities
Impact:        Incomplete RoPA = non-compliance with fundamental obligation
Remediation:   1. Legal team defines retention periods for all 14 activities
               2. Update Article 30 register with specific durations
               3. Implement automated deletion after retention expires
Owner:         Legal + Data Governance
Due Date:      2026-04-15 (30 days)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

HIGH PRIORITY FINDINGS (1-3 Months)
═════════════════════════════════════

[F-004] 🟡 DSAR Response Capability Gaps
[F-005] 🟡 No Legitimate Interest Assessments (LIAs)
[F-006] 🟡 Consent Mechanism Not Granular
[F-007] 🟡 Missing Data Processing Agreements
[... 3 more findings]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

REMEDIATION ROADMAP
═══════════════════

Phase 1 (0-30 days): Address Critical Findings
┌─────────────┬────────────────────────────┬────────────┬────────────┐
│ Milestone   │ Task                       │ Owner      │ Deadline   │
├─────────────┼────────────────────────────┼────────────┼────────────┤
│ Week 1      │ Sign Segment SCCs          │ Legal      │ 2026-03-22 │
│ Week 2      │ Complete advertising DPIA  │ Privacy    │ 2026-04-05 │
│ Week 3-4    │ Document retention periods │ Legal+Data │ 2026-04-15 │
└─────────────┴────────────────────────────┴────────────┴────────────┘

Phase 2 (1-3 months): High Priority Remediation
Phase 3 (3-6 months): Medium Priority Improvements
Phase 4 (6-12 months): Continuous Enhancement

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

NEXT STEPS
══════════
1. Executive briefing: Present findings to C-suite within 3 business days
2. Immediate actions: Begin critical finding remediation (F-001, F-002, F-003)
3. Budget approval: Allocate resources for OneTrust/TrustArc implementation
4. External support: Engage privacy counsel for DPO designation assessment
5. Follow-up assessment: Re-assess in 90 days to measure improvement

ASSESSMENT SIGN-OFF
═══════════════════
Assessed by:  [Privacy Officer], 2026-03-15
Reviewed by:  [CISO], 2026-03-16
Approved by:  [CEO], 2026-03-17

Report Generated: 2026-03-15T16:45:00Z
Next Review Due:  2026-06-15 (Quarterly)
```

## Verification Checklist

- [ ] **Territorial applicability** confirmed (Article 3 scope determination documented)
- [ ] **Article 30 RoPA** complete with all mandatory fields for every processing activity
- [ ] **Lawful basis** identified and documented for 100% of processing activities
- [ ] **Legitimate Interest Assessments (LIAs)** conducted for all "legitimate interest" claims
- [ ] **Special category data** (Article 9) has documented additional legal basis
- [ ] **Data subject rights** procedures documented for all 8 rights (Articles 12-23)
- [ ] **DSAR capability** tested end-to-end (≤30 day response time verified)
- [ ] **Machine-readable export** functionality confirmed (CSV/JSON format)
- [ ] **Cascade deletion** capability verified across all systems
- [ ] **DPIAs completed** for all mandatory high-risk processing (Article 35)
- [ ] **Breach notification procedure** tested (72-hour timeline achievable)
- [ ] **Breach register** maintained per Article 33(5)
- [ ] **International transfer safeguards** verified for ALL non-EU/EEA transfers
- [ ] **SCCs signed** (2021 version) with all processors outside adequacy countries
- [ ] **Transfer Impact Assessments (TIAs)** conducted for high-risk destination countries
- [ ] **Data Processing Agreements (DPAs)** signed with ALL processors (Article 28 requirements)
- [ ] **Sub-processors disclosed** and controller approval obtained
- [ ] **Encryption at-rest** implemented (AES-256 or equivalent)
- [ ] **Encryption in-transit** implemented (TLS 1.2+ for all personal data)
- [ ] **Access control** enforced (least privilege, RBAC, MFA for admin)
- [ ] **Audit logging** enabled and retained (6-12 months minimum)
- [ ] **Backup and recovery** tested (RPO/RTO defined and met)
- [ ] **Penetration testing** conducted (annual minimum for high-risk systems)
- [ ] **Security awareness training** completed (annual for all staff handling personal data)
- [ ] **Privacy policies** updated and accessible at point of data collection
- [ ] **DPO designated** (if required by Article 37 criteria)
- [ ] **DPO contact published** in privacy policy and communicated to supervisory authority
- [ ] **Compliance review scheduled** (annual reassessment date confirmed)

---

*This skill provides a comprehensive framework for GDPR compliance assessment. For ongoing compliance, pair with `implementing-privacy-by-design` and `automating-dsar-fulfillment` skills. Always consult qualified legal counsel for jurisdiction-specific guidance and enforcement matters.*
