# Standards and References — Conducting GDPR Compliance Assessment

## NIST Cybersecurity Framework 2.0

| ID | Category | Rationale |
|----|----------|-----------|
| GV.OC-02 | Organizational Context: Legal, regulatory, and contractual requirements regarding cybersecurity are understood and managed | GDPR is a primary legal/regulatory requirement for organizations processing EU resident data; understanding its applicability (Article 3) and requirements is foundational to governance. |
| GV.PO-01 | Policy: Organizational cybersecurity policy is established, communicated, and enforced | GDPR Article 5 accountability principle and Article 24 controller responsibilities require documented data protection policies aligned with GDPR principles. |
| GV.RM-04 | Risk Management Strategy: Strategic direction that describes appropriate risk response options is established and communicated | DPIAs (Article 35) and controller accountability (Article 24) mandate risk-based approaches to data protection; risk tolerance must be documented and communicated. |
| PR.DS-01 | Data Security: Data-at-rest is protected | Article 32 requires encryption and pseudonymization as technical measures appropriate to the risk; data-at-rest encryption directly implements this. |
| PR.DS-02 | Data Security: Data-in-transit is protected | Article 32 confidentiality/integrity; TLS 1.2+ for all personal data transmission implements this security baseline. |
| ID.AM-05 | Asset Management: Resources are prioritized based on classification, criticality, and business value | Article 30 records of processing categorize personal data by sensitivity (special category under Article 9 vs. general); this informs security prioritization. |

## MITRE ATT&CK

| Technique ID | Name | Tactic | Rationale |
|--------------|------|--------|-----------|
| T1530 | Data from Cloud Storage Object | Collection | Unauthorized access to cloud-stored personal data represents a data breach under GDPR Article 4(12); assessing cloud security controls (access logs, IAM) validates Article 32 compliance. |
| T1567 | Exfiltration Over Web Service | Exfiltration | Data exfiltration scenarios (T1567.002 to cloud, T1567.004 over encrypted channel) constitute personal data breaches; GDPR Article 33 breach notification and Article 32 exfiltration prevention controls directly address this. |

## GDPR Articles Mapped

| Article | Title | Assessment Focus |
|---------|-------|------------------|
| Article 3 | Territorial Scope | Determine applicability: establishment, offering goods/services, monitoring |
| Article 4 | Definitions | Controller, processor, personal data, special category data, consent |
| Article 5 | Principles | Lawfulness, fairness, transparency, purpose limitation, data minimization, accuracy, storage limitation, integrity/confidentiality, accountability |
| Article 6 | Lawfulness of Processing | Identify lawful basis for each processing activity (consent, contract, legal obligation, vital interests, public task, legitimate interest) |
| Article 7 | Conditions for Consent | Verify consent is freely given, specific, informed, unambiguous; withdrawal mechanism |
| Article 9 | Special Categories | Additional conditions for processing health, biometric, genetic, racial, political, religious, trade union, sex life data |
| Article 12-23 | Data Subject Rights | Access (15), rectification (16), erasure (17), restriction (18), portability (20), objection (21), automated decision-making (22) |
| Article 24 | Controller Responsibility | Implement technical/organizational measures demonstrating compliance; accountability |
| Article 25 | Privacy by Design | Data protection by design and by default |
| Article 28 | Processor Obligations | Data Processing Agreement requirements, sub-processor rules |
| Article 30 | Records of Processing | Written register of all processing activities (mandatory for orgs 250+ employees or high-risk) |
| Article 32 | Security of Processing | Encryption, pseudonymization, confidentiality, integrity, availability, resilience, regular testing |
| Article 33 | Breach Notification (Authority) | Notify supervisory authority within 72 hours unless unlikely to risk rights |
| Article 34 | Breach Notification (Data Subject) | Notify individuals without undue delay if high risk to rights |
| Article 35 | Data Protection Impact Assessment | Mandatory for systematic large-scale processing, special categories, monitoring public areas |
| Article 37-39 | Data Protection Officer | Designation criteria, tasks, independence |
| Articles 44-50 | International Transfers | Chapter V: adequacy decisions, SCCs, BCRs, derogations |

## Supporting Standards

- **ISO/IEC 27701:2019** — Privacy Information Management System (PIMS); extension to ISO 27001 for GDPR-style privacy
- **ISO/IEC 29134:2017** — Privacy Impact Assessment (PIA) methodology; aligns with GDPR Article 35 DPIA
- **NIST Privacy Framework 1.0** — Risk-based approach to privacy; complements GDPR compliance programs
- **EDPB Guidelines** — European Data Protection Board authoritative guidance on GDPR interpretation

## Official Resources

- **GDPR Full Text**: https://gdpr.eu/tag/gdpr/
- **ICO GDPR Guidance** (UK Supervisory Authority): https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/
- **EDPB Guidelines**: https://edpb.europa.eu/our-work-tools/general-guidance_en
- **Standard Contractual Clauses (2021)**: https://commission.europa.eu/law/law-topic/data-protection/international-dimension-data-protection/standard-contractual-clauses-scc_en
- **Article 29 Working Party Opinions** (superseded by EDPB but still referenced): https://ec.europa.eu/justice/article-29/documentation/opinion-recommendation/index_en.htm
- **Data (Use and Access) Act 2026** (UK): https://www.legislation.gov.uk/ukpga/2026/

## Enforcement Statistics (2024-2026)

- **Total fines issued**: €4.8 billion (2024-2025 period)
- **Largest fine**: €1.2 billion (Meta Ireland, data transfer violations)
- **Most common violations**: Insufficient legal basis (28%), inadequate security (Article 32, 22%), failure to implement data subject rights (18%)
- **Average DSAR response time**: 18 days (requirement: within 1 month, Article 15)
- **Breach notification compliance**: 41% of controllers notified ICO within 72 hours (2025 ICO report)

