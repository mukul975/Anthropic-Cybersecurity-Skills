# Standards Reference - Redacting PII with Microsoft Presidio

## NIST SP 800-122: Guide to Protecting the Confidentiality of PII

NIST SP 800-122 provides guidelines for identifying, assessing risk, and safeguarding Personally Identifiable Information.

### PII Confidentiality Impact Levels

- **High Impact**: PII whose unauthorized disclosure could cause severe or catastrophic harm (loss of life, severe financial ruin, criminal liability). Examples: Social Security numbers, medical records, financial credentials.
- **Moderate Impact**: PII whose compromise causes serious adverse effects (credit damage, employment complications). Examples: Date of birth, home address, mother's maiden name.
- **Low Impact**: PII with limited adverse effect when disclosed in isolation. Examples: First and last name, office telephone number.

### De-Identification Techniques

- **De-Identification**: Removing the association between the identifying dataset and the data subject.
- **Pseudonymization**: Replacing private identifiers with pseudonyms or hashes such that additional information is required to re-identify the subject.
- **Aggregation / Generalization**: Coarsening attribute precision (e.g., transforming full zip code to 3-digit prefix).

---

## NIST Cybersecurity Framework (CSF) 2.0 Mapping

| Control ID | Function / Category | Application to Presidio PII Redaction |
|---|---|---|
| **PR.DS-01** | Protect: Data Security | Confidentiality, integrity, and availability of data at rest are protected by redacting direct personal identifiers before long-term persistent storage. |
| **PR.DS-02** | Protect: Data Security | Data in transit is protected by filtering sensitive PII tokens prior to external API dispatch (e.g., LLM gateway egress). |
| **PR.DS-05** | Protect: Data Security | Protections against data leaks are implemented via automated pattern matching and DLP sanitization filters. |
| **PR.PS-01** | Protect: Platform Security | Configuration of redaction pipelines ensures default masking for unclassified sensitive string tokens. |

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Mitigating Presidio Control |
|---|---|---|
| **T1005** | Data from Local System | Sanitizes sensitive customer files and local logs so that adversarial host reconnaissance acquires only pseudonymized or masked tokens. |
| **T1530** | Data from Cloud Storage Object | Enforces automated redaction before data ingestion into S3/Blob storage buckets, minimizing exposure in unauthenticated exfiltration scenarios. |
| **T1552** | Unsecured Credentials | Custom recognizers intercept API tokens, private keys, and credential strings embedded within conversational or transactional datasets. |

---

## HIPAA Safe Harbor De-Identification (45 CFR § 164.514(b))

Under the HIPAA Privacy Rule Safe Harbor method, health data is considered de-identified when 18 designated categories of identifiers are removed:

1. Names
2. Geographic subdivisions smaller than state (street address, city, county, ZIP code)
3. All dates directly related to an individual (birth date, admission date, discharge date, date of death)
4. Telephone numbers
5. Fax numbers
6. Email addresses
7. Social Security numbers
8. Medical record numbers
9. Health plan beneficiary numbers
10. Account numbers
11. Certificate/license numbers
12. Vehicle identifiers and serial numbers (license plates)
13. Device identifiers and serial numbers
14. Web Universal Resource Locators (URLs)
15. Internet Protocol (IP) addresses
16. Biometric identifiers (finger and voice prints)
17. Full-face photographic images
18. Any other unique identifying number, characteristic, or code

Presidio provides out-of-the-box entity recognizers covering categories 1, 2, 3, 4, 6, 7, 8, 10, 11, 14, and 15, with `PatternRecognizer` extensibility covering the remainder.

---

## GDPR Article 32 & ISO/IEC 27701

- **GDPR Article 32(1)(a)**: Explicitly mandates "the pseudonymisation and encryption of personal data" as technical safeguards. Presidio provides verifiable SHA-256 pseudonymization and reversible AES encryption.
- **ISO/IEC 27701 Section 7.4.2**: Requires controls over privacy by design and by default, fulfilled by embedding automated sanitization into data lifecycle ingestion stages.
