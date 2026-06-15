---
name: implementing-gdpr-data-subject-access-request
description: 'Automates GDPR Data Subject Access Request (DSAR) workflows including
  identity verification, PII discovery across databases and files using regex and
  NER, data mapping, response templating per Article 15 requirements, deadline tracking,
  and audit logging. Covers ICO/EDPB guidance compliance, exemption handling, and
  scalable batch processing. Use when building or auditing DSAR response capabilities
  under GDPR/UK GDPR.

  '
domain: cybersecurity
subdomain: privacy-compliance
tags:
- gdpr
- dsar
- privacy
- pii-discovery
- data-subject-rights
- compliance
- article-15
version: '1.0'
author: mukul975
license: Apache-2.0
nist_csf:
- GV.PO-01
- PR.DS-01
- GV.OC-05
mitre_attack:
- T1078
- T1190
- T1059
---

# Implementing GDPR Data Subject Access Request (DSAR) Workflow

## When to Use

- When building automated DSAR processing pipelines for GDPR/UK GDPR compliance
- When implementing PII discovery across structured and unstructured data sources
- When creating response templates that satisfy Article 15 disclosure requirements
- When auditing existing DSAR handling for regulatory compliance gaps
- When scaling DSAR processing from manual to automated workflows

## Prerequisites

- Python 3.8+ with required dependencies (spacy, presidio-analyzer, jinja2)
- Access to data sources where personal data resides (databases, file shares, logs)
- Understanding of GDPR Article 15 requirements and ICO/EDPB guidance
- Appropriate authorization and data protection officer (DPO) approval
- Test environment with synthetic or anonymized data for validation

## Background

### GDPR Article 15 - Right of Access

Under GDPR Article 15, data subjects have the right to obtain from the controller:

1. **Confirmation** that their personal data is being processed
2. **A copy** of all personal data held about them
3. **Supplementary information** including:
   - Purposes of processing
   - Categories of personal data
   - Recipients or categories of recipients
   - Retention periods or criteria to determine them
   - Right to rectification, erasure, restriction, or objection
   - Right to lodge a complaint with a supervisory authority
   - Source of the data (if not collected directly from the subject)
   - Existence of automated decision-making, including profiling

### Timeline Requirements

- **Standard deadline**: 1 calendar month from receipt of valid request
- **Complex extension**: Up to 2 additional months (must notify within first month)
- **Clock pause**: Permitted when identity verification or clarification is needed
- **Format**: Electronic form if request made electronically (unless otherwise requested)
- **Cost**: Free of charge (unless manifestly unfounded/excessive)

### ICO/EDPB Guidance Key Points

- No formal format required for DSARs - verbal, written, social media all valid
- Request need not mention "subject access request" or cite Article 15
- Identity verification must be proportionate to the risk
- Exemptions exist for legal privilege, third-party data, trade secrets
- EDPB coordinated enforcement actions cover right of access compliance

## Instructions

### Step 1: DSAR Intake and Verification

Implement a request intake system that captures the request through any channel,
verifies the requester's identity, and starts the compliance clock.

```python
from agent import DSARWorkflowEngine

engine = DSARWorkflowEngine(config_path="dsar_config.json")

# Register a new DSAR
request = engine.register_dsar(
    requester_name="Jane Smith",
    requester_email="jane.smith@example.com",
    request_channel="email",
    request_text="I would like a copy of all personal data you hold about me.",
    identity_docs=["passport_verified"],
)
print(f"DSAR ID: {request['dsar_id']}, Deadline: {request['deadline']}")
```

### Step 2: PII Discovery Across Data Sources

Scan databases, files, and logs using regex patterns and NER to find all
personal data associated with the data subject.

```python
from agent import PIIDiscoveryEngine

pii_engine = PIIDiscoveryEngine()

# Scan structured data (database)
db_results = pii_engine.scan_database(
    connection_string="postgresql://user:pass@localhost/appdb",
    search_identifiers={"email": "jane.smith@example.com", "name": "Jane Smith"},
)

# Scan unstructured data (files, logs)
file_results = pii_engine.scan_files(
    directories=["/var/log/app", "/data/exports", "/data/documents"],
    search_identifiers={"email": "jane.smith@example.com", "name": "Jane Smith"},
)

# Scan with NER for contextual PII detection
ner_results = pii_engine.scan_with_ner(
    text_corpus=file_results["raw_text_matches"],
    entity_types=["PERSON", "EMAIL", "PHONE_NUMBER", "LOCATION", "DATE_OF_BIRTH"],
)

all_pii = pii_engine.consolidate_results(db_results, file_results, ner_results)
print(f"Found {all_pii['total_records']} PII records across {all_pii['source_count']} sources")
```

### Step 3: Data Mapping and Classification

Map discovered PII to processing purposes, legal bases, and retention periods
as required by Article 15.

```python
from agent import DataMapper

mapper = DataMapper(data_inventory_path="data_inventory.json")

# Map PII to Article 15 categories
mapped_data = mapper.map_to_article15(
    pii_records=all_pii,
    data_subject_id="jane.smith@example.com",
)

# Output includes processing purposes, recipients, retention for each data category
for category in mapped_data["categories"]:
    print(f"Category: {category['name']}")
    print(f"  Purpose: {category['processing_purpose']}")
    print(f"  Legal basis: {category['legal_basis']}")
    print(f"  Retention: {category['retention_period']}")
    print(f"  Recipients: {', '.join(category['recipients'])}")
```

### Step 4: Exemption Review

Apply exemptions where lawful (third-party data, legal privilege, trade secrets)
before compiling the response.

```python
from agent import ExemptionReviewer

reviewer = ExemptionReviewer()

# Check for applicable exemptions
review_result = reviewer.review_exemptions(
    mapped_data=mapped_data,
    exemption_checks=[
        "third_party_data",
        "legal_professional_privilege",
        "trade_secrets",
        "crime_prevention",
        "management_forecasting",
    ],
)

# Apply redactions where exemptions apply
redacted_data = reviewer.apply_redactions(mapped_data, review_result["exemptions"])
print(f"Applied {review_result['exemption_count']} exemptions")
```

### Step 5: Response Generation

Generate a compliant DSAR response package with cover letter, data export,
and supplementary information document.

```python
from agent import DSARResponseGenerator

generator = DSARResponseGenerator(template_dir="templates/")

# Generate complete response package
response = generator.generate_response(
    dsar_id=request["dsar_id"],
    data_subject="Jane Smith",
    mapped_data=redacted_data,
    format="pdf",  # or "json", "csv"
)

# Package includes: cover letter, data export, supplementary info, audit log
for doc in response["documents"]:
    print(f"Generated: {doc['filename']} ({doc['type']})")
```

### Step 6: Audit Trail and Compliance Logging

Maintain complete audit trail of the DSAR lifecycle for accountability.

```python
from agent import DSARAuditLogger

logger = DSARAuditLogger(log_path="dsar_audit_logs/")

# Log complete DSAR lifecycle
logger.log_event(request["dsar_id"], "request_received", {
    "channel": "email",
    "identity_verified": True,
})
logger.log_event(request["dsar_id"], "pii_discovery_complete", {
    "records_found": all_pii["total_records"],
    "sources_scanned": all_pii["source_count"],
})
logger.log_event(request["dsar_id"], "response_sent", {
    "format": "pdf",
    "documents_count": len(response["documents"]),
    "exemptions_applied": review_result["exemption_count"],
})

# Generate compliance report
compliance_report = logger.generate_compliance_report(request["dsar_id"])
```

## Examples

### Complete DSAR Processing Pipeline

```python
from agent import DSARWorkflowEngine, PIIDiscoveryEngine, DSARResponseGenerator

# Full automated pipeline
engine = DSARWorkflowEngine(config_path="dsar_config.json")
pii = PIIDiscoveryEngine()
gen = DSARResponseGenerator(template_dir="templates/")

# 1. Intake
req = engine.register_dsar(
    requester_name="John Doe",
    requester_email="john.doe@example.com",
    request_channel="web_form",
    request_text="Please provide all my data under GDPR Article 15.",
    identity_docs=["email_verified", "account_match"],
)

# 2. Discover
results = pii.full_scan(
    search_identifiers={"email": "john.doe@example.com"},
    sources=["database", "files", "logs"],
)

# 3. Generate response
response = gen.generate_response(
    dsar_id=req["dsar_id"],
    data_subject="John Doe",
    mapped_data=results,
)

# 4. Track deadline
engine.update_status(req["dsar_id"], "response_sent")
print(f"DSAR {req['dsar_id']} completed, {engine.days_remaining(req['dsar_id'])} days remaining")
```

### PII Regex Pattern Testing

```python
from agent import PIIPatternMatcher

matcher = PIIPatternMatcher()

# Test individual patterns
test_text = "Contact jane.smith@example.com or call +44 20 7946 0958. SSN: 123-45-6789"
matches = matcher.scan_text(test_text)
for m in matches:
    print(f"  [{m['type']}] '{m['value']}' (confidence: {m['confidence']})")
```

## References

- GDPR Article 15: https://gdpr-info.eu/art-15-gdpr/
- ICO Subject Access Request Guidance: https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/subject-access-requests/
- EDPB Guidelines 01/2022 on Right of Access: https://www.edpb.europa.eu/system/files/2023-04/edpb_guidelines_202201_data_subject_rights_access_v2_en.pdf
- GDPR Article 12 (DSAR Modalities): https://gdpr-info.eu/art-12-gdpr/
- Regulation (EU) 2025/2518 (Procedural Rules): Cross-border GDPR enforcement procedural rules
