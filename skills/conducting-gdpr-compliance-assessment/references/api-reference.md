# API Reference: GDPR Compliance Tools and Commands

## Python GDPR Compliance Helper Commands

### Article 30 Parser
```bash
# Parse DPAs and privacy policies for Article 30 fields
python scripts/article30_parser.py --input contracts/processors/ --output ropa.json

# Validate completeness against mandatory fields
python scripts/article30_validator.py --ropa ropa.json --check-retention --check-transfers

# Generate Article 30 register in supervisory authority format
python scripts/generate_ropa_report.py --input ropa.json --output Article30_Register.pdf
```

## Data Subject Access Request (DSAR) Automation

### Open Data Rights (ODR)
```bash
# Initialize ODR project
npm install @opendatarights/odr-core

# Submit DSAR programmatically
node scripts/submit_dsar.js --email user@example.com --company "Acme Corp"

# Check DSAR status
node scripts/check_dsar_status.js --request-id abc123
```

## GDPR Compliance Scanning Tools

### BigID Data Discovery
```bash
# Scan for personal data across data sources
bigid-cli scan --source "s3://company-bucket" --classification PII

# Generate data inventory report
bigid-cli report --format json --output data_inventory.json
```

### OneTrust Cookie Consent API
```bash
# Verify cookie consent compliance
curl -H "Authorization: Bearer $TOKEN" \
  "https://api.onetrust.com/v1/consent/categories" | jq

# Check GDPR consent records
curl -H "Authorization: Bearer $TOKEN" \
  "https://api.onetrust.com/v1/consent/receipts?user=john@example.com"
```

## Standard Contractual Clauses (SCCs) Templates

| SCC Module | Use Case | Download |
|------------|----------|----------|
| Module One | Controller to Controller | https://commission.europa.eu/law/law-topic/data-protection/international-dimension-data-protection/standard-contractual-clauses-scc_en |
| Module Two | Controller to Processor | Same link (2021 version) |
| Module Three | Processor to Processor | Same link |
| Module Four | Processor to Controller | Same link |

## Data Processing Agreement (DPA) Checklist

| Article 28 Requirement | DPA Clause Reference |
|------------------------|----------------------|
| Subject matter and duration | § 1.1 |
| Nature and purpose | § 1.2 |
| Type of personal data | § 1.3, Annex A |
| Categories of data subjects | § 1.4, Annex A |
| Controller obligations and rights | § 2 |
| Processor obligations | § 3-8 |
| Sub-processor approval | § 9 |
| Data subject rights assistance | § 10 |
| Security measures | § 11, Annex B |
| Breach notification | § 12 |
| Deletion/return of data | § 13 |
| Audits | § 14 |
| Liability and indemnity | § 15-16 |

## DPIA (Data Protection Impact Assessment) Template Structure

```yaml
# DPIA for [Processing Activity Name]
date: 2026-03-15
version: 1.0
assessor: [Name, Role]

1. Description of Processing:
  - purpose:
  - categories_of_data:
  - categories_of_subjects:
  - retention_period:
  - recipients:

2. Necessity and Proportionality:
  - necessity_justification:
  - proportionality_assessment:

3. Risks to Data Subject Rights:
  - risk_1:
      description:
      likelihood: [low/medium/high]
      severity: [low/medium/high]
      risk_level: [likelihood × severity]
  - risk_2: ...

4. Mitigation Measures:
  - measure_1:
      description:
      effectiveness: [reduces risk to ...]
      responsibility: [who implements]
  - measure_2: ...

5. Residual Risk:
  - residual_risk_assessment:
  - supervisory_authority_consultation: [yes/no, if yes why]

6. Sign-off:
  - dpo_review_date:
  - dpo_approval:
  - controller_approval:
```

## Breach Notification API (Supervisory Authority)

### ICO Data Security Incident Reporting Tool
```bash
# UK: Report breach to ICO
# https://ico.org.uk/for-organisations/report-a-breach/

# EU Member State: Check your supervisory authority
# https://edpb.europa.eu/about-edpb/about-edpb/members_en
```

### Breach Register Template
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
  "measures_taken": "Mandatory password reset, notification sent to all users, MFA enforced",
  "supervisory_authority": "ICO",
  "notification_reference": "ICO-BR-2026-12345"
}
```

## GDPR-Compliant Logging Commands

### Audit Log Retention Check
```bash
# Verify retention periods align with Article 30 documented periods
grep -r "retention" Article30_Register.json | jq

# Check if logs contain personal data (must be protected under Article 32)
grep -iE "(email|name|ip_address)" /var/log/app/*.log
```

### Pseudonymization Example (Python)
```python
import hashlib
import hmac

def pseudonymize(email, secret_key):
    """Pseudonymize email using HMAC-SHA256"""
    return hmac.new(
        secret_key.encode(),
        email.encode(),
        hashlib.sha256
    ).hexdigest()

# Usage
secret = "your-secret-key-store-securely"
pseudonym = pseudonymize("user@example.com", secret)
# Output: 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
```

## Data Subject Rights Verification

| Right | Verification Check | Command/Tool |
|-------|-------------------|--------------|
| Right to Access (Art 15) | Can org deliver all data within 1 month? | Test DSAR workflow end-to-end |
| Right to Erasure (Art 17) | Can org delete across all systems? | `python scripts/test_deletion.py --user-id 12345` |
| Right to Portability (Art 20) | Can org export in machine-readable format? | Verify CSV/JSON export functionality |
| Right to Object (Art 21) | Can org stop direct marketing? | Test unsubscribe mechanism |

## International Transfer Checklist

```bash
# Identify all non-EU/EEA data flows
grep -r "transfer_destination" Article30_Register.json | grep -v "EU\|EEA"

# Verify safeguards for each transfer
for dest in $(jq -r '.transfers[].destination_country' Article30_Register.json); do
  echo "Transfer to: $dest"
  echo "Safeguard: $(jq -r ".transfers[] | select(.destination_country==\"$dest\") | .safeguard" Article30_Register.json)"
done
```

## References

- **ICO Self-Assessment Tool**: https://ico.org.uk/for-organisations/sme-web-hub/checklists/self-assessment/
- **EDPB Interactive Tool**: https://ec.europa.eu/info/law/law-topic/data-protection/reform/rights-citizens/how-my-personal-data-protected_en
- **GDPR.eu Compliance Checklist**: https://gdpr.eu/checklist/
- **NIST Privacy Framework**: https://www.nist.gov/privacy-framework

