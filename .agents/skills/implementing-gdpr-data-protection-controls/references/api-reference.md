# API Reference: Implementing GDPR Data Protection Controls

## Key GDPR Articles

| Article | Requirement | Technical Control |
|---------|-------------|-------------------|
| Art 5 | Processing principles | Data minimization, retention policies |
| Art 25 | Privacy by design | Default privacy settings |
| Art 30 | Records of processing | ROPA documentation system |
| Art 32 | Security of processing | Encryption, access controls, testing |
| Art 33 | Breach notification | 72-hour DPA notification |
| Art 35 | DPIA | Impact assessment for high-risk processing |

## Data Subject Rights (Art 12-22)

| Right | Article | SLA |
|-------|---------|-----|
| Access | Art 15 | 1 month |
| Rectification | Art 16 | 1 month |
| Erasure | Art 17 | 1 month |
| Portability | Art 20 | 1 month |
| Object | Art 21 | Without undue delay |

## PII Detection Patterns

```python
import re
patterns = {
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "iban": r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b",
    "ip_address": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
}
```

## ROPA Required Fields (Art 30)

| Field | Description |
|-------|-------------|
| controller_name | Data controller identity |
| purposes | Processing purposes |
| data_categories | Types of personal data |
| data_subjects | Categories of data subjects |
| recipients | Data recipients |
| transfers | Cross-border transfers |
| retention_periods | Data retention schedules |
| security_measures | Art 32 controls |

## Cross-Border Transfer Mechanisms (Art 44-49)

| Mechanism | Use Case |
|-----------|----------|
| Adequacy Decision | Transfer to adequate countries (Art 45) |
| Standard Contractual Clauses (SCCs) | Most common mechanism (Art 46) |
| Binding Corporate Rules (BCRs) | Intra-group transfers (Art 47) |
| Derogations | Consent, contract necessity (Art 49) |

### References

- GDPR Official Text: https://gdpr-info.eu/
- EDPB Guidelines: https://edpb.europa.eu/our-work-tools/general-guidance/guidelines-recommendations-best-practices_en
- ICO GDPR Guide: https://ico.org.uk/for-organisations/guide-to-data-protection/guide-to-the-general-data-protection-regulation-gdpr/
