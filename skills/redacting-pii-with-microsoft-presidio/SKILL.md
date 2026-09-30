---
name: redacting-pii-with-microsoft-presidio
description: >-
  Scans unstructured text, structured records, and documents for personally identifiable
  information (PII) using Microsoft Presidio Analyzer, then applies configurable masking,
  hashing, encryption, or synthetic redaction through Presidio Anonymizer. Use when auditing
  datasets for sensitive personal data, stripping PII from application logs or LLM prompts,
  or enforcing privacy controls for GDPR, HIPAA, and CCPA compliance. Keywords: Presidio,
  AnalyzerEngine, AnonymizerEngine, PII, redaction, PatternRecognizer, entity recognition,
  masking, faker. Do not use for enterprise cloud DLP policy enforcement across SaaS
  services - use implementing-data-loss-prevention-with-microsoft-purview; for scanning code
  repositories for secrets use implementing-secret-scanning-with-gitleaks.
domain: cybersecurity
subdomain: data-protection
tags:
  - data-protection
  - pii
  - presidio
  - privacy
  - dlp
  - anonymization
version: "1.0"
author: ayuuXploits
license: Apache-2.0
nist_csf:
  - PR.DS-01
  - PR.DS-02
  - PR.DS-05
  - PR.PS-01
mitre_attack:
  - T1005
  - T1552
  - T1530
---

# Redacting PII with Microsoft Presidio

## When to Use

- When auditing databases, log streams, or object storage for unencrypted personally identifiable information (PII)
- When sanitizing raw prompt inputs or model outputs in Generative AI pipelines before transmission or logging
- When preparing datasets for analytics, external testing, or cross-border transfers under GDPR, HIPAA, or CCPA/CPRA
- When implementing data loss prevention (DLP) and automated data de-identification gateways for internal APIs
- When responding to privacy compliance assessments requiring mathematical or cryptographic de-identification of data at rest

## Prerequisites

- Python 3.9+ environment
- `pip install presidio-analyzer presidio-anonymizer`
- spaCy language model: `python -m spacy download en_core_web_lg` (or `en_core_web_sm` for lightweight environments)
- (Optional) Docker for containerized Presidio REST API deployment
- (Optional) PyCryptodome for AES key management when reversible tokenization is required

## Key Concepts

| Component / Operator | Purpose | Configuration / Mechanism |
|---|---|---|
| `AnalyzerEngine` | Orchestrates entity recognition across NLP engines, regex patterns, and context | Configured via `RecognizerRegistry` and `NlpEngineProvider` |
| `PatternRecognizer` | Detects structured entities (credit cards, tax IDs, internal badges) using regex & context | Requires regex pattern, score (0.0-1.0), and context keywords |
| `AnonymizerEngine` | Executes transformation operators over identified text ranges | Applies redaction, masking, replacement, hashing, or custom encryption |
| `replace` operator | Replaces PII value with entity type tag or fixed placeholder | `{"type": "replace", "new_value": "<EMAIL_ADDRESS>"}` |
| `mask` operator | Obscures characters with a masking character while retaining formatting | `{"type": "mask", "masking_char": "*", "chars_to_mask": 6, "from_back": True}` |
| `hash` operator | Generates cryptographic digest (SHA-256) of sensitive value | `{"type": "hash", "hash_type": "sha256"}` |
| `encrypt` operator | AES-CBC reversible encryption requiring a 128/192/256-bit key | `{"type": "encrypt", "key": "UnbreakableKey32BytesLong123456"}` |

## Tools & Systems

- **Microsoft Presidio**: Open-source, production-grade SDK for privacy-preserving data processing
- **spaCy NLP Engine**: Tokenization, named entity recognition (NER), and part-of-speech tagging backend
- **Presidio Analyzer REST Service**: Containerized HTTP microservice for multi-language PII detection
- **Presidio Anonymizer REST Service**: Containerized HTTP microservice for policy-driven redaction

## Workflow

### Step 1: Install Presidio and Download NLP Model

```bash
# Install core Presidio analyzer and anonymizer libraries
pip install presidio-analyzer presidio-anonymizer

# Download the English medium or large language model for spaCy
python -m spacy download en_core_web_sm
```

### Step 2: Initialize Analyzer and Detect PII Entities

```python
from presidio_analyzer import AnalyzerEngine

# Initialize the default analyzer with spaCy NLP pipeline
analyzer = AnalyzerEngine()

text_sample = "Employee Alice Martin (SSN: 900-12-3456) emailed alice.martin@corp.internal regarding account 4532-1234-5678-9012."

# Analyze text for all supported standard entities
results = analyzer.analyze(
    text=text_sample,
    entities=["PERSON", "US_SSN", "EMAIL_ADDRESS", "CREDIT_CARD"],
    language="en",
    score_threshold=0.6,
)

for res in sorted(results, key=lambda x: x.start):
    print(f"Detected: {res.entity_type:<15} Score: {res.score:.2f} Range: [{res.start}:{res.end}] Content: {text_sample[res.start:res.end]}")
```

### Step 3: Configure Anonymization Policies and Redact Text

```python
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

anonymizer = AnonymizerEngine()

# Define transformation operators for detected entities
operators = {
    "PERSON": OperatorConfig("replace", {"new_value": "[NAME]"}),
    "US_SSN": OperatorConfig("mask", {"type": "mask", "masking_char": "X", "chars_to_mask": 7, "from_back": False}),
    "EMAIL_ADDRESS": OperatorConfig("hash", {"hash_type": "sha256"}),
    "CREDIT_CARD": OperatorConfig("mask", {"type": "mask", "masking_char": "*", "chars_to_mask": 12, "from_back": False}),
    "DEFAULT": OperatorConfig("replace", {"new_value": "<REDACTED>"}),
}

anonymized_result = anonymizer.anonymize(
    text=text_sample,
    analyzer_results=results,
    operators=operators,
)

print("\nAnonymized Text:")
print(anonymized_result.text)
```

### Step 4: Build Custom Pattern Recognizer with Context Enhancement

```python
from presidio_analyzer import Pattern, PatternRecognizer

# Custom employee employee badge pattern: "CORP-EMP-12345"
badge_pattern = Pattern(
    name="corp_badge_pattern",
    regex=r"\bCORP-EMP-[0-9]{5}\b",
    score=0.7,
)

# Context words that increase detection confidence
context_words = ["badge", "employee id", "staff number", "credential"]

badge_recognizer = PatternRecognizer(
    supported_entity="CORP_EMPLOYEE_ID",
    patterns=[badge_pattern],
    context=context_words,
)

# Register recognizer into analyzer
analyzer.registry.add_recognizer(badge_recognizer)

custom_text = "Security badge issued to staff: CORP-EMP-84920 for internal facility access."
custom_results = analyzer.analyze(text=custom_text, language="en")
print("Custom Recognizer Findings:", [(r.entity_type, r.score) for r in custom_results])
```

### Step 5: Batch Processing of Data Files via CLI Script

```bash
# Run process.py to audit and redact a sensitive log or CSV file
python scripts/process.py \
  --input /var/log/audit.log \
  --output /var/log/audit_sanitized.log \
  --policy mask \
  --threshold 0.75 \
  --format json
```

### Step 6: Deploy Containerized Presidio Microservices

```bash
# Pull and start Presidio Analyzer container
docker run -d -p 5001:3000 --name presidio-analyzer mcr.microsoft.com/presidio-analyzer:latest

# Pull and start Presidio Anonymizer container
docker run -d -p 5002:3000 --name presidio-anonymizer mcr.microsoft.com/presidio-anonymizer:latest

# Verify analyzer health and entity listing
curl -s http://localhost:5001/healthz
curl -s http://localhost:5001/api/v1/analyzer/supportedentities | jq .
```

### Step 7: Query Presidio Services via REST API

```bash
# Send text to analyzer service endpoint
curl -s -X POST http://localhost:5001/api/v1/analyzer/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Contact compliance officer John Doe at jdoe@enterprise.org or 415-555-0199.",
    "language": "en"
  }' | jq .

# Pipe analyzer response to anonymizer service endpoint
ANALYZER_RESP=$(curl -s -X POST http://localhost:5001/api/v1/analyzer/analyze \
  -H "Content-Type: application/json" \
  -d '{"text": "Call Robert at 415-555-0144", "language": "en"}')

curl -s -X POST http://localhost:5002/api/v1/anonymizer/anonymize \
  -H "Content-Type: application/json" \
  -d "{
    \"text\": \"Call Robert at 415-555-0144\",
    \"analyzer_results\": $ANALYZER_RESP
  }" | jq .
```

## Common Scenarios

### Scenario 1: LLM Prompt Sanitization Gateway

Before submitting user prompts to public or commercial LLMs, scan and sanitize direct identifiers (names, SSNs, account numbers) while preserving semantic meaning:

```python
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

prompt = "Analyze symptoms for patient John Smith, age 42, medical record MRN-984321."
findings = analyzer.analyze(text=prompt, language="en", score_threshold=0.6)

# Use synthetic or entity replacement for AI context preservation
sanitized = anonymizer.anonymize(
    text=prompt,
    analyzer_results=findings,
    operators={"PERSON": OperatorConfig("replace", {"new_value": "[PATIENT_NAME]"})}
)
print("Sanitized Prompt:", sanitized.text)
```

### Scenario 2: Structured CSV Column De-Identification

Read CSV records containing customer transaction logs, apply specific masking to email and phone columns, and export anonymized data for third-party auditing:

```python
import csv
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine

analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

records = [
    {"user": "Bob Vance", "email": "bob@vancerefrig.com", "phone": "570-555-0123"},
    {"user": "Phyllis Lapin", "email": "phyllis@dundermifflin.com", "phone": "570-555-0198"}
]

for row in records:
    for key in ["user", "email", "phone"]:
        findings = analyzer.analyze(text=row[key], language="en")
        row[key] = anonymizer.anonymize(text=row[key], analyzer_results=findings).text

print("Sanitized records:", records)
```

## Output Format

Presidio execution generates structured JSON audit records containing location offsets, entity classifications, confidence scores, and redaction verification:

```json
{
  "scan_metadata": {
    "timestamp": "2026-10-01T01:00:00Z",
    "engine": "Microsoft Presidio v2.2.35",
    "nlp_model": "en_core_web_sm",
    "confidence_threshold": 0.65
  },
  "summary": {
    "total_entities_detected": 3,
    "entities_by_type": {
      "PERSON": 1,
      "EMAIL_ADDRESS": 1,
      "US_SSN": 1
    },
    "anonymization_strategy": "hybrid_mask_and_hash"
  },
  "findings": [
    {
      "entity_type": "PERSON",
      "start": 0,
      "end": 12,
      "confidence": 0.85,
      "applied_operator": "replace",
      "replacement_value": "[NAME]"
    },
    {
      "entity_type": "EMAIL_ADDRESS",
      "start": 14,
      "end": 35,
      "confidence": 1.0,
      "applied_operator": "hash",
      "replacement_value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
  ],
  "verification": {
    "raw_length": 68,
    "sanitized_length": 92,
    "residual_pii_detected": false
  }
}
```
