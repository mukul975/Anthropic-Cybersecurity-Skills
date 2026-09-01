---
name: anonymizing-pii-with-microsoft-presidio
description: >-
  Detects and de-identifies PII (names, emails, phone numbers, credit cards, SSNs,
  IBANs, IP addresses) in free text, structured records, and images using Microsoft
  Presidio's analyzer, anonymizer, and image-redactor engines, including custom regex
  and deny-list recognizers, reversible encrypt/decrypt operators, and batch processing
  over dicts and JSON. Use when redacting PII before sending data to an LLM or
  third-party service, pseudonymizing a dataset for a lower environment, or building a
  reusable de-identification pipeline. Keywords: Presidio, PII detection, AnalyzerEngine,
  AnonymizerEngine, OperatorConfig, PatternRecognizer, NlpEngine, presidio-image-redactor.
  Do not use for AWS S3-native classification - use
  implementing-aws-macie-for-data-classification; for GDPR DSAR workflow automation
  use implementing-gdpr-data-subject-access-request; for LLM prompt/output guardrail
  wiring use implementing-llm-guardrails-for-security.
domain: cybersecurity
subdomain: data-protection
tags:
- presidio
- pii
- data-anonymization
- data-masking
- de-identification
- nlp
- gdpr
- redaction
version: '1.0'
author: sunnykumar-jonwal
license: Apache-2.0
nist_csf:
- PR.DS-01
- PR.DS-11
- ID.AM-08
mitre_attack:
- T1005
- T1213
---

# Anonymizing PII with Microsoft Presidio

## Overview

Microsoft Presidio is an open-source framework for detecting and de-identifying
personally identifiable information (PII) in text, structured data, and images. It
ships as three independent Python packages — `presidio-analyzer` (detection),
`presidio-anonymizer` (redaction/replacement/encryption of detected spans), and
`presidio-image-redactor` (OCR-based redaction on images and DICOM files) — plus
prebuilt Docker images that expose the same engines as a REST API. Detection combines
predefined entity recognizers, an NLP backend (spaCy by default; Stanza and Hugging
Face transformers are also supported) for named-entity recognition, and custom
pattern/deny-list recognizers you register yourself.

## When to Use

- Redacting or masking PII in support tickets, logs, or documents before they are
  sent to an LLM, a third-party API, or a data lake.
- Pseudonymizing a production dataset for use in staging/dev/analytics while keeping
  a reversible mapping (encrypt/decrypt) for authorized re-identification.
- Building a de-identification step for outbound webhook payloads, exports, or ETL
  pipelines that must not leak raw PII.
- Redacting scanned ID photos, forms, or DICOM images before archival.
- Extending PII coverage with organization-specific identifiers (employee IDs,
  internal account numbers) that Presidio's built-in recognizers do not cover.

## Prerequisites

- Python 3.9–3.12.
- `pip install presidio-analyzer presidio-anonymizer` (add `presidio-image-redactor`
  for image/DICOM redaction).
- A spaCy model for the analyzer's default NLP engine:
  `python -m spacy download en_core_web_lg`.
- Docker, only if you want the REST API deployment instead of the Python SDK.
- No paid licence or account is required — Presidio is MIT-licensed and fully
  self-hosted; there is no managed/cloud offering to sign up for.

## Key Concepts

| Concept | Description |
|---|---|
| Recognizer | Component that detects one entity type — predefined (`PHONE_NUMBER`, `CREDIT_CARD`, `US_SSN`, ...), regex-based (`PatternRecognizer`), deny-list-based, or ML-based |
| NLP Engine | spaCy/Stanza/transformers backend providing tokenization and NER that context-aware recognizers rely on |
| Ad-hoc recognizer | A recognizer passed directly to `analyze()` for one call, without registering it in the engine |
| Operator | The anonymization action applied to a detected span: `replace`, `redact`, `mask`, `hash`, `encrypt`, `keep`, or a custom callable |
| Context words | Surrounding tokens (e.g. "SSN:", "phone") that raise or lower a recognizer's confidence score |
| `score_threshold` | Minimum confidence for a detected entity to be returned by `analyze()` |

## Workflow

### Step 1: Install and verify

```bash
pip install presidio-analyzer presidio-anonymizer
python -m spacy download en_core_web_lg

python -c "from presidio_analyzer import AnalyzerEngine; \
a = AnalyzerEngine(); \
print(a.analyze(text='Call John Smith at 212-555-0100', language='en'))"
```

### Step 2: Detect PII in free text

```python
from presidio_analyzer import AnalyzerEngine

analyzer = AnalyzerEngine()
text = "My name is John Smith, my email is john.smith@example.com and my SSN is 078-05-1120."

results = analyzer.analyze(text=text, language="en")
for r in results:
    print(r.entity_type, r.start, r.end, round(r.score, 2))
# PERSON 11 21 0.85
# EMAIL_ADDRESS 35 58 1.0
# US_SSN 78 89 0.85
```

Restrict to specific entities, filter by confidence, or allow-list known-safe terms:

```python
results = analyzer.analyze(
    text=text,
    language="en",
    entities=["PERSON", "EMAIL_ADDRESS"],
    score_threshold=0.6,
    allow_list=["Presidio Corp"],
)
```

### Step 3: Anonymize the detected spans

```python
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

anonymizer = AnonymizerEngine()
anonymized = anonymizer.anonymize(
    text=text,
    analyzer_results=results,
    operators={
        "PERSON": OperatorConfig("replace", {"new_value": "<PERSON>"}),
        "EMAIL_ADDRESS": OperatorConfig("mask", {"masking_char": "*", "chars_to_mask": 10, "from_end": True}),
        "US_SSN": OperatorConfig("redact"),
        "DEFAULT": OperatorConfig("hash"),
    },
)
print(anonymized.text)
# My name is <PERSON>, my email is john.sm**********m and my SSN is .
```

`anonymized.items` returns an `OperatorResult` per span (entity type, offsets,
operator applied) — log this alongside the anonymized text for audit trails.

### Step 4: Add a custom recognizer for org-specific identifiers

```python
from presidio_analyzer import Pattern, PatternRecognizer

employee_id_pattern = Pattern(name="employee_id", regex=r"EMP-\d{6}", score=0.85)
employee_id_recognizer = PatternRecognizer(
    supported_entity="EMPLOYEE_ID", patterns=[employee_id_pattern]
)

# Register permanently ...
analyzer.registry.add_recognizer(employee_id_recognizer)

# ... or pass it ad hoc for a single call without registering it
results = analyzer.analyze(text=text, language="en", ad_hoc_recognizers=[employee_id_recognizer])
```

A deny-list recognizer works the same way for a fixed vocabulary:

```python
titles_recognizer = PatternRecognizer(supported_entity="TITLE", deny_list=["Mr.", "Mrs.", "Dr.", "Prof."])
```

### Step 5: Reversible anonymization (encrypt / decrypt)

```python
from presidio_anonymizer import AnonymizerEngine, DeanonymizeEngine
from presidio_anonymizer.entities import OperatorConfig

crypto_key = "WmZq4t7w!z%C&F)J"  # 16/24/32-byte AES key, from a secrets manager in real use

anonymized = anonymizer.anonymize(
    text=text, analyzer_results=results,
    operators={"DEFAULT": OperatorConfig("encrypt", {"key": crypto_key})},
)

deanonymizer = DeanonymizeEngine()
restored = deanonymizer.deanonymize(
    text=anonymized.text,
    entities=anonymized.items,
    operators={"DEFAULT": OperatorConfig("decrypt", {"key": crypto_key})},
)
print(restored.text == text)  # True
```

### Step 6: Batch-process structured data (dicts / JSON)

```python
from presidio_analyzer import BatchAnalyzerEngine
from presidio_anonymizer import BatchAnonymizerEngine

record = {
    "name": "John Smith",
    "email": "john.smith@example.com",
    "notes": "Called about billing, SSN 078-05-1120 on file.",
}

batch_analyzer = BatchAnalyzerEngine(analyzer_engine=analyzer)
analyzer_results = batch_analyzer.analyze_dict(input_dict=record, language="en")

batch_anonymizer = BatchAnonymizerEngine(anonymizer_engine=anonymizer)
anonymized_record = batch_anonymizer.anonymize_dict(analyzer_results=analyzer_results)
```

### Step 7: Redact PII from images

```bash
pip install presidio-image-redactor
```

```python
from presidio_image_redactor import ImageRedactorEngine
from PIL import Image

image = Image.open("scanned_id.png")
engine = ImageRedactorEngine()
redacted_image = engine.redact(image, (255, 192, 203))  # fill colour for redacted boxes
redacted_image.save("scanned_id_redacted.png")
```

### Step 8: Run Presidio as a REST API (Docker)

```bash
docker run -d -p 5002:3000 mcr.microsoft.com/presidio-analyzer:latest
docker run -d -p 5001:3000 mcr.microsoft.com/presidio-anonymizer:latest

curl -X POST http://localhost:5002/analyze \
  -H "Content-Type: application/json" \
  -d '{"text": "John Smith lives in New York, SSN 078-05-1120.", "language": "en"}'
```

### Step 9: Add a second language

```yaml
# languages-config.yml
nlp_engine_name: spacy
models:
  - lang_code: en
    model_name: en_core_web_lg
  - lang_code: es
    model_name: es_core_news_md
```

```python
from presidio_analyzer.nlp_engine import NlpEngineProvider

provider = NlpEngineProvider(conf_file="languages-config.yml")
nlp_engine = provider.create_engine()
analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en", "es"])
```

## Tools & Systems

- **presidio-analyzer** (PyPI) — PII detection engine and recognizer registry
- **presidio-anonymizer** (PyPI) — de-identification and de-anonymization engine
- **presidio-image-redactor** (PyPI) — OCR-based redaction for images and DICOM
- **Microsoft Presidio Docker images** (`mcr.microsoft.com/presidio-analyzer`,
  `mcr.microsoft.com/presidio-anonymizer`) — REST API deployment
- **spaCy / Stanza / Hugging Face transformers** — pluggable NLP backends for NER

## Common Scenarios

1. **Pre-LLM redaction**: strip PII from a user's message before forwarding it to a
   third-party model, then reinsert placeholders in the response.
2. **Lower-environment pseudonymization**: replace PII with consistent fake values
   (`replace` operator) so a staging dataset stays referentially useful without
   exposing real customer data.
3. **DLP pre-processing**: run the analyzer on outbound export files or webhook
   payloads and block/redact before the request leaves the network.
4. **Reversible masking for support tooling**: encrypt PII shown in a shared
   dashboard, decrypt only in an authorized backend service.
5. **Document archival**: redact photos of IDs or scanned forms before long-term
   storage using `presidio-image-redactor`.

## Output Format

- `analyzer.analyze()` returns a list of `RecognizerResult` objects: `entity_type`,
  `start`, `end`, `score`.
- `anonymizer.anonymize()` returns an `EngineResult` with `.text` (the de-identified
  string) and `.items` (a list of `OperatorResult`, each with `entity_type`, `start`,
  `end`, `operator`) — persist `.items` for an audit trail of what was changed.
- `batch_anonymizer.anonymize_dict()` returns the input dict/JSON structure with PII
  values replaced in place, preserving non-PII fields and structure.
- The REST API returns the same fields as JSON in the HTTP response body.

## References

- [Presidio Documentation](https://microsoft.github.io/presidio/)
- [Presidio GitHub Repository](https://github.com/microsoft/presidio)
- [Presidio Analyzer — Supported Entities](https://microsoft.github.io/presidio/supported_entities/)
- [Presidio Anonymizer — Operators](https://microsoft.github.io/presidio/anonymizer/)
- [Presidio Image Redactor](https://microsoft.github.io/presidio/image-redactor/)
