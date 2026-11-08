---
name: redacting-pii-with-microsoft-presidio
description: >-
  Detects and de-identifies PII (names, emails, phone numbers, credit cards, IBANs,
  national IDs, IP/MAC addresses) in free text with Microsoft Presidio, using
  AnalyzerEngine over spaCy NER plus pattern/checksum recognisers, then redacts,
  masks, hashes, or encrypts matches with AnonymizerEngine and custom OperatorConfig.
  Covers adding custom PatternRecognizer entities, allow/deny lists, score
  thresholds, batch processing, and reversible pseudonymisation for data-sharing
  and test-data pipelines. Use when anonymising logs, documents, support tickets,
  or datasets before sharing, storage, or model training. Keywords: presidio,
  AnalyzerEngine, AnonymizerEngine, RecognizerResult, OperatorConfig, PatternRecognizer,
  en_core_web_lg, replace, mask, hash, encrypt. Do not use for live DLP policy
  enforcement across Microsoft 365 - use implementing-data-loss-prevention-with-microsoft-purview;
  for running a full GDPR access-request workflow use implementing-gdpr-data-subject-access-request.
domain: cybersecurity
subdomain: data-protection
tags:
- presidio
- pii
- anonymization
- data-protection
- redaction
- pseudonymization
- gdpr
version: "1.0"
author: rendrabaru777
license: Apache-2.0
nist_csf:
- PR.DS-01
- PR.DS-02
- GV.OC-05
---

# Redacting PII with Microsoft Presidio

## When to Use

- When anonymising application logs, support tickets, or chat transcripts before they leave a trust boundary.
- When producing a de-identified copy of a dataset for analytics, sharing with a third party, or model training.
- When building a reusable text-sanitisation step in an ETL or data-pipeline job.
- When you need reversible pseudonymisation (consistent tokens, or encrypt-then-decrypt) rather than destructive redaction.
- When extending detection with organisation-specific identifiers (employee IDs, case numbers, internal hostnames).

Do not use this skill to enforce DLP policy across Exchange/SharePoint/Teams — that is `implementing-data-loss-prevention-with-microsoft-purview`. Do not use it to run the end-to-end GDPR subject-access process — that is `implementing-gdpr-data-subject-access-request`. This skill is the text de-identification engine those workflows can call.

## Prerequisites

- Python 3.9+.
- Install the libraries and a spaCy model:

  ```bash
  pip install presidio-analyzer presidio-anonymizer
  python -m spacy download en_core_web_lg
  ```

  `en_core_web_lg` gives materially better `PERSON`/`LOCATION`/`ORGANIZATION` recall than `en_core_web_sm`; the small model is acceptable for test environments only.

- For the `encrypt`/`decrypt` operators, a 128-, 192-, or 256-bit key (16/24/32 bytes). Presidio uses AES-CBC under the hood.
- Validate on synthetic or already-approved data first. Presidio is recall-imperfect: it reduces exposure, it does not guarantee zero leakage.

## Workflow

### Step 1 — Analyze: find the PII spans

`AnalyzerEngine` returns a list of `RecognizerResult` objects (`entity_type`, `start`, `end`, `score`).

```python
from presidio_analyzer import AnalyzerEngine

analyzer = AnalyzerEngine()  # loads en_core_web_lg + built-in recognizers

text = "Contact Jane Smith at jane.smith@example.com or +44 20 7946 0958."
results = analyzer.analyze(text=text, language="en")
for r in results:
    print(r.entity_type, r.score, repr(text[r.start:r.end]))
```

Constrain to the entities you care about and set a score floor to cut false positives:

```python
results = analyzer.analyze(
    text=text,
    language="en",
    entities=["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "IBAN_CODE"],
    score_threshold=0.5,
)
```

### Step 2 — Anonymize: apply an operator per entity

`AnonymizerEngine.anonymize` consumes the analyzer results and an `operators` map. Built-in operators: `replace`, `redact`, `mask`, `hash`, `encrypt`, `keep`.

```python
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

anonymizer = AnonymizerEngine()
result = anonymizer.anonymize(
    text=text,
    analyzer_results=results,
    operators={
        "DEFAULT": OperatorConfig("replace", {"new_value": "<REDACTED>"}),
        "PERSON": OperatorConfig("replace", {"new_value": "<PERSON>"}),
        "CREDIT_CARD": OperatorConfig("mask", {
            "masking_char": "*", "chars_to_mask": 12, "from_end": False}),
        "EMAIL_ADDRESS": OperatorConfig("hash", {"hash_type": "sha256"}),
    },
)
print(result.text)
```

### Step 3 — Add a custom recogniser for your identifiers

Built-ins miss org-specific formats. A `PatternRecognizer` adds one with a regex and optional context words that boost the score.

```python
from presidio_analyzer import PatternRecognizer, Pattern

emp = PatternRecognizer(
    supported_entity="EMPLOYEE_ID",
    patterns=[Pattern(name="emp_id", regex=r"\bEMP-\d{6}\b", score=0.85)],
    context=["employee", "staff", "badge"],
)
analyzer.registry.add_recognizer(emp)
```

Use a `deny_list` recogniser for a fixed vocabulary (internal hostnames, project codenames), and pass an `allow_list` to `analyze()` for known-safe tokens you never want flagged.

### Step 4 — Reversible pseudonymisation

For data you must re-link later, use `encrypt` on the way out and `DeanonymizeEngine` + `decrypt` on the way back. The key is a secret — store it in a KMS/secret manager, never in the dataset.

```python
from presidio_anonymizer import DeanonymizeEngine
from presidio_anonymizer.entities import OperatorResult

key = "WmZq4t7w!z%C&F)J"  # 16 bytes; load from a secret store in production
enc = anonymizer.anonymize(
    text=text, analyzer_results=results,
    operators={"DEFAULT": OperatorConfig("encrypt", {"key": key})})

deanon = DeanonymizeEngine()
clear = deanon.deanonymize(
    text=enc.text,
    entities=enc.items,
    operators={"DEFAULT": OperatorConfig("decrypt", {"key": key})})
```

### Step 5 — Batch and operationalise

Use `BatchAnalyzerEngine`/`BatchAnonymizerEngine` for lists and dict/column data rather than looping `analyze()` per row — it reuses the loaded NLP pipeline. Drive the whole flow with the bundled helper:

```bash
# Redact a file; write a de-identified copy + a JSON findings report
python scripts/agent.py redact --in support_ticket.txt --out ticket.clean.txt \
    --operator replace --report findings.json

# Audit only (no rewrite): count entity types and show offsets
python scripts/agent.py audit --in dataset.csv --column notes --threshold 0.6
```

### Step 6 — Verify

Re-run the analyzer over the anonymised output; a correct run finds nothing above threshold for the targeted entity types. Keep the findings report (entity types and counts, never the raw values) as evidence of what was removed. Sample-review output, because NER recall is below 100% on names and addresses.

Calibrate the threshold to the entity mix. Score is not uniform: a checksum-backed `CREDIT_CARD` or `IBAN_CODE` scores ~0.9–1.0, but a `PHONE_NUMBER` embedded in running text (e.g. "Call me at +44 20 7946 0958") scores ~0.4 — below the 0.5 default — while the same number bare (`+442079460958`) scores ~0.75. If phone numbers matter, either drop `--threshold` to 0.4 (accepting more false positives) or add a `PatternRecognizer` for your national format. Tune against a labelled sample rather than guessing.

## Key Concepts

| Concept | What it is | Why it matters |
|---|---|---|
| `AnalyzerEngine` | NER + recogniser pipeline returning `RecognizerResult` spans | Detection stage; decoupled from transformation |
| `RecognizerResult` | `entity_type`, `start`, `end`, `score` | The span and confidence you threshold and anonymise |
| `score_threshold` | Minimum confidence to keep a match | Trades recall against false positives |
| `AnonymizerEngine` | Applies an operator per entity type | Transformation stage |
| `OperatorConfig` | Chosen operator + its params | `replace`/`redact`/`mask`/`hash`/`encrypt`/`keep` |
| `PatternRecognizer` | Regex (+context) custom entity | Catches org-specific identifiers built-ins miss |
| `allow_list` / `deny_list` | Never-flag / always-flag token sets | Cut known false positives; catch fixed vocab |
| `DeanonymizeEngine` | Reverses `encrypt` with `decrypt` | Reversible pseudonymisation vs destructive redaction |

## Tools & Systems

- **Microsoft Presidio** — `presidio-analyzer`, `presidio-anonymizer` (MIT, open source). Docs: https://microsoft.github.io/presidio/
- **spaCy** — NER backbone; `en_core_web_lg` model. https://spacy.io/models/en
- Optional: `presidio-image-redactor` for PII in images (OCR), and the Presidio Structured package for tabular data.

## Common Scenarios

- **Log sanitisation before shipping to a SaaS SIEM**: restrict entities to `EMAIL_ADDRESS`, `IP_ADDRESS`, `PERSON`; operator `replace` with typed placeholders so log structure survives.
- **Test-data generation from production**: operator `replace` with a faker-backed callback, or `encrypt` for re-linkable records; run in a batch job over CSV columns.
- **Analyst-safe support tickets**: `hash` emails (joinable across tickets without revealing the address), `mask` card numbers, `replace` names.
- **Right-to-be-forgotten scrub** of a free-text field: `redact` all targeted entities, keep the findings report as deletion evidence.

## Output Format

- A de-identified copy of the input (file or column), structure preserved.
- A JSON findings report: per entity type a count and the character offsets removed — never the raw PII values.
- For reversible flows, the ciphertext output plus a separately-stored key reference (KMS ARN / secret path), not the key itself.

See `references/api-reference.md` for the operator parameter reference and the built-in entity list, and `scripts/agent.py` for the runnable `redact`/`audit` CLI.
