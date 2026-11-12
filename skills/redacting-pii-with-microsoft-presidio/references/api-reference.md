# API Reference - Redacting PII with Microsoft Presidio

## Python SDK Interfaces

### `presidio_analyzer.AnalyzerEngine`

The primary coordinator class responsible for orchestrating NLP artifacts, recognizer registries, and text analysis.

#### Methods

- `analyze(text: str, language: str = "en", entities: list[str] | None = None, score_threshold: float | None = None, return_decision_process: bool = False, correlation_id: str | None = None) -> list[RecognizerResult]`
  - `text`: Input string to inspect for sensitive entity occurrences.
  - `language`: Two-letter ISO language code (e.g., `"en"`, `"de"`, `"es"`).
  - `entities`: Explicit list of entity types to evaluate. If omitted, all enabled recognizers are queried.
  - `score_threshold`: Minimum confidence value (0.0 to 1.0) required for a detection to be returned.
  - `return_decision_process`: If True, attaches the analytical trace explaining why an entity was classified.

- `get_supported_entities(language: str = "en") -> list[str]`
  - Returns all registered entity slugs for the designated language (e.g., `["CREDIT_CARD", "CRYPTO", "DATE_TIME", "EMAIL_ADDRESS", "IBAN_CODE", "IP_ADDRESS", "NRP", "LOCATION", "PERSON", "PHONE_NUMBER", "MEDICAL_LICENSE", "US_BANK_NUMBER", "US_DRIVER_LICENSE", "US_ITIN", "US_PASSPORT", "US_SSN"]`).

---

### `presidio_analyzer.PatternRecognizer`

Base class for regex-based and context-augmented entity recognizers.

#### Initialization Parameters

- `supported_entity: str`: Entity name identifier (e.g., `"CORP_EMPLOYEE_ID"`).
- `name: str | None`: Recognizer unique name.
- `patterns: list[Pattern]`: List of compiled or raw regex patterns with base confidence scores.
- `context: list[str] | None`: Surrounding tokens that boost confidence score when present within window.
- `supported_language: str`: Target language (defaults to `"en"`).

---

### `presidio_anonymizer.AnonymizerEngine`

Executes transformations over text segments identified by `RecognizerResult` structures.

#### Methods

- `anonymize(text: str, analyzer_results: list[RecognizerResult], operators: dict[str, OperatorConfig] | None = None, conflict_resolution: ConflictResolutionStrategy = ConflictResolutionStrategy.MERGE_SIMILAR_OR_CONTAINED) -> EngineResult`
  - `text`: Original unredacted text.
  - `analyzer_results`: List of identified entity spans.
  - `operators`: Mapping of entity names (or `"DEFAULT"`) to `OperatorConfig` instances.

---

### `presidio_anonymizer.entities.OperatorConfig`

Defines the redaction operator type and operational parameters.

```python
OperatorConfig(operator_name="mask", params={"masking_char": "*", "chars_to_mask": 4, "from_back": True})
OperatorConfig(operator_name="replace", params={"new_value": "[ANONYMIZED]"})
OperatorConfig(operator_name="hash", params={"hash_type": "sha256"})
OperatorConfig(operator_name="encrypt", params={"key": "Wm3q4t6w9z$C&F)J@NcRfUjWnZr4u7x!"})
OperatorConfig(operator_name="redact", params={})
```

Supported `operator_name` values:
- `replace`: Swaps span with static text or entity tag.
- `redact`: Completely deletes characters from span.
- `mask`: Replaces a subset of characters with a mask character.
- `hash`: Replaces value with SHA-256 / SHA-512 cryptographic digest.
- `encrypt`: Reversibly encrypts text using AES-CBC with PKCS7 padding.
- `custom`: Invokes a lambda or callable function.

---

## HTTP REST Endpoints

### Presidio Analyzer Service (`port 5001 / 3000`)

- `POST /api/v1/analyzer/analyze`
  - Payload:
    ```json
    {
      "text": "Email test to john@example.com",
      "language": "en",
      "entities": ["EMAIL_ADDRESS"],
      "score_threshold": 0.6
    }
    ```
  - Response:
    ```json
    [
      {
        "entity_type": "EMAIL_ADDRESS",
        "start": 14,
        "end": 30,
        "score": 1.0
      }
    ]
    ```

### Presidio Anonymizer Service (`port 5002 / 3000`)

- `POST /api/v1/anonymizer/anonymize`
  - Payload:
    ```json
    {
      "text": "Email test to john@example.com",
      "anonymizers_config": {
        "EMAIL_ADDRESS": {
          "type": "mask",
          "masking_char": "*",
          "chars_to_mask": 4,
          "from_back": false
        }
      },
      "analyzer_results": [
        {
          "start": 14,
          "end": 30,
          "score": 1.0,
          "entity_type": "EMAIL_ADDRESS"
        }
      ]
    }
    ```
  - Response:
    ```json
    {
      "text": "Email test to ****@example.com",
      "items": [
        {
          "start": 14,
          "end": 30,
          "entity_type": "EMAIL_ADDRESS",
          "text": "****@example.com",
          "operator": "mask"
        }
      ]
    }
    ```
