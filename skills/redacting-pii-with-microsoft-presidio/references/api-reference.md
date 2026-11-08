# Presidio API Reference (as used by this skill)

Pinned behaviour verified against `presidio-analyzer` / `presidio-anonymizer` 2.2.x.
Authoritative docs: https://microsoft.github.io/presidio/

## AnalyzerEngine.analyze()

```python
analyzer.analyze(
    text: str,
    language: str = "en",
    entities: list[str] | None = None,   # None = all registered recognisers
    score_threshold: float = 0.0,        # drop results below this confidence
    allow_list: list[str] | None = None, # tokens never flagged
    return_decision_process: bool = False,
) -> list[RecognizerResult]
```

`RecognizerResult` fields: `entity_type: str`, `start: int`, `end: int`, `score: float`.
Offsets are Python string indices: the span is `text[start:end]`.

## AnonymizerEngine.anonymize()

```python
anonymizer.anonymize(
    text: str,
    analyzer_results: list[RecognizerResult],
    operators: dict[str, OperatorConfig],  # key = entity type, or "DEFAULT"
) -> EngineResult   # .text (str), .items (list[OperatorResult])
```

Resolution order for an entity's operator: exact `entity_type` key, else `"DEFAULT"`.

## Built-in anonymizer operators

| Operator | Params | Effect |
|---|---|---|
| `replace` | `new_value` | Substitute a fixed string (default `<ENTITY_TYPE>`) |
| `redact` | — | Remove the span entirely |
| `mask`   | `masking_char`, `chars_to_mask`, `from_end` (bool) | Replace N chars with a mask char |
| `hash`   | `hash_type` in `{"md5","sha256","sha512"}` | One-way hash of the span |
| `encrypt`| `key` (16/24/32-byte str) | AES-CBC; reversible with `decrypt` |
| `keep`   | — | Leave the span unchanged (useful with a `DEFAULT` redact) |

`DeanonymizeEngine.deanonymize(text, entities, operators)` reverses `encrypt`
using `OperatorConfig("decrypt", {"key": key})`. `entities` is the `.items`
list returned by the encrypting `anonymize()` call.

## Custom recognisers

```python
from presidio_analyzer import PatternRecognizer, Pattern

PatternRecognizer(
    supported_entity="EMPLOYEE_ID",
    patterns=[Pattern(name="emp", regex=r"\bEMP-\d{6}\b", score=0.85)],
    context=["employee", "badge"],   # nearby words raise the score
)
analyzer.registry.add_recognizer(recognizer)
```

`deny_list=[...]` on `PatternRecognizer` flags a fixed vocabulary without a regex.

## Commonly used built-in entity types

Global: `CREDIT_CARD`, `CRYPTO`, `DATE_TIME`, `EMAIL_ADDRESS`, `IBAN_CODE`,
`IP_ADDRESS`, `NRP`, `LOCATION`, `PERSON`, `PHONE_NUMBER`, `MEDICAL_LICENSE`, `URL`.

Region-specific (examples): `US_SSN`, `US_PASSPORT`, `US_DRIVER_LICENSE`,
`UK_NHS`, `UK_NINO`, `ES_NIF`, `IT_FISCAL_CODE`, `AU_TFN`, `SG_NRIC_FIN`,
`IN_PAN`, `IN_AADHAAR`. Full, versioned list:
https://microsoft.github.io/presidio/supported_entities/

## Batch

- `BatchAnalyzerEngine.analyze_iterator(texts, language=...)` for a list of strings.
- `BatchAnalyzerEngine.analyze_dict(...)` / `BatchAnonymizerEngine.anonymize_dict(...)`
  for column/record data; reuses the loaded NLP pipeline instead of re-loading per row.

## Operational notes

- Recall depends on the spaCy model; prefer `en_core_web_lg` for `PERSON`/`LOCATION`.
- Checksum-backed recognisers (`CREDIT_CARD`, `IBAN_CODE`) validate the number, so
  their scores are high and stable; free-form names are the weakest class.
- `encrypt` keys are secrets. Store in a KMS/secret manager, never alongside output.
