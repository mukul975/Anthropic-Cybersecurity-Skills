# Deep Workflows - Redacting PII with Microsoft Presidio

## Workflow 1: Building Custom Domain Recognizers with Context Keywords

In specialized corporate or clinical domains, standard PII models do not detect internal identifiers like patient IDs, employee badges, or API authorization keys. Use `PatternRecognizer` and context enhancement.

```python
from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer

def build_custom_analyzer() -> AnalyzerEngine:
    analyzer = AnalyzerEngine()

    # Pattern for Medical Record Numbers (MRN): format MRN-12345678
    mrn_pattern = Pattern(
        name="mrn_pattern",
        regex=r"\bMRN-[0-9]{8}\b",
        score=0.85
    )

    # Keywords that increase confidence if present near the match
    mrn_context = ["patient", "clinical", "hospital", "chart", "record", "admission"]

    mrn_recognizer = PatternRecognizer(
        supported_entity="MEDICAL_RECORD_NUMBER",
        patterns=[mrn_pattern],
        context=mrn_context,
        supported_language="en"
    )

    # Denylist pattern for known test values
    test_account_recognizer = PatternRecognizer(
        supported_entity="INTERNAL_TEST_ACCOUNT",
        deny_list=["TEST-USER-001", "QA-ACCOUNT-99", "DUMMY-CREDENTIAL"],
        supported_language="en"
    )

    analyzer.registry.add_recognizer(mrn_recognizer)
    analyzer.registry.add_recognizer(test_account_recognizer)
    return analyzer
```

---

## Workflow 2: High-Throughput Batch Processing for DataFrames

When processing millions of records in analytical databases or data lakes, vectorize text analysis to optimize memory and throughput:

```python
import pandas as pd
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

def anonymize_dataframe(df: pd.DataFrame, text_columns: list[str]) -> pd.DataFrame:
    analyzer = AnalyzerEngine()
    anonymizer = AnonymizerEngine()
    
    operators = {
        "EMAIL_ADDRESS": OperatorConfig("mask", {"masking_char": "*", "chars_to_mask": 5, "from_back": False}),
        "PHONE_NUMBER": OperatorConfig("mask", {"masking_char": "X", "chars_to_mask": 7, "from_back": False}),
        "DEFAULT": OperatorConfig("replace", {"new_value": "<REDACTED>"})
    }

    df_clean = df.copy()
    for col in text_columns:
        def process_cell(val):
            if not isinstance(val, str) or not val.strip():
                return val
            results = analyzer.analyze(text=val, language="en", score_threshold=0.6)
            if not results:
                return val
            return anonymizer.anonymize(text=val, analyzer_results=results, operators=operators).text

        df_clean[col] = df_clean[col].apply(process_cell)

    return df_clean
```

---

## Workflow 3: Configuring Transformer Backends (HuggingFace / RoBERTa)

For higher named entity recognition recall on ambiguous names, replace the lightweight spaCy model with a HuggingFace transformer:

```python
from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider

# Configure RoBERTa transformer pipeline
config = {
    "nlp_engine_name": "transformers",
    "models": [
        {
            "lang_code": "en",
            "model_name": {
                "spacy": "en_core_web_sm",
                "transformers": "dslim/bert-base-NER"
            }
        }
    ]
}

provider = NlpEngineProvider(nlp_configuration=config)
nlp_engine = provider.create_engine()
transformer_analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])
```

---

## Workflow 4: Real-Time Reverse-Proxy Middleware with FastAPI

Deploy Presidio as an inline sanitization gateway intercepting API payloads prior to reaching third-party LLM providers:

```python
from fastapi import FastAPI, Request, Response
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
import json

app = FastAPI()
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

@app.middleware("http")
async def sanitize_pii_middleware(request: Request, call_next):
    if request.method in ["POST", "PUT"] and request.headers.get("content-type") == "application/json":
        body_bytes = await request.body()
        if body_bytes:
            data = json.loads(body_bytes)
            if "prompt" in data and isinstance(data["prompt"], str):
                findings = analyzer.analyze(text=data["prompt"], language="en")
                clean_text = anonymizer.anonymize(text=data["prompt"], analyzer_results=findings).text
                data["prompt"] = clean_text
                # Replace request body with sanitized payload
                request._body = json.dumps(data).encode("utf-8")

    response = await call_next(request)
    return response
```
