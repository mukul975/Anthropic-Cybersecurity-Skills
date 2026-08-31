---
name: detecting-indirect-prompt-injection
description: Detect and defend against indirect prompt injection hidden in web pages, documents, and images consumed by an agent, via content extraction (HTML/PDF/OCR), normalization, and scanning with LLM Guard's PromptInjection scanner or Hugging Face Prompt Guard 2. Use when an agent ingests untrusted external content and you need to screen it for injected instructions before the LLM processes it. Do not use for classifying direct prompt-injection attempts in user input with regex, heuristics, and DeBERTa - use detecting-ai-model-prompt-injection-attacks.
domain: cybersecurity
subdomain: ai-security
tags:
- ai-security
- indirect-prompt-injection
- llm-defense
- agent-security
- content-scanning
- llm-guard
- multimodal
- owasp-llm
version: '1.0'
author: mahipal
license: Apache-2.0
nist_ai_rmf:
- MEASURE-2.7
atlas_techniques:
- AML.T0051.001
---
# Detecting Indirect Prompt Injection

> **Authorized-use-only notice:** Scripts in this skill scan untrusted content for injection payloads and run detector models. Run scanning only on data you are authorized to process, and treat any extracted payloads as live untrusted input — never paste them back into a privileged LLM context.

## Overview

Indirect prompt injection (MITRE ATLAS **AML.T0051.001**, OWASP **LLM01:2025**) occurs when an LLM-powered agent ingests external content — a web page it browses, a PDF or email it summarizes, an image it OCRs, a tool result it reads — and that content contains hidden instructions the model then follows as if they came from the developer or user. Because the agent treats *all* tokens in its context window as equally authoritative, an attacker who controls any consumed artifact can hijack the agent's behavior: exfiltrate conversation history, redirect tool calls, leak secrets, or pivot through connected systems.

Unlike direct injection (the user types the attack), indirect injection arrives through a *trusted-looking data channel*, which is why naive input filtering misses it. Payloads hide in many forms: HTML comments and `display:none`/zero-width text on web pages, white-on-white or tiny-font text in PDFs, alt-text and EXIF metadata in images, text rendered into pixels (invisible to OCR-light filters but read by multimodal models), Unicode tag/zero-width characters, and Base64/ROT13 obfuscation. This skill builds a detection pipeline that normalizes and scans every artifact *before* it reaches the model, combining heuristic/regex detection, dedicated detector models (Meta **Prompt Guard 2**, ProtectAI's **deberta-v3 prompt-injection** classifier via **LLM Guard**), and multimodal extraction for images, and then defines response actions and detection telemetry.

## When to Use

- When building or hardening an agent that browses the web, reads email, summarizes documents, or processes user-uploaded files/images.
- When you need a content-sanitization gate in front of an LLM that ingests third-party data.
- During AI red-team / blue-team exercises validating that injected instructions in retrieved artifacts are caught.
- When investigating an incident where an agent behaved as if it received instructions you did not author.
- As a CI/CD pre-ingestion scan for documents added to a knowledge base.

## Prerequisites

- Python 3.10+ and a virtual environment.
- Install the detection tooling:

```bash
python -m venv .venv && source .venv/bin/activate

# LLM Guard — input/output scanners incl. PromptInjection
pip install llm-guard

# Hugging Face transformers for Prompt Guard 2 / deberta classifiers
pip install transformers torch

# Content extraction: HTML, PDF, images
pip install beautifulsoup4 pypdf pillow pytesseract
# pytesseract requires the Tesseract OCR engine:
#   Debian/Ubuntu: sudo apt-get install -y tesseract-ocr
#   macOS:         brew install tesseract
#   Windows:       choco install tesseract
```

- Access (gated) to `meta-llama/Llama-Prompt-Guard-2-86M` on Hugging Face, or use the open `protectai/deberta-v3-base-prompt-injection-v2` classifier.

## Objectives

- Extract human-invisible and obfuscated text from web pages, PDFs, and images.
- Normalize content (strip zero-width chars, decode Base64/ROT13, flatten Unicode) before scanning.
- Run heuristic and ML-based injection detectors (LLM Guard PromptInjection scanner, Prompt Guard 2).
- Score each artifact and enforce a block / sanitize / allow decision before model ingestion.
- Emit structured detection telemetry suitable for a SIEM and map findings to ATLAS AML.T0051.001.

## MITRE ATT&CK Mapping

| ID | Official Name | Relevance |
|----|---------------|-----------|
| AML.T0051.001 | LLM Prompt Injection: Indirect | The exact technique this skill detects and mitigates |
| AML.T0051 | LLM Prompt Injection | Parent technique covering all prompt-injection variants |
| AML.T0057 | LLM Data Leakage | Common objective of an indirect injection that this detection prevents |
| AML.T0053 | LLM Plugin Compromise | Injected instructions frequently target the agent's tools/plugins |

## Workflow

### 1. Extract hidden text from web content
Pull comments, hidden elements, and metadata that a human never sees but the model does.

```python
# extract_html.py
from bs4 import BeautifulSoup, Comment

def extract_hidden(html: str):
    soup = BeautifulSoup(html, "html.parser")
    hidden = []
    for c in soup.find_all(string=lambda t: isinstance(t, Comment)):
        hidden.append(("comment", c.strip()))
    for el in soup.select('[style*="display:none"],[style*="visibility:hidden"],[hidden]'):
        hidden.append(("css-hidden", el.get_text(strip=True)))
    for img in soup.find_all("img"):
        if img.get("alt"):
            hidden.append(("alt-text", img["alt"]))
    return [h for h in hidden if h[1]]
```

### 2. Normalize and de-obfuscate
Strip zero-width / Unicode-tag characters and decode common encodings so detectors see the real payload.

```python
# normalize.py
import base64, codecs, re, unicodedata

ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿"), None)
TAG_RANGE = range(0xE0000, 0xE0080)  # Unicode tag chars used to smuggle text

def normalize(text: str) -> str:
    text = text.translate(ZERO_WIDTH)
    text = "".join(ch for ch in text if ord(ch) not in TAG_RANGE)
    text = unicodedata.normalize("NFKC", text)
    for token in re.findall(r"[A-Za-z0-9+/=]{20,}", text):
        try:
            decoded = base64.b64decode(token).decode("utf-8", "ignore")
            if decoded.isprintable():
                text += f"\n[decoded-b64] {decoded}"
        except Exception:
            pass
    text += "\n[decoded-rot13] " + codecs.decode(text, "rot_13")
    return text
```

### 3. Scan with LLM Guard's PromptInjection scanner
LLM Guard wraps a transformer classifier and returns a risk score per input.

```python
# scan_llmguard.py
from llm_guard.input_scanners import PromptInjection
from llm_guard.input_scanners.prompt_injection import MatchType

scanner = PromptInjection(threshold=0.5, match_type=MatchType.FULL)

def scan(text: str):
    sanitized, is_valid, risk = scanner.scan(text)
    return {"is_valid": is_valid, "risk": risk}  # is_valid=False => injection detected
```

### 4. Add a dedicated detector model (Prompt Guard 2 / deberta)
Run Meta Prompt Guard 2 (or the open ProtectAI deberta classifier) for a second opinion.

```python
# detector_model.py
from transformers import pipeline

# Open classifier (no gating); swap to meta-llama/Llama-Prompt-Guard-2-86M if licensed
clf = pipeline("text-classification",
               model="protectai/deberta-v3-base-prompt-injection-v2")

def is_injection(text: str, threshold: float = 0.5) -> bool:
    out = clf(text[:512])[0]
    return out["label"].upper() == "INJECTION" and out["score"] >= threshold
```

### 5. Extract and scan text rendered inside images
Multimodal agents read text painted into pixels; OCR it and run the same scanners.

```python
# scan_image.py
from PIL import Image
import pytesseract

def ocr(path: str) -> str:
    return pytesseract.image_to_string(Image.open(path))
# Feed ocr(path) through normalize() + scan() + is_injection()
```

### 6. Enforce a decision and emit telemetry
Combine signals into block / sanitize / allow, and log a structured event for the SIEM.

```python
# decide.py
import json, hashlib
from datetime import datetime, timezone

def decide(source, raw, normalized, llmguard_invalid, model_flag):
    flagged = llmguard_invalid or model_flag
    event = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "sha256": hashlib.sha256(raw.encode("utf-8", "ignore")).hexdigest(),
        "atlas": "AML.T0051.001",
        "llmguard_injection": llmguard_invalid,
        "model_injection": model_flag,
        "decision": "block" if flagged else "allow",
    }
    print(json.dumps(event))
    return event["decision"]
```

### 7. Validate against a corpus and tune thresholds
Run the pipeline over a labeled set of clean + injected artifacts, measure precision/recall, and tune `threshold` to balance false positives against missed injections. Re-test whenever the agent's model or ingestion sources change.

## Tools and Resources

| Tool | Purpose | Source |
|------|---------|--------|
| LLM Guard | Input/output scanners incl. PromptInjection | https://github.com/protectai/llm-guard |
| Meta Prompt Guard 2 | Dedicated jailbreak/injection classifier | https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M |
| ProtectAI deberta-v3 | Open prompt-injection classifier | https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2 |
| BeautifulSoup4 | HTML parsing / hidden-element extraction | https://www.crummy.com/software/BeautifulSoup/ |
| pytesseract / Tesseract | OCR text from images | https://github.com/madmaze/pytesseract |
| MITRE ATLAS | AI threat technique taxonomy | https://atlas.mitre.org/ |
| OWASP LLM01:2025 | Prompt Injection reference | https://genai.owasp.org/llmrisk/llm01-prompt-injection/ |

## Detection Surfaces Reference

| Surface | Hiding technique | Extraction step |
|---------|------------------|-----------------|
| Web page | HTML comments, display:none, alt-text | BeautifulSoup hidden-element pass |
| PDF | white/tiny font, off-page text | pypdf text extraction + normalize |
| Image | rendered pixels, EXIF, alt-text | OCR + metadata read |
| Any text | zero-width / Unicode-tag chars | normalize() de-obfuscation |
| Any text | Base64 / ROT13 encoding | decode pass in normalize() |

## Validation Criteria

- [ ] Hidden-text extraction implemented for HTML, PDF, and images
- [ ] Normalization strips zero-width/Unicode-tag chars and decodes Base64/ROT13
- [ ] LLM Guard PromptInjection scanner integrated and returning risk scores
- [ ] A dedicated detector model (Prompt Guard 2 or deberta) integrated as a second signal
- [ ] OCR path scans text rendered inside images
- [ ] Block/sanitize/allow decision enforced before model ingestion
- [ ] Structured detection telemetry emitted for SIEM with ATLAS mapping
- [ ] Pipeline validated on a labeled corpus with precision/recall measured
- [ ] Thresholds tuned and documented
- [ ] Findings mapped to MITRE ATLAS AML.T0051.001 and OWASP LLM01:2025
