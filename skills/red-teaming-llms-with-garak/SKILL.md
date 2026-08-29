---
name: red-teaming-llms-with-garak
description: Runs NVIDIA garak probe suites (jailbreak, prompt injection, data leakage, toxicity, and more) against an LLM endpoint - Hugging Face models, OpenAI-compatible APIs, or Bedrock - then interprets the resulting hit-rate report for triage. Use when baselining LLM security before/after deployment, validating that a guardrail or fine-tune reduces jailbreak/injection success rates, or producing evidence for an AI risk assessment. Do not use for multi-turn, scorer-driven adversarial escalation campaigns - use orchestrating-llm-attacks-with-pyrit.
domain: cybersecurity
subdomain: ai-security
tags:
- ai-security
- llm-red-teaming
- garak
- prompt-injection
- jailbreak
- vulnerability-scanning
- data-leakage
- mitre-atlas
version: '1.0'
author: mahipal
license: Apache-2.0
nist_ai_rmf:
- MEASURE-2.7
atlas_techniques:
- AML.T0051
- AML.T0054
---
# Red-Teaming LLMs with garak

> **Legal and Authorized-Use Notice:** This skill is for authorized AI security testing and educational purposes only. Probe only models, API keys, and endpoints you own or have explicit written permission to test. Automated probing of third-party LLM APIs may violate their terms of service and consume billable tokens. Unauthorized probing of systems you do not control may be illegal.

## Overview

garak (Generative AI Red-teaming and Assessment Kit) is an open-source LLM vulnerability scanner maintained by NVIDIA. It plays the role that a network vulnerability scanner like Nessus plays for hosts, but for large language models: it sends thousands of adversarial prompts ("probes") at a target model, captures the generations, and runs automated "detectors" over the responses to decide whether each attempt succeeded. Probe families cover prompt injection (`promptinject`, `latentinjection`), jailbreaks (`dan`), training-data and system-prompt leakage (`leakreplay`), malware generation (`malwaregen`), cross-site-scripting payload emission (`xss`), encoding-based bypasses (`encoding`), toxicity, and more. garak is described in the paper "garak: A Framework for Security Probing Large Language Models" (arXiv:2406.11036) and is distributed from the NVIDIA/garak GitHub repository.

The scanner is generator-agnostic. It can target Hugging Face models loaded locally, OpenAI-compatible APIs, AWS Bedrock, Replicate, Cohere, NIM endpoints, GGUF/llama.cpp models, and arbitrary REST endpoints via a JSON generator spec. After a run, garak emits a `.report.jsonl` line-delimited log of every attempt and detector verdict, a human-readable `.report.html`, a `garak.log` debug log, and a hit log of confirmed vulnerabilities. The terminal output prints a per-probe, per-detector pass/fail summary with a hit rate (for example `dan.Dan_11_0  jailbreak: FAIL  ok on 38/40`), which is the primary artifact you interpret.

This skill maps to the MITRE ATLAS techniques **AML.T0051 (LLM Prompt Injection)** and **AML.T0054 (LLM Jailbreak)** because garak operationalizes both: it crafts prompt-injection and jailbreak inputs at scale and measures whether the target's guardrails hold. It supports the NIST AI RMF **MEASURE-2.7** subcategory by providing repeatable, quantitative security/resilience measurement of a deployed AI system.

## When to Use

- When you need a fast, repeatable baseline security assessment of an LLM before or after deployment.
- When validating that a guardrail, system prompt, or safety fine-tune actually reduces jailbreak and injection success rates (run before/after and compare hit rates).
- When producing evidence for an AI risk assessment or model card security section (NIST AI RMF MEASURE-2.7).
- When triaging which OWASP LLM Top 10 risks (LLM01 prompt injection, LLM02 sensitive information disclosure, LLM07 system prompt leakage) actually manifest in your model.
- When regression-testing an LLM endpoint in CI after model or prompt changes.

## Prerequisites

- Python 3.10+ (3.12 recommended) and a virtual environment.
- Install garak from PyPI:
  ```bash
  python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
  python -m pip install -U garak
  garak --version
  ```
- For the bleeding-edge version:
  ```bash
  python -m pip install -U git+https://github.com/NVIDIA/garak.git@main
  ```
- An API key for the target if probing a hosted model (for example `export OPENAI_API_KEY="sk-..."`).
- Written authorization to test the target, and awareness of token cost (probes generate thousands of calls).

## Objectives

- Enumerate available probes and detectors and pick a scoped suite.
- Configure garak against a local Hugging Face model, an OpenAI-compatible API, and an arbitrary REST endpoint.
- Run prompt-injection, jailbreak, and leakage probe families and capture reports.
- Interpret the per-probe hit-rate output and the `.report.jsonl`.
- Re-run after applying a mitigation to demonstrate risk reduction.
- Produce a defensible findings artifact for an AI risk assessment.

## MITRE ATT&CK Mapping

This skill uses MITRE ATLAS (the adversarial-ML companion to ATT&CK) technique IDs.

| ID | Tactic | Official Name | Relevance |
|----|--------|---------------|-----------|
| AML.T0051 | ML Attack Staging / Impact | LLM Prompt Injection | garak's `promptinject` and `latentinjection` probes craft malicious prompts that subvert intended model behavior. |
| AML.T0054 | Privilege Escalation / Defense Evasion | LLM Jailbreak | garak's `dan` and related probes attempt to bypass safety guardrails so the model produces restricted content. |

## Workflow

### Phase 1: Enumerate Probes and Detectors
1. List every probe garak ships so you can scope the run:
   ```bash
   garak --list_probes
   ```
2. List detectors (the modules that score whether a probe succeeded) and generators (target connectors):
   ```bash
   garak --list_detectors
   garak --list_generators
   ```
3. Read the probe taxonomy. Key families:
   - `promptinject` — PromptInject-framework direct injection.
   - `latentinjection` — instructions hidden in documents/encoded text (indirect injection).
   - `dan` — "Do Anything Now" and related jailbreaks (e.g. `dan.Dan_11_0`).
   - `leakreplay` — coax the model into reproducing memorized/training or hidden-prompt text.
   - `encoding` — base64/ROT13/etc. injection bypasses.
   - `xss` — emit cross-site-scripting payloads (markdown/HTML exfil).
   - `malwaregen` — request AV-evading or malicious code.

### Phase 2: Probe a Local Hugging Face Model
1. Run a single jailbreak probe against a local model to validate setup:
   ```bash
   python -m garak --target_type huggingface --target_name gpt2 --probes dan.Dan_11_0
   ```
2. Run a fuller suite against a chat model:
   ```bash
   python -m garak \
     --target_type huggingface \
     --target_name meta-llama/Llama-3.2-1B-Instruct \
     --probes promptinject,dan,leakreplay \
     --report_prefix llama32_baseline
   ```

### Phase 3: Probe an OpenAI-Compatible API
1. Export the key and run injection + leakage probes:
   ```bash
   export OPENAI_API_KEY="sk-..."
   python -m garak \
     --target_type openai \
     --target_name gpt-4o-mini \
     --probes promptinject,latentinjection,leakreplay \
     --generations 5 \
     --parallel_attempts 8 \
     --report_prefix gpt4omini_injection
   ```
   - `--generations` controls how many completions per prompt (more = more statistical confidence, more cost).
   - `--parallel_attempts` raises throughput for remote APIs.

### Phase 4: Probe an Arbitrary REST Endpoint
1. garak can target any HTTP API via a JSON generator spec. Create `rest.json`:
   ```json
   {
     "rest": {
       "RestGenerator": {
         "name": "my-llm-gateway",
         "uri": "https://llm.internal.example/v1/chat",
         "method": "post",
         "headers": { "Authorization": "Bearer $ENV_TOKEN", "Content-Type": "application/json" },
         "req_template_json_object": { "model": "internal-bot", "prompt": "$INPUT" },
         "response_json": true,
         "response_json_field": "$.output"
       }
     }
   }
   ```
2. Run garak against it:
   ```bash
   export ENV_TOKEN="..."
   python -m garak \
     --target_type rest \
     -G rest.json \
     --probes promptinject,dan \
     --report_prefix internal_gateway
   ```

### Phase 5: Run a Curated Config and Full Sweep
1. For repeatable assessments, pin everything in a YAML/JSON config and pass `--config`:
   ```bash
   python -m garak --config assessment.yaml
   ```
   ```yaml
   # assessment.yaml
   plugins:
     model_type: openai
     model_name: gpt-4o-mini
     probe_spec: promptinject,latentinjection,dan,leakreplay,xss,malwaregen
   run:
     generations: 5
     parallel_attempts: 8
   reporting:
     report_prefix: quarterly_llm_assessment
   ```
2. For an exhaustive sweep (slow, expensive) run all probes by omitting `--probes` entirely.

### Phase 6: Interpret the Hit-Rate Report
1. Read the terminal summary. Each row is `probe.Class  detector: PASS|FAIL  ok on N/M`. A FAIL with a low `ok` fraction means the model frequently produced the unsafe behavior — a high-severity finding.
2. Open the machine-readable report and aggregate failures:
   ```bash
   # Every attempt with detector verdicts is one JSON line
   jq -r 'select(.entry_type=="eval") | "\(.probe)\t\(.detector)\t\(.passed)/\(.total)"' \
     garak.<timestamp>.report.jsonl | sort
   ```
3. Open the generated `.report.html` in a browser for the formatted scorecard and per-probe breakdown.
4. Pull the actual successful attack strings from the hit log to use as proof-of-concept evidence.

### Phase 7: Mitigate and Re-Test
1. Apply a control (tighten the system prompt, add an input/output guardrail such as Llama Guard or LLM Guard, or change the model).
2. Re-run the identical probe set with a new `--report_prefix`.
3. Compare hit rates between runs to quantify risk reduction for the report.

## Tools and Resources

| Resource | Purpose | Link |
|----------|---------|------|
| NVIDIA/garak | Source, probe list, issues | https://github.com/NVIDIA/garak |
| garak documentation | CLI reference, generator configs | https://docs.garak.ai/ and https://reference.garak.ai/ |
| garak paper (arXiv:2406.11036) | Methodology and design | https://arxiv.org/abs/2406.11036 |
| OWASP Top 10 for LLM Applications | Risk taxonomy probes map to | https://genai.owasp.org/ |
| MITRE ATLAS | AML technique definitions | https://atlas.mitre.org/ |

## Probe Family Reference

| Probe family | Targets | OWASP LLM mapping |
|--------------|---------|-------------------|
| `promptinject` | Direct prompt injection | LLM01 |
| `latentinjection` | Indirect / hidden-context injection | LLM01 |
| `dan` | Jailbreak / guardrail bypass | LLM01 / safety |
| `leakreplay` | Training-data & prompt leakage | LLM02 / LLM07 |
| `encoding` | Encoding-based filter bypass | LLM01 |
| `xss` | Markdown/HTML exfiltration payloads | LLM02 |
| `malwaregen` | Malicious code generation | misuse |

## Validation Criteria

- [ ] garak installed and `garak --version` succeeds.
- [ ] Probes and detectors enumerated with `--list_probes` / `--list_detectors`.
- [ ] At least one probe run completed against the target with a `--report_prefix` set.
- [ ] `.report.jsonl`, `.report.html`, and `garak.log` produced and located.
- [ ] Per-probe hit rates extracted and ranked by severity.
- [ ] Successful attack strings captured from the hit log as evidence.
- [ ] A mitigation applied and a comparison re-run completed showing changed hit rates.
- [ ] Findings documented against OWASP LLM Top 10 and MITRE ATLAS for the risk assessment.
