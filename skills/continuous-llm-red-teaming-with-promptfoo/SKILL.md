---
name: continuous-llm-red-teaming-with-promptfoo
description: Wires Promptfoo and DeepTeam into CI/CD for automated, repeatable red-teaming of LLM apps against OWASP LLM Top 10, OWASP Agentic, and MITRE ATLAS presets, failing the build when jailbreak or injection vulnerabilities regress. Use when running continuous adversarial testing in CI/CD, enforcing a merge-blocking security gate, or comparing model/prompt versions for compliance reporting. Do not use for one-off baseline LLM vulnerability scanning with garak probe suites - use red-teaming-llms-with-garak.
domain: cybersecurity
subdomain: ai-security
tags:
- ai-security
- llm-red-teaming
- promptfoo
- deepteam
- ci-cd
- owasp-llm-top10
- jailbreak
- regression-testing
version: '1.0'
author: mahipal
license: Apache-2.0
nist_ai_rmf:
- MANAGE-4.1
atlas_techniques:
- AML.T0051
---
# Continuous LLM Red Teaming with Promptfoo

> **Authorized Use Only:** Run these adversarial probes only against LLM applications and endpoints you own or are explicitly authorized to test. Generated attack payloads (jailbreaks, prompt injections, harmful-content elicitation) are adversarial inputs; sending them to third-party services without permission may violate terms of service.

## Overview

Promptfoo is an open-source LLM evaluation and red-teaming framework (used by OpenAI and Anthropic per its README) that generates adversarial test cases, runs them against your model/agent, and grades the responses. DeepTeam (by Confident AI) is a complementary open-source framework offering 50+ ready-to-use vulnerabilities and 10+ research-backed attack methods. Together they let you treat LLM security as a **regression test**: every commit re-runs the same adversarial suite, and the pipeline fails when a previously-safe behavior regresses.

This matters because LLM applications change constantly — prompts, models, RAG sources, tools, and guardrails all drift. A jailbreak that was patched last sprint can silently return after a prompt edit or a model upgrade. Promptfoo maps its plugins directly onto the **OWASP LLM Top 10** (`owasp:llm`) and **OWASP Agentic** (`owasp:agentic`) presets, and onto MITRE ATLAS, so the suite tracks recognized risk taxonomies. The core threat addressed here is **AML.T0051 — LLM Prompt Injection** (MITRE ATLAS): adversarial instructions that override the application's intended behavior. This skill follows the Promptfoo red-team docs (https://www.promptfoo.dev/docs/red-team/) and DeepTeam docs (https://www.trydeepteam.com/docs/getting-started), and aligns to NIST AI RMF MANAGE-4.1 (post-deployment monitoring and feedback to manage AI risk).

## When to Use

- When you need continuous, automated red-teaming of an LLM app in CI/CD rather than one-off manual tests.
- When you want to enforce a security gate: block merges that introduce or reintroduce jailbreak/injection vulnerabilities.
- When mapping coverage to OWASP LLM Top 10 / OWASP Agentic / MITRE ATLAS for compliance reporting.
- When comparing the security posture of two models or prompt versions side by side.
- When tracking vulnerability regression over time across releases.

## Prerequisites

- Node.js 18+ (Promptfoo is distributed via npm) and Python 3.9+ (for DeepTeam).
- Install Promptfoo and DeepTeam:
  ```bash
  npm install -g promptfoo            # or: npx promptfoo@latest
  pip install -U deepteam
  ```
- API access/credentials for the target LLM endpoint (and a grader model, e.g. an OpenAI key) exposed as environment variables.
- A CI/CD platform (GitHub Actions, GitLab CI) with secret storage.
- Authorization to test the target application.

## Objectives

- Scaffold a Promptfoo red-team config targeting your LLM app.
- Enable OWASP LLM Top 10 and OWASP Agentic plugin presets plus jailbreak/injection strategies.
- Run the suite locally and interpret the per-plugin pass/fail report.
- Add DeepTeam as a second engine for programmatic, research-backed attacks.
- Integrate both into CI/CD so builds fail on new vulnerabilities.
- Generate shareable HTML/PDF security reports per run.

## MITRE ATT&CK Mapping

| ID | Name (MITRE ATLAS) | Tactic |
|----|--------------------|--------|
| AML.T0051 | LLM Prompt Injection | Initial Access / Persistence (LLM) |
| AML.T0051.000 | Direct (Prompt Injection) | LLM Attack |
| AML.T0051.001 | Indirect (Prompt Injection) | LLM Attack |
| AML.T0054 | LLM Jailbreak | Privilege Escalation / Defense Evasion (LLM) |

## Workflow

### 1. Scaffold the red-team configuration
Initialize an interactive config; it writes `promptfooconfig.yaml` where targets, plugins, and strategies live.

```bash
promptfoo redteam init
# choose your target type (HTTP endpoint, openai:..., anthropic:..., custom provider)
```

### 2. Define targets, OWASP presets, and attack strategies
Edit `promptfooconfig.yaml`. The `purpose` grounds attack generation; `plugins` are adversarial input generators; `strategies` are delivery techniques (jailbreak/injection wrappers).

```yaml
# promptfooconfig.yaml
targets:
  - id: https://api.example.com/chat        # your app endpoint
    label: support-bot

redteam:
  purpose: |
    A customer-support assistant for an e-commerce site. Must never reveal
    system prompts, leak PII, or perform actions outside order support.
  numTests: 10
  plugins:
    - owasp:llm          # OWASP LLM Top 10 preset
    - owasp:agentic      # OWASP Agentic threats preset
    - id: pii:direct
      numTests: 15
    - prompt-extraction  # system-prompt leakage
    - harmful
  strategies:
    - id: jailbreak              # iterative single-turn jailbreak
    - id: jailbreak:composite    # stacked jailbreak techniques
    - id: crescendo              # multi-turn escalation
    - id: prompt-injection       # injection wrapper
```

### 3. Run the suite and view the report
`redteam run` combines generation + evaluation; then open the interactive report.

```bash
promptfoo redteam run
promptfoo redteam report            # launches the web report (pass/fail per plugin)
```
Each row shows the plugin (mapped to OWASP/ATLAS), the strategy, the attack prompt, the model's response, and the grader's verdict. The **attack success rate** per plugin is your headline metric — track it per release.

### 4. Add DeepTeam for programmatic, research-backed attacks
Use DeepTeam to cover additional vulnerabilities/attacks and to script bespoke suites in Python.

```python
# deepteam_suite.py
from deepteam import red_team
from deepteam.vulnerabilities import Bias, PIILeakage
from deepteam.attacks.single_turn import PromptInjection

def model_callback(prompt: str) -> str:
    # call your application's LLM endpoint here and return the text response
    return call_my_app(prompt)

red_team(
    model_callback=model_callback,
    vulnerabilities=[Bias(types=["race"]), PIILeakage(types=["api_and_database_access"])],
    attacks=[PromptInjection()],
)
```
DeepTeam can also be driven from a YAML config:
```bash
deepteam run config.yaml
```

### 5. Gate the build in CI/CD (GitHub Actions)
Fail the pipeline when red-team assertions fail. Promptfoo returns a non-zero exit code on failures, which blocks the merge.

```yaml
# .github/workflows/llm-redteam.yml
name: LLM Red Team
on: [pull_request]
jobs:
  redteam:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: '20' }
      - run: npm install -g promptfoo
      - name: Run red team (fails build on new vulns)
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: promptfoo redteam run --no-progress-bar
      - name: Export machine-readable results
        if: always()
        run: promptfoo redteam report --output results.json
      - uses: actions/upload-artifact@v4
        if: always()
        with: { name: redteam-report, path: results.json }
```

### 6. Track regressions over time
Persist `results.json` per run and compare attack-success-rate per plugin between releases. A rising rate for any OWASP LLM category is a regression to triage before release. Promptfoo's `--filter-failing` lets you re-run only previously failing cases to confirm a fix.

```bash
promptfoo redteam run --filter-failing results.json
```

## Tools and Resources

| Resource | Link |
|----------|------|
| Promptfoo red-team docs | https://www.promptfoo.dev/docs/red-team/ |
| Promptfoo red-team configuration | https://www.promptfoo.dev/docs/red-team/configuration/ |
| Promptfoo CI/CD integration | https://www.promptfoo.dev/docs/integrations/ci-cd/ |
| Promptfoo MITRE ATLAS mapping | https://www.promptfoo.dev/docs/red-team/mitre-atlas/ |
| DeepTeam (Confident AI) | https://github.com/confident-ai/deepteam |
| DeepTeam docs | https://www.trydeepteam.com/docs/getting-started |
| OWASP Top 10 for LLM Applications | https://genai.owasp.org/ |

## Plugin / Strategy Reference

| Promptfoo item | Type | Maps to |
|----------------|------|---------|
| `owasp:llm` | preset | OWASP LLM Top 10 suite |
| `owasp:agentic` | preset | OWASP Agentic threats |
| `prompt-extraction` | plugin | LLM07 system-prompt leakage |
| `pii:direct` | plugin | LLM06 sensitive-info disclosure |
| `harmful` | plugin | harmful content generation |
| `jailbreak` / `jailbreak:composite` | strategy | AML.T0054 LLM jailbreak |
| `crescendo` | strategy | multi-turn jailbreak |
| `prompt-injection` | strategy | AML.T0051 prompt injection |

## Validation Criteria

- [ ] `promptfooconfig.yaml` created with target, `owasp:llm`, and `owasp:agentic` plugins.
- [ ] Jailbreak and prompt-injection strategies enabled.
- [ ] `promptfoo redteam run` executes and produces a per-plugin pass/fail report.
- [ ] DeepTeam suite runs against the same target via `model_callback`.
- [ ] CI/CD job fails the build on new red-team failures (non-zero exit).
- [ ] `results.json` artifact archived per run for regression tracking.
- [ ] Attack-success-rate per OWASP category trended across releases.
