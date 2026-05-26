---
name: sanitizing-pii-before-llm-processing
description: 'Sanitizes Personally Identifiable Information (PII) from text before
  it reaches LLMs in autonomous AI agent pipelines. Detects and redacts emails, phone
  numbers, national IDs, API keys, financial data, and credentials across 8 languages
  including LATAM identifiers (RFC, CPF, CUIT) not covered by standard regex tools.
  Returns sanitized text, safety_score (0.0-1.0), risk_category (CRITICAL/PRIVATE/SENSITIVE/CLEAN),
  and an immutable Proof of Sanitization anchored on Solana for EU AI Act audit trails.
  Use before any LLM call that processes user-generated or external data. Fail-closed:
  blocks input if API unreachable rather than passing unsanitized text through.'
domain: cybersecurity
subdomain: data-protection
tags:
- pii
- sanitization
- llm-security
- privacy
- gdpr
- eu-ai-act
- solana
- x402
- m2m
- autonomous-agents
version: '2.6'
author: teodorofodocrispin-cmyk
license: MIT
nist_csf:
- PR.DS-01
- PR.DS-02
- DE.CM-01
- GV.OV-01
nist_ai_rmf:
- MAP-1.6
- MEA-2.5
- GOV-1.7
mitre_atlas:
- AML.T0057
endpoint: https://api.trustboost.dev/sanitize
agent_card: https://api.trustboost.dev/.well-known/agent-card.json
llms_txt: https://api.trustboost.dev/llms.txt
payment: x402 — 149 USDC on Solana mainnet
trial: tx_hash=TRIAL (50 free sanitizations per wallet)
---

# Sanitizing PII Before LLM Processing

Privacy firewall for autonomous AI agent pipelines. Sanitizes PII before text reaches
LLMs — with immutable Proof of Sanitization anchored on Solana.

## When to Use

- Before any LLM call that processes user-generated text
- When agents handle documents, emails, or forms containing personal data
- For GDPR, LGPD, CCPA, or EU AI Act compliance in AI pipelines
- When agents process LATAM data (RFC, CPF, CUIT, CURP, RUT)
- For audit trail generation required by EU AI Act Articles 12, 13, 26

## Quick Start — TRIAL mode (no wallet needed)

```bash
curl -X POST https://api.trustboost.dev/sanitize   -H "Content-Type: application/json"   -d '{
    "text": "Contact John at john@example.com, SSN: 123-45-6789",
    "tx_hash": "TRIAL",
    "wallet_address": "your-agent-id",
    "context": "general"
  }'
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "sanitized_content": "Contact [REDACTED] at [REDACTED], SSN: [REDACTED]",
    "safety_score": 0.85,
    "risk_category": "CRITICAL",
    "context_applied": "general"
  }
}
```

## Autonomous Payment Flow (x402)

```bash
# Step 1: Call without payment → receive HTTP 402
curl -X POST https://api.trustboost.dev/sanitize   -H "Content-Type: application/json"   -d '{"text": "Contact john@example.com"}'
# → HTTP 402 with USDC payment instructions

# Step 2: Pay 149 USDC on Solana mainnet autonomously

# Step 3: Retry with tx_hash → sanitized text + on-chain proof
```

## Context Modes

| Context | Use Case |
|---------|----------|
| `general` | Standard PII detection (default) |
| `legal` | Maximum redaction for legal documents |
| `financial` | Financial identifiers focus |
| `medical` | HIPAA-grade sanitization |
| `code` | API keys and credentials only |

## Languages & PII Patterns

| Language | Region | Key Identifiers |
|----------|--------|-----------------|
| English | Global | SSN, API keys, credit cards |
| Spanish LATAM | Mexico, Argentina, Colombia | RFC, CUIT, CURP, DNI |
| Portuguese | Brazil & Portugal | CPF, CNPJ, NIF |
| German | DE/AT/CH | Personalausweis, IBAN DE |
| Japanese | Japan | マイナンバー, 運転免許証 |
| French | France/Belgium | NIR, SIRET, Carte Vitale |
| Italian | Italy | Codice Fiscale, Partita IVA |
| Korean | Korea | 주민등록번호 (RRN) |

## Proof of Sanitization — EU AI Act Compliance

```bash
# Verify any paid sanitization independently
curl https://api.trustboost.dev/verify/{anchor_tx}
# → {"status": "verified", "proof": {...}}
```

Supports EU AI Act Articles 12 (Record-keeping), 13 (Transparency),
26 (Deployer obligations).

## MCP Integration

```json
{
  "mcpServers": {
    "trustboost": {
      "url": "https://api.trustboost.dev/mcp"
    }
  }
}
```

Compatible with: Claude Code · Cursor · Windsurf · Glama

## Security Properties

- **Fail-closed**: If API unreachable, blocks input — never passes unsanitized text
- **Server-side redaction**: LLM detects, server enforces — no hallucination bypass
- **Anti-replay**: Each tx_hash valid for one sanitization only
- **Immutable proof**: On-chain anchor via Helius — mathematically unforgeable

## Resources

- GitHub: https://github.com/teodorofodocrispin-cmyk/TrustBoost-PII-Sanitizer
- Agent Card: https://api.trustboost.dev/.well-known/agent-card.json
- llms.txt: https://api.trustboost.dev/llms.txt
- OpenAPI: https://api.trustboost.dev/openapi.json
- Health: https://api.trustboost.dev/health
- Live Demo: https://huggingface.co/spaces/TrustBoost/pii-sanitizer
