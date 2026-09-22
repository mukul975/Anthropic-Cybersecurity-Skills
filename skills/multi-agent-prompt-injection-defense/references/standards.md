# Standards and References — Multi-Agent Prompt Injection Defense

## MITRE ATLAS References

| Technique ID | Name | Rationale |
|--------------|------|-----------|
| AML.T0051 | LLM Prompt Injection | Core technique for adversarial instructions hidden in a model's context |
| AML.T0051.001 | LLM Prompt Injection: Indirect | Injection delivered via intermediate or retrieved content rather than direct user input |
| AML.T0054 | LLM Jailbreak | Subversion of model constraints through crafted prompt content |
| AML.T0070 | RAG Data Poisoning | Poisoned retrieval context or data stores used by downstream agents |
| AML.T0066 | LLM Input Manipulation | Manipulation of inputs that flow between agents, tools, and memory |

## NIST AI RMF References

| ID | Name | Rationale |
|----|------|-----------|
| MEASURE-2.7 | AI system security and resilience are evaluated and documented | Defensive analysis and testing of multi-agent injection risk |
| MANAGE-2.4 | AI risk management activities are integrated into system processes | Formal management of trust boundaries and message provenance |

## OWASP References

| ID | Name | Rationale |
|----|------|-----------|
| ASI06 | Memory/Context Poisoning | Core risk from poisoned inter-agent memory and context handoffs |
| LLM01:2025 | Prompt Injection | Primary risk class for adversarial instruction injection |
| LLM05:2025 | Improper Output Handling | Downstream agents must not treat output as trusted instructions |

## Related Resources

- OWASP Agent Memory Guard: https://github.com/OWASP/www-project-agent-memory-guard
- OWASP Agent Threat Bench: https://github.com/OWASP/www-project-agent-threat-bench
- MITRE ATLAS: https://atlas.mitre.org/
- OWASP LLM Top 10: https://genai.owasp.org/llmrisk/
- NIST AI RMF: https://www.nist.gov/itl/ai-risk-management-framework
