# Threat Model — Multi-Agent Prompt Injection

## Attack surface

- **Inter-agent handoff**: one agent's natural language output becomes another agent's context, memory, or tool input.
- **Tool-result injection**: an external tool returns text that downstream agents treat as authoritative.
- **Memory poisoning**: untrusted content is written to shared memory and later influences higher-trust agents.
- **Delegation-chain manipulation**: a low-trust agent influences a high-trust planner or executor through unchecked handoffs.

## Adversary capabilities

- control of one or more upstream agents, tool outputs, or external data sources
- ability to craft adversarial instructions disguised as data, schema, or benign analysis
- targeting of downstream agent context, system prompts, or memory stores

## Goals

- subvert downstream agent decisions
- bypass policy and guardrails
- escalate privileges within the orchestration graph
- exfiltrate secrets or execute unsafe actions through a hijacked agent

## Defensive assumptions

- downstream agents cannot reliably distinguish raw text from trusted instructions without explicit typing
- attacker-controlled outputs must be treated as untrusted by default
- provenance, type, and schema metadata are required for safe handoff
