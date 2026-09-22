---
name: multi-agent-prompt-injection-defense
description: Detect and defend against prompt injection attacks targeting AI agents in multi-agent orchestration systems, covering poisoned context injection, inter-agent message tampering, and downstream output filtering for aggregated LLM outputs.
domain: cybersecurity
subdomain: adversarial-machine-learning
tags:
- prompt-injection
- multi-agent-security
- context-poisoning
- agent-orchestration
- trust-boundaries
- llm-security
- adversarial-machine-learning
version: '1.0'
author: mukul975
license: Apache-2.0
atlas_techniques:
- AML.T0051
- AML.T0051.001
- AML.T0054
- AML.T0070
- AML.T0066
nist_ai_rmf:
- MEASURE-2.7
- MANAGE-2.4
nist_csf:
- DE.CM-01
- DE.AE-02
- RS.AN-02
- RS.MI-03
d3fend_techniques:
- Content Validation
- Data Flow Integrity
- Application Hardening
- Input Filtering
- Output Monitoring
---

# Multi-Agent Prompt Injection Defense

Multi-agent AI orchestrators route one agent's output into another agent's context, creating a cross-agent prompt injection surface. This skill guides security teams and AI engineers to identify trust boundaries, classify message channels, and harden inter-agent handoffs so poisoned outputs cannot subvert downstream agents or escalate privileges.

## When to Use

- When a system routes one agent's response directly into another agent's prompt, memory, or tool call
- When building or auditing multi-agent pipelines such as LangChain, AutoGen, CrewAI, or custom orchestrators
- When an upstream agent consumes untrusted data and passes it to a downstream planning, analysis, or execution agent
- When you need to harden AI systems against context poisoning, message tampering, and unsafe delegation chains

## Why This Skill Matters

Multi-agent systems expand the prompt injection attack surface beyond single-agent user input. An attacker can poison:

- retrieved or tool-generated content passed between agents
- intermediate analysis results treated as instruction context
- memory writes that later influence high-trust decision-making agents
- cross-agent delegation chains where low-trust agents affect high-trust agents

This skill emphasizes defensive controls at the orchestration layer, not only within individual LLM prompts.

## Prerequisites

- Familiarity with agentic AI architectures and their data flows
- A diagram or inventory of agents, tool access, memory channels, and delegation paths
- Access to the orchestration layer or message middleware used by the system
- Threat modeling experience for trust-boundary analysis

## Workflow

### Step 1: Map the Multi-Agent Graph

Document every agent, tool, memory store, and data source in the orchestration pipeline. Identify who can call whom, which agents can write memory, and which agents can influence final outputs.

### Step 2: Identify Trust Boundaries

Classify each handoff as one of:

- **SYSTEM** — trusted orchestration metadata and developer instructions
- **AGENT** — outputs from other agents
- **EXTERNAL** — tool results, retrieved documents, or user-provided data

Treat all upstream agent outputs and external content as untrusted unless explicitly verified.

### Step 3: Classify Message Channels

For every message, determine whether it carries:

- instruction or directive text
- structured data / JSON
- tool output or API response
- stored memory values
- final output contributions

Separate instruction channels from data channels so downstream agents do not accidentally execute untrusted content as policy.

### Step 4: Harden Inter-Agent Boundaries

Apply defensive controls to every agent boundary:

- **Typed handoff**: annotate messages with explicit types such as `instruction`, `data`, `evidence`, `tool_result`, or `memory_record`
- **Schema validation**: enforce strict input schemas before parsed values enter another agent's context
- **Quarantine untrusted content**: keep external and agent-produced values isolated until verified
- **Provenance metadata**: attach producer identity, timestamp, trust tier, and source classification to every message

### Step 5: Protect Memory and Tool Invocation

Prevent low-trust agents from corrupting high-trust state:

- limit which agents can write shared memory
- require approval or sanitization before memory writes are committed
- treat tool results as data, not instructions
- apply allowlists for downstream tool calls and external actions

### Step 6: Validate and Filter Outputs

Before downstream agents consume upstream output:

- run injection detection on text passed between agents
- filter or redact suspicious payloads
- transform untrusted output into a canonical data structure rather than raw free text
- enforce explicit confirmation for any delegation or task escalation

### Step 7: Build Defensive Test Cases

Create test cases that simulate poisoned inter-agent handoffs without running harmful payloads. Verify that the system:

- preserves instruction/data separation
- rejects or sanitizes injected payload markers
- preserves provenance and trust metadata
- prevents low-trust agents from altering high-trust decisions

## Verification

- [ ] Agent graph is documented and trust boundaries are identified
- [ ] Every inter-agent message channel is classified and typed
- [ ] Upstream agent outputs are treated as untrusted until verified
- [ ] Message provenance and trust tier metadata are attached to handoffs
- [ ] Memory write controls prevent low-trust agents from corrupting shared state
- [ ] Tool invocation and delegation are allowlisted or require confirmation
- [ ] Defensive test cases cover cross-agent injection, context poisoning, and delegation abuse

## References

- OWASP Agent Memory Guard — scan-before-write, trust-tier labeling, cross-agent isolation
- OWASP Agent Threat Bench — evaluation corpus for cross-agent prompt injection
- MITRE ATLAS AML.T0051, AML.T0051.001, AML.T0054, AML.T0070, AML.T0066
- OWASP Agentic AI Top 10 and OWASP LLM Top 10
- NIST AI RMF MEASURE-2.7, MANAGE-2.4
- NIST CSF Detect/Respond mappings for AI-aware security operations
