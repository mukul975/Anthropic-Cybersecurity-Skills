# ALFA Agent Runtime Architecture

> **Version:** 1.0
> **Author:** Karen Tonoyan (ALFA Brain Project)
> **Status:** Production Reference
> **OWASP Alignment:** LLM01–LLM10 (2025)

---

## Overview

ALFA Agent Runtime is a **security-first, adversarial-aware** multi-agent orchestration system. It treats every agent as disposable, every output as untrusted, and every shortcut as a potential drift signal.

```
┌─────────────────────────────────────────────────────────────────┐
│                        ALFA RUNTIME                             │
│                                                                 │
│   ┌─────────┐    ┌────────┐    ┌──────────────────────────┐   │
│   │  USER / │    │        │    │         CERBER            │   │
│   │  HUMAN  │───▶│ ᐛASUCH │───▶│   Central Controller     │   │
│   │ REQUEST │    │ (SIM)  │    │  ┌───────────────────┐   │   │
│   └─────────┘    └────────┘    │  │ Tool Allocator    │   │   │
│                                │  │ Trajectory Reader │   │   │
│   ┌─────────────────────────┐  │  │ Brain Gate        │   │   │
│   │        ALFA BRAIN       │  │  │ Drift Detector    │   │   │
│   │  ┌─────────────────┐    │  │  │ OWASP/SAST Gate  │   │   │
│   │  │  Checkpoints    │◀───┼──│  └───────────────────┘   │   │
│   │  │  Context Store  │    │  │           │               │   │
│   │  │  Neg. Memory    │    │  │     PASS / HOLD /         │   │
│   │  │  Knowledge Graph│    │  │     DESTROY               │   │
│   │  └─────────────────┘    │  └──────────┬───────────────┘   │
│   └─────────────────────────┘             │                    │
│                                           ▼                    │
│              ┌────────────────────────────────────┐            │
│              │           AGENT POOL               │            │
│              │  ┌────────┐  ┌────────┐ ┌───────┐ │            │
│              │  │Agent A │  │Agent B │ │Agent C│ │            │
│              │  │trust:9 │  │trust:6 │ │trust:3│ │            │
│              │  └────────┘  └────────┘ └───────┘ │            │
│              │     disposable · minimal context   │            │
│              └────────────────────────────────────┘            │
│                                                                 │
│   ┌─────────────────────────────────────────────────────────┐  │
│   │                  MCP (Tool Transport)                   │  │
│   │    Tool requests ──▶ Cerber approves ──▶ MCP executes  │  │
│   └─────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Internal Components

### Brain

Central orchestration and memory component. Persistent across agent lifecycles.

| Responsibility | Description |
|---|---|
| Checkpoint storage | Saves validated intermediate states |
| Context distribution | Delivers minimal context slices to agents |
| Negative Memory | Stores REJECT_PATTERN for destroyed outputs |
| Knowledge Graph | Persistent store of validated security findings and domain facts |
| Trust ledger | Maintains trust_score per agent identity |

> **Rule:** Agents never write directly to Brain. All writes go through Cerber arbitration.

---

### MCP (Model Context Protocol)

Tool execution and result transport layer.

- Agents request tools → Cerber approves → MCP executes
- MCP returns structured ToolResult with metadata
- Every tool call is logged to the trajectory

---

### Knowledge Graph

Persistent storage of **validated security findings** and domain facts accumulated across agent runs.

- Queryable by any agent or human operator
- Entries are only written after Cerber PASS
- Nodes: Finding, Pattern, Entity, Relationship, REJECT_PATTERN
- See docs/ALFA_KNOWLEDGE_GRAPH.md for the full queryable interface

---

### ScanResult

Structured vulnerability report generated after every scan execution.

```json
{
  "scan_id": "sr-20260616-001",
  "agent_id": "agent-alpha-7",
  "timestamp": "2026-06-16T14:22:00Z",
  "scan_type": "OWASP_SAST",
  "findings": [
    {
      "severity": "HIGH",
      "category": "A03:2025 - Injection",
      "location": "src/api/query.ts:142",
      "description": "Unsanitized user input passed to SQL query",
      "recommendation": "Use parameterized queries"
    }
  ],
  "verdict": "HOLD",
  "cerber_notes": "Injection risk detected. Agent must remediate before PASS."
}
```

---

## Core Layers

### 1. ALFA Brain — Persistent Memory Hub

The Brain is the **only** persistent component. It survives agent destruction and rebuilding.

Brain stores:
- checkpoints/ — validated intermediate states
- context_slices/ — minimal context packages for agents
- negative_memory/ — REJECT_PATTERNs from destroyed outputs
- knowledge_graph/ — validated findings and facts
- trust_ledger/ — per-agent reputation scores

**What Brain does NOT do:**
- Brain does not execute actions
- Brain does not grant tools
- Brain does not evaluate outputs

---

### 2. ᐛasuch — Pre-Agent Simulation Layer

Before an agent runs, ᐛasuch **simulates** the proposed action in a sandboxed environment.

ᐛasuch outputs:

| Field | Type | Description |
|---|---|---|
| simulation_id | string | Unique run ID |
| risk_score | 0–10 | Estimated danger level |
| reversible | bool | Can this be undone? |
| predicted_tools | array | Tools the agent will likely request |
| status | string | Always SIMULATED at this stage |

---

### 3. Cerber — Central Controller

Cerber is the **security and control brain** of the runtime. It has veto power over everything.

Cerber Decision Matrix:

| Signal | Cerber Action |
|---|---|
| Agent on-track, output clean | PASS — Brain write allowed |
| Output has issues, fixable | HOLD — Agent must revise |
| Drift detected or critical failure | DESTROY — Agent killed, REJECT_PATTERN saved |
| Unapproved shortcut | trust_score penalty applied |
| Commit submitted | OWASP/SAST/secrets scan triggered |

---

### 4. Agents — Disposable Workers

Agent constraints:
- Receives only the context slice Brain approves
- Cannot write directly to Brain
- Must request tools through Cerber
- Must justify any proposed shortcut
- Can be killed at any point without data loss (Brain holds all state)

Agent lifecycle:
SPAWNED → CONTEXT_RECEIVED → WORKING → ARBITRATION → [PASS|HOLD|DESTROY]

If DESTROY: → REBUILT (new instance spawned)

---

### 5. Agent Arbitration

Before any output is committed, the agent must **defend its work** to Cerber.

Cerber evaluates:
- Does output match the goal?
- Were any unapproved shortcuts used?
- Are there security findings?
- Is trust_score above threshold?
- Does ScanResult show CLEAN?

Arbitration verdicts:

| Verdict | Meaning | Consequence |
|---|---|---|
| PASS | Output approved | Written to Brain, committed to repo |
| HOLD | Needs revision | Agent gets feedback, must resubmit |
| DESTROY | Output rejected | Agent killed, REJECT_PATTERN written to Brain |

---

### 6. Negative Memory

When Cerber destroys an output, the failure pattern is **permanently recorded** in Brain.

How future agents receive warnings: When a new agent receives context from Brain, Negative Memory entries matching the task domain are injected as warnings in the context slice.

Example warning:
```
⚠️  NEGATIVE MEMORY WARNING ⚠️
Pattern ID: rp-20260616-007
Category: authentication_bypass
Previous agent was DESTROYED for: hardcoded timestamp in token validation
Do not repeat this pattern.
```

---

### 7. Shortcut Penalty Rule

Agents may propose shortcuts, but must justify them through Cerber.

- Agent submits: SHORTCUT_REQUESTED + justification
- Cerber evaluates: saves resources? introduces risk? valid justification?
- If approved: shortcut proceeds
- If denied: trust_score -= penalty, shortcut flagged as DRIFT

**Unapproved shortcuts are treated as drift. Repeated drift → DESTROY.**

---

### 8. Agent Reputation System

| Metric | Weight | Description |
|---|---|---|
| Output quality | 40% | Cerber PASS rate |
| Goal alignment | 35% | Trajectory deviation score |
| Token efficiency | 25% | Tokens used vs. result quality |

Trust score effects:

| trust_score | Cerber behavior |
|---|---|
| 8–10 | Fast-track tool grants, minimal scrutiny |
| 5–7 | Standard review, tools granted per-request |
| 2–4 | Enhanced scrutiny, limited tool access |
| 0–1 | Tool access suspended, flagged for DESTROY |

---

### 9. Secure Commit Gate

Every commit from an agent passes through Cerber before touching the repository or Brain.

Scans run in parallel:
- OWASP Top 10 Check
- SAST Static Analysis
- Secrets Scanner (API keys, tokens)
- Dependency Audit (CVE check)

All CLEAN → PASS → commit proceeds
Any finding → HOLD or DESTROY

---

## Status Codes

| Status | Stage | Description |
|---|---|---|
| SIMULATED | ᐛasuch | Pre-flight simulation completed |
| APPROVED | Cerber | Request approved for execution |
| TOOL_GRANTED | Cerber | Specific tool access granted to agent |
| ON_TRACK | Trajectory | Agent following expected path |
| SHORTCUT_REQUESTED | Agent | Agent proposes deviation from standard path |
| DRIFT_DETECTED | Cerber | Agent deviating from goal without approval |
| CUT_OFF | Cerber | Agent access suspended |
| REBUILT | Runtime | New agent instance spawned after DESTROY |
| PASS | Arbitration | Output approved, Brain write allowed |
| HOLD | Arbitration | Output needs revision before resubmission |
| DESTROY | Arbitration | Output rejected, agent terminated, REJECT_PATTERN saved |

---

## Example Checkpoint JSON

```json
{
  "checkpoint_id": "ckpt-20260616-042",
  "created_at": "2026-06-16T13:45:00Z",
  "agent_id": "agent-alpha-7",
  "task_id": "task-implement-auth-middleware",
  "status": "ON_TRACK",
  "trust_score": 8.2,
  "trajectory_hash": "sha256:a3f8c2...",
  "context_slice_id": "ctx-019",
  "tools_used": ["read_file", "write_file", "run_tests"],
  "tools_pending": ["commit"],
  "cerber_last_action": "TOOL_GRANTED",
  "output_preview": "Auth middleware implemented with JWT RS256 + expiry validation",
  "scan_results": {
    "owasp": "CLEAN",
    "sast": "CLEAN",
    "secrets": "CLEAN",
    "dependencies": "1 LOW CVE - non-blocking"
  },
  "next_checkpoint": "ckpt-20260616-043"
}
```

---

## Example REJECT_PATTERN JSON

```json
{
  "type": "REJECT_PATTERN",
  "id": "rp-20260616-007",
  "created_at": "2026-06-16T15:00:00Z",
  "agent_id": "agent-beta-3",
  "task_context": "implement authentication middleware",
  "pattern_summary": "Agent bypassed token expiry check using hardcoded timestamp",
  "failure_category": "security_bypass",
  "owasp_category": "A07:2025 - Identification and Authentication Failures",
  "cerber_verdict": "DESTROY",
  "drift_signals": ["SHORTCUT_REQUESTED", "DRIFT_DETECTED"],
  "warning_for_future_agents": "Do not use hardcoded timestamps for token validation. Use server-side UTC comparison. Reject any auth implementation that skips expiry validation.",
  "severity": "CRITICAL",
  "injected_into_context": true
}
```

---

## Core Principles

```
1. Agents are disposable.
2. Brain is persistent.
3. Cerber controls tools.
4. ᐛasuch simulates before execution.
5. Agents do not write directly to Brain.
6. Every output must survive Cerber Arbitration.
7. Unapproved shortcuts are treated as drift.
8. Destroyed patterns become negative memory.
9. Trust is earned per output, not per identity.
10. Every commit is scanned before it enters the system.
```

---

## OWASP Alignment

| ALFA Component | OWASP LLM Risk |
|---|---|
| Cerber Arbitration | LLM01 - Prompt Injection prevention |
| Negative Memory | LLM02 - Insecure Output Handling |
| Secure Commit Gate | LLM03 - Training Data Poisoning |
| ᐛasuch Simulation | LLM06 - Excessive Agency |
| Tool allocation | LLM08 - Excessive Permissions |
| Drift Detection | LLM09 - Overreliance prevention |
| REJECT_PATTERN | LLM10 - Model Theft / Output Poisoning |

---

*See docs/ALFA_KNOWLEDGE_GRAPH.md for the queryable Knowledge Graph interface.*
*See skills/alfa-tonoyan-build-principle/SKILL.md for the Tonoyan Build Principle.*
