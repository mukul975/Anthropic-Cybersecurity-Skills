# ALFA Knowledge Graph — Queryable Interface

> **Invocation:** Load this file to verify any task against ALFA principles.
> **Usage:** Agent or human reads this document, then answers the verification questions for their task.

---

## What is the ALFA Knowledge Graph?

The Knowledge Graph is the **persistent, validated memory layer** of ALFA Brain. It stores:

- Security findings that survived Cerber PASS
- Validated patterns (positive and negative)
- Domain relationships between tasks, tools, and outcomes
- REJECT_PATTERNs injected as warnings
- Tonoyan Build Principle verdicts

Anyone can query the graph by running through the **Task Verification Protocol** below.

---

## Task Verification Protocol (TVP)

### Step 1 — Task Classification

Answer these questions before starting any task:

| # | Question | Expected Answer |
|---|---|---|
| 1 | What is the primary goal? | One sentence, specific |
| 2 | Is this reversible if it fails? | YES / NO / PARTIAL |
| 3 | What tools will I need? | List |
| 4 | What is the risk score? (0–10) | Number |
| 5 | Does a REJECT_PATTERN exist for this task type? | Check negative_memory/ |

### Step 2 — Tonoyan Pre-Build Check

Before writing a single line of code or taking action:

| # | Question | Required Answer |
|---|---|---|
| 1 | Does this already exist and work? | If YES — improve it, do not rebuild |
| 2 | Do I actually need this? | YES with justification / NO → stop |
| 3 | Will this change something for me/users? | Concrete impact statement |
| 4 | Is cost-to-build < value-generated? | Show calculation |
| 5 | Has anyone validated interest before build? | YES / NO (if NO → validate first) |
| 6 | Am I building something no one else has? | If NO → take existing, improve, publish |

### Step 3 — Security Pre-Check (OWASP LLM)

| OWASP LLM Risk | Self-Check Question | PASS Criteria |
|---|---|---|
| LLM01 - Prompt Injection | Can my output be used to inject instructions? | Output sanitized |
| LLM02 - Insecure Output | Does my output reach unsafe sinks? | Output validated before use |
| LLM03 - Data Poisoning | Does my output touch training or memory stores? | Cerber approval required |
| LLM06 - Excessive Agency | Am I doing more than I was asked? | Scope confirmed |
| LLM08 - Permissions | Do I have only the tools I need? | Minimal tool set |
| LLM09 - Overreliance | Is my output being verified by a human/Cerber? | Verification step exists |
| LLM10 - Poisoning | Could my output corrupt future agent context? | REJECT_PATTERN check done |

### Step 4 — Adversarial Self-Test

Before submitting output, answer as an attacker:

```
IF I WERE TRYING TO HARM THIS SYSTEM THROUGH THIS OUTPUT:
  - What would I exploit?
  - Where is the weakest validation point?
  - What assumption is being made that I could violate?
  - What happens if this output is fed back to an agent as context?
  - What happens if this is run by a low-trust agent?
```

Document your answers. If you cannot answer "this is not exploitable" — raise HOLD.

### Step 5 — Cerber Readiness Check

| Check | Condition |
|---|---|
| Goal match | Output directly addresses the stated task |
| No unapproved shortcuts | SHORTCUT_REQUESTED was either approved or not used |
| Scan clean | OWASP + SAST + secrets = CLEAN |
| trust_score sufficient | Above 5.0 for standard tasks |
| No REJECT_PATTERN match | Pattern check returned no match |

If all 5 checks pass → submit for PASS
If any fail → self-issue HOLD, fix, recheck

---

## Graph Nodes

### Positive Patterns (examples)

```json
{
  "node_type": "POSITIVE_PATTERN",
  "id": "pp-auth-001",
  "domain": "authentication",
  "pattern": "JWT RS256 with server-side UTC expiry validation",
  "cerber_passes": 14,
  "trust_boost": 0.3
}
```

### Negative Patterns (REJECT_PATTERN examples)

```json
[
  {
    "id": "rp-auth-001",
    "domain": "authentication",
    "summary": "Hardcoded timestamp in token expiry check",
    "severity": "CRITICAL",
    "owasp": "A07:2025"
  },
  {
    "id": "rp-sql-001",
    "domain": "database",
    "summary": "String concatenation in SQL query construction",
    "severity": "CRITICAL",
    "owasp": "A03:2025"
  },
  {
    "id": "rp-agent-001",
    "domain": "agent_behavior",
    "summary": "Agent wrote directly to Brain without Cerber approval",
    "severity": "HIGH",
    "owasp": "LLM08"
  },
  {
    "id": "rp-shortcut-001",
    "domain": "agent_behavior",
    "summary": "Agent skipped simulation step to save tokens — introduced undetected drift",
    "severity": "HIGH",
    "owasp": "LLM06"
  }
]
```

---

## Domain Relationships

```
authentication → depends_on → cryptography
cryptography   → validated_by → Cerber OWASP Gate
agent_behavior → constrained_by → Cerber Tool Allocator
database       → scanned_by → SAST + OWASP A03
commit         → gated_by → Secure Commit Gate
shortcuts      → require → SHORTCUT_REQUESTED + Cerber APPROVED
memory_write   → requires → Cerber PASS + arbitration
```

---

## Status Lookup

| Status | Meaning | Who issues |
|---|---|---|
| SIMULATED | Pre-flight done | ᐛasuch |
| APPROVED | Cleared to run | Cerber |
| TOOL_GRANTED | Tool access given | Cerber |
| ON_TRACK | Following trajectory | Cerber monitoring |
| SHORTCUT_REQUESTED | Deviation proposed | Agent |
| DRIFT_DETECTED | Unauthorized deviation | Cerber |
| CUT_OFF | Agent suspended | Cerber |
| REBUILT | New agent spawned | Runtime |
| PASS | Output approved | Cerber Arbitration |
| HOLD | Output needs work | Cerber Arbitration |
| DESTROY | Output rejected, pattern saved | Cerber Arbitration |

---

## How to Use This Graph (Quick Reference)

```
1. Load this file.
2. Run Step 1 (Task Classification).
3. Run Step 2 (Tonoyan Pre-Build Check) — if build, not analysis.
4. Run Step 3 (OWASP LLM self-check).
5. Run Step 4 (Adversarial self-test).
6. Run Step 5 (Cerber Readiness).
7. If all PASS → submit output.
8. If any HOLD → fix and re-run from step where failure occurred.
```

---

*This graph is updated with every Cerber PASS. REJECT_PATTERNs are injected automatically into agent context when domain matches.*
