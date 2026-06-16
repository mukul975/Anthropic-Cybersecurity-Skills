---
name: ALFA Tonoyan Build Principle
description: Pre-build decision framework. Prevents wasted effort by forcing validation before construction. Use before any build, feature, tool, or system. Answers: do I need this, will it change anything, is the cost worth it, is there demand.
type: decision_framework
author: Karen Tonoyan
version: 1.0
tags: [build, decision, efficiency, anti-waste, pre-flight]
---

# ALFA Tonoyan Build Principle

> *“If you are going to build something — build what no one else has built.
> If it needs to exist again — take what exists, improve it, publish it.
> But do not boast until you have created something truly unique.”*

---

## The Five Questions (answer ALL before building)

### 1. Does this already exist and work?

- Search for existing solutions
- If found and functional: **take it, improve it, publish the improvement**
- Do not rebuild what already works — you waste tokens, time, and attention
- Exception: you see a specific flaw that others missed → document the flaw first, then build the fix

### 2. Do I actually need this?

- Will it change something for me or my users in a concrete, measurable way?
- If the answer is “maybe” or “it would be nice” → **stop. Do not build.**
- Required answer format: “This solves [specific problem] for [specific person] by [specific mechanism].”

### 3. Is the cost to build less than the value generated?

- Estimate build cost: time + tokens + maintenance
- Estimate value: hours saved × frequency + risk reduced
- If cost > value → **do not build**
- If cost < value → proceed to question 4

### 4. Has anyone validated interest before you started?

- “I think people want this” is not validation
- Validation = at least one person said “I would use/pay for this”
- If no validation → **get validation first, then build**
- If you cannot get validation → document why, then decide

### 5. Are you building something no one else has built?

- If YES → build it, own it, publish it proudly
- If NO → improve what exists, give credit, add your layer
- Do not present a copy as an original

---

## Build Security Rules (ALFA mandatory)

These apply to every build, without exception:

```
RULE 1: Trust no one. Verify every input, every dependency, every assumption.
RULE 2: Check the system twice. One review is not enough.
RULE 3: Stress test without mercy. Find your own weaknesses before others do.
RULE 4: Think like an attacker. Before submitting, ask: how would I damage this?
RULE 5: Scan frequently. OWASP + SAST + secrets + dependency — not once, continuously.
RULE 6: Every output through Cerber. No exceptions. No direct Brain writes.
```

---

## Anti-Patterns (NEVER do these)

| Anti-Pattern | Consequence |
|---|---|
| Build first, validate later | Wasted effort, DESTROY verdict likely |
| Copy without improvement | REJECT_PATTERN: plagiarism_without_value |
| Claim originality for existing work | trust_score penalty |
| Skip the adversarial self-test | Undetected vulnerability |
| Boast before the build is proven | Credibility loss |
| Take a shortcut without justification | DRIFT_DETECTED, trust_score penalty |

---

## Decision Tree

```
Has this been built before and works?
        │
       YES ──▶ Take it. Improve it. Publish the improvement.
        │
        NO
        │
        ▼
Do I actually need this?
        │
        NO ──▶ STOP. Do not build.
        │
       YES
        │
        ▼
Is cost < value?
        │
        NO ──▶ STOP. Document why. Revisit later.
        │
       YES
        │
        ▼
Is there validated demand?
        │
        NO ──▶ Validate first. Then return here.
        │
       YES
        │
        ▼
Is this something no one else has built?
        │
       YES ──▶ BUILD. Own it. Stress test. Scan. Publish when proven.
        │
        NO ──▶ Take the best version. Add your layer. Publish the delta.
```

---

## Cerber Integration

When applying this skill, Cerber expects:

```json
{
  "principle_check": {
    "already_exists": false,
    "need_confirmed": true,
    "cost_benefit_positive": true,
    "demand_validated": true,
    "novel_contribution": true,
    "adversarial_self_test_run": true,
    "scan_status": "CLEAN"
  },
  "verdict": "APPROVED_TO_BUILD"
}
```

If any field is `false` → verdict is `HOLD_PENDING_VALIDATION`.

---

## Summary

| Principle | Rule |
|---|---|
| Uniqueness | Only build what does not exist or is broken |
| Efficiency | Never waste tokens on known solutions |
| Validation | Demand proof of need before first commit |
| Security | Scan, stress test, think adversarially — always |
| Honesty | Do not boast until the build is proven and unique |
