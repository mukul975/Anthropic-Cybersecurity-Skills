# ALFA Execution Security Protocol v1.0

## Purpose

This document defines the default execution safety procedure for ALFA agents, Cerber, Lasuch, Guardian, ALFA Brain, and external application or skill installation workflows.

The goal is simple: no agent, application, skill, repository, workflow, file, or automation is allowed to execute before passing controlled security checkpoints.

---

## Core Principle

Every action must pass through layered verification:

```text
SCAN -> LASUCH -> CERBER -> SECONDARY SCAN -> AGENT RELEASE -> GUARDIAN MONITORING -> ALFA BRAIN MEMORY UPDATE
```

No direct execution is allowed without a checkpoint.

---

## Phase 0 — Pre-Installation Scan

Before installing any application, package, model, agent, plugin, repository, skill, or workflow:

1. Run a static scan of all files.
2. Inspect dependencies, scripts, prompts, configs, and external calls.
3. Detect:
   - malicious files,
   - hidden skills,
   - prompt injection vectors,
   - privilege escalation attempts,
   - suspicious executables,
   - hidden network calls,
   - data exfiltration logic,
   - unsafe automation hooks.
4. If risk is detected, execution state becomes `HOLD`.
5. Cerber must approve before the workflow continues.

Default decision states:

```text
PASS  -> continue
HOLD  -> manual or higher-model review
BLOCK -> stop execution
```

---

## Phase 1 — Large Model Planning

A large reasoning model prepares the execution plan.

The plan must be divided into checkpoints.

Each checkpoint must include:

- objective,
- expected result,
- files touched,
- tools required,
- risk level,
- rollback strategy,
- validation method,
- Cerber decision requirement.

The full plan is injected into ALFA Brain before execution.

---

## Phase 2 — ALFA Brain Memory Registry

ALFA Brain maintains the live architecture memory of every operational component:

- every agent,
- every Cerber instance,
- every Lasuch instance,
- every Guardian instance,
- each recovery template,
- each checkpoint state,
- each active dependency.

For each component ALFA Brain stores:

```text
component_id
component_type
version
role
state
dependencies
last_known_good_state
backup_available
recovery_template
risk_score
```

---

## Phase 3 — Component Self-Recovery

If any component becomes damaged, corrupted, manipulated, unstable, or unresponsive:

1. Guardian reports the anomaly.
2. ALFA Brain checks the last known good state.
3. Cerber freezes execution.
4. Backup instance is loaded.
5. Recovery template rebuilds the damaged component.
6. New instance is validated by Lasuch and Cerber.
7. Execution resumes only after `PASS`.

Recovery rule:

```text
Damaged component must never self-certify recovery.
Recovery must be verified by a separate component.
```

---

## Phase 4 — Cerber Helper Scaling

Cerber receives helper instances when project complexity increases.

Rules:

- minimum: one Cerber per agent,
- high-risk task: one Cerber + one helper,
- large project: Cerber helpers may scale to match the number of active agents,
- each helper validates only a limited scope,
- final decision remains with the main Cerber instance.

Cerber helpers may duplicate when required by workload.

---

## Phase 5 — Per-Agent Protection Layer

Every agent receives its own Lasuch and Cerber protection pair.

```text
Agent_X
  -> Lasuch_X
  -> Cerber_X
  -> Guardian observation
  -> ALFA Brain state memory
```

No unprotected agent is allowed to execute.

---

## Phase 6 — Lasuch Forward Scout

Before an agent performs an action, Lasuch goes first.

Lasuch responsibilities:

- inspect prompt and context,
- detect prompt injection,
- detect narrative drift,
- inspect files and instructions,
- identify semantic traps,
- test if the path is safe,
- report to Cerber.

If Lasuch fails, the agent does not move.

---

## Phase 7 — Cerber Validation

Cerber observes Lasuch.

If Lasuch returns `PASS`, Cerber performs secondary validation:

1. check Lasuch output,
2. verify risk score,
3. request SCAN confirmation,
4. check checkpoint integrity,
5. approve or stop the agent.

Cerber decisions:

```text
PASS  -> release agent
HOLD  -> request review or additional scan
BLOCK -> stop execution and alert Guardian
```

---

## Phase 8 — Secondary SCAN Confirmation

After Lasuch passes and before the agent executes, SCAN runs again.

Purpose:

- confirm no new files appeared,
- confirm no dependency changed,
- confirm no injected instruction entered the context,
- confirm no external connection was added,
- confirm no agent memory was modified unexpectedly.

Only after SCAN returns clean may Cerber release the agent.

---

## Phase 9 — Agent Release

Agent execution is allowed only when all three gates pass:

```text
Lasuch PASS
Cerber PASS
SCAN PASS
```

Then the agent receives permission to execute the current checkpoint only.

The agent is not allowed to jump ahead to future checkpoints.

---

## Phase 10 — Guardian Monitoring

Guardian observes live execution.

Guardian tracks:

- tool misuse,
- unexpected file writes,
- abnormal network calls,
- context corruption,
- memory corruption,
- repeated failure loops,
- hallucinated files,
- unauthorized scope expansion,
- agent role drift.

If Guardian detects anomaly:

```text
HOLD -> CERBER REVIEW -> ALFA BRAIN STATE CHECK -> RECOVERY OR BLOCK
```

---

## Phase 11 — Checkpoint Control

Each checkpoint must be validated before the next begins.

Checkpoint validation requires:

- execution log,
- file diff,
- scan result,
- Cerber decision,
- Guardian observation,
- rollback snapshot.

If checkpoint fails:

```text
rollback to last valid checkpoint
freeze affected agent
restore from backup if required
log failure pattern
```

---

## Phase 12 — Failure Memory

Every failure is saved into ALFA Brain.

Failure entry format:

```json
{
  "task": "...",
  "checkpoint": "...",
  "agent": "...",
  "failure_type": "...",
  "evidence": "...",
  "cerber_decision": "PASS|HOLD|BLOCK",
  "fix_that_worked": "...",
  "lesson": "..."
}
```

Purpose:

- prevent repeated mistakes,
- train future supervisors,
- strengthen Cerber rules,
- improve Lasuch detection,
- preserve operational memory.

---

## Phase 13 — Final Audit

After task completion:

1. Guardian creates final report.
2. Cerber signs final state.
3. ALFA Brain stores lessons.
4. Checkpoint map is archived.
5. Failures and successes are separated into datasets.

Output datasets:

```text
success_patterns.jsonl
failure_patterns.jsonl
cerber_decisions.jsonl
lasuch_detections.jsonl
guardian_alerts.jsonl
```

---

## Operating Rule

Agents do not decide whether they are safe.

Lasuch scouts.
Cerber judges.
SCAN verifies.
Guardian watches.
ALFA Brain remembers.

Only then may an agent act.
