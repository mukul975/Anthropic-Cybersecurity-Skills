# ALFA Brain Continuous Skill Evolution v1.0

## Purpose

This document extends the ALFA Execution Security Protocol with a continuous learning layer.

ALFA Brain must not only store task history. It must divide every completed action into successes and failures, generate skill renewal reports, and prevent agents from rebuilding existing work from zero when a similar project already exists.

The objective is simple:

```text
Do not repeat mistakes.
Do not rewrite solved projects.
Convert every action into operational memory.
```

---

## Core Principle

After every completed action, ALFA Brain performs post-execution analysis.

The result is divided into two memory streams:

```text
SUCCESS MEMORY
FAILURE MEMORY
```

Both streams are used to regenerate and improve ALFA skills.

---

## Phase 14 — Success and Failure Split

After each completed task, ALFA Brain separates the result into two datasets.

### Success Memory

Stores:

- successful checkpoints,
- working code patterns,
- correct agent decisions,
- effective prompts,
- clean execution paths,
- successful Cerber decisions,
- useful Lasuch detections,
- Guardian confirmations,
- reusable project structures.

Storage target:

```text
ALFA_BRAIN/SUCCESS/
```

### Failure Memory

Stores:

- failed checkpoints,
- wrong assumptions,
- hallucinated files,
- bad imports,
- wrong working directories,
- ignored instructions,
- repeated agent mistakes,
- failed scans,
- Cerber HOLD/BLOCK decisions,
- Guardian alerts,
- rollback events.

Storage target:

```text
ALFA_BRAIN/FAILURE/
```

---

## Phase 15 — Post-Action Skill Renewal Report

After every completed action, ALFA Brain generates a Skill Renewal Report.

The report contains:

- task name,
- project name,
- agent list,
- checkpoints completed,
- success patterns,
- failure patterns,
- mistakes to avoid,
- reusable code,
- reusable architecture,
- new Cerber rules,
- new Lasuch detections,
- new Guardian watch conditions,
- recommended skill update.

Report format:

```json
{
  "task": "...",
  "project": "...",
  "status": "SUCCESS|PARTIAL|FAILURE",
  "successes": [],
  "failures": [],
  "reusable_assets": [],
  "new_rules": [],
  "skill_update_required": true,
  "recommended_skill_patch": "..."
}
```

---

## Phase 16 — ALFA Cloud Skill Renewal

The Skill Renewal Report is sent to ALFA Cloud.

ALFA Cloud uses the report to renew ALFA skills.

Generated updates may include:

- new anti-drift rules,
- new Cerber validation rules,
- new Lasuch scouting rules,
- new Guardian alert rules,
- new project templates,
- new code reuse instructions,
- new failure-prevention checklists,
- new success-pattern templates.

Goal:

```text
Every completed action improves the next action.
```

---

## Phase 17 — Mistake Prevention Skill

If a mistake appears more than once, ALFA Cloud creates or updates a prevention rule.

Example:

```text
Failure: agent executed script from wrong directory
Frequency: 4
Skill update: before running any script, verify current working directory and project root
Cerber rule: HOLD if cwd does not match expected project root
```

The updated skill is then injected into future agent execution context.

---

## Phase 18 — Project Reuse Routing

Before starting a new project, ALFA Brain checks whether a similar project already exists.

Search criteria:

- project name similarity,
- task description similarity,
- architecture similarity,
- code structure similarity,
- dependency similarity,
- previous checkpoint map,
- reusable module match.

If match is found:

```text
DO NOT REBUILD FROM ZERO
ROUTE TO ALFA BRAIN PROJECT COPY
REUSE EXISTING CODE
IMPROVE INSTEAD OF REWRITE
```

The agent receives:

- previous source code,
- previous architecture,
- previous documentation,
- previous failure list,
- previous success list,
- previous checkpoint plan,
- previous Cerber decisions.

---

## Phase 19 — Project Copy Memory

ALFA Brain stores project copies for reuse.

Each project copy contains:

```text
project_id
project_name
purpose
stack
architecture
source_code_snapshot
docs_snapshot
checkpoint_map
success_patterns
failure_patterns
reusable_modules
last_known_good_state
```

When a repeated or similar project appears, ALFA Brain points the agent to the existing project copy.

This prevents:

- rewriting code from scratch,
- repeating old mistakes,
- losing architecture decisions,
- wasting agent tokens,
- creating inconsistent duplicate systems.

---

## Phase 20 — Skill Patch Generation

After analysis, ALFA Cloud generates a skill patch.

Skill patch format:

```markdown
# ALFA Skill Patch

## New Rule
...

## Mistake Prevented
...

## Success Pattern Added
...

## Reusable Workflow
...

## Cerber Update
...

## Lasuch Update
...

## Guardian Update
...
```

The patch is reviewed by Cerber before becoming active.

No skill update may activate without review.

---

## Phase 21 — Operational Memory Loop

The complete loop:

```text
Action completed
↓
ALFA Brain separates success and failure
↓
Skill Renewal Report generated
↓
Report sent to ALFA Cloud
↓
Skill patch generated
↓
Cerber reviews patch
↓
ALFA Brain stores updated rule
↓
Future agents use improved skill
```

---

## Final Rule

ALFA does not only execute.

ALFA learns from execution.

Successes become reusable patterns.
Failures become prevention rules.
Repeated projects become memory routes.
Skills are renewed after every completed action.

The system gets stronger because it remembers what worked and what failed.
