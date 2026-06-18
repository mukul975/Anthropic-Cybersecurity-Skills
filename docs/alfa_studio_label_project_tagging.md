# ALFA Studio Label and Project Tagging Protocol v1.0

## Purpose

This document adds a Studio Label layer to ALFA Brain.

The goal is to classify every open-source tool, repository, project, skill, agent, workflow, and dependency with structured labels before it is trusted, reused, scanned, or executed.

Cerber must be able to check projects by labels, not only by raw file content.

---

## Core Principle

Every project receives labels before execution.

```text
PROJECT -> STUDIO LABEL -> ALFA BRAIN TAG INDEX -> CERBER TAG CHECK -> SCAN -> LASUCH -> AGENT RELEASE
```

No unlabeled project should be treated as safe.

---

## Phase 22 — Open-Source Tool Review

All open-source tools must be reviewed before integration.

Review targets:

- repository purpose,
- license,
- maintainers,
- dependency tree,
- scripts,
- binaries,
- network behavior,
- permission requirements,
- installation commands,
- known security issues,
- prompt or skill behavior if AI-related.

Each reviewed tool is stored in ALFA Brain with labels.

---

## Phase 23 — Studio Label Creation

ALFA Studio assigns labels to every project.

Label categories:

```text
DOMAIN
RISK
ROLE
STACK
DATA_ACCESS
NETWORK_ACCESS
EXECUTION_LEVEL
AGENT_COMPATIBILITY
REUSE_STATUS
TRUST_LEVEL
```

Example:

```json
{
  "project": "example-security-tool",
  "domain": ["security", "ioc", "scan"],
  "risk": ["medium"],
  "role": ["scanner"],
  "stack": ["python"],
  "data_access": ["files", "hashes"],
  "network_access": ["external_api"],
  "execution_level": ["local_script"],
  "agent_compatibility": ["cerber", "guardian"],
  "reuse_status": ["candidate"],
  "trust_level": ["unverified"]
}
```

---

## Phase 24 — ALFA Brain Tag Index

ALFA Brain maintains a searchable tag index.

Every stored project includes:

```text
project_id
project_name
source_url
local_path
labels
risk_score
scan_status
cerber_status
lasuch_status
guardian_status
last_reviewed_at
last_known_good_state
reuse_allowed
```

The tag index allows agents to find existing tools and avoid rebuilding known systems.

---

## Phase 25 — Cerber Tag Check

Before Cerber allows execution, it checks project labels.

Cerber verifies:

- whether the project is labeled,
- whether labels match the requested task,
- whether risk level is acceptable,
- whether the project has required scan status,
- whether the tool is allowed for this agent,
- whether reuse is allowed,
- whether the trust level is sufficient.

Cerber decisions by tag:

```text
trusted + scanned + matching role -> PASS
unverified + network access -> HOLD
unknown binary + high privilege -> BLOCK
missing labels -> HOLD
malicious label -> BLOCK
```

---

## Phase 26 — Label-Based Routing

If a task appears, ALFA Brain searches by labels.

Example:

```text
Task: scan URL reputation
Tags needed: security, ioc, url, external_api, low_risk
```

ALFA Brain returns tools matching those labels.

Cerber then chooses the safest matching tool.

This prevents agents from:

- inventing tools,
- reinstalling unsafe packages,
- rewriting solved modules,
- using wrong tools for the task,
- executing unreviewed repositories.

---

## Phase 27 — Label Trust Levels

Trust levels:

```text
UNKNOWN     -> not reviewed
UNVERIFIED  -> reviewed but not tested
TESTED      -> passed basic tests
TRUSTED     -> passed security and integration tests
LOCKED      -> approved production asset
BANNED      -> blocked from execution
```

Cerber rules:

```text
UNKNOWN    -> HOLD
UNVERIFIED -> HOLD unless sandboxed
TESTED     -> PASS for low-risk tasks
TRUSTED    -> PASS
LOCKED     -> PASS with priority reuse
BANNED     -> BLOCK
```

---

## Phase 28 — Studio Labels for Agent Memory

Every agent action receives labels too.

Example labels:

```text
ACTION: install_dependency
RISK: medium
TOOL: npm
NETWORK: yes
FILES_CHANGED: package.json, package-lock.json
CERBER: PASS
GUARDIAN: clean
```

This makes later failure analysis easier.

ALFA Brain can answer:

- which tool caused the failure,
- which label category was risky,
- which agent used it,
- which Cerber rule allowed it,
- whether the same pattern happened before.

---

## Phase 29 — Tag-Based Failure Learning

When a failure occurs, ALFA Brain attaches labels to the failure.

Example:

```json
{
  "failure_type": "unsafe_dependency",
  "labels": ["npm", "network_access", "unverified", "install_script"],
  "cerber_decision": "HOLD",
  "lesson": "Unverified packages with install scripts require sandbox scan before use."
}
```

Future Cerber decisions use these labels.

If a new project has the same risky tag pattern, Cerber raises risk automatically.

---

## Phase 30 — Open-Source Tool Inventory

ALFA Studio must maintain an inventory of reviewed open-source tools.

Inventory format:

```json
{
  "tool_name": "...",
  "repo_url": "...",
  "license": "...",
  "purpose": "...",
  "labels": [],
  "risk_score": 0,
  "trust_level": "UNKNOWN|UNVERIFIED|TESTED|TRUSTED|LOCKED|BANNED",
  "approved_for": [],
  "blocked_for": [],
  "notes": "..."
}
```

This inventory becomes a reusable tool catalog for ALFA agents.

---

## Final Rule

ALFA Brain remembers projects by labels.

Cerber checks by labels.

Agents reuse by labels.

Guardian monitors label-risk patterns.

Studio Label turns open-source chaos into structured operational memory.
