---
name: bpm-plus-modeling
description: >
  Create and validate OMG BPM+ models (BPMN, DMN, CMMN) for security processes. Use when creating process models,
  decision models, or case management models for security operations and governance workflows.
domain: cybersecurity
subdomain: compliance-governance
tags: [bpmn, dmn, cmmn, process-modeling, business-process]
version: "1.0"
author: HRD-Security
license: Apache-2.0
---

# BPM+ Modeling Skill

Create and validate OMG BPM+ models (BPMN, DMN, CMMN) for security processes.

## Supported Model Types

### BPMN 2.0 (Business Process Model and Notation)

Process flow models for security operations such as incident response, change management,
and governance workflows.

- File format: `.bpmn` (XML)
- Visual export: `.svg` for documentation embedding

### DMN 1.3 (Decision Model and Notation)

Decision tables for security classifications, severity assessments, and access control logic.

- File format: `.dmn` (XML)
- Common uses: severity matrices, risk scoring, escalation decisions

### CMMN (Case Management Model and Notation)

Case-based models for non-linear security processes such as investigations and audits.

## Naming Conventions

| Type       | Pattern                      | Example                          |
| ---------- | ---------------------------- | -------------------------------- |
| BPMN (IR)  | `ir-[number]-[name].bpmn`   | `ir-001-account-compromise.bpmn` |
| BPMN (Gov) | `[process-name].bpmn`       | `policy-exception-request.bpmn`  |
| DMN        | `[playbook-id]-severity.dmn` | `ir-001-severity.dmn`            |
| SVG        | Same base name as source     | `ir-001-account-compromise.svg`  |

## Documentation Requirements

Each model must have:

1. Source XML file (version controlled)
2. Exported SVG (for markdown embedding)
3. Corresponding markdown documentation linking to the SVG

## Embedding Pattern

When embedding BPM+ diagrams in markdown:

```markdown
![Process Name](path/to/model.svg)

**Source**: [model.bpmn](path/to/model.bpmn)
```

## Validation Checklist

Before finalizing BPM+ models:

1. Validate XML syntax
2. Export SVG for visual review
3. Update corresponding documentation with embedded SVG
4. Ensure all paths reach end events (BPMN)
5. Verify hit policy is appropriate (DMN)
6. Cross-reference with related playbooks or procedures

## Common Security Process Models

- Incident response workflows
- Policy exception request processes
- Risk assessment decision tables
- Severity classification matrices
- Access control decision models
- Change management approval flows
- Audit and compliance workflows
