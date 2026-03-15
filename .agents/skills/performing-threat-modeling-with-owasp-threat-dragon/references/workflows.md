# Threat Modeling Workflows

## Workflow 1: Feature-Level Threat Modeling

```
Product team proposes new feature
       |
Security champion schedules threat modeling session
       |
Gather architecture docs, API specs, DFDs
       |
Workshop session (60-90 min):
  - Review DFD for new feature
  - Apply STRIDE to each element
  - Identify threats and rank by severity
  - Document mitigations needed
       |
Threats documented in Threat Dragon
       |
Mitigation tasks created in backlog
       |
Security acceptance criteria added to user stories
       |
Feature development includes mitigations
       |
Threat model updated during code review
```

## Workflow 2: Architecture Review Threat Model

```
New system or major refactor proposed
       |
Create Level 0 DFD (context diagram)
       |
Identify trust boundaries and data sensitivity
       |
Decompose into Level 1 DFDs per subsystem
       |
Apply STRIDE per element in each diagram
       |
Auto-generate threats using Threat Dragon rule engine
       |
Review and refine auto-generated threats
       |
Assign severity ratings
       |
Document existing controls as mitigations
       |
Identify gaps (open threats without mitigations)
       |
Generate PDF report for architecture review board
       |
Remediation plan approved and tracked
```

## Workflow 3: Continuous Threat Modeling in Agile

```
Sprint planning identifies security-relevant stories
       |
Pull existing threat model from version control
       |
Update DFD to reflect planned changes
       |
Quick STRIDE review (30 min) focused on changes
       |
New threats added, mitigations defined
       |
Threat model committed alongside code changes
       |
Sprint retrospective reviews threat model accuracy
       |
Quarterly full threat model review cycle
```
