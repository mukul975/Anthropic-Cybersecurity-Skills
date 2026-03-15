# Standards and References - Alert Triage with Elastic SIEM

## Elastic Common Schema (ECS)

ECS is a standardized field naming convention for Elasticsearch data. All Elastic Security detections and triage workflows rely on ECS compliance.

### Key ECS Field Categories for Triage

| Category | Fields | Usage |
|---|---|---|
| Base | `@timestamp`, `message`, `tags` | Event timing and classification |
| Agent | `agent.name`, `agent.type` | Data source identification |
| Host | `host.name`, `host.ip`, `host.os` | Affected system context |
| User | `user.name`, `user.domain` | Identity attribution |
| Process | `process.name`, `process.pid`, `process.command_line` | Execution context |
| Network | `source.ip`, `destination.ip`, `destination.port` | Network activity |
| File | `file.name`, `file.hash.sha256`, `file.path` | File-related events |
| Threat | `threat.tactic.name`, `threat.technique.id` | MITRE ATT&CK mapping |

## MITRE ATT&CK Integration

Elastic Security maps detection rules and alerts to MITRE ATT&CK tactics and techniques, providing a common taxonomy for triage prioritization.

## NIST SP 800-61 Rev 2

Triage aligns with NIST incident handling phases:
- Detection and Analysis (triage is the core of this phase)
- Prioritization based on functional impact, information impact, and recoverability

## SOC Maturity Model

### Triage Capability Levels

| Level | Capability |
|---|---|
| Level 1 | Manual review of individual alerts |
| Level 2 | Grouped alert triage with correlation |
| Level 3 | AI-assisted triage with automated enrichment |
| Level 4 | Automated classification with human oversight |
| Level 5 | Fully autonomous triage with exception-based review |
