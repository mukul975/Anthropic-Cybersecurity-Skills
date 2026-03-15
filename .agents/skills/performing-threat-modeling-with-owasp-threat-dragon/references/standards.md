# Standards Reference for Threat Modeling

## OWASP Threat Modeling Process

1. **Decompose the application**: Create DFDs showing data flows, trust boundaries, entry points
2. **Determine and rank threats**: Apply STRIDE per element, rank by DREAD or risk matrix
3. **Determine countermeasures and mitigations**: Map threats to controls
4. **Review and validate**: Peer review the model, validate against architecture

## NIST SP 800-154: Guide to Data-Centric System Threat Modeling

- Identify data assets and their sensitivity levels
- Map data flows through system components
- Identify threat actors and attack vectors targeting data
- Assess risk based on data exposure and impact
- Document countermeasures protecting data at rest, in transit, and in use

## ISO 27005 Risk Assessment Alignment

| ISO 27005 Step | Threat Dragon Activity |
|----------------|----------------------|
| Context establishment | Define system scope and trust boundaries |
| Risk identification | STRIDE threat enumeration per DFD element |
| Risk analysis | Severity rating and likelihood assessment |
| Risk evaluation | Prioritize threats by risk score |
| Risk treatment | Define mitigations (mitigate, accept, transfer, avoid) |

## STRIDE-per-Element Mapping

| DFD Element | S | T | R | I | D | E |
|-------------|---|---|---|---|---|---|
| External Entity | x | | x | | | |
| Process | x | x | x | x | x | x |
| Data Store | | x | | x | x | |
| Data Flow | | x | | x | x | |

## Threat Severity Rating Scale

| Rating | Score | Description |
|--------|-------|-------------|
| Critical | 9-10 | Immediate exploitation possible, severe business impact |
| High | 7-8 | Likely exploitation, significant business impact |
| Medium | 4-6 | Possible exploitation, moderate business impact |
| Low | 1-3 | Unlikely exploitation or minimal impact |
