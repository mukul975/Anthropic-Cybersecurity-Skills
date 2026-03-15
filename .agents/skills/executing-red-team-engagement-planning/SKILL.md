---
name: executing-red-team-engagement-planning
description: Red team engagement planning is the foundational phase that defines scope, objectives, rules of engagement (ROE), threat model selection, and operational timelines before any offensive testing begins.
domain: cybersecurity
subdomain: red-teaming
tags: [red-team, adversary-simulation, mitre-attack, exploitation, post-exploitation, engagement-planning, rules-of-engagement]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Executing Red Team Engagement Planning

## Overview

Red team engagement planning is the foundational phase that defines scope, objectives, rules of engagement (ROE), threat model selection, and operational timelines before any offensive testing begins. A well-structured engagement plan ensures the red team simulates realistic adversary behavior while maintaining safety guardrails that prevent unintended business disruption.

## Objectives

- Define clear engagement scope including in-scope and out-of-scope assets, networks, and personnel
- Establish Rules of Engagement (ROE) with emergency stop procedures, communication channels, and legal boundaries
- Select appropriate threat profiles from the MITRE ATT&CK framework aligned to the organization's threat landscape
- Create a detailed attack plan mapping adversary TTPs to engagement objectives
- Develop deconfliction procedures with the organization's SOC/blue team
- Produce a comprehensive engagement brief for stakeholder approval

## Core Concepts

### Engagement Types

| Type | Description | Scope |
|------|-------------|-------|
| Full Scope | Complete adversary simulation with physical, social, and cyber vectors | Entire organization |
| Assumed Breach | Starts from initial foothold, focuses on post-exploitation | Internal network |
| Objective-Based | Target specific crown jewels (e.g., domain admin, PII exfiltration) | Defined targets |
| Purple Team | Collaborative with blue team for detection improvement | Specific controls |

### Rules of Engagement Components

1. **Scope Definition**: IP ranges, domains, physical locations, personnel
2. **Restrictions**: Systems/networks that must not be touched (e.g., production databases, medical devices)
3. **Communication Plan**: Primary and secondary contact channels, escalation procedures
4. **Emergency Procedures**: Code word for immediate cessation, incident response coordination
5. **Legal Authorization**: Signed authorization letters, get-out-of-jail letters for physical tests
6. **Data Handling**: How sensitive data discovered during testing will be handled and destroyed
7. **Timeline**: Start/end dates, blackout windows, reporting deadlines

### Threat Profile Selection

Map organizational threats using MITRE ATT&CK Navigator to select relevant adversary profiles:

- **APT29 (Cozy Bear)**: Government/defense sector targeting via spearphishing, supply chain
- **APT28 (Fancy Bear)**: Government organizations, credential harvesting, zero-days
- **FIN7**: Financial sector, POS malware, social engineering
- **Lazarus Group**: Financial institutions, cryptocurrency exchanges, destructive malware
- **Conti/Royal**: Ransomware operators, double extortion, RaaS model

## Implementation Steps

### Phase 1: Pre-Engagement

1. Conduct initial scoping meeting with stakeholders
2. Identify crown jewels and critical business assets
3. Review previous security assessments and audit findings
4. Define success criteria and engagement objectives
5. Draft Rules of Engagement document

### Phase 2: Threat Modeling

1. Identify relevant threat actors using MITRE ATT&CK
2. Map threat actor TTPs to organizational attack surface
3. Select primary and secondary attack scenarios
4. Define adversary emulation plan with specific technique IDs
5. Establish detection checkpoints for purple team opportunities

### Phase 3: Operational Planning

1. Set up secure communication channels (encrypted email, Signal, etc.)
2. Create operational security (OPSEC) guidelines for the red team
3. Establish infrastructure requirements (C2 servers, redirectors, phishing domains)
4. Develop phased attack timeline with go/no-go decision points
5. Create deconfliction matrix with SOC/IR team

### Phase 4: Documentation and Approval

1. Compile engagement plan document
2. Review with legal counsel
3. Obtain executive sponsor signature
4. Brief red team operators on ROE and restrictions
5. Distribute emergency contact cards

## Tools and Resources

- **MITRE ATT&CK Navigator**: Threat actor TTP mapping and visualization
- **VECTR**: Red team engagement tracking and metrics platform
- **Cobalt Strike / Nighthawk**: C2 framework planning and infrastructure design
- **PlexTrac**: Red team reporting and engagement management platform
- **SCYTHE**: Adversary emulation platform for attack plan creation

## Validation Criteria

- [ ] Signed Rules of Engagement document
- [ ] Defined scope with explicit in/out boundaries
- [ ] Selected threat profile with mapped MITRE ATT&CK techniques
- [ ] Emergency stop procedures tested and verified
- [ ] Communication plan distributed to all stakeholders
- [ ] Legal authorization obtained and filed
- [ ] Red team operators briefed and acknowledged ROE

## Common Pitfalls

1. **Scope Creep**: Expanding testing beyond approved boundaries during execution
2. **Inadequate Deconfliction**: SOC investigating red team activity as real incidents
3. **Missing Legal Authorization**: Testing without proper signed authorization
4. **Unrealistic Threat Models**: Simulating threats irrelevant to the organization
5. **Poor Communication**: Failing to maintain contact with stakeholders during engagement

## Related Skills

- performing-open-source-intelligence-gathering
- conducting-adversary-simulation-with-atomic-red-team
- performing-assumed-breach-red-team-exercise
- building-red-team-infrastructure-with-redirectors
