---
name: purple-team
description: Hypothetical attack path composition with detection gap overlays. Composes threat models, MITRE ATT&CK coverage, SIEM detections, and cloud security findings into multi-step kill chains that reveal defensive blind spots.
domain: cybersecurity
subdomain: red-teaming
tags: [purple-team, attack-simulation, detection-gaps, kill-chain, mitre-attack]
version: "1.0"
author: HRD-Security
license: Apache-2.0
---

# Purple Team Skill

Conceptual purple teaming for enterprise platforms. Composes existing security data sources into **hypothetical multi-step attack paths** that reveal defensive blind spots. Output is strictly **evaluation-only** -- no live exploitation, no system actions, no exploit code.

> **EVALUATION ONLY**: This skill produces hypothetical attack scenarios based on documentation review and telemetry analysis. No live exploitation, no system actions, no exploit code.

## Core Expertise

- **Attack Path Composition**: Chain MITRE ATT&CK techniques into realistic multi-step kill chains
- **Detection Gap Analysis**: Overlay detection posture (DETECTED / GAP / PARTIAL) on each kill chain step
- **Blind Spot Identification**: Find sequences of consecutive undetected steps
- **Gaming-Specific Threat Scenarios**: ATO, payment fraud, bonus abuse, geolocation bypass, odds manipulation
- **Cross-Platform Correlation**: SIEM, CSPM, WAF, case management -- unified view
- **Risk Quantification**: 5x5 risk matrix with industry-specific impact categories
- **Defensive Recommendations**: ISO 27001 Annex A mapped, ZTMM aligned

## Methodology

### Phase 1: Reconnaissance (Documentation Review)

- Review existing threat models for target system
- Identify attack surface from architecture documentation
- Map data flows and trust boundaries
- Identify regulated components

### Phase 2: Threat Landscape Assessment

- Query threat intelligence for relevant actor profiles
- Map known TTPs to MITRE ATT&CK
- Identify industry-specific threat scenarios
- Prioritize by likelihood and business impact

### Phase 3: Kill Chain Composition

For each prioritized threat scenario, map the full kill chain:

1. **Initial Access**: How does the attacker get in?
2. **Execution**: What does the attacker run?
3. **Persistence**: How does the attacker maintain access?
4. **Privilege Escalation**: How does the attacker escalate?
5. **Lateral Movement**: How does the attacker spread?
6. **Collection/Exfiltration**: What is the attacker's objective?

### Phase 4: Detection Overlay

For each kill chain step:

| Step | Technique | Detection Source | Status   | Rule/Alert Name | Confidence |
| ---- | --------- | ---------------- | -------- | --------------- | ---------- |
| 1    | T1XXX     | Sentinel         | DETECTED | [Rule name]     | High       |
| 2    | T1YYY     | None             | GAP      | N/A             | N/A        |
| 3    | T1ZZZ     | Wiz              | PARTIAL  | [Control name]  | Medium     |

### Phase 5: Blind Spot Analysis

Identify:

- **Silent corridors**: 3+ consecutive GAP steps where an attacker progresses undetected
- **Detection islands**: Isolated detections surrounded by gaps
- **Single-source dependencies**: Steps detected by only one tool

### Phase 6: Report Generation

Output attack scenario report with:

1. Executive summary with risk rating
2. Kill chain diagram with detection overlay
3. Blind spot analysis
4. Prioritized remediation recommendations
5. Framework cross-references (ISO 27001, NIST CSF, MITRE ATT&CK)

## Gaming-Specific Threat Scenarios

| Scenario              | Kill Chain Focus                                       | Primary Impact        |
| --------------------- | ------------------------------------------------------ | --------------------- |
| Account Takeover      | Credential stuffing -> session hijack -> fund drain    | Player trust, revenue |
| Payment Fraud         | Card testing -> deposit fraud -> withdrawal abuse      | Financial, regulatory |
| Bonus Abuse           | Multi-account -> identity fraud -> bonus exploitation  | Revenue               |
| Geolocation Bypass    | VPN/proxy -> spoofed location -> illegal wagering      | Regulatory, license   |
| Odds Manipulation     | API abuse -> timing exploitation -> arbitrage          | Revenue, integrity    |
| Insider Threat        | Privileged access -> data exfiltration -> cover tracks | Data, regulatory      |

## Risk Quantification

Use 5x5 risk matrix:

| Impact Category | Score 1      | Score 3     | Score 5         |
| --------------- | ------------ | ----------- | --------------- |
| Revenue         | <$10K        | $10K-$500K  | >$500K          |
| Regulatory      | No impact    | Finding     | License risk    |
| Player Trust    | Not visible  | Limited     | Public incident |
| Operations      | No downtime  | Hours       | Days+           |
| Data            | No exposure  | Internal    | PII/PCI breach  |
