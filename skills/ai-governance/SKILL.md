---
name: ai-governance
description: >-
  AI/ML risk assessment and governance for regulated industries. Use when evaluating AI tools, creating AI policies, or
  assessing AI-related risks.
domain: cybersecurity
subdomain: compliance-governance
tags:
  - ai-governance
  - ai-risk
  - iso-42001
  - responsible-ai
  - machine-learning
version: "1.0"
author: HRD-Security
license: Apache-2.0
---

# AI Governance Skill

Assess and govern AI/ML systems for the organization.

## Formal Policy Authority

**AI Governance Policy** is the authoritative policy for AI governance at the organization. This skill provides
operational guidance aligned with organizational AI policy.

**ISO 42001 Compliance** documents AIMS alignment and applicability.

## Governance Framework

### AI Center of Excellence Risk Committee

- Security is a voting member
- Evaluates all AI tool adoptions
- Sets usage policies and restrictions
- Reviews AI-related incidents

### Policy Positions

#### Prohibited External AI Services

Per organizational AI policy and aligned with OFAC sanctions, the following external AI services are prohibited:

- External AI services that process data on infrastructure hosted in, or operated by entities legally controlled by,
  adversary jurisdictions (China, Russia, North Korea, Iran)
- AI services that train on customer data without explicit contractual consent
- AI services accessed via personal accounts (Shadow AI) — all access must be via enterprise SSO
- AI services without enterprise agreements and data protection commitments

#### Approved AI Tools

> **Authoritative source**: The service registry is the single source of truth for AI service authorization.

| Tool               | Status   | Use Case              | Restrictions           |
| ------------------ | -------- | --------------------- | ---------------------- |
| Claude (Anthropic) | Primary  | General AI assistance | No PII without review  |
| ChatGPT (OpenAI)   | Approved | General use           | No PII, no gaming data |
| GitHub Copilot     | Approved | Development           | Code only              |
| Cody               | Approved | Development           | Code only              |
| Amazon Bedrock     | Approved | Infrastructure        | Enterprise controls    |
| Ollama             | Approved | Local development     | No production data     |
| LM Studio          | Approved | Local development     | No production data     |

### Risk Assessment Framework

| Risk Category    | Assessment Criteria                            | Weight |
| ---------------- | ---------------------------------------------- | ------ |
| Data Privacy     | What data is processed? Where is it stored?    | High   |
| Data Sovereignty | Where are servers located? Which jurisdiction? | High   |
| Model Training   | Is company data used for training?             | High   |
| Output Control   | Can outputs be logged and audited?             | Medium |
| Bias/Fairness    | Are there industry-specific bias concerns?     | Medium |
| Availability     | What happens if the service is unavailable?    | Low    |
| Cost             | Total cost of ownership                        | Low    |

### Gaming-Specific AI Considerations

#### Responsible Gaming

- AI in player risk identification
- Problem gambling detection algorithms
- Self-exclusion enforcement
- Player protection algorithms
- Age verification systems

#### Fraud Detection

- AI for account takeover detection
- Bonus abuse identification
- Coordinated betting detection
- Money laundering indicators
- Synthetic identity detection

#### Odds and Wagering

- AI in odds calculation
- Risk management algorithms
- Market manipulation detection
- Arbitrage detection

#### Regulatory Implications

- AI decision transparency for regulators
- Audit trail requirements
- Explainability for player-impacting decisions
- GLI requirements for AI in gaming systems
- State-specific AI regulations

## Assessment Output

### AI Tool Risk Assessment

```markdown
## AI Tool Risk Assessment

### 1. Tool Overview

- **Tool Name**: [Name]
- **Vendor**: [Company]
- **Version**: [Version]
- **Assessment Date**: [Date]

### 2. Proposed Use Case

[Description of intended use]

### 3. Data Flow Analysis

- **Input Data**: [What data goes in]
- **Processing Location**: [Where is data processed]
- **Output Data**: [What comes out]
- **Data Retention**: [How long is data kept]
- **Training Usage**: [Is data used for training]

### 4. Risk Assessment

| Category         | Rating          | Notes   |
| ---------------- | --------------- | ------- |
| Data Privacy     | High/Medium/Low | [Notes] |
| Data Sovereignty | High/Medium/Low | [Notes] |
| Model Training   | High/Medium/Low | [Notes] |
| Output Control   | High/Medium/Low | [Notes] |
| Bias/Fairness    | High/Medium/Low | [Notes] |
| Availability     | High/Medium/Low | [Notes] |

**Overall Risk**: [High/Medium/Low]

### 5. Compliance Implications

- [ ] GDPR compliant
- [ ] SOC 2 controls in place
- [ ] Gaming regulatory approval needed
- [ ] DPA/BAA required

### 6. Recommendation

**Decision**: [Approve/Conditional/Deny]

**Conditions** (if applicable):

- [Condition 1]
- [Condition 2]

### 7. Review Schedule

- **Next Review**: [Date]
- **Trigger for Re-review**: [Conditions]
```

### AI Incident Review

```markdown
## AI Incident Review

### 1. Incident Description

- **Date**: [Date]
- **Severity**: [High/Medium/Low]
- **AI System**: [System name]

### 2. What Happened

[Detailed description]

### 3. AI Component Involved

- **Model/Tool**: [Name]
- **Function**: [What it was doing]
- **Failure Mode**: [How it failed]

### 4. Root Cause Analysis

[Analysis]

### 5. Impact Assessment

- **Business Impact**: [Description]
- **Data Impact**: [Was data exposed/corrupted]
- **Regulatory Impact**: [Notification required?]

### 6. Remediation Steps

- [ ] [Step 1]
- [ ] [Step 2]

### 7. Policy Updates Needed

[Recommended policy changes]
```

## AI Policy Enforcement

### Monitoring Requirements

- Log all AI tool usage
- Alert on unapproved tool access
- Periodic access review
- Usage pattern analysis

### Compliance Checks

- Quarterly AI tool inventory
- Annual vendor security review
- Regulatory change monitoring
- Policy effectiveness assessment
