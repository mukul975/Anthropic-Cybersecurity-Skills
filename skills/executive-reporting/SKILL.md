---
name: executive-reporting
description: >
  Generate board-level and regulatory reporting on security posture. Use for quarterly board updates, audit committee
  reports, and regulatory submissions.
domain: cybersecurity
subdomain: compliance-governance
tags: [board-reporting, regulatory-reporting, executive-communication, metrics]
version: "1.0"
author: HRD-Security
license: Apache-2.0
---

# Executive Reporting Skill

Generate executive and regulatory security reports.

## Report Types

### Quarterly Board Security Update

**Audience**: Board of Directors **Frequency**: Quarterly **Length**: 1-2 pages + appendix

#### Structure

1. **Executive Summary**
   - Overall security posture (Green/Yellow/Red)
   - Key changes since last quarter
   - Material incidents (if any)

2. **Risk Dashboard**
   - Top 5 risks with trend indicators
   - New/emerging risks
   - Closed/mitigated risks

3. **Compliance Status**
   - Framework compliance percentages
   - Upcoming audits
   - Certification status (ISO, SOC 2, PCI)

4. **Incidents Summary**
   - Count by severity
   - Business impact
   - Lessons learned

5. **Investment Summary**
   - Budget utilization (YTD)
   - Key initiatives progress
   - Upcoming investment needs

6. **Peer Comparison**
   - Industry benchmark positioning
   - Competitive landscape insights

### Audit Committee Report

**Audience**: Audit Committee **Frequency**: Quarterly **Length**: 3-5 pages

#### Structure

1. **Control Environment Assessment**
   - Overall effectiveness rating
   - Changes to control environment
   - Key control testing results

2. **Internal Audit Findings**
   - Open findings by severity
   - New findings this quarter
   - Closed findings

3. **External Audit Status**
   - Current audit activities
   - Preliminary findings
   - Timeline to completion

4. **Remediation Tracking**
   - Open items aging
   - Past due items
   - Remediation velocity

5. **Policy Updates**
   - New/revised policies
   - Upcoming policy reviews
   - Policy exceptions

6. **Regulatory Changes**
   - New requirements
   - Impact assessment
   - Implementation status

## Metrics Framework

### Security Posture Metrics

| Metric                       | Green    | Yellow     | Red      |
| ---------------------------- | -------- | ---------- | -------- |
| Critical vulnerabilities     | 0        | 1-3        | >3       |
| High vulnerabilities (aging) | <30 days | 30-60 days | >60 days |
| MTTD (hours)                 | <4       | 4-24       | >24      |
| MTTR (hours)                 | <24      | 24-72      | >72      |
| Patch compliance             | >95%     | 85-95%     | <85%     |
| MFA adoption                 | >99%     | 95-99%     | <95%     |
| Security training completion | >95%     | 85-95%     | <85%     |

### Compliance Metrics

| Framework | Target | Calculation                           |
| --------- | ------ | ------------------------------------- |
| ISO 27001 | 100%   | Controls implemented / Total controls |
| SOC 2     | 100%   | Criteria met / Total criteria         |
| PCI DSS   | 100%   | Requirements met / Total requirements |

### Trend Indicators

- Improving (better than last period)
- Stable (same as last period)
- Declining (worse than last period)

## Tone and Style

- Factual, balanced, forward-looking
- Acknowledge challenges while demonstrating progress
- Avoid technical jargon
- Quantify impact in business terms
- Provide context for any concerning metrics
- Include competitive context where relevant

## Report Templates

### Board Update Template

```markdown
# Quarterly Security Update

## Q[X] [Year]

### Security Posture: [GREEN/YELLOW/RED]

**Key Highlights:**

- [Highlight 1]
- [Highlight 2]
- [Highlight 3]

### Risk Dashboard

| Risk     | Trend | Status                             |
| -------- | ----- | ---------------------------------- |
| [Risk 1] | [...] | [Mitigating/Monitoring/Escalating] |

### Compliance Status

| Framework | Status | Next Audit |
| --------- | ------ | ---------- |
| ISO 27001 | [X]%   | [Date]     |
| SOC 2     | [X]%   | [Date]     |
| PCI DSS   | [X]%   | [Date]     |

### Incidents (Q[X])

- **Total**: [X]
- **Material**: [X]
- **MTTD**: [X] hours
- **MTTR**: [X] hours

### Investment Summary

- **YTD Spend**: $[X] of $[Y] budget
- **Key Initiative**: [Name] - [Status]

### Looking Ahead

- [Initiative 1]
- [Initiative 2]
```
