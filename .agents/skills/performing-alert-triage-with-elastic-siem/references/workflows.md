# Workflows - Alert Triage with Elastic SIEM

## 5-Step Rapid Triage Framework

```
1. Alert Reception (30 seconds)
   - Review alert title, severity, risk score
   - Check MITRE ATT&CK mapping
   |
   v
2. Context Assessment (2 minutes)
   - Examine affected host and user
   - Check asset criticality
   - Review process tree for endpoint alerts
   |
   v
3. Intelligence Enrichment (2 minutes)
   - Check threat intelligence feeds
   - Query for related alerts (same source/user)
   - Search for known IOCs
   |
   v
4. Classification (1 minute)
   - True Positive / False Positive / Needs Investigation
   - Assign confidence level
   |
   v
5. Action (2 minutes)
   - Document findings in alert notes
   - Escalate or close with rationale
   - Create tuning task if false positive
```

## Alert Grouping Strategy

### Smart Grouping Criteria
- Time window: Group alerts within 15-minute windows
- Entity: Group by affected host or user
- Kill chain stage: Group by MITRE ATT&CK tactic
- Source: Group by originating IP or detection rule

### Group Triage Process
1. Sort alert groups by highest severity member
2. Triage group as single unit when correlated
3. Escalate entire group if attack chain detected
4. Close group if false positive pattern identified

## Shift-Based Triage Queue Management

| Queue Priority | Alert Criteria | Analyst Tier |
|---|---|---|
| Immediate | Critical severity, critical assets | Tier 2+ |
| High | High severity or multiple related alerts | Tier 1/2 |
| Standard | Medium severity, standard assets | Tier 1 |
| Low | Low/info severity, non-critical | Tier 1 (batch review) |
