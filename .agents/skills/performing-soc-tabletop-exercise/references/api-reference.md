# API Reference: SOC Tabletop Exercise Agent

## Overview

Manages SOC tabletop exercise lifecycle: scenario generation from templates, participant tracking, inject delivery, response scoring, and after-action report generation.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| json | stdlib | Report serialization |
| datetime | stdlib | Exercise scheduling and IDs |

## Core Functions

### `create_exercise(scenario_type, participants, duration_hours=3)`
Creates a structured tabletop exercise from a scenario template.
- **Parameters**: `scenario_type` (str) - one of `ransomware`, `data_breach`, `supply_chain`; `participants` (list[dict]) - role/count pairs
- **Returns**: `dict` - full exercise object with phases and objectives

### `score_response(category, score)`
Scores participant response in a specific evaluation category.
- **Parameters**: `category` (str) - one of `detection_and_triage`, `containment_decision`, `communication`, `business_continuity`; `score` (int) - 0-100
- **Returns**: `dict` - category, score, rating, weight

### `calculate_overall_score(scores)`
Computes weighted average across all scored categories.
- **Parameters**: `scores` (list[dict]) - output from `score_response`
- **Returns**: `float` - overall score

### `generate_after_action_report(exercise, scores, gaps, strengths)`
Produces the formal after-action report document.
- **Parameters**: `exercise` (dict), `scores` (list), `gaps` (list[dict]), `strengths` (list[str])
- **Returns**: `dict` - AAR with scores, findings, and next exercise date

## Scenario Templates

| Template | Phases | Focus Areas |
|----------|--------|-------------|
| `ransomware` | 6 injects | Detection, containment, ransom decision, recovery |
| `data_breach` | 4 injects | DLP, insider threat, PII notification |
| `supply_chain` | 4 injects | Vendor compromise, lateral movement, credential reset |

## Scoring Criteria

| Category | Weight | Rating Thresholds |
|----------|--------|-------------------|
| detection_and_triage | 25% | >=85 Excellent, >=70 Good, >=55 Adequate |
| containment_decision | 25% | >=85 Excellent, >=70 Good, >=55 Adequate |
| communication | 25% | >=85 Excellent, >=70 Good, >=55 Adequate |
| business_continuity | 25% | >=85 Excellent, >=70 Good, >=55 Adequate |

## Output Schema

```json
{
  "exercise_id": "TTX-2026-Q1",
  "overall_score": "72/100 (Adequate)",
  "scores": {"detection_and_triage": "85/100 (Excellent)"},
  "gaps": [{"finding": "...", "risk": "High", "owner": "SOC Manager"}],
  "strengths": ["Ransomware indicators correctly identified"]
}
```
