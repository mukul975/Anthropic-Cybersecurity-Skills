# Splunk SPL Detection Rule Template

## Rule Metadata

| Field | Value |
|---|---|
| Rule Name | |
| Rule ID | |
| Description | |
| Author | |
| Date Created | |
| Last Modified | |
| Severity | |
| MITRE ATT&CK | |
| Data Sources | |
| Status | Draft / Testing / Production / Retired |

## SPL Query

```spl
| tstats summariesonly=true count
    from datamodel=<DataModel>
    where <conditions>
    by <fields>, _time span=<interval>
| rename "<DataModel>.*" as *
| stats <aggregation> by <grouping_fields>
| where <threshold_condition>
| lookup asset_lookup ip as src OUTPUT asset_name, asset_priority
| lookup identity_lookup identity as user OUTPUT department, manager
| eval severity=case(<critical_condition>, "critical", <high_condition>, "high", true(), "medium")
| eval description="<dynamic description string>"
| eval mitre_technique="<T-number>"
```

## Detection Logic

### What This Rule Detects
<!-- Describe the adversary behavior being detected -->

### Data Sources Required
<!-- List all required data sources and their sourcetypes -->

| Source | Sourcetype | Index | Required Fields |
|---|---|---|---|
| | | | |

### Threshold Justification
<!-- Explain why the threshold values were chosen -->

### Enrichment Details
<!-- List lookups and threat intel sources used -->

## Testing Plan

### True Positive Test
<!-- Describe how to simulate the attack to validate detection -->

```
Step 1:
Step 2:
Step 3:
Expected Result:
```

### False Positive Analysis
<!-- Document known benign scenarios that trigger this rule -->

| Scenario | Source | Mitigation |
|---|---|---|
| | | |

## Tuning History

| Date | Change | Reason | Impact |
|---|---|---|---|
| | | | |

## Correlation Search Configuration

```
Schedule: */15 * * * *
Time Window: earliest=-20m latest=now
Suppress: 1h by src_ip
Notable Event Security Domain: threat
Adaptive Response: <actions>
```

## Analyst Guidance

### Triage Steps
1.
2.
3.

### Escalation Criteria
-

### Related Rules
-
