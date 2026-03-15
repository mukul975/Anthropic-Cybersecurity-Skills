# Workflows - Building Detection Rules with Splunk SPL

## Detection Rule Development Workflow

```
1. Identify Threat Scenario
   |
   v
2. Map to MITRE ATT&CK Technique
   |
   v
3. Identify Required Data Sources
   |
   v
4. Validate Data Availability in Splunk
   |
   v
5. Write Base SPL Query
   |
   v
6. Add Aggregation and Filtering
   |
   v
7. Add Enrichment (Lookups, Threat Intel)
   |
   v
8. Test Against Historical Data
   |
   v
9. Calculate False Positive Rate
   |
   v
10. Deploy as Correlation Search
    |
    v
11. Monitor Detection Metrics
    |
    v
12. Tune and Iterate
```

## Rule Testing Workflow

### Phase 1: Development
- Write SPL query in Search & Reporting
- Test with `earliest=-7d latest=now()`
- Verify expected events are captured

### Phase 2: Validation
- Run Atomic Red Team tests to generate known-bad events
- Confirm detection triggers on simulated attacks
- Check no duplicate or redundant notable events generated

### Phase 3: Tuning
- Identify false positives from 7-day burn-in period
- Add exclusions for known benign activity
- Adjust thresholds based on environment baseline

### Phase 4: Production
- Schedule as correlation search in ES
- Configure adaptive response actions
- Set notable event severity and urgency mapping

## Correlation Search Scheduling Guide

| Rule Severity | Schedule Interval | Time Window |
|---|---|---|
| Critical | Every 5 minutes | 10 minutes |
| High | Every 15 minutes | 20 minutes |
| Medium | Every 30 minutes | 35 minutes |
| Low | Every 60 minutes | 65 minutes |
| Informational | Every 4 hours | 4.5 hours |

Note: Time window should slightly exceed schedule interval to prevent event gaps.

## Alert Output Workflow

```
Correlation Search Fires
    |
    v
Notable Event Created in ES
    |
    v
SOC Analyst Reviews in Incident Review Dashboard
    |
    v
Analyst Triages: True Positive / False Positive / Needs Investigation
    |
    v
True Positive --> Create Investigation --> Escalate if needed
False Positive --> Document exclusion --> Update correlation search
```
