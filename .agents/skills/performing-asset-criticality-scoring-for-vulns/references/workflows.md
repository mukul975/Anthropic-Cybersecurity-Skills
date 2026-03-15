# Workflows - Asset Criticality Scoring

## Workflow 1: Scoring Process
```
Identify Asset -> Gather Business Context -> Score Each Factor ->
Calculate Weighted Score -> Assign Tier -> Map to SLA Modifier ->
Store in CMDB -> Apply to Vulnerability Management
```

## Workflow 2: Quarterly Review
```
Quarter Start:
    1. Export current asset criticality ratings
    2. Identify changes (new systems, decommissioned, role changes)
    3. Rescore changed assets with business owners
    4. Update CMDB with new scores
    5. Recalculate vulnerability SLAs for affected assets
```
