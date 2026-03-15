# Workflows - CVSS Vulnerability Prioritization

## Workflow 1: Vulnerability Scoring Pipeline

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│ Receive CVE /    │────>│ Look Up NVD      │────>│ Extract CVSS     │
│ Scan Results     │     │ Base Score       │     │ Vector String    │
└──────────────────┘     └──────────────────┘     └──────────────────┘
                                                          │
        ┌────────────────────────────────────────────────┘
        v
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│ Enrich with EPSS │────>│ Check CISA KEV   │────>│ Apply Env Metrics│
│ Threat Score     │     │ Catalog          │     │ (Asset Context)  │
└──────────────────┘     └──────────────────┘     └──────────────────┘
        │
        v
┌──────────────────┐     ┌──────────────────┐
│ Calculate Final  │────>│ Assign Priority  │
│ Risk Score       │     │ & SLA            │
└──────────────────┘     └──────────────────┘
```

## Workflow 2: Risk-Weighted Prioritization

```
For each vulnerability:
    1. base_score = NVD CVSS v4.0 base score (0-10)
    2. epss_score = FIRST EPSS probability (0-1)
    3. asset_score = CMDB criticality rating (1-5)
    4. exposure_score = Network exposure (1=internal, 3=DMZ, 5=internet)
    5. kev_bonus = 2.0 if in CISA KEV, else 0

    risk_score = (base_score * 0.25) +
                 (epss_score * 10 * 0.25) +
                 (asset_score * 2 * 0.20) +
                 (exposure_score * 2 * 0.15) +
                 kev_bonus * 0.15

    priority = map_to_sla(risk_score)
```

## Workflow 3: Continuous Re-Scoring

| Trigger | Action |
|---------|--------|
| New CVE published | Score with base metrics, schedule review |
| EPSS update (daily) | Refresh EPSS scores, re-prioritize |
| Exploit published | Update Exploit Maturity to POC or Attacked |
| Added to CISA KEV | Elevate priority to P1/P2 |
| Patch available | Add to remediation queue |
| Asset decommissioned | Close associated findings |
