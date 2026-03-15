# Workflows - False Positive Reduction

## Tuning Cycle
```
Identify Noisy Rules --> Analyze FP Root Causes --> Tune Rules -->
Validate with Testing --> Measure Improvement --> Report --> Repeat
```

## FP Analysis Categorization
| Category | Action | Example |
|---|---|---|
| Known benign | Add to allowlist | Vulnerability scanner IPs |
| Threshold too low | Raise threshold | Login failure count from 5 to 20 |
| Missing context | Add correlation | PowerShell + network = suspicious |
| Missing enrichment | Add lookup | Asset criticality context |
| Rule outdated | Rewrite or retire | Legacy detection no longer relevant |
