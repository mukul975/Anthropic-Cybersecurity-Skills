# Standards - False Positive Reduction in SIEM

## Detection Quality Metrics (Industry Standards)

| Metric | Excellent | Good | Needs Improvement | Critical |
|---|---|---|---|---|
| False Positive Rate | < 10% | 10-20% | 20-40% | > 40% |
| Rule Precision | > 0.90 | 0.80-0.90 | 0.60-0.80 | < 0.60 |
| Mean Triage Time | < 5 min | 5-10 min | 10-20 min | > 20 min |
| Alert-to-Incident Ratio | 1:5 | 1:10 | 1:20 | > 1:50 |

## Tuning Frameworks

### NIST Continuous Monitoring (SP 800-137)
- Requires regular assessment and adjustment of detection capabilities
- Defines metrics-based approach to monitoring effectiveness

### SANS Detection Maturity Model
- Level 1: Basic alerts with high FP rate
- Level 2: Tuned alerts with correlation
- Level 3: Behavioral analytics reducing noise
- Level 4: Automated tuning with ML feedback loops

## Allowlist Management Standards
- All exclusions require documented justification
- Expiry dates mandatory (90-day maximum default)
- Quarterly review of all active exclusions
- Approval from detection engineering lead required
