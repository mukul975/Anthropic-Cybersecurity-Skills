# EPSS Vulnerability Prioritization Policy Template

## Priority Matrix

| Priority | EPSS Threshold | CVSS Range | KEV Status | Remediation SLA |
|----------|---------------|-----------|------------|-----------------|
| P0 - Immediate | > 0.70 | >= 9.0 | Any | 24 hours |
| P0 - Immediate | Any | Any | In KEV + Critical CVSS | 24 hours |
| P1 - Urgent | > 0.70 | >= 7.0 | Any | 48 hours |
| P1 - Urgent | Any | Any | In KEV | 48 hours |
| P2 - High | > 0.40 | >= 7.0 | Not in KEV | 7 days |
| P3 - Medium | > 0.10 | >= 4.0 | Not in KEV | 30 days |
| P3 - Medium | <= 0.10 | >= 7.0 | Not in KEV | 30 days |
| P4 - Low | <= 0.10 | < 7.0 | Not in KEV | 90 days |

## Daily EPSS Enrichment Schedule

```
# crontab entry for daily EPSS enrichment
0 6 * * * /opt/vuln-mgmt/scripts/process.py --input /data/open_vulns.csv --output /data/prioritized.csv --bulk
```

## Input CSV Format

```csv
cve_id,host,port,cvss_score,severity,description
CVE-2024-3400,fw-01.corp.local,443,10.0,critical,PAN-OS command injection
CVE-2024-21887,vpn-01.corp.local,443,9.1,critical,Ivanti Connect Secure auth bypass
CVE-2023-44228,app-01.corp.local,8080,10.0,critical,Log4Shell RCE
```

## EPSS Score Interpretation Guide

| EPSS Range | Interpretation | Recommended Action |
|-----------|---------------|-------------------|
| 0.90 - 1.00 | Near certainty of exploitation | Immediate patching or isolation |
| 0.70 - 0.89 | Very high exploitation probability | Priority remediation queue |
| 0.40 - 0.69 | Significant exploitation risk | Accelerated remediation |
| 0.10 - 0.39 | Moderate exploitation probability | Standard remediation cycle |
| 0.01 - 0.09 | Low exploitation probability | Normal patch cycle |
| 0.00 - 0.009 | Negligible exploitation probability | Best-effort remediation |
