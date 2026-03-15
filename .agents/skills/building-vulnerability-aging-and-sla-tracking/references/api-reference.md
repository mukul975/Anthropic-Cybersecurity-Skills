# API Reference: Vulnerability Aging and SLA Tracking

## SLA Definitions
| Severity | Remediation SLA | Patch SLA | Exception Max |
|----------|----------------|-----------|---------------|
| Critical | 7 days | 15 days | 30 days |
| High | 30 days | 45 days | 90 days |
| Medium | 90 days | 120 days | 180 days |
| Low | 180 days | 365 days | 365 days |

## Aging Buckets
| Bucket | Range |
|--------|-------|
| New | 0-7 days |
| Recent | 8-30 days |
| Aging | 31-60 days |
| Old | 61-90 days |
| Stale | 91-180 days |
| Ancient | 181-365 days |
| Critical Overdue | 365+ days |

## Nessus API (Tenable.io)
```bash
# List vulnerabilities
curl -H "X-ApiKeys: accessKey=$ACCESS;secretKey=$SECRET" \
  "https://cloud.tenable.com/workbenches/vulnerabilities"

# Export vulns
curl -X POST -H "X-ApiKeys: accessKey=$ACCESS;secretKey=$SECRET" \
  "https://cloud.tenable.com/vulns/export" \
  -d '{"filters":{"severity":["critical","high"]}}'
```

## Qualys API
```bash
# Vulnerability list
curl -u "user:pass" -X POST \
  "https://qualysapi.qualys.com/api/2.0/fo/knowledge_base/vuln/" \
  -d "action=list&details=All&published_after=2024-01-01"
```

## Key Metrics
| Metric | Description |
|--------|------------|
| MTTR | Mean Time to Remediate |
| SLA Compliance % | Vulns resolved within SLA / Total |
| Overdue Count | Vulns past SLA deadline |
| Risk Score | CVSS * age_factor * asset_criticality |
