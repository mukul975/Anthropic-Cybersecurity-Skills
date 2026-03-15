# DefectDojo Configuration Template

## Product Hierarchy Setup

### Product Types (Business Units)
| Product Type | Description |
|-------------|------------|
| Web Applications | Customer-facing web applications |
| Mobile Applications | iOS and Android apps |
| Internal Tools | Employee-facing internal applications |
| Infrastructure | Network and cloud infrastructure |
| APIs | REST and GraphQL API services |

### Scanner Type Mappings
| Scanner | DefectDojo Scan Type | File Format |
|---------|---------------------|-------------|
| Nessus | Nessus Scan | .csv or .nessus |
| OWASP ZAP | ZAP Scan | .xml or .json |
| Burp Suite | Burp XML | .xml |
| Trivy | Trivy Scan | .json |
| Semgrep | Semgrep JSON Report | .json |
| Snyk | Snyk Scan | .json |
| SonarQube | SonarQube Scan | .json |
| Checkov | Checkov Scan | .json |
| Bandit | Bandit Scan | .json |
| OpenVAS | OpenVAS CSV | .csv |
| Qualys | Qualys Scan | .xml |

## SLA Configuration

| Severity | Days to Remediate |
|----------|------------------|
| Critical | 7 |
| High | 30 |
| Medium | 90 |
| Low | 120 |
| Info | No SLA |

## Jira Integration Settings

```
Jira URL: https://company.atlassian.net
Project Key: SEC
Issue Type: Bug
Priority Mapping:
  Critical -> Blocker
  High -> Critical
  Medium -> Major
  Low -> Minor
Auto-close: Yes (when finding is closed in DefectDojo)
```

## CI/CD Integration Snippet

```yaml
# Generic CI/CD step for DefectDojo upload
- name: Upload scan results to DefectDojo
  env:
    DD_URL: ${{ secrets.DEFECTDOJO_URL }}
    DD_API_KEY: ${{ secrets.DEFECTDOJO_API_KEY }}
  run: |
    curl -X POST "${DD_URL}/api/v2/reimport-scan/" \
      -H "Authorization: Token ${DD_API_KEY}" \
      -F "scan_type=${SCAN_TYPE}" \
      -F "file=@${SCAN_FILE}" \
      -F "product_name=${PRODUCT_NAME}" \
      -F "auto_create_context=true" \
      -F "close_old_findings=true"
```
