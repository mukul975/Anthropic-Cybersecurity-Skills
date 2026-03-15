# API Reference: Implementing API Security Testing with 42Crunch

## 42Crunch API Security Audit

```bash
# Upload OpenAPI spec for audit
curl -X POST https://platform.42crunch.com/api/v2/apis \
  -H "X-API-KEY: $CRUNCH_KEY" \
  -F "specfile=@openapi.yaml"

# Get audit report
curl https://platform.42crunch.com/api/v2/apis/{api_id}/assessmentreport \
  -H "X-API-KEY: $CRUNCH_KEY"
```

## OWASP API Security Top 10 (2023)

| ID | Risk | Audit Check |
|----|------|-------------|
| API1 | Broken Object Level Auth | BOLA path patterns |
| API2 | Broken Authentication | Security schemes |
| API3 | Broken Object Property Auth | Mass assignment |
| API4 | Unrestricted Resource Consumption | Rate limits |
| API5 | Broken Function Level Auth | Admin endpoints |
| API8 | Security Misconfiguration | HTTP, CORS, headers |

## Security Score Deductions

| Issue | Deduction | Severity |
|-------|-----------|----------|
| No security schemes | -30 | CRITICAL |
| Security disabled on endpoint | -25 | CRITICAL |
| No global security | -20 | HIGH |
| HTTP server URL | -15 | HIGH |
| No input schema | -15 | HIGH |
| Mass assignment risk | -10 | MEDIUM |
| Unbounded string param | -5 | MEDIUM |

## CI/CD Integration (GitHub Actions)

```yaml
- uses: 42Crunch/api-security-audit-action@v3
  with:
    api-token: ${{ secrets.CRUNCH_TOKEN }}
    min-score: 70
```

### References

- 42Crunch Platform: https://42crunch.com/
- OWASP API Top 10: https://owasp.org/API-Security/
- 42Crunch GitHub Action: https://github.com/42Crunch/api-security-audit-action
