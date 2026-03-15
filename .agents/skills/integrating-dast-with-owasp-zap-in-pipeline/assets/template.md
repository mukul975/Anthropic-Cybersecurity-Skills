# DAST with OWASP ZAP Templates

## ZAP Rules File

```tsv
# .zap/rules.tsv
# Rule ID	Action	Description
10003	IGNORE	# Vulnerable JS Library (handled by SCA tools)
10015	WARN	# Incomplete Cache-control Header
10020	WARN	# X-Frame-Options Header Not Set
10021	FAIL	# X-Content-Type-Options Missing
10035	FAIL	# Strict-Transport-Security Missing
10038	FAIL	# Content Security Policy Missing
10098	IGNORE	# Cross-Domain Misconfiguration (CDN expected)
40012	FAIL	# XSS Reflected
40014	FAIL	# XSS Persistent
40018	FAIL	# SQL Injection
40019	FAIL	# SQL Injection (MySQL)
40024	FAIL	# SQL Injection (PostgreSQL)
40032	WARN	# .htaccess Info Leak
90033	WARN	# Loosely Scoped Cookie
```

## GitHub Actions: Complete DAST Pipeline

```yaml
# .github/workflows/dast.yml
name: DAST Pipeline

on:
  workflow_run:
    workflows: ["Deploy to Staging"]
    types: [completed]

jobs:
  zap-scan:
    runs-on: ubuntu-latest
    if: ${{ github.event.workflow_run.conclusion == 'success' }}
    steps:
      - uses: actions/checkout@v4

      - name: Wait for staging
        run: |
          for i in $(seq 1 30); do
            if curl -sf https://staging.example.com/health; then break; fi
            sleep 10
          done

      - name: ZAP Baseline Scan
        uses: zaproxy/action-baseline@v0.12.0
        with:
          target: 'https://staging.example.com'
          rules_file_name: '.zap/rules.tsv'

      - name: ZAP API Scan
        uses: zaproxy/action-api-scan@v0.12.0
        with:
          target: 'https://staging.example.com/api/v1/openapi.json'
          format: openapi
          rules_file_name: '.zap/rules.tsv'

      - name: Upload Reports
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: dast-reports
          path: report_*.html
```

## Docker Compose for Local DAST Testing

```yaml
# docker-compose.dast.yml
services:
  app:
    build: .
    ports: ["8080:8080"]
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 5s
      retries: 10

  zap:
    image: zaproxy/zap-stable:latest
    depends_on:
      app:
        condition: service_healthy
    volumes:
      - ./zap-reports:/zap/wrk
      - ./.zap/rules.tsv:/zap/wrk/rules.tsv
    command: >
      zap-baseline.py
        -t http://app:8080
        -r /zap/wrk/report.html
        -J /zap/wrk/report.json
        -c /zap/wrk/rules.tsv
        -I
```
