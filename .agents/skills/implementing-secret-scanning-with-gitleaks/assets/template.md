# Gitleaks Secret Scanning Templates

## Pre-Commit Configuration

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.21.2
    hooks:
      - id: gitleaks
        name: Detect secrets with Gitleaks
        entry: gitleaks protect --staged --verbose --redact
        language: golang
        pass_filenames: false
```

## Organization Gitleaks Configuration

```toml
# .gitleaks.toml
title = "Organization Secret Scanning Rules"

[extend]
useDefault = true

# ─── Custom Rules ───

[[rules]]
id = "internal-service-token"
description = "Internal service-to-service authentication token"
regex = '''(?i)(service[_-]?token|internal[_-]?key)["\s:=]+["']?([A-Za-z0-9_\-]{36,})["']?'''
entropy = 3.5
keywords = ["service_token", "service-token", "internal_key", "internal-key"]

[[rules]]
id = "database-url-with-password"
description = "Database connection URL with embedded password"
regex = '''(?i)(DATABASE_URL|DB_URL|SQLALCHEMY_DATABASE_URI)\s*=\s*["']?(postgres|mysql|mongodb)\+?[a-z]*://[^:]+:[^@]+@'''
keywords = ["DATABASE_URL", "DB_URL", "SQLALCHEMY_DATABASE_URI"]

[[rules]]
id = "encryption-key-hex"
description = "Encryption key in hexadecimal format"
regex = '''(?i)(encryption[_-]?key|aes[_-]?key|secret[_-]?key)\s*=\s*["']?([0-9a-fA-F]{32,64})["']?'''
entropy = 3.0
keywords = ["encryption_key", "aes_key", "secret_key"]

# ─── Allowlist ───

[allowlist]
description = "Global allowlist for false positive reduction"
paths = [
  '''(^|/)test(s)?/''',
  '''(^|/)spec(s)?/''',
  '''\.test\.(js|ts|py|go|rb)$''',
  '''\.spec\.(js|ts|py|go|rb)$''',
  '''(^|/)__tests__/''',
  '''(^|/)__mocks__/''',
  '''(^|/)fixtures/''',
  '''(^|/)testdata/''',
  '''(^|/)vendor/''',
  '''(^|/)node_modules/''',
  '''\.md$''',
  '''CHANGELOG'''
]
regexes = [
  '''(?i)EXAMPLE''',
  '''(?i)PLACEHOLDER''',
  '''(?i)CHANGEME''',
  '''(?i)your[-_]?(api[-_]?key|secret|token|password)''',
  '''(?i)test[-_]?(key|secret|token|password|credential)''',
  '''example\.com''',
  '''localhost''',
  '''0{8,}''',
  '''x{8,}'''
]

# Per-rule allowlists
[[rules.allowlist]]
description = "Allow AWS example keys"
regexes = ["AKIAIOSFODNN7EXAMPLE"]
```

## GitHub Actions Workflow

```yaml
# .github/workflows/secret-scanning.yml
name: Secret Scanning

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 6 * * *'

jobs:
  gitleaks:
    name: Gitleaks
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Install Gitleaks
        run: |
          GITLEAKS_VERSION="8.21.2"
          wget -qO- "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" | tar xz
          sudo mv gitleaks /usr/local/bin/

      - name: Run scan
        run: |
          if [ "${{ github.event_name }}" == "pull_request" ]; then
            gitleaks detect \
              --source . \
              --log-opts="${{ github.event.pull_request.base.sha }}..${{ github.sha }}" \
              --report-format sarif \
              --report-path gitleaks.sarif \
              --exit-code 1 \
              --verbose
          else
            gitleaks detect \
              --source . \
              --baseline-path .gitleaks-baseline.json \
              --report-format sarif \
              --report-path gitleaks.sarif \
              --exit-code 1 \
              --verbose
          fi

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: gitleaks.sarif
          category: gitleaks
```

## Incident Response Template for Exposed Secrets

```markdown
## Secret Exposure Incident Report

**Date Detected**: YYYY-MM-DD
**Detected By**: Gitleaks CI scan / Pre-commit hook / Manual review
**Repository**: org/repo-name
**Severity**: Critical / High

### Exposed Credential Details
- **Type**: [AWS Access Key | GitHub PAT | Database Password | etc.]
- **Rule ID**: [gitleaks rule that detected it]
- **File**: [path/to/file:line]
- **Commit**: [short SHA]
- **Author**: [email]
- **Date Committed**: [date]
- **Exposure Duration**: [time from commit to detection]

### Remediation Actions
- [ ] Credential revoked at service provider
- [ ] New credential generated and stored in secrets manager
- [ ] Consuming services updated to use new credential
- [ ] Service functionality verified
- [ ] Git history cleaned (if required)
- [ ] Baseline updated
- [ ] Root cause documented

### Root Cause
[Why was the secret committed? Missing pre-commit hook? Developer education gap?]

### Preventive Measures
[What changes prevent recurrence? Hook enforcement? Rule addition?]
```
