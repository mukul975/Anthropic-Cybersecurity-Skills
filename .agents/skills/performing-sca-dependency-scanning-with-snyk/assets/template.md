# Snyk SCA Scanning Templates

## GitHub Actions: Multi-Language SCA Pipeline

```yaml
# .github/workflows/sca-scanning.yml
name: SCA Dependency Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
    paths:
      - 'package*.json'
      - 'requirements*.txt'
      - 'Pipfile*'
      - 'pom.xml'
      - 'build.gradle*'
      - 'go.mod'
      - 'Gemfile*'

jobs:
  snyk-node:
    name: Snyk Node.js
    runs-on: ubuntu-latest
    if: hashFiles('package.json') != ''
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: '20' }
      - run: npm ci
      - uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          args: --severity-threshold=high --fail-on=upgradable

  snyk-python:
    name: Snyk Python
    runs-on: ubuntu-latest
    if: hashFiles('requirements.txt') != ''
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pip install -r requirements.txt
      - uses: snyk/actions/python-3.10@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          args: --severity-threshold=high

  monitor:
    name: Snyk Monitor
    needs: [snyk-node, snyk-python]
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          command: monitor
          args: --all-projects
```

## Snyk Policy File

```yaml
# .snyk
version: v1.25.0
ignore:
  # Accepted risk with documented justification and expiry
  SNYK-JS-LODASH-1018905:
    - '*':
        reason: "Not exploitable: user input never reaches _.template()"
        expires: 2026-06-01T00:00:00.000Z
        created: 2026-02-23T00:00:00.000Z

patch: {}
```

## Snyk Configuration for License Compliance

```json
{
  "org_settings": {
    "license_policy": {
      "approved": ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unlicense", "0BSD"],
      "review_required": ["LGPL-2.1", "LGPL-3.0", "MPL-2.0", "CDDL-1.0"],
      "restricted": ["GPL-2.0", "GPL-3.0", "AGPL-3.0", "SSPL-1.0"],
      "severity_for_unknown": "high"
    }
  }
}
```

## OWASP Dependency-Check Alternative (Free)

```yaml
# .github/workflows/dependency-check.yml
name: OWASP Dependency Check

on:
  push:
    branches: [main]
  schedule:
    - cron: '0 8 * * 1'

jobs:
  dependency-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run OWASP Dependency-Check
        uses: dependency-check/Dependency-Check_Action@main
        with:
          project: 'my-app'
          path: '.'
          format: 'HTML'
          args: >
            --failOnCVSS 7
            --enableRetired
      - name: Upload report
        uses: actions/upload-artifact@v4
        with:
          name: dependency-check-report
          path: reports/
```
