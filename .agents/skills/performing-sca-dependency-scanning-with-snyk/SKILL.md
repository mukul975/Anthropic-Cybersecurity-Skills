---
name: performing-sca-dependency-scanning-with-snyk
description: >
  This skill covers implementing Software Composition Analysis (SCA) using Snyk to detect
  vulnerable open-source dependencies in CI/CD pipelines. It addresses scanning package
  manifests and lockfiles, automated fix pull request generation, license compliance
  checking, continuous monitoring of deployed applications, and integration with
  GitHub, GitLab, and Jenkins pipelines.
domain: cybersecurity
subdomain: devsecops
tags: [devsecops, cicd, sca, snyk, dependency-scanning, secure-sdlc]
version: 1.0.0
author: mahipal
license: Apache-2.0
---

# Performing SCA Dependency Scanning with Snyk

## When to Use

- When applications use open-source packages that may contain known vulnerabilities
- When compliance requires tracking and remediating vulnerable dependencies (PCI DSS, SOC 2)
- When needing automated fix PRs for vulnerable dependencies in CI/CD
- When license compliance requires visibility into open-source license obligations
- When continuous monitoring is needed for newly disclosed vulnerabilities in deployed dependencies

**Do not use** for scanning proprietary application code for logic vulnerabilities (use SAST), for runtime vulnerability detection (use DAST), or for container OS package scanning alone (use Trivy for a free alternative).

## Prerequisites

- Snyk account (free tier covers up to 200 tests per month for open source)
- Snyk CLI installed or Snyk GitHub/GitLab integration configured
- SNYK_TOKEN environment variable set with API authentication token
- Project with supported package manifests: package.json, requirements.txt, pom.xml, go.mod, Gemfile, etc.

## Workflow

### Step 1: Install and Authenticate Snyk CLI

```bash
# Install Snyk CLI
npm install -g snyk

# Authenticate with Snyk
snyk auth $SNYK_TOKEN

# Test the connection
snyk test --json | jq '.summary'
```

### Step 2: Scan Dependencies in CI/CD Pipeline

```yaml
# .github/workflows/dependency-scan.yml
name: Dependency Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 8 * * 1'  # Weekly Monday 8am

jobs:
  snyk-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install dependencies
        run: npm ci

      - name: Run Snyk to check for vulnerabilities
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          args: >
            --severity-threshold=high
            --fail-on=upgradable
            --json-file-output=snyk-results.json

      - name: Upload results to Snyk
        if: always()
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          command: monitor
          args: --project-name=${{ github.repository }}

      - name: Upload SARIF
        if: always()
        run: |
          npx snyk-to-html -i snyk-results.json -o snyk-report.html
```

### Step 3: Configure Snyk for Multiple Languages

```bash
# Python project scanning
snyk test --file=requirements.txt --severity-threshold=high --json > snyk-python.json

# Java/Maven project
snyk test --file=pom.xml --severity-threshold=medium --json > snyk-java.json

# Go module scanning
snyk test --file=go.mod --severity-threshold=high --json > snyk-go.json

# Docker image dependency scanning
snyk container test myapp:latest --severity-threshold=high --json > snyk-container.json

# Monorepo: scan all projects
snyk test --all-projects --severity-threshold=high --json > snyk-all.json

# IaC scanning (bonus)
snyk iac test terraform/ --severity-threshold=medium --json > snyk-iac.json
```

### Step 4: Configure Snyk Policies for Organization

```yaml
# .snyk policy file
version: v1.25.0
ignore:
  SNYK-JS-LODASH-1018905:
    - '*':
        reason: "Prototype pollution in lodash. Not exploitable in our usage - no user input reaches affected function."
        expires: 2026-06-01T00:00:00.000Z
        created: 2026-02-23T00:00:00.000Z

  SNYK-PYTHON-REQUESTS-6241864:
    - '*':
        reason: "SSRF in requests redirect handling. Mitigated by allowlist at proxy layer."
        expires: 2026-04-01T00:00:00.000Z

patch: {}

# Severity threshold for CI failures
failOnSeverity: high
```

### Step 5: Enable Automated Fix Pull Requests

```bash
# Snyk fix: generate fix PRs for vulnerable dependencies
snyk fix --dry-run  # Preview changes

# Apply fixes locally
snyk fix

# Enable auto-fix PRs via Snyk dashboard:
# 1. Navigate to Organization Settings > Integrations > GitHub
# 2. Enable "Automatic fix pull requests"
# 3. Set "Fix only direct dependencies" or "Fix direct and transitive"
# 4. Configure branch target (main or develop)
```

### Step 6: License Compliance Scanning

```bash
# Check license compliance
snyk test --json | jq '.licensesPolicy'

# Snyk license policy configuration via organization settings:
# - Approved licenses: MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC
# - Restricted licenses: GPL-3.0, AGPL-3.0 (copyleft risk)
# - Unknown licenses: Flag for manual review
```

## Key Concepts

| Term | Definition |
|------|------------|
| SCA | Software Composition Analysis — identifies vulnerabilities and license risks in open-source dependencies |
| Transitive Dependency | A dependency of a direct dependency, often invisible to developers but still a vulnerability vector |
| Fix PR | Automated pull request generated by Snyk that upgrades a vulnerable dependency to a patched version |
| Snyk Monitor | Continuous monitoring mode that watches deployed projects for newly disclosed vulnerabilities |
| Exploit Maturity | Snyk's assessment of whether a vulnerability has known exploits, proof-of-concept, or no known exploit |
| Reachable Vulnerability | A vulnerability in a function that is actually called by the application code, not just present in the dependency |
| License Policy | Organization-level rules defining which open-source licenses are approved, restricted, or require review |

## Tools & Systems

- **Snyk Open Source**: SCA tool for scanning dependencies across 10+ language ecosystems
- **Snyk CLI**: Command-line interface for local and CI/CD scanning of dependencies
- **Snyk Advisor**: Package health scoring tool evaluating maintenance, popularity, and security signals
- **OWASP Dependency-Check**: Free alternative SCA tool using NVD data for vulnerability matching
- **npm audit / pip-audit**: Language-specific built-in audit tools for basic vulnerability checking

## Common Scenarios

### Scenario: Triaging a Critical Transitive Dependency Vulnerability

**Context**: Snyk reports a critical RCE vulnerability in a transitive dependency (log4j in a Java application). The direct dependency has not released a patch.

**Approach**:
1. Use `snyk test --json` and examine the dependency path to identify which direct dependency pulls in the vulnerable transitive
2. Check exploit maturity: if "Mature" or "Proof of Concept", prioritize immediately
3. If no direct fix exists, use Snyk's patch mechanism or override the transitive version in the build config
4. For Maven: add `<dependencyManagement>` section to force the safe version of the transitive dependency
5. For npm: add an `overrides` section in package.json to pin the safe version
6. Add a Snyk ignore with expiration date if no patch is available yet
7. Monitor the direct dependency for a release that updates the transitive

**Pitfalls**: Ignoring transitive vulnerabilities because "we don't use that function directly" is risky. Attackers can chain vulnerabilities across dependency boundaries. Version overrides can break API compatibility between the direct and transitive dependency.

## Output Format

```
Snyk Dependency Scan Report
=============================
Project: org/web-application
Manifest: package.json
Dependencies: 342 (47 direct, 295 transitive)
Scan Date: 2026-02-23

VULNERABILITY SUMMARY:
  Critical: 1  (1 fixable)
  High: 4      (3 fixable)
  Medium: 12   (8 fixable)
  Low: 23      (15 fixable)

CRITICAL:
  SNYK-JS-EXPRESS-1234567
    Package: express@4.17.1 (direct)
    Severity: Critical (CVSS 9.8)
    Exploit: Mature
    Fix: Upgrade to express@4.21.0
    Path: express@4.17.1

HIGH:
  SNYK-JS-JSONWEBTOKEN-5678901
    Package: jsonwebtoken@8.5.1 (transitive)
    Severity: High (CVSS 7.6)
    Exploit: Proof of Concept
    Fix: Upgrade passport@0.7.0 (which upgrades jsonwebtoken)
    Path: passport@0.6.0 > jsonwebtoken@8.5.1

LICENSE ISSUES:
  [RESTRICTED] GPL-3.0: some-package@1.2.3 (transitive via other-pkg)

QUALITY GATE: FAILED (1 Critical with fix available)
```
