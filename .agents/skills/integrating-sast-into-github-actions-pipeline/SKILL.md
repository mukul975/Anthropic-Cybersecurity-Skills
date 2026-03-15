---
name: integrating-sast-into-github-actions-pipeline
description: >
  This skill covers integrating Static Application Security Testing (SAST) tools—CodeQL
  and Semgrep—into GitHub Actions CI/CD pipelines. It addresses configuring automated code
  scanning on pull requests and pushes, tuning rules to reduce false positives, uploading
  SARIF results to GitHub Advanced Security, and establishing quality gates that block merges
  when high-severity vulnerabilities are detected.
domain: cybersecurity
subdomain: devsecops
tags: [devsecops, cicd, sast, codeql, semgrep, secure-sdlc]
version: 1.0.0
author: mahipal
license: Apache-2.0
---

# Integrating SAST into GitHub Actions Pipeline

## When to Use

- When development teams need automated code-level vulnerability detection on every pull request
- When security teams require consistent SAST enforcement across all repositories in an organization
- When migrating from manual or periodic security reviews to continuous security testing
- When compliance frameworks (SOC 2, PCI DSS, NIST SSDF) require evidence of automated code analysis
- When multiple languages coexist in a monorepo and need unified scanning under one workflow

**Do not use** for runtime vulnerability detection (use DAST instead), for scanning third-party dependencies (use SCA tools like Snyk), or for infrastructure-as-code scanning (use Checkov or tfsec).

## Prerequisites

- GitHub repository with GitHub Actions enabled
- GitHub Advanced Security license (required for CodeQL on private repos; free for public repos)
- Semgrep account for managed rules and Semgrep App dashboard (free tier available)
- Repository code in a supported language: Python, JavaScript/TypeScript, Java, C/C++, C#, Go, Ruby, Swift, Kotlin

## Workflow

### Step 1: Configure CodeQL Analysis Workflow

Create a CodeQL workflow that runs on pull requests and on a weekly schedule to catch vulnerabilities in existing code.

```yaml
# .github/workflows/codeql-analysis.yml
name: "CodeQL Analysis"

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: '30 2 * * 1'  # Weekly Monday 2:30 AM

jobs:
  analyze:
    name: Analyze (${{ matrix.language }})
    runs-on: ubuntu-latest
    permissions:
      actions: read
      contents: read
      security-events: write

    strategy:
      fail-fast: false
      matrix:
        language: ['javascript', 'python']

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Initialize CodeQL
        uses: github/codeql-action/init@v3
        with:
          languages: ${{ matrix.language }}
          queries: security-extended,security-and-quality

      - name: Autobuild
        uses: github/codeql-action/autobuild@v3

      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v3
        with:
          category: "/language:${{ matrix.language }}"
```

### Step 2: Add Semgrep Scanning for Custom Rules

Semgrep complements CodeQL with faster scans and support for custom pattern-based rules. Configure it to upload SARIF results to the same GitHub Security tab.

```yaml
# .github/workflows/semgrep.yml
name: "Semgrep SAST Scan"

on:
  pull_request:
    branches: [main, develop]
  push:
    branches: [main]

jobs:
  semgrep:
    name: Semgrep Scan
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read

    container:
      image: semgrep/semgrep:latest

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Run Semgrep
        run: |
          semgrep ci \
            --config auto \
            --config p/owasp-top-ten \
            --config p/cwe-top-25 \
            --sarif --output semgrep-results.sarif \
            --severity ERROR \
            --error
        env:
          SEMGREP_APP_TOKEN: ${{ secrets.SEMGREP_APP_TOKEN }}

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: semgrep-results.sarif
          category: semgrep
```

### Step 3: Create Custom Semgrep Rules for Organization Patterns

Write organization-specific rules to catch patterns unique to your codebase, such as deprecated internal APIs or insecure configuration patterns.

```yaml
# .semgrep/custom-rules.yml
rules:
  - id: hardcoded-database-url
    patterns:
      - pattern: |
          $DB_URL = "...$PROTO://...:...$PASS@..."
    message: |
      Hardcoded database connection string with credentials detected.
      Use environment variables or a secrets manager instead.
    languages: [python, javascript, typescript]
    severity: ERROR
    metadata:
      cwe: "CWE-798: Use of Hard-coded Credentials"
      owasp: "A07:2021 - Identification and Authentication Failures"

  - id: unsafe-deserialization
    patterns:
      - pattern-either:
          - pattern: pickle.loads(...)
          - pattern: yaml.load(..., Loader=yaml.Loader)
          - pattern: yaml.load(..., Loader=yaml.FullLoader)
    message: |
      Unsafe deserialization detected. Use safe alternatives to prevent
      remote code execution vulnerabilities.
    languages: [python]
    severity: ERROR
    metadata:
      cwe: "CWE-502: Deserialization of Untrusted Data"

  - id: missing-csrf-protection
    patterns:
      - pattern: |
          @app.route("...", methods=["POST"])
          def $FUNC(...):
              ...
      - pattern-not-inside: |
          @csrf.exempt
          ...
    message: "POST endpoint may lack CSRF protection."
    languages: [python]
    severity: WARNING
```

### Step 4: Establish Quality Gates with Branch Protection

Configure branch protection rules that require SAST checks to pass before merging, preventing vulnerable code from reaching production branches.

```bash
# Use GitHub CLI to set branch protection requiring SAST checks
gh api repos/{owner}/{repo}/branches/main/protection \
  --method PUT \
  --field required_status_checks='{"strict":true,"contexts":["Analyze (javascript)","Analyze (python)","Semgrep Scan"]}' \
  --field enforce_admins=true \
  --field required_pull_request_reviews='{"required_approving_review_count":1}'
```

### Step 5: Tune and Suppress False Positives

Manage false positives through CodeQL query filters and Semgrep nosemgrep annotations to maintain developer trust in scan results.

```yaml
# codeql-config.yml - Custom CodeQL configuration
name: "Custom CodeQL Config"
queries:
  - uses: security-extended
  - uses: security-and-quality
  - excludes:
      id: js/unused-local-variable
paths-ignore:
  - '**/test/**'
  - '**/tests/**'
  - '**/vendor/**'
  - '**/node_modules/**'
  - '**/*.test.js'
  - '**/*.spec.py'
```

```python
# Example: Suppressing a known false positive in Semgrep
import subprocess

def run_safe_command(cmd_list):
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use
    result = subprocess.run(cmd_list, capture_output=True, text=True, shell=False)
    return result.stdout
```

### Step 6: Aggregate and Report Findings

Use the GitHub Security Overview dashboard and configure notifications for security alerts across repositories.

```bash
# Query SARIF results via GitHub API for reporting
gh api repos/{owner}/{repo}/code-scanning/alerts \
  --jq '.[] | select(.state=="open") | {rule: .rule.id, severity: .rule.security_severity_level, file: .most_recent_instance.location.path, line: .most_recent_instance.location.start_line}'

# Count open alerts by severity
gh api repos/{owner}/{repo}/code-scanning/alerts \
  --jq '[.[] | select(.state=="open")] | group_by(.rule.security_severity_level) | map({severity: .[0].rule.security_severity_level, count: length})'
```

## Key Concepts

| Term | Definition |
|------|------------|
| SAST | Static Application Security Testing — analyzes source code without executing it to find security vulnerabilities |
| SARIF | Static Analysis Results Interchange Format — standardized JSON format for expressing results from static analysis tools |
| CodeQL | GitHub's semantic code analysis engine that treats code as data and queries it for vulnerability patterns |
| Semgrep | Lightweight static analysis tool using pattern matching to find bugs and security issues across many languages |
| Security Extended | CodeQL query suite that includes additional security queries beyond the default set for deeper analysis |
| Quality Gate | Automated checkpoint that blocks code from progressing through the pipeline unless security criteria are met |
| False Positive | A scan finding that incorrectly identifies secure code as vulnerable, requiring suppression or tuning |

## Tools & Systems

- **CodeQL**: GitHub's semantic code analysis engine with deep dataflow and taint tracking analysis
- **Semgrep**: Fast, lightweight pattern-matching SAST tool with 3000+ community rules and custom rule support
- **GitHub Advanced Security**: Platform providing code scanning, secret scanning, and dependency review in GitHub
- **SARIF Viewer**: VS Code extension for reviewing SARIF results locally during development
- **GitHub Security Overview**: Organization-level dashboard aggregating security alerts across all repositories

## Common Scenarios

### Scenario: Monorepo with Multiple Languages Needs Unified SAST

**Context**: A platform team manages a monorepo containing Python microservices, TypeScript frontends, and Go infrastructure tools. Security reviews happen manually every quarter, missing vulnerabilities between reviews.

**Approach**:
1. Configure CodeQL with a matrix strategy covering Python, JavaScript, and Go languages
2. Add Semgrep with `--config auto` to detect language automatically and apply relevant rulesets
3. Create path-based triggers so only changed language directories trigger their respective scans
4. Upload all SARIF results to GitHub Security tab with unique categories per tool and language
5. Set branch protection requiring all SAST jobs to pass before merge
6. Schedule weekly full-repository scans to catch issues in unchanged code from newly published CVE patterns

**Pitfalls**: Setting CodeQL to analyze all languages on every PR increases CI time significantly. Use path filters to trigger only relevant language scans. Semgrep's `--config auto` may enable rules that conflict with CodeQL findings, creating duplicate alerts.

### Scenario: Reducing Alert Fatigue from High False Positive Rate

**Context**: After enabling SAST, developers ignore findings because 40% are false positives, undermining the security program.

**Approach**:
1. Export all current alerts and categorize them as true positive, false positive, or informational
2. Create a custom CodeQL config excluding noisy query IDs that produce the most false positives
3. Write `.semgrepignore` patterns for test files, generated code, and vendored dependencies
4. Establish a weekly triage meeting where security and development leads review new rule additions
5. Track false positive rate as a metric and target below 15% for developer trust

**Pitfalls**: Over-suppressing rules to reduce noise can create blind spots. Always validate suppressions against the OWASP Top 10 and CWE Top 25 to ensure critical vulnerability classes remain covered.

## Output Format

```
SAST Pipeline Scan Report
==========================
Repository: org/web-application
Branch: feature/user-auth-refactor
Scan Date: 2026-02-23
Commit: a1b2c3d4

CodeQL Results:
  Language    Queries Run   Findings   Critical   High   Medium
  javascript  312           4          1          2      1
  python      287           2          0          1      1

Semgrep Results:
  Ruleset          Rules Matched   Findings   Errors   Warnings
  auto             1,847           3          1        2
  owasp-top-ten    186             2          1        1
  custom-rules     12              1          0        1

QUALITY GATE: FAILED
  Blocking findings: 2 Critical/High severity issues
  - [CRITICAL] CWE-89: SQL Injection in src/api/users.py:47
  - [HIGH] CWE-79: Cross-site Scripting in src/components/Search.tsx:123

Action Required: Fix blocking findings before merge is permitted.
```
