---
name: implementing-devsecops-security-scanning
description: 'Integrates Static Application Security Testing (SAST), Dynamic Application
  Security Testing (DAST), and Software Composition Analysis (SCA) into CI/CD pipelines
  using open-source tools. Covers Semgrep for SAST, Trivy for SCA and container scanning,
  OWASP ZAP for DAST, and Gitleaks for secrets detection. Activates for requests involving
  DevSecOps pipeline setup, automated security scanning in CI/CD, SAST/DAST/SCA integration,
  or shift-left security implementation.

  '
domain: cybersecurity
subdomain: application-security
tags:
- devsecops
- SAST
- DAST
- SCA
- semgrep
- trivy
- owasp-zap
- gitleaks
- CI-CD
- shift-left
version: 1.0.0
author: mahipal
license: Apache-2.0
nist_csf:
- PR.PS-01
- PR.PS-04
- ID.RA-01
- PR.DS-10
mitre_attack:
- T1078
- T1190
- T1059
- T1610
- T1611
---

# Implementing DevSecOps Security Scanning

## When to Use

- Setting up automated security scanning in a new or existing CI/CD pipeline
- Shifting security left by catching vulnerabilities before code reaches production
- Meeting compliance requirements (SOC 2, PCI-DSS, ISO 27001) that mandate automated security testing
- Integrating SAST, DAST, and SCA together to achieve comprehensive application security coverage
- Establishing security gates that block deployments containing critical or high-severity vulnerabilities

**Do not use** as a replacement for manual penetration testing. Automated scanning catches common vulnerability patterns but cannot replace human-driven security assessments for business logic flaws and complex attack chains.

## Prerequisites

- CI/CD platform: GitHub Actions, GitLab CI, Jenkins, or Azure DevOps
- Container runtime (Docker) for running scanning tools
- A staging environment URL for DAST scanning (DAST cannot test static code)
- Repository access with permissions to modify CI/CD workflow files
- Tool-specific requirements:
  - Semgrep: free for open-source rulesets (`p/security-audit`, `p/owasp-top-ten`)
  - Trivy: free, no account required
  - OWASP ZAP: free, Docker image available
  - Gitleaks: free, no account required

## Workflow

### Step 1: Add Secrets Detection with Gitleaks

Secrets detection runs first because leaked credentials are the highest-priority finding. Add to `.github/workflows/security.yml`:

```yaml
name: DevSecOps Security Pipeline
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  secrets-scan:
    name: Secrets Detection (Gitleaks)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for scanning all commits

      - name: Run Gitleaks
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

Configure `.gitleaks.toml` in the repository root for custom rules and allowlists:

```toml
[extend]
useDefault = true

[allowlist]
description = "Global allowlist"
paths = [
  '''\.gitleaks\.toml''',
  '''test/fixtures/.*''',
  '''docs/examples/.*'''
]

[[rules]]
id = "custom-internal-api-key"
description = "Internal API key pattern"
regex = '''INTERNAL_KEY_[A-Za-z0-9]{32}'''
tags = ["internal", "api-key"]
```

### Step 2: Add SAST Scanning with Semgrep

Semgrep performs static code analysis to find security vulnerabilities, bugs, and code patterns:

```yaml
  sast-scan:
    name: SAST (Semgrep)
    runs-on: ubuntu-latest
    container:
      image: semgrep/semgrep
    steps:
      - uses: actions/checkout@v4

      - name: Run Semgrep SAST scan
        run: |
          semgrep scan \
            --config p/security-audit \
            --config p/owasp-top-ten \
            --config p/secrets \
            --severity ERROR \
            --error \
            --json \
            --output semgrep-results.json \
            .

      - name: Upload SAST results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: semgrep-results
          path: semgrep-results.json
```

For custom rules, create `.semgrep/custom-rules.yml`:

```yaml
rules:
  - id: no-exec-user-input
    patterns:
      - pattern: exec($INPUT)
      - pattern-not: exec("...")
    message: >
      User input passed to exec(). This is a command injection vulnerability.
    severity: ERROR
    languages: [python]
    metadata:
      cwe: "CWE-78: OS Command Injection"
      owasp: "A03:2021 - Injection"

  - id: no-raw-sql-queries
    patterns:
      - pattern: cursor.execute(f"...")
      - pattern: cursor.execute("..." + ...)
    message: >
      SQL query built with string concatenation or f-strings. Use parameterized queries.
    severity: ERROR
    languages: [python]
    metadata:
      cwe: "CWE-89: SQL Injection"
      owasp: "A03:2021 - Injection"
```

### Step 3: Add SCA Scanning with Trivy

Trivy scans dependencies, container images, IaC files, and generates SBOM:

```yaml
  sca-scan:
    name: SCA & Container Scan (Trivy)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Trivy filesystem scan (dependencies)
        uses: aquasecurity/trivy-action@0.28.0
        with:
          scan-type: 'fs'
          scan-ref: '.'
          severity: 'CRITICAL,HIGH'
          exit-code: '1'
          format: 'json'
          output: 'trivy-fs-results.json'

      - name: Run Trivy IaC scan (Terraform, CloudFormation)
        uses: aquasecurity/trivy-action@0.28.0
        with:
          scan-type: 'config'
          scan-ref: '.'
          severity: 'CRITICAL,HIGH'
          exit-code: '1'
          format: 'json'
          output: 'trivy-iac-results.json'

      - name: Upload SCA results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: trivy-results
          path: trivy-*.json

  container-scan:
    name: Container Image Scan (Trivy)
    runs-on: ubuntu-latest
    needs: [sast-scan]  # Build image only after SAST passes
    steps:
      - uses: actions/checkout@v4

      - name: Build Docker image
        run: docker build -t app:${{ github.sha }} .

      - name: Scan container image
        uses: aquasecurity/trivy-action@0.28.0
        with:
          image-ref: 'app:${{ github.sha }}'
          severity: 'CRITICAL,HIGH'
          exit-code: '1'
          format: 'json'
          output: 'trivy-image-results.json'

      - name: Generate SBOM
        uses: aquasecurity/trivy-action@0.28.0
        with:
          image-ref: 'app:${{ github.sha }}'
          format: 'cyclonedx'
          output: 'sbom.json'

      - name: Upload SBOM
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sbom.json
```

### Step 4: Add DAST Scanning with OWASP ZAP

DAST runs against a deployed staging environment. It is slower than SAST/SCA and should run asynchronously or on a schedule:

```yaml
  dast-scan:
    name: DAST (OWASP ZAP)
    runs-on: ubuntu-latest
    needs: [deploy-staging]  # Must run after app is deployed to staging
    steps:
      - uses: actions/checkout@v4

      - name: Run ZAP Baseline Scan (fast, suitable for CI)
        uses: zaproxy/action-baseline@v0.14.0
        with:
          target: ${{ vars.STAGING_URL }}
          rules_file_name: '.zap/rules.tsv'
          cmd_options: '-a -j'

      # For nightly full scans, use action-full-scan instead:
      # - name: Run ZAP Full Scan (comprehensive, 30-60 min)
      #   uses: zaproxy/action-full-scan@v0.12.0
      #   with:
      #     target: ${{ vars.STAGING_URL }}
```

Create `.zap/rules.tsv` to configure alert thresholds:

```tsv
10010	IGNORE	(Cookie No HttpOnly Flag - acceptable for non-sensitive cookies)
10011	IGNORE	(Cookie Without Secure Flag - staging uses HTTP)
90033	WARN	(Loosely Scoped Cookie)
10038	FAIL	(Content Security Policy Header Not Set)
40012	FAIL	(Cross Site Scripting - Reflected)
40014	FAIL	(Cross Site Scripting - Persistent)
40018	FAIL	(SQL Injection)
90019	FAIL	(Server Side Code Injection)
90020	FAIL	(Remote OS Command Injection)
```

### Step 5: Aggregate Results and Enforce Security Gates

Create a summary job that aggregates all scan results and enforces pass/fail gates:

```yaml
  security-gate:
    name: Security Gate
    runs-on: ubuntu-latest
    needs: [secrets-scan, sast-scan, sca-scan, container-scan]
    if: always()
    steps:
      - name: Check scan results
        run: |
          echo "Checking security scan results..."

          # Fail the pipeline if any upstream job failed
          if [[ "${{ needs.secrets-scan.result }}" == "failure" ]]; then
            echo "BLOCKED: Secrets detected in repository"
            exit 1
          fi

          if [[ "${{ needs.sast-scan.result }}" == "failure" ]]; then
            echo "BLOCKED: SAST found critical/high vulnerabilities"
            exit 1
          fi

          if [[ "${{ needs.sca-scan.result }}" == "failure" ]]; then
            echo "BLOCKED: SCA found critical/high vulnerable dependencies"
            exit 1
          fi

          if [[ "${{ needs.container-scan.result }}" == "failure" ]]; then
            echo "BLOCKED: Container image has critical/high vulnerabilities"
            exit 1
          fi

          echo "All security gates passed"
```

### Step 6: Configure Branch Protection Rules

Enforce the security pipeline as a required status check:

```
GitHub Repository > Settings > Branches > Branch Protection Rules

Branch name pattern: main
  Require status checks to pass before merging: Enabled
    Required status checks:
      - Secrets Detection (Gitleaks)
      - SAST (Semgrep)
      - SCA & Container Scan (Trivy)
      - Security Gate
  Require branches to be up to date before merging: Enabled
```

### Step 7: Set Up Developer Feedback Loop

Configure pre-commit hooks so developers catch issues before pushing:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.22.1
    hooks:
      - id: gitleaks

  - repo: https://github.com/semgrep/semgrep
    rev: v1.102.0
    hooks:
      - id: semgrep
        args: ['--config', 'p/security-audit', '--config', 'p/owasp-top-ten', '--error']
```

Install and activate pre-commit:

```bash
pip install pre-commit
pre-commit install
pre-commit run --all-files  # Test against existing codebase
```

## Key Concepts

| Term | Definition |
|------|------------|
| **SAST (Static Application Security Testing)** | Analyzes source code without executing it to find security vulnerabilities; runs fast, catches issues early, but cannot find runtime flaws |
| **DAST (Dynamic Application Security Testing)** | Tests a running application by sending requests and analyzing responses; finds runtime issues but requires a deployed environment |
| **SCA (Software Composition Analysis)** | Scans project dependencies against vulnerability databases (NVD, GitHub Advisory) to find known-vulnerable libraries |
| **SBOM (Software Bill of Materials)** | Machine-readable inventory of all components and dependencies in an application, used for vulnerability tracking and compliance |
| **Shift Left** | Security practice of moving security testing earlier in the SDLC, from post-deployment to pre-commit and CI stages |
| **Security Gate** | A CI/CD pipeline checkpoint that blocks deployment if security scan results exceed defined severity thresholds |
| **Pre-commit Hook** | Local Git hook that runs security checks before code is committed, providing the fastest developer feedback loop |

## Verification

- [ ] Gitleaks blocks commits and PRs containing hardcoded secrets (test with a dummy API key)
- [ ] Semgrep scan runs on every PR and reports findings as annotations or comments
- [ ] Trivy filesystem scan detects a known-vulnerable dependency (test by adding a vulnerable package)
- [ ] Trivy container scan runs successfully against the built Docker image
- [ ] SBOM is generated and stored as a build artifact in CycloneDX or SPDX format
- [ ] OWASP ZAP baseline scan runs against the staging URL without crashing
- [ ] Security gate job blocks merges to main when any scan finds critical/high severity issues
- [ ] Branch protection rules enforce required status checks before merge
- [ ] Pre-commit hooks catch secrets and SAST findings locally before push
- [ ] Developer documentation explains how to interpret scan results and fix common findings
