# API Reference: DevSecOps Security Scanning

## Semgrep CLI (SAST)
```bash
# Scan with auto-detected rules
semgrep scan --config auto --json /path/to/code

# Scan with specific ruleset
semgrep scan --config p/owasp-top-ten --json /path/to/code

# Custom rule file
semgrep scan --config my_rules.yaml --json /path/to/code

# SARIF output for GitHub integration
semgrep scan --config auto --sarif -o results.sarif /path/to/code
```

## Trivy CLI (SCA / Container)
```bash
# Scan container image
trivy image --format json --quiet nginx:latest

# Scan filesystem for vulnerabilities
trivy fs --format json --scanners vuln,secret /path/to/project

# Scan with severity filter
trivy image --severity CRITICAL,HIGH --format json myapp:latest

# Scan IaC files
trivy config --format json /path/to/terraform/
```

## Gitleaks CLI (Secret Detection)
```bash
# Detect secrets in git repo
gitleaks detect --source /path/to/repo --report-format json --report-path report.json

# Scan specific commit range
gitleaks detect --source . --log-opts="HEAD~10..HEAD" --report-format json

# Protect mode (pre-commit)
gitleaks protect --staged --report-format json
```

## CI/CD Pipeline Gate Logic
| Severity | Exit Code | Action |
|----------|-----------|--------|
| CRITICAL | 1 (fail) | Block merge/deploy |
| HIGH | 1 (fail) | Block merge/deploy |
| MEDIUM | 0 (warn) | Warning in PR comment |
| LOW | 0 (pass) | Informational only |

## JSON Output Schema (Semgrep)
| Field | Description |
|-------|------------|
| results[].check_id | Rule identifier |
| results[].extra.severity | ERROR, WARNING, INFO |
| results[].path | Affected file path |
| results[].start.line | Line number |
| results[].extra.message | Finding description |

## JSON Output Schema (Trivy)
| Field | Description |
|-------|------------|
| Results[].Target | Scanned target name |
| Results[].Vulnerabilities[].VulnerabilityID | CVE identifier |
| Results[].Vulnerabilities[].Severity | CRITICAL/HIGH/MEDIUM/LOW |
| Results[].Vulnerabilities[].FixedVersion | Version with fix |
