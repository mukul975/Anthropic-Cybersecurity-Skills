---
name: implementing-secrets-scanning-in-ci-cd
description: Integrate gitleaks and trufflehog into CI/CD pipelines to detect leaked secrets before deployment
domain: cybersecurity
subdomain: devsecops
tags: [secrets-scanning, gitleaks, trufflehog, ci-cd]
version: "1.0"
author: mahipal
license: Apache-2.0
---

## Overview

This skill covers implementing automated secrets scanning in CI/CD pipelines using gitleaks and trufflehog. It enables security teams to detect API keys, tokens, passwords, and other credentials that have been accidentally committed to source code repositories, providing a CI gate that blocks deployments containing high-severity findings.

Gitleaks scans git repositories and directories for hardcoded secrets using regex patterns and entropy analysis. TruffleHog performs filesystem and git history scans with optional secret verification against live services. Together they provide comprehensive coverage for secrets detection.

## Prerequisites

- Python 3.9 or later
- gitleaks v8.x installed and available on PATH
- trufflehog v3.x installed and available on PATH
- A git repository or directory to scan
- Access to CI/CD platform (GitHub Actions, GitLab CI, Jenkins)

## Steps

1. **Install scanning tools**: Install gitleaks via package manager or binary download. Install trufflehog via `brew install trufflehog` or download from GitHub releases.

2. **Configure gitleaks**: Create a `.gitleaks.toml` configuration file in the repository root to define custom rules, allowlists, and path exclusions. Use `--config` flag to point to custom configs.

3. **Run gitleaks directory scan**: Execute `gitleaks dir --source . --report-format json --report-path gitleaks-report.json` to scan the working directory and generate a JSON report.

4. **Run trufflehog filesystem scan**: Execute `trufflehog filesystem /path/to/repo --json > trufflehog-report.json` to scan files and output JSON findings to a report file.

5. **Parse and filter findings**: Use the agent script to parse both JSON reports, filter findings by severity (critical, high, medium, low), and determine whether the CI pipeline should pass or fail.

6. **Integrate into CI pipeline**: Add the scanning step to your GitHub Actions workflow, GitLab CI config, or Jenkins pipeline as a pre-deployment gate. Use `--exit-code` flag in gitleaks to control pipeline behavior.

7. **Configure pre-commit hooks**: Set up gitleaks as a pre-commit hook using `gitleaks protect --staged` to catch secrets before they are committed.

8. **Review and triage findings**: Examine the JSON output for false positives, add legitimate entries to `.gitleaksignore`, and rotate any confirmed leaked credentials immediately.

## Expected Output

The agent script produces a JSON report containing:
- Total findings count from each scanner
- Findings grouped by severity level
- Individual finding details including file path, line number, rule ID, and redacted secret
- A CI gate verdict (pass/fail) based on the configured severity threshold
- Execution metadata including scan duration and tool versions

```json
{
  "scan_summary": {
    "tool": "both",
    "total_findings": 3,
    "critical": 1,
    "high": 1,
    "medium": 1,
    "low": 0,
    "ci_gate": "FAIL",
    "fail_reason": "Found 1 critical and 1 high severity findings"
  },
  "findings": [...]
}
```
