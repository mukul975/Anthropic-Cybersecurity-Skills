---
name: implementing-github-advanced-security-for-code-scanning
description: Configure GitHub Advanced Security with CodeQL to perform automated static analysis and vulnerability detection across repositories at enterprise scale.
domain: cybersecurity
subdomain: devsecops
tags: [github-advanced-security, codeql, sast, code-scanning, supply-chain-security, devops-security, shift-left]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Implementing GitHub Advanced Security for Code Scanning

## Overview

GitHub Advanced Security (GHAS) integrates CodeQL-powered static application security testing directly into the GitHub development workflow. CodeQL treats code as data, enabling semantic analysis that identifies security vulnerabilities such as SQL injection, cross-site scripting, buffer overflows, and authentication flaws with significantly fewer false positives than traditional pattern-matching scanners. GHAS encompasses code scanning, secret scanning, dependency review, and Dependabot alerts to provide a comprehensive security posture for repositories.

## Prerequisites

- GitHub Enterprise Cloud or GitHub Enterprise Server 3.0+ with GHAS license
- Repository admin or organization owner permissions
- Familiarity with GitHub Actions workflow syntax (YAML)
- Supported languages: C/C++, C#, Go, Java/Kotlin, JavaScript/TypeScript, Python, Ruby, Swift

## Core Concepts

### CodeQL Analysis Engine

CodeQL compiles source code into a queryable database, then executes security-focused queries against that database. The query suites ship with hundreds of checks mapped to CWE identifiers and cover OWASP Top 10, SANS Top 25, and language-specific vulnerability patterns. Custom queries can be authored using the CodeQL query language (QL) to detect organization-specific anti-patterns.

### Default Setup vs. Advanced Setup

**Default Setup** enables code scanning with a single click from the repository's Code Security settings. GitHub automatically determines the languages present, selects appropriate query suites, and configures scanning triggers. This approach requires no workflow file and is ideal for rapid onboarding.

**Advanced Setup** generates a `.github/workflows/codeql.yml` workflow file that can be customized. Teams control scheduling, language matrices, build commands for compiled languages, additional query packs, and integration with third-party SARIF producers. Advanced setup is required when custom build steps, monorepo configurations, or private query packs are needed.

### Organization-Wide Rollout

For enterprises managing hundreds of repositories, GHAS supports configuring code scanning at scale using the organization-level security overview. Administrators can enable default setup across all eligible repositories, define custom security configurations, and monitor adoption through the security coverage dashboard.

## Implementation Steps

### Step 1 --- Enable GHAS on the Organization

1. Navigate to Organization Settings > Code security and analysis
2. Enable GitHub Advanced Security for all repositories or selected repositories
3. Confirm license seat allocation (GHAS is billed per active committer)

### Step 2 --- Configure Default Setup for Quick Wins

1. Go to Repository Settings > Code security > Code scanning
2. Click "Set up" in the CodeQL analysis row and select "Default"
3. Review the auto-detected languages and query suite (default or extended)
4. Click "Enable CodeQL" to activate scanning on push and pull request events

### Step 3 --- Advanced Setup with Custom Workflow

Create `.github/workflows/codeql-analysis.yml`:

```yaml
name: "CodeQL Analysis"

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: '30 2 * * 1'  # Weekly Monday 2:30 AM UTC

jobs:
  analyze:
    name: Analyze (${{ matrix.language }})
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
      actions: read

    strategy:
      fail-fast: false
      matrix:
        language: ['javascript-typescript', 'python', 'java-kotlin']

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Initialize CodeQL
        uses: github/codeql-action/init@v3
        with:
          languages: ${{ matrix.language }}
          queries: +security-extended,security-and-quality
          # For compiled languages, add build commands below

      - name: Autobuild
        uses: github/codeql-action/autobuild@v3

      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v3
        with:
          category: "/language:${{ matrix.language }}"
```

### Step 4 --- Custom Query Packs

Install organization-specific query packs by referencing them in the workflow:

```yaml
- name: Initialize CodeQL
  uses: github/codeql-action/init@v3
  with:
    languages: java-kotlin
    packs: |
      my-org/java-custom-queries@1.0.0
      codeql/java-queries:cwe/cwe-089
```

### Step 5 --- Configure Branch Protection Rules

1. Navigate to Repository Settings > Branches > Branch protection rules
2. Enable "Require status checks to pass" and add the CodeQL analysis check
3. Enable "Require code scanning results" and set severity thresholds (e.g., block on High/Critical)

### Step 6 --- Secret Scanning and Push Protection

1. Enable secret scanning from Code security settings
2. Activate push protection to block commits containing detected secrets
3. Configure custom patterns for organization-specific secrets (API keys, internal tokens)

### Step 7 --- Dependency Review and Dependabot

1. Enable Dependabot alerts and security updates
2. Configure `.github/dependabot.yml` for automated dependency version updates
3. Enable dependency review enforcement on pull requests to block PRs that introduce known vulnerable dependencies

## Query Suite Reference

| Suite | Description | Use Case |
|-------|-------------|----------|
| `default` | High-confidence security queries | Production scanning with minimal false positives |
| `security-extended` | Broader security queries including lower-severity findings | Comprehensive security coverage |
| `security-and-quality` | Security plus code quality queries | Teams wanting both security and maintainability checks |
| Custom packs | Organization-authored queries | Detecting internal anti-patterns and compliance violations |

## Integration with Security Workflows

### SARIF Upload from Third-Party Tools

GHAS accepts SARIF (Static Analysis Results Interchange Format) uploads from external tools:

```yaml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
    category: "semgrep"
```

### Security Overview Dashboard

The organization-level security overview provides:
- Risk view showing repositories with open alerts by severity
- Coverage view showing GHAS feature enablement across repositories
- Alert trends over time for tracking remediation progress
- Filter by team, language, and alert type for targeted review

## Monitoring and Metrics

- Track mean time to remediate (MTTR) for code scanning alerts
- Monitor false positive rates and tune query configurations accordingly
- Review alert dismissal reasons to identify areas for developer training
- Use the API (`/repos/{owner}/{repo}/code-scanning/alerts`) for custom reporting dashboards

## Common Pitfalls

1. **Compiled language build failures** --- CodeQL requires successful compilation for C/C++, Java, C#, Go, and Swift; ensure build dependencies are available in the Actions runner
2. **Ignoring scheduled scans** --- Push/PR scanning misses vulnerabilities in dependencies; weekly scheduled scans catch newly disclosed CVEs in existing code
3. **Over-alerting with security-and-quality** --- Start with `default` suite and expand gradually to avoid developer alert fatigue
4. **Missing GHAS license seats** --- Only active committers to GHAS-enabled repositories consume license seats; plan capacity accordingly

## References

- [GitHub Code Scanning Documentation](https://docs.github.com/en/code-security/code-scanning)
- [CodeQL Documentation](https://codeql.github.com/docs/)
- [CodeQL Query Repository](https://github.com/github/codeql)
- [SARIF Specification](https://sarifweb.azurewebsites.net/)
- [GitHub Security Overview](https://docs.github.com/en/code-security/security-overview/about-security-overview)
