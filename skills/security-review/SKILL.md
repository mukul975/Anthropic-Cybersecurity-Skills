---
name: security-review
description: Perform AI-driven security code reviews to detect vulnerabilities, exposed secrets, insecure dependencies, and access control flaws across multi-language codebases.
domain: cybersecurity
subdomain: appsec
tags: [security-review, code-audit, vulnerability-scanning, sast, appsec, secrets-detection]
version: "1.0"
author: Mrigank-Singh
license: Apache-2.0
---

# Security Review

## Overview

This skill performs comprehensive security code reviews by reasoning about codebases the way a human security researcher would, tracing data flows, understanding component interactions, and catching vulnerabilities that pattern-matching tools miss. It analyzes source code across multiple languages (JavaScript, TypeScript, Python, Java, PHP, Go, Ruby, Rust) to identify injection flaws, authentication weaknesses, exposed secrets, insecure dependencies, cryptographic issues, and business logic vulnerabilities.

Rather than relying solely on regex-based pattern matching, this skill performs contextual analysis across files, traces user-controlled input from entry points to dangerous sinks, and self-verifies each finding to filter false positives. Every identified vulnerability includes a severity rating, confidence level, and a concrete patch proposal for human review.


## When to Use

- When performing security code reviews or vulnerability assessments on application source code
- When auditing codebases for exposed secrets, hardcoded credentials, or insecure configurations
- When assessing dependency security and identifying packages with known CVEs
- When tracing data flows across files to identify injection flaws, access control issues, or business logic vulnerabilities


## Prerequisites

- Access to the target codebase source files
- Supported languages: JavaScript/TypeScript, Python, Java, PHP, Go, Ruby, Rust
- Package manifest files for dependency auditing (package.json, requirements.txt, pom.xml, Gemfile, Cargo.toml, go.sum, or equivalent)


## Workflow

### Step 1 --- Scope Resolution

Determine what to scan:
- If a specific path was provided, scan only that scope
- If no path was given, scan the entire project starting from the root
- Identify the languages and frameworks in use by checking manifest files (package.json, requirements.txt, go.mod, Cargo.toml, pom.xml, Gemfile, composer.json)
- Load language-specific vulnerability patterns from `references/language-patterns.md`

### Step 2 --- Dependency Audit

Audit project dependencies before scanning source code:
- **Node.js**: Check `package.json` and `package-lock.json` for known vulnerable packages
- **Python**: Check `requirements.txt`, `pyproject.toml`, or `Pipfile`
- **Java**: Check `pom.xml` or `build.gradle`
- **Ruby**: Check `Gemfile.lock`
- **Rust**: Check `Cargo.toml`
- **Go**: Check `go.sum`
- Flag packages with known CVEs, deprecated crypto libraries, or suspiciously old pinned versions
- Reference the curated watchlist in `references/vulnerable-packages.md`

### Step 3 --- Secrets and Exposure Scan

Scan all files including configuration, environment, CI/CD, Dockerfiles, and IaC templates for:
- Hardcoded API keys, tokens, passwords, and private keys
- Committed `.env` files
- Secrets in comments or debug log statements
- Cloud credentials (AWS, GCP, Azure, Stripe, Twilio)
- Database connection strings with embedded credentials
- Apply regex patterns and entropy heuristics from `references/secret-patterns.md`

### Step 4 --- Vulnerability Deep Scan

Perform contextual analysis across the codebase. Reference `references/vuln-categories.md` for full detection guidance on each category:

**Injection Flaws**: SQL injection (including second-order), XSS (stored, reflected, DOM-based), command injection, LDAP/XPath/header/log injection, SSRF

**Authentication and Access Control**: Missing authentication on sensitive endpoints, broken object-level authorization (BOLA/IDOR), JWT weaknesses (algorithm confusion, weak secrets, missing expiry), session fixation, CSRF, privilege escalation, mass assignment

**Data Handling**: Sensitive data in logs or API responses, missing encryption, insecure deserialization, path traversal, XXE processing

**Cryptography**: Weak algorithms (MD5, SHA1, DES), hardcoded IVs or salts, insecure random number generation, missing TLS validation

**Business Logic**: Race conditions (TOCTOU), integer overflow in financial calculations, missing rate limiting, predictable resource identifiers

### Step 5 --- Cross-File Data Flow Analysis

After the per-file scan, perform a holistic review:
- Trace user-controlled input from entry points (HTTP parameters, headers, body, file uploads) to sinks (database queries, exec calls, HTML output, file writes)
- Identify vulnerabilities that only appear when examining multiple files together
- Check for insecure trust boundaries between services or modules

### Step 6 --- Self-Verification Pass

For each finding:
1. Re-read the relevant code with fresh context
2. Determine whether the vulnerability is actually exploitable or if sanitization was missed
3. Check if a framework or middleware already handles the issue upstream
4. Downgrade or discard findings that are not genuine vulnerabilities
5. Assign final severity: CRITICAL, HIGH, MEDIUM, LOW, or INFO

### Step 7 --- Generate Security Report

Output the full report using the format defined in `references/report-format.md`. The report includes:
- Executive summary table with finding counts by severity
- Individual finding cards grouped by category with location, vulnerable code, risk explanation, and recommended fix
- Dependency audit section
- Secrets scan section
- Scan coverage footer

### Step 8 --- Propose Patches

For every CRITICAL and HIGH finding, generate a concrete patch:
- Show the vulnerable code (before) and fixed code (after)
- Explain what changed and why
- Preserve the original code style, variable names, and structure
- All patches are presented for human review only and are never auto-applied


## Severity Classification

| Severity | Meaning | Example |
|----------|---------|---------|
| CRITICAL | Immediate exploitation risk, data breach likely | SQL injection, RCE, authentication bypass |
| HIGH | Serious vulnerability, exploit path exists | XSS, IDOR, hardcoded production secrets |
| MEDIUM | Exploitable with conditions or chaining | CSRF, open redirect, weak cryptography |
| LOW | Best practice violation, low direct risk | Verbose error messages, missing security headers |
| INFO | Observation worth noting, not a vulnerability | Outdated dependency without known CVE |


## Expected Output

The skill produces a structured security report containing:
- A findings summary table with counts by severity level
- Individual finding details including file path, line number, vulnerable code snippet, risk explanation, and recommended fix
- A confidence rating per finding (High, Medium, or Low)
- Findings grouped by category rather than by file
- Patch proposals for all CRITICAL and HIGH severity issues
- Dependency audit results and secrets scan results

If the codebase is clean, the report states this clearly with a summary of what was scanned.

Full output template: `references/report-format.md`


## Best Practices

1. Start with a scoped scan on high-risk directories (authentication, API routes, database access) before running a full project scan
2. Review each patch proposal carefully before applying as AI-generated patches may need adjustment for project-specific context
3. Rotate any confirmed leaked credentials immediately and audit git history for exposure in previous commits
4. Pair static analysis findings with dynamic testing (DAST) for comprehensive security coverage
5. Re-run the scan after applying fixes to verify remediation and catch any regressions
6. Add identified vulnerability patterns to CI/CD pipeline checks to prevent recurrence
