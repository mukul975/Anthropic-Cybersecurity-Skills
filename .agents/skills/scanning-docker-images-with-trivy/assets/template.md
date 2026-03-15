# Trivy Image Scan Report Template

## Scan Information

| Field | Value |
|-------|-------|
| Image | |
| Tag/Digest | |
| Scan Date | |
| Trivy Version | |
| DB Version | |
| Scanners Used | vuln / misconfig / secret / license |

## Vulnerability Summary

| Severity | Count | Threshold | Status |
|----------|-------|-----------|--------|
| CRITICAL | | 0 | PASS/FAIL |
| HIGH | | 5 | PASS/FAIL |
| MEDIUM | | 20 | PASS/FAIL |
| LOW | | N/A | INFO |
| UNKNOWN | | N/A | INFO |

## Critical Findings

| CVE ID | Package | Installed | Fixed | CVSS | Description |
|--------|---------|-----------|-------|------|-------------|
| | | | | | |

## High Findings

| CVE ID | Package | Installed | Fixed | CVSS | Description |
|--------|---------|-----------|-------|------|-------------|
| | | | | | |

## Secrets Detected

| Rule ID | Category | Severity | File | Match (redacted) |
|---------|----------|----------|------|------------------|
| | | | | |

## Misconfigurations

| ID | Type | Severity | Title | Resolution |
|----|------|----------|-------|------------|
| | | | | |

## SBOM Summary

| Package Type | Count |
|-------------|-------|
| OS packages | |
| Python packages | |
| Node.js packages | |
| Go modules | |
| Java libraries | |

## Policy Decision

- [ ] APPROVED for deployment
- [ ] BLOCKED - requires remediation
- [ ] EXCEPTION GRANTED (see risk acceptance below)

## Risk Acceptance (if applicable)

| CVE ID | Justification | Expiry Date | Approved By |
|--------|--------------|-------------|-------------|
| | | | |

## Remediation Actions

| Priority | CVE/Finding | Action | Owner | ETA |
|----------|-------------|--------|-------|-----|
| P1 | | | | |
| P2 | | | | |
