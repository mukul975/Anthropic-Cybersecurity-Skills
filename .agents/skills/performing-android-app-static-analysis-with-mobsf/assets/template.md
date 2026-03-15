# MobSF Static Analysis Report Template

## Engagement Information

| Field | Value |
|-------|-------|
| Application Name | [APP_NAME] |
| Package Name | [PACKAGE_NAME] |
| Version | [VERSION] |
| Target SDK | [TARGET_SDK] |
| Min SDK | [MIN_SDK] |
| File Hash (SHA256) | [HASH] |
| Analysis Date | [DATE] |
| Analyst | [ANALYST] |
| MobSF Version | [MOBSF_VERSION] |

## Executive Summary

**Security Score**: [SCORE]/100

**Overall Risk Rating**: [HIGH/MEDIUM/LOW]

[Brief narrative of key findings and overall security posture]

## Findings Summary

| Severity | Count | Categories |
|----------|-------|------------|
| Critical | [N] | [Categories] |
| High | [N] | [Categories] |
| Medium | [N] | [Categories] |
| Low | [N] | [Categories] |
| Info | [N] | [Categories] |

## Manifest Analysis

### Exported Components

| Component Type | Name | Permission Guard | Risk |
|---------------|------|-------------------|------|
| Activity | [NAME] | [PERMISSION/None] | [RISK] |
| Service | [NAME] | [PERMISSION/None] | [RISK] |
| Receiver | [NAME] | [PERMISSION/None] | [RISK] |
| Provider | [NAME] | [PERMISSION/None] | [RISK] |

### Permissions Requested

| Permission | Protection Level | Justification | Risk |
|-----------|-----------------|---------------|------|
| [PERMISSION] | [dangerous/normal/signature] | [JUSTIFICATION] | [RISK] |

### Manifest Flags

| Flag | Value | Expected | Status |
|------|-------|----------|--------|
| android:debuggable | [VALUE] | false | [PASS/FAIL] |
| android:allowBackup | [VALUE] | false | [PASS/FAIL] |
| android:usesCleartextTraffic | [VALUE] | false | [PASS/FAIL] |

## Code Analysis Findings

### Finding [N]: [TITLE]

- **Severity**: [CRITICAL/HIGH/MEDIUM/LOW]
- **CWE**: [CWE-ID]
- **OWASP Mobile**: [M1-M10]
- **MASVS**: [MASVS-CATEGORY]
- **Description**: [DESCRIPTION]
- **Affected Files**:
  - [FILE_PATH:LINE_NUMBER]
- **Evidence**: [CODE_SNIPPET]
- **Recommendation**: [REMEDIATION_STEPS]

## Network Security Analysis

| Check | Result | Details |
|-------|--------|---------|
| Certificate Pinning | [Present/Absent] | [DETAILS] |
| Network Security Config | [Present/Absent] | [DETAILS] |
| Cleartext Traffic | [Allowed/Blocked] | [DETAILS] |
| TLS Version | [VERSION] | [DETAILS] |

## Binary Analysis

| Check | Result | Details |
|-------|--------|---------|
| Code Obfuscation | [Yes/No] | [DETAILS] |
| Root Detection | [Present/Absent] | [DETAILS] |
| Debug Detection | [Present/Absent] | [DETAILS] |
| Emulator Detection | [Present/Absent] | [DETAILS] |
| Native Libraries (NX) | [Enabled/Disabled] | [DETAILS] |
| Native Libraries (PIE) | [Enabled/Disabled] | [DETAILS] |
| Native Libraries (Stack Canary) | [Present/Absent] | [DETAILS] |

## Recommendations

### Critical (Immediate Action Required)

1. [RECOMMENDATION]

### High (Fix Before Release)

1. [RECOMMENDATION]

### Medium (Address in Next Sprint)

1. [RECOMMENDATION]

### Low (Track in Backlog)

1. [RECOMMENDATION]

## OWASP Mobile Top 10 2024 Compliance

| ID | Risk | Status | Findings |
|----|------|--------|----------|
| M1 | Improper Credential Usage | [PASS/FAIL] | [DETAILS] |
| M2 | Inadequate Supply Chain Security | [PASS/FAIL] | [DETAILS] |
| M3 | Insecure Authentication/Authorization | [PASS/FAIL] | [DETAILS] |
| M4 | Insufficient Input/Output Validation | [PASS/FAIL] | [DETAILS] |
| M5 | Insecure Communication | [PASS/FAIL] | [DETAILS] |
| M6 | Inadequate Privacy Controls | [PASS/FAIL] | [DETAILS] |
| M7 | Insufficient Binary Protections | [PASS/FAIL] | [DETAILS] |
| M8 | Security Misconfiguration | [PASS/FAIL] | [DETAILS] |
| M9 | Insecure Data Storage | [PASS/FAIL] | [DETAILS] |
| M10 | Insufficient Cryptography | [PASS/FAIL] | [DETAILS] |
