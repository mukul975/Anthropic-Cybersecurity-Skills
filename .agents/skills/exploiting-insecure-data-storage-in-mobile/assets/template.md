# Insecure Data Storage Assessment Report

## Target Application

| Field | Value |
|-------|-------|
| Application | [APP_NAME] |
| Platform | [Android/iOS] |
| Package/Bundle ID | [ID] |
| Assessment Date | [DATE] |
| Device State | [Rooted/Jailbroken] |

## Storage Analysis Summary

| Storage Type | Items Found | Sensitive Data | Encrypted | Risk |
|-------------|------------|----------------|-----------|------|
| SharedPreferences/Plists | [N] | [YES/NO] | [YES/NO] | [RISK] |
| SQLite Databases | [N] | [YES/NO] | [YES/NO] | [RISK] |
| Files on Disk | [N] | [YES/NO] | [YES/NO] | [RISK] |
| Keychain/Keystore | [N] | [YES/NO] | [YES/NO] | [RISK] |
| Backup Data | [N] | [YES/NO] | [YES/NO] | [RISK] |

## Detailed Findings

### Finding [N]: [TITLE]

- **Severity**: [CRITICAL/HIGH/MEDIUM/LOW]
- **OWASP Mobile**: M9 - Insecure Data Storage
- **CWE**: [CWE-ID]
- **Storage Location**: [PATH]
- **Data Type**: [credentials/PII/tokens/keys]
- **Encrypted**: [YES/NO]
- **Evidence**: [SANITIZED_SAMPLE]
- **Recommendation**: [REMEDIATION]

## Recommendations

### Immediate Actions
1. [RECOMMENDATION]

### Short-Term Improvements
1. [RECOMMENDATION]

### Long-Term Architecture Changes
1. [RECOMMENDATION]
