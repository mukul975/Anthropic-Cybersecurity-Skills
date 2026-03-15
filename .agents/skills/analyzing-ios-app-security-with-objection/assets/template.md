# iOS Objection Security Assessment Report

## Engagement Information

| Field | Value |
|-------|-------|
| Application | [APP_NAME] |
| Bundle ID | [BUNDLE_ID] |
| iOS Version | [IOS_VERSION] |
| Device | [DEVICE_MODEL] |
| Device State | [Jailbroken/Non-Jailbroken] |
| Assessment Date | [DATE] |
| Analyst | [ANALYST] |
| Objection Version | [VERSION] |

## Executive Summary

[Brief narrative of findings from Objection runtime analysis]

## Keychain Analysis

| Service | Account | Data Type | Protection Class | Risk |
|---------|---------|-----------|-----------------|------|
| [SERVICE] | [ACCOUNT] | [TYPE] | [CLASS] | [RISK] |

**Findings**: [Description of sensitive data found in keychain]

## Data Storage Assessment

### NSUserDefaults
| Key | Contains Sensitive Data | Risk |
|-----|----------------------|------|
| [KEY] | [YES/NO] | [RISK] |

### SQLite Databases
| Database | Encrypted | Sensitive Tables | Risk |
|----------|-----------|-----------------|------|
| [DB_NAME] | [YES/NO] | [TABLES] | [RISK] |

### Filesystem
| Path | Contents | Protection | Risk |
|------|----------|-----------|------|
| [PATH] | [DESCRIPTION] | [ATTRIBUTE] | [RISK] |

## Network Security

| Check | Result | Details |
|-------|--------|---------|
| SSL Pinning Present | [YES/NO] | [IMPLEMENTATION_DETAILS] |
| SSL Pinning Bypass | [SUCCESS/FAIL] | [METHOD_USED] |
| ATS Configuration | [STRICT/RELAXED] | [EXCEPTIONS] |

## Binary Protection Assessment

| Protection | Status | Details |
|-----------|--------|---------|
| Jailbreak Detection | [Present/Absent] | [BYPASS_DIFFICULTY] |
| Frida Detection | [Present/Absent] | [DETAILS] |
| Debug Detection | [Present/Absent] | [DETAILS] |
| Code Obfuscation | [Yes/No] | [DETAILS] |

## Memory Analysis

| Search Pattern | Found | Risk | Details |
|---------------|-------|------|---------|
| Passwords | [YES/NO] | [RISK] | [DETAILS] |
| Auth Tokens | [YES/NO] | [RISK] | [DETAILS] |
| API Keys | [YES/NO] | [RISK] | [DETAILS] |
| JWTs | [YES/NO] | [RISK] | [DETAILS] |

## Recommendations

### Critical
1. [RECOMMENDATION]

### High
1. [RECOMMENDATION]

### Medium
1. [RECOMMENDATION]
