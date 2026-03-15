# Mobile API Authentication Test Report

## Target
| Field | Value |
|-------|-------|
| API Base URL | [URL] |
| Application | [APP_NAME] |
| Token Type | [JWT/OAuth/Opaque] |
| Test Date | [DATE] |

## JWT/Token Analysis
| Check | Result | Severity |
|-------|--------|----------|
| Algorithm | [ALG] | [SEVERITY] |
| Expiration | [DURATION] | [SEVERITY] |
| Sensitive Claims | [YES/NO] | [SEVERITY] |
| Signing Key Strength | [WEAK/STRONG] | [SEVERITY] |

## Authentication Tests
| Test | Endpoint | Result | Severity |
|------|----------|--------|----------|
| Missing Auth | [ENDPOINT] | [PASS/FAIL] | [SEVERITY] |
| Expired Token | [ENDPOINT] | [PASS/FAIL] | [SEVERITY] |
| Empty Token | [ENDPOINT] | [PASS/FAIL] | [SEVERITY] |

## Authorization Tests (IDOR)
| Endpoint | Own ID | Other ID | Accessible | Severity |
|----------|--------|----------|-----------|----------|
| [ENDPOINT] | [ID] | [ID] | [YES/NO] | [SEVERITY] |

## Recommendations
1. [RECOMMENDATION]
