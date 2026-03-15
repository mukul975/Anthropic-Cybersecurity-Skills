# Mobile Traffic Interception Assessment Report

## Engagement Information

| Field | Value |
|-------|-------|
| Application | [APP_NAME] |
| Platform | [Android/iOS] |
| Proxy Tool | Burp Suite [VERSION] |
| Assessment Date | [DATE] |
| Total Requests Captured | [COUNT] |
| Unique Endpoints | [COUNT] |

## API Surface Map

| Method | Endpoint | Auth Required | Description |
|--------|----------|---------------|-------------|
| [METHOD] | [PATH] | [YES/NO] | [DESCRIPTION] |

## Traffic Security Findings

### Finding [N]: [TITLE]

- **Severity**: [CRITICAL/HIGH/MEDIUM/LOW]
- **OWASP Mobile**: [M1-M10]
- **CWE**: [CWE-ID]
- **Affected Endpoint**: [URL]
- **Description**: [DESCRIPTION]
- **Evidence**: [REQUEST/RESPONSE_SNIPPET]
- **Recommendation**: [REMEDIATION]

## Authentication Analysis

| Check | Result | Details |
|-------|--------|---------|
| Token Format | [JWT/Opaque/Other] | [DETAILS] |
| Token Expiration | [DURATION] | [DETAILS] |
| Token in URL | [YES/NO] | [DETAILS] |
| Refresh Mechanism | [Present/Absent] | [DETAILS] |
| Session Invalidation | [Works/Fails] | [DETAILS] |

## Security Header Compliance

| Header | Present | Value | Status |
|--------|---------|-------|--------|
| Strict-Transport-Security | [YES/NO] | [VALUE] | [PASS/FAIL] |
| Content-Security-Policy | [YES/NO] | [VALUE] | [PASS/FAIL] |
| X-Content-Type-Options | [YES/NO] | [VALUE] | [PASS/FAIL] |
| Cache-Control | [YES/NO] | [VALUE] | [PASS/FAIL] |

## Recommendations

1. [RECOMMENDATION]
