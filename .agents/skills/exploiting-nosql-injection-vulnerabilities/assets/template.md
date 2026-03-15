# NoSQL Injection Assessment Report Template

## Target Information
- **Application URL**: [url]
- **Database Type**: MongoDB / CouchDB / Other
- **Assessment Date**: [date]
- **Tester**: [name]

## Findings Summary

| Finding | Severity | Endpoint | Impact |
|---------|----------|----------|--------|
| Operator Injection | Critical | POST /api/login | Authentication Bypass |
| Blind Regex Extraction | High | POST /api/login | Data Leakage |
| $where JS Injection | Critical | POST /api/search | Potential RCE |

## Detailed Findings

### Finding 1: Authentication Bypass via Operator Injection
- **Endpoint**: POST /api/login
- **Payload**: `{"username":{"$ne":""},"password":{"$ne":""}}`
- **Impact**: Complete authentication bypass allowing access to any account
- **CVSS Score**: 9.8 (Critical)

### Remediation Steps
1. Validate input types — reject objects/arrays where strings are expected
2. Use MongoDB driver parameterized query methods
3. Implement server-side schema validation with JSON Schema
4. Disable $where and mapReduce JavaScript execution
5. Apply least-privilege database user permissions
