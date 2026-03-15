# Standards Reference: DAST with OWASP ZAP

## OWASP Top 10 - DAST Coverage

| OWASP Category | ZAP Detection | Alert IDs |
|----------------|---------------|-----------|
| A01: Broken Access Control | Partial | 10020, 10035, 40012 |
| A02: Cryptographic Failures | Yes | 10003, 10041 |
| A03: Injection | Yes | 40012, 40014, 40018, 40019 |
| A05: Security Misconfiguration | Yes | 10015, 10020, 10021, 10035 |
| A07: Auth Failures | Partial | 10010, 10054 |
| A09: Logging Failures | Yes | 10035 |
| A10: SSRF | Partial | Custom scan |

## OWASP SAMM - Verification: Security Testing

### Level 2: DAST Integration
- Automated DAST scanning in CI/CD pipelines
- Baseline scans on every deployment, full scans weekly
- Findings tracked and triaged with defined SLAs

### Level 3: Advanced DAST
- Authenticated scanning with session management
- API-specific scanning with OpenAPI specifications
- Custom scan policies tuned for application-specific risks

## NIST SSDF (SP 800-218)

### PW.8: Test Executable Code
- PW.8.1: Test executable code using dynamic analysis
- DAST validates running application behavior against security requirements
- Integration into CI/CD automates regular testing

## PCI DSS v4.0

- 6.2.4: Use automated methods to prevent common attacks (XSS, SQLi)
- 6.4.1: Web applications are protected against known attacks
- 11.3.1: Internal vulnerability scans performed at least quarterly
