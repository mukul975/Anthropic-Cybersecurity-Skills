# Standards - Semgrep Custom SAST Rules

## OWASP Top 10 (2021) Coverage

| Category | Semgrep Detection |
|----------|------------------|
| A01 Broken Access Control | Authorization bypass patterns |
| A02 Cryptographic Failures | Weak crypto, hardcoded secrets |
| A03 Injection | SQL, XSS, command injection (taint mode) |
| A04 Insecure Design | Missing input validation |
| A05 Security Misconfiguration | Debug mode, insecure defaults |
| A06 Vulnerable Components | Deprecated API usage |
| A07 Auth Failures | JWT misconfig, session issues |
| A08 Software/Data Integrity | Deserialization, unsigned data |
| A09 Logging Failures | Missing audit logging |
| A10 SSRF | Server-side request forgery (taint mode) |

## CWE Coverage
Common CWEs detectable via Semgrep custom rules: CWE-79 (XSS), CWE-89 (SQLi), CWE-798 (Hardcoded Credentials), CWE-330 (Insecure Random), CWE-502 (Deserialization), CWE-918 (SSRF)

## NIST SP 800-53 Rev 5
- SA-11: Developer Security Testing
- SA-15: Development Process, Standards, and Tools

## Compliance
- PCI DSS v4.0 Req 6.3.2: Secure development with automated tools
- SOC 2 CC8.1: Change management with code scanning
