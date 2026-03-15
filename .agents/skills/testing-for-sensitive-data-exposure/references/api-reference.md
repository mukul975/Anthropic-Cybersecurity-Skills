# API Reference: Testing for Sensitive Data Exposure

## requests Library

### TLS Verification
```python
# Check HTTP to HTTPS redirect
resp = requests.get("http://target.com/", allow_redirects=False)

# Check HSTS header
resp = requests.get("https://target.com/")
hsts = resp.headers.get("Strict-Transport-Security", "")
```

## Secret Detection Patterns
| Pattern | Regex | Example |
|---------|-------|---------|
| AWS Access Key | `AKIA[0-9A-Z]{16}` | AKIAIOSFODNN7EXAMPLE |
| Google API Key | `AIza[0-9A-Za-z\-_]{35}` | AIzaSyA... |
| Stripe Secret | `sk_live_[0-9a-zA-Z]{24,}` | sk_live_... |
| GitHub Token | `ghp_[a-zA-Z0-9]{36}` | ghp_xxxx... |
| Private Key | `-----BEGIN PRIVATE KEY-----` | PEM format |

## Exposed File Checks
| File | Risk |
|------|------|
| `.env` | Environment variables with secrets |
| `.git/config` | Git configuration (may contain tokens) |
| `config.json` | Application configuration |
| `.aws/credentials` | AWS access keys |
| `phpinfo.php` | Server configuration disclosure |

## Sensitive API Response Fields
Fields that should never appear in API responses:
- `password`, `password_hash`, `salt`
- `ssn`, `credit_card`, `cvv`
- `api_key`, `secret_key`, `private_key`
- `access_token`, `refresh_token`

## Cache-Control for Sensitive Pages
```
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
```

## References
- OWASP A02:2021 Cryptographic Failures: https://owasp.org/Top10/A02_2021-Cryptographic_Failures/
- OWASP Sensitive Data Exposure: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/
- trufflehog: https://github.com/trufflesecurity/trufflehog
- gitleaks: https://github.com/gitleaks/gitleaks
