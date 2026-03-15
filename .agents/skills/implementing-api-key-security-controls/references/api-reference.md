# API Reference: Implementing API Key Security Controls

## Secure Key Generation

```python
import secrets, hashlib
key = f"sk_{secrets.token_hex(32)}"
key_hash = hashlib.sha256(key.encode()).hexdigest()  # Store hash only
```

## Leaked Key Patterns

| Pattern | Service |
|---------|---------|
| `sk_live_[a-zA-Z0-9]{24,}` | Stripe |
| `AKIA[0-9A-Z]{16}` | AWS |
| `AIza[0-9A-Za-z_-]{35}` | Google |
| `ghp_[a-zA-Z0-9]{36}` | GitHub PAT |
| `sk-[a-zA-Z0-9]{48}` | OpenAI |

## Key Rotation Policy

| Criteria | Threshold | Severity |
|----------|-----------|----------|
| Key age > 90 days | Rotation required | HIGH |
| Unused > 30 days | Revocation candidate | MEDIUM |
| Wildcard scope | Scope reduction needed | HIGH |
| Shared across IPs | Possible leak | HIGH |

## TruffleHog Scanning

```bash
trufflehog filesystem --directory /path/to/code --json
trufflehog git https://github.com/org/repo --json
```

## GitHub Secret Scanning API

```bash
curl -H "Authorization: token $TOKEN" \
  https://api.github.com/repos/OWNER/REPO/secret-scanning/alerts
```

### References

- GitHub Secret Scanning: https://docs.github.com/en/code-security/secret-scanning
- TruffleHog: https://github.com/trufflesecurity/trufflehog
- OWASP API Key Management: https://cheatsheetseries.owasp.org/cheatsheets/API_Security_Cheat_Sheet.html
