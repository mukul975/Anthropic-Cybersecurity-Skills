# API Reference: Implementing DMARC/DKIM/SPF Email Security

## dnspython Lookups

```python
import dns.resolver
# SPF
answers = dns.resolver.resolve("example.com", "TXT")
# DMARC
answers = dns.resolver.resolve("_dmarc.example.com", "TXT")
# DKIM
answers = dns.resolver.resolve("selector._domainkey.example.com", "TXT")
```

## SPF Record Syntax

| Mechanism | Example | Meaning |
|-----------|---------|---------|
| `include:` | `include:_spf.google.com` | Authorize sender |
| `ip4:` | `ip4:203.0.113.0/24` | Allow IP range |
| `-all` | End of record | Hard fail others |
| `~all` | End of record | Soft fail (weak) |
| `+all` | End of record | Allow all (insecure) |

## DMARC Policy Levels

| Policy | Action | Severity if Missing |
|--------|--------|---------------------|
| `p=reject` | Reject failing mail | Recommended |
| `p=quarantine` | Send to spam | Acceptable |
| `p=none` | Monitor only | HIGH risk |

## Recommended DNS Records

```
# SPF
v=spf1 include:_spf.google.com -all

# DMARC
v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@example.com; adkim=s; aspf=s

# DKIM (provider-specific key)
selector._domainkey.example.com TXT "v=DKIM1; k=rsa; p=MIIBIjAN..."
```

### References

- SPF RFC 7208: https://www.rfc-editor.org/rfc/rfc7208
- DMARC RFC 7489: https://www.rfc-editor.org/rfc/rfc7489
- DKIM RFC 6376: https://www.rfc-editor.org/rfc/rfc6376
- dnspython: https://dnspython.readthedocs.io/
