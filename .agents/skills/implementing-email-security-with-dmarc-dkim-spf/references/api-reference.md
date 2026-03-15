# API Reference: Email Security (SPF/DKIM/DMARC)

## dnspython TXT Query
```python
import dns.resolver
answers = dns.resolver.resolve("example.com", "TXT")
for rdata in answers:
    txt = b"".join(rdata.strings).decode("utf-8")
```

## SPF Record Format
```
v=spf1 [mechanisms] [qualifier]all
```
| Mechanism | Example | Description |
|-----------|---------|-------------|
| `include:` | `include:_spf.google.com` | Include other SPF record |
| `ip4:` | `ip4:203.0.113.0/24` | Allow IPv4 range |
| `ip6:` | `ip6:2001:db8::/32` | Allow IPv6 range |
| `a:` | `a:mail.example.com` | Allow A record IP |
| `mx:` | `mx:example.com` | Allow MX record IPs |
| `redirect=` | `redirect=_spf.example.com` | Redirect to another SPF |

| Qualifier | Meaning | Effect |
|-----------|---------|--------|
| `-all` | Fail | Reject unauthorized senders |
| `~all` | Softfail | Accept but mark |
| `?all` | Neutral | No policy |
| `+all` | Pass | Allow all (insecure) |

**Limit**: Max 10 DNS lookups (includes, a, mx, ptr, exists, redirect).

## DKIM Record Query
```
{selector}._domainkey.{domain} TXT
```
```
v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEB...
```
| Tag | Description |
|-----|-------------|
| `v` | Version (DKIM1) |
| `k` | Key type (rsa, ed25519) |
| `p` | Public key (Base64) |
| `t` | Flags (y=testing, s=strict) |

Common selectors: `google`, `default`, `selector1`, `selector2`, `k1`, `mail`, `dkim`, `s1`, `s2`, `mandrill`, `smtpapi`

## DMARC Record Query
```
_dmarc.{domain} TXT
```
```
v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100
```
| Tag | Values | Description |
|-----|--------|-------------|
| `p` | none/quarantine/reject | Policy for domain |
| `sp` | none/quarantine/reject | Subdomain policy |
| `pct` | 0-100 | Percentage of messages to apply policy |
| `rua` | mailto:URI | Aggregate report destination |
| `ruf` | mailto:URI | Forensic report destination |
| `adkim` | r/s | DKIM alignment (relaxed/strict) |
| `aspf` | r/s | SPF alignment (relaxed/strict) |

## Risk Scoring
| Condition | Score |
|-----------|-------|
| No SPF record | +40 critical |
| SPF +all | +40 critical |
| SPF ~all | +10 medium |
| No DKIM | +25 high |
| No DMARC | +40 critical |
| DMARC p=none | +25 high |
| DMARC pct < 100 | +10 medium |
