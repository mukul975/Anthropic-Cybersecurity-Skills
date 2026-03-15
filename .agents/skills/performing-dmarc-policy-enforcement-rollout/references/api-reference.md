# API Reference — Performing DMARC Policy Enforcement Rollout

## Libraries Used
- **dnspython** (dns.resolver): DNS TXT record queries for DMARC, SPF, DKIM

## CLI Interface

```
python agent.py check --domain example.com
python agent.py audit --domains example.com example.org [--selectors default google k1]
```

## Core Functions

### `check_dmarc(domain)` — Query `_dmarc.<domain>` TXT
### `check_spf(domain)` — Query domain TXT for `v=spf1`
### `check_dkim(domain, selector)` — Query `<selector>._domainkey.<domain>`
### `audit_domains(domains, selectors)` — Full DMARC/SPF/DKIM audit with scoring

## DMARC Policy Levels
| Policy | Enforcement | Score |
|--------|------------|-------|
| `none` | No enforcement (monitoring only) | 0 |
| `quarantine` | Suspicious mail sent to spam | +20 |
| `reject` | Unauthorized mail rejected | +40 |

## Dependencies
```
pip install dnspython>=2.4
```
