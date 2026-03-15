# API Reference: Implementing Honeypot for Ransomware Detection

## Canary File Strategy

| Name Pattern | Extension | Purpose |
|-------------|-----------|---------|
| `!Accounting_*` | .docx, .xlsx | Sorted first alphabetically |
| `~$Confidential_*` | .pdf, .csv | Mimics temp/open Office files |
| `!Payroll_*` | .xlsx, .bak | High-value bait |

## Integrity Monitoring

```python
import hashlib
from pathlib import Path
content = Path("canary.docx").read_bytes()
sha256 = hashlib.sha256(content).hexdigest()
```

## Ransomware Extension Indicators

| Extension | Ransomware Family |
|-----------|------------------|
| `.encrypted` | Generic |
| `.locked` | LockBit, GandCrab |
| `.crypto` | CryptoLocker variants |
| `.ransom` | Generic |
| `.enc` | Various |

## Samba Honeypot Share (full_audit VFS)

```ini
[FinanceArchive]
    path = /srv/honeypot
    vfs objects = full_audit
    full_audit:success = open opendir write rename unlink
    full_audit:failure = open
    full_audit:facility = LOCAL7
    full_audit:priority = NOTICE
```

## Thinkst Canary API

```bash
# List incidents
curl "https://DOMAIN.canary.tools/api/v1/incidents/all" \
  -d auth_token=TOKEN

# Acknowledge incident
curl "https://DOMAIN.canary.tools/api/v1/incident/acknowledge" \
  -d auth_token=TOKEN -d incident=INC_ID
```

## Detection Thresholds

| Metric | Threshold | Severity |
|--------|----------|----------|
| Files modified in 60s | > 50 | CRITICAL |
| Canary file deleted | Any | CRITICAL |
| Canary hash changed | Any | CRITICAL |
| Known ransom extensions | Any | CRITICAL |

### References

- Thinkst Canary: https://canary.tools/
- CISA Ransomware Guide: https://www.cisa.gov/stopransomware
- Canarytokens: https://canarytokens.org/
