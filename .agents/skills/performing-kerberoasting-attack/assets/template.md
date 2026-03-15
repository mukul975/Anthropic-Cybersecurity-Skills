# Kerberoasting Assessment Report Template

## Document Control
| Field | Value |
|-------|-------|
| Domain | [DOMAIN.LOCAL] |
| Engagement ID | [ID] |
| Assessor | [NAME] |
| Date | [DATE] |

---

## 1. Summary
Total Kerberoastable Accounts: [X]
Credentials Cracked: [Y] / [X]

## 2. Vulnerable Accounts

| Account | SPN | Admin | Cracked | Password Age (days) |
|---------|-----|-------|---------|-------------------|
| | | Yes/No | Yes/No | |

## 3. Attack Evidence

### TGS Request Command
```
[command used]
```

### Cracking Command
```
[hashcat command]
```

### Cracked Output
```
[account:password]
```

## 4. Impact Assessment

| Account | Access Level | Systems Affected | Risk |
|---------|-------------|-----------------|------|
| | | | Critical/High/Medium |

## 5. Recommendations

| # | Recommendation | Priority | Effort |
|---|---------------|----------|--------|
| 1 | Convert to gMSA | Critical | Medium |
| 2 | Set 25+ char passwords | Critical | Low |
| 3 | Disable RC4 encryption | High | Medium |
| 4 | Deploy SPN honeypots | Medium | Low |

## 6. MITRE ATT&CK Reference
- T1558.003 - Kerberoasting
- T1087.002 - Domain Account Discovery
