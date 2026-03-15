# Active Directory Penetration Test — Report Template

## Document Control
| Field | Value |
|-------|-------|
| Domain | [corp.local] |
| Test Type | Active Directory Security Assessment |
| Starting Access | Standard Domain User |
| Period | [Start] — [End] |

## Executive Summary
[Summary of AD security posture, key attack paths discovered, and domain compromise status]

## Attack Path Diagram
```
testuser (Domain User)
  → Kerberoasting svc_sql (T1558.003)
    → Cracked password: "SqlServer2024!"
      → Local admin on SQL01 (T1078)
        → Mimikatz LSASS dump (T1003.001)
          → DA credentials: da_admin
            → DCSync all hashes (T1003.006)
              → FULL DOMAIN COMPROMISE
```

## Findings

### Finding [N]: [Title]
| Attribute | Detail |
|-----------|--------|
| Severity | [Critical/High/Medium/Low] |
| MITRE ATT&CK | [Technique] |
| Affected | [Accounts/Systems] |
| Remediation | [Fix] |

## Remediation Priority
| # | Action | Timeline |
|---|--------|----------|
| 1 | Deploy gMSA for service accounts | 2 weeks |
| 2 | Fix ADCS vulnerable templates | 1 week |
| 3 | Implement tiered admin model | 30 days |
| 4 | Enable LAPS | 30 days |
