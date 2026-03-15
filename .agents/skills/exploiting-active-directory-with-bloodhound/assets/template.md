# BloodHound AD Assessment Report Template

## Document Control

| Field | Value |
|-------|-------|
| Domain | [DOMAIN.LOCAL] |
| Engagement ID | [ID] |
| Assessor | [NAME] |
| Date | [DATE] |
| Classification | CONFIDENTIAL |

---

## 1. Executive Summary

[Overview of AD security posture based on BloodHound analysis]

**Critical Findings:**
- [X] attack paths to Domain Admin identified
- [Y] Kerberoastable accounts with privileged access
- [Z] systems with unconstrained delegation

---

## 2. Attack Path Summary

### 2.1 Shortest Path to Domain Admin

| # | Step | From | To | Edge/Method | Tool Required |
|---|------|------|----|-------------|--------------|
| 1 | | | | | |
| 2 | | | | | |

### 2.2 ACL-Based Paths

| Source | Target | Right | Abuse Method |
|--------|--------|-------|-------------|
| | | GenericAll/WriteDACL/etc. | |

### 2.3 Session-Based Paths

| Computer | Privileged Session | Path to Computer |
|----------|-------------------|-----------------|
| | | |

---

## 3. Kerberoasting Targets

| Account | SPN | Admin Count | Cracked | Password |
|---------|-----|-------------|---------|----------|
| | | Yes/No | Yes/No | [REDACTED] |

## 4. AS-REP Roasting Targets

| Account | Hash Type | Cracked | Notes |
|---------|-----------|---------|-------|
| | | Yes/No | |

## 5. Delegation Issues

### Unconstrained Delegation
| Computer | OS | DC | Notes |
|----------|----|----|-------|
| | | No | |

### Constrained Delegation
| Object | Allowed To Delegate To | Abuse Potential |
|--------|------------------------|-----------------|
| | | |

---

## 6. Recommendations

### Critical (Immediate)
1. [Recommendation]

### High (30 days)
1. [Recommendation]

### Medium (90 days)
1. [Recommendation]

---

## Appendix: Cypher Queries Used

```cypher
[Query 1]
```

```cypher
[Query 2]
```
