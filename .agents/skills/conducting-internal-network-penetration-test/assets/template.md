# Internal Network Penetration Test — Report Template

## Document Control

| Field | Value |
|-------|-------|
| Client | [Client Name] |
| Assessment Type | Internal Network Penetration Test |
| Access Model | Assumed Breach / Unauthenticated |
| Test Period | [Start] — [End] |
| Classification | CONFIDENTIAL |

---

## 1. Executive Summary

### Scope
- **Subnet(s):** [Internal ranges]
- **Domain:** [AD domain]
- **Starting Position:** [Network drop location / VPN / credentials provided]

### Key Findings

| Severity | Count | Example |
|----------|-------|---------|
| Critical | [N] | Domain compromise via credential relay |
| High | [N] | Kerberoastable service accounts with weak passwords |
| Medium | [N] | SMB signing disabled on file servers |
| Low | [N] | Excessive share permissions |

### Attack Path Summary
[Describe the primary attack chain from initial access to domain compromise]

---

## 2. Technical Findings

### Finding [N]: [Title]

| Attribute | Detail |
|-----------|--------|
| Severity | [Critical/High/Medium/Low] |
| CVSS v3.1 | [Score] |
| MITRE ATT&CK | [Technique ID] |
| Affected Assets | [Hosts/accounts] |

**Description:** [Details]
**Steps to Reproduce:** [Steps]
**Evidence:** [Screenshots/logs]
**Remediation:** [Fix]

---

## 3. Recommendations Priority

| Priority | Action | Timeline |
|----------|--------|----------|
| P1 | Disable LLMNR/NBT-NS, enable SMB signing | 1 week |
| P2 | Deploy LAPS, implement tiered admin | 30 days |
| P3 | Enforce strong password policy | 30 days |
| P4 | Review share permissions | 60 days |
