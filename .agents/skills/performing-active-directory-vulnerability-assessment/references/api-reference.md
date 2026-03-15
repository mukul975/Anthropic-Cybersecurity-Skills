# Active Directory Vulnerability Assessment - API Reference

## PingCastle XML Report

PingCastle generates XML health check reports with scoring across four categories:

| Category | Description |
|----------|-------------|
| StaleObjects | Dormant accounts, old computer objects, unused groups |
| PrivilegiedGroup | Excessive admin memberships, unprotected privileged accounts |
| Trust | Insecure trust relationships, SID filtering |
| Anomaly | Unusual configurations, legacy protocols |

### Score Interpretation
- 0-20: Excellent
- 21-50: Good
- 51-75: Needs improvement
- 76-100: Critical

### XML Structure
```xml
<HealthcheckData>
  <GlobalScore>45</GlobalScore>
  <StaleObjectsScore>15</StaleObjectsScore>
  <PrivilegiedGroupScore>20</PrivilegiedGroupScore>
  <RiskRules>
    <HealthcheckRiskRule>
      <RiskId>P-AdminCount</RiskId>
      <Category>PrivilegiedGroup</Category>
      <Points>30</Points>
      <Rationale>15 accounts with adminCount=1</Rationale>
    </HealthcheckRiskRule>
  </RiskRules>
</HealthcheckData>
```

## LDAP Checks (ldap3)

### Password Policy Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `minPwdLength` | int | Minimum password length |
| `lockoutThreshold` | int | Failed attempts before lockout (0 = disabled) |
| `pwdHistoryLength` | int | Number of remembered passwords |
| `maxPwdAge` | interval | Maximum password age |

### krbtgt Account
The krbtgt account key encrypts all Kerberos tickets. If compromised (Golden Ticket attack), all tickets must be invalidated by resetting krbtgt password twice. Recommended rotation: every 180 days.

```python
conn.search(base_dn, "(&(objectClass=user)(sAMAccountName=krbtgt))",
            attributes=["pwdLastSet"])
```

## Vulnerability Categories

### Critical
- No account lockout policy
- krbtgt password > 180 days old
- PingCastle risk rules with 50+ points

### High
- Minimum password length < 12
- Accounts with adminCount=1 not in privileged groups
- Legacy protocols enabled (NTLMv1, LM hashes)

### Medium
- Password history < 12
- Stale computer objects > 90 days
- Unconstrained delegation

## Output Schema

```json
{
  "report": "ad_vulnerability_assessment",
  "pingcastle_scores": {"global": 45, "staleobjects": 15},
  "total_findings": 20,
  "severity_summary": {"critical": 3, "high": 10, "medium": 7}
}
```

## CLI Usage

```bash
python agent.py --pingcastle-xml report.xml --server ldaps://dc.example.com --username "DOMAIN\\user" --password "pass" --output report.json
```
