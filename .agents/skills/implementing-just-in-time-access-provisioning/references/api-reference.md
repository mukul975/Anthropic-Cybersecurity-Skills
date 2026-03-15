# API Reference: Implementing Just-In-Time Access Provisioning

## Azure AD PIM API (JIT for Azure)

```python
import requests
headers = {"Authorization": "Bearer <token>"}
# Activate eligible role
requests.post(
    "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleRequests",
    headers=headers,
    json={"action": "selfActivate", "roleDefinitionId": ROLE_ID,
          "directoryScopeId": "/", "justification": "Incident response",
          "scheduleInfo": {"expiration": {"type": "afterDuration", "duration": "PT4H"}}})
```

## JIT Risk-Based Approval

| Risk Level | Approval | Max Duration |
|-----------|----------|-------------|
| Low | Auto-approve | 4 hours |
| Medium | Manager | 8 hours |
| High | Manager + Security | 4 hours |
| Critical | CISO + Manager + Security | 2 hours |

## AWS IAM Access Analyzer

```bash
# Find unused permissions for JIT conversion
aws accessanalyzer list-findings --analyzer-arn ARN --filter '{"status": {"eq": ["ACTIVE"]}}'
```

## CyberArk PAS REST API (JIT Privileged Access)

```bash
# Request JIT access
curl -X POST "https://VAULT/PasswordVault/api/MyRequests" \
  -H "Authorization: $TOKEN" \
  -d '{"AccountId": "ACC_ID", "Reason": "Maintenance", "TicketingSystemName": "ServiceNow"}'
```

## Key Metrics

| Metric | Target |
|--------|--------|
| Avg approval time | < 15 min |
| Auto-approval rate | 40-60% (low risk) |
| Standing privilege reduction | > 80% |
| Expired access auto-revoked | 100% |

### References

- Azure PIM: https://learn.microsoft.com/en-us/azure/active-directory/privileged-identity-management/
- CyberArk JIT: https://docs.cyberark.com/
- NIST 800-53 AC-6: Least Privilege
