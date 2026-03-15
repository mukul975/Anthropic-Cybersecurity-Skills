# API Reference: Vulnerability Exception Tracking

## Exception States
| State | Description |
|-------|------------|
| draft | Initial creation, not yet submitted |
| pending_approval | Awaiting approval chain |
| approved | All approvers accepted |
| rejected | Any approver denied |
| expired | Past expiration date |
| revoked | Manually revoked |

## Approval Chain by Severity
| Severity | Approvers |
|----------|----------|
| Critical | Security Lead -> CISO -> Risk Committee |
| High | Security Lead -> CISO |
| Medium | Security Lead |
| Low | Security Lead |

## Maximum Exception Duration
| Severity | Max Days |
|----------|---------|
| Critical | 30 |
| High | 90 |
| Medium | 180 |
| Low | 365 |

## ServiceNow GRC API
```bash
# Create risk exception
curl -X POST "https://instance.service-now.com/api/now/table/sn_grc_exception" \
  -u "user:pass" \
  -H "Content-Type: application/json" \
  -d '{"short_description":"CVE-2024-1234 exception","risk_score":"8.5","state":"draft"}'
```

## Archer GRC API
```bash
# Create exception record
curl -X POST "https://archer.example.com/api/core/content" \
  -H "Authorization: Archer session-token=$TOKEN" \
  -d '{"Content":{"LevelId":42,"FieldContents":{"1001":{"Value":"Exception for CVE-2024-1234"}}}}'
```

## Compensating Control Categories
| Category | Examples |
|----------|---------|
| Network | Segmentation, ACLs, micro-segmentation |
| Monitoring | Enhanced logging, alerting, SIEM rules |
| Application | WAF rules, input validation, rate limiting |
| Access | MFA, PAM, least privilege enforcement |
| Process | Manual review, change control, audit |
