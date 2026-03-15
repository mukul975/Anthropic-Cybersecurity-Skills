# API Reference: Securing API Gateway with AWS WAF

## boto3 WAFv2 Client

### Installation
```bash
pip install boto3
```

### Client Initialization
```python
client = boto3.client("wafv2", region_name="us-east-1")
```

### Key Methods

| Method | Description |
|--------|-------------|
| `create_web_acl()` | Create a new Web ACL with rules and default action |
| `update_web_acl()` | Modify rules, requires `LockToken` for optimistic concurrency |
| `get_web_acl()` | Retrieve full Web ACL configuration and lock token |
| `list_web_acls()` | List all Web ACLs in a scope (REGIONAL or CLOUDFRONT) |
| `associate_web_acl()` | Attach Web ACL to API Gateway, ALB, or AppSync |
| `get_sampled_requests()` | Retrieve sampled requests for a specific rule metric |
| `get_rate_based_statement_managed_keys()` | Get IPs currently rate-limited |
| `put_logging_configuration()` | Configure WAF logging to Firehose/S3 |
| `list_resources_for_web_acl()` | List resources associated with a Web ACL |

### Managed Rule Groups
| Rule Group | Protection |
|-----------|------------|
| `AWSManagedRulesCommonRuleSet` | OWASP Top 10 common attacks |
| `AWSManagedRulesSQLiRuleSet` | SQL injection patterns |
| `AWSManagedRulesKnownBadInputsRuleSet` | Known bad request patterns |
| `AWSManagedRulesAmazonIpReputationList` | Malicious IP blocking |
| `AWSManagedRulesBotControlRuleSet` | Bot detection and management |

### Rate-Based Rule Parameters
| Parameter | Type | Description |
|-----------|------|-------------|
| `Limit` | int | Max requests per 5-minute window (min: 100) |
| `AggregateKeyType` | str | `IP` or `FORWARDED_IP` |
| `ScopeDownStatement` | dict | Optional filter to scope rate limiting |

### CloudWatch Metrics (Namespace: AWS/WAFV2)
| Metric | Description |
|--------|-------------|
| `AllowedRequests` | Requests allowed by WAF |
| `BlockedRequests` | Requests blocked by WAF |
| `CountedRequests` | Requests matched in Count mode |
| `PassedRequests` | Requests not matching any rule |

## References
- boto3 WAFv2 docs: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/wafv2.html
- AWS WAF Developer Guide: https://docs.aws.amazon.com/waf/latest/developerguide/
- AWS Managed Rules list: https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-list.html
