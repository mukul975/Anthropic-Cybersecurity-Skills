# API Reference: Implementing Cloud WAF Rules

## Libraries

### boto3 -- AWS WAFv2
- **Install**: `pip install boto3`
- **Docs**: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/wafv2.html

### Key Methods

| Method | Description |
|--------|-------------|
| `create_web_acl()` | Create a new Web ACL |
| `update_web_acl()` | Add/modify rules in a Web ACL |
| `get_web_acl()` | Retrieve Web ACL details and rules |
| `list_web_acls()` | List all Web ACLs in scope |
| `associate_web_acl()` | Attach ACL to ALB, API Gateway, CloudFront |
| `get_sampled_requests()` | View sampled WAF request data |
| `list_available_managed_rule_groups()` | List AWS managed rule sets |
| `create_ip_set()` | Create IP allowlist/blocklist |
| `create_regex_pattern_set()` | Custom regex matching patterns |

## AWS Managed Rule Groups

| Name | Protection |
|------|-----------|
| `AWSManagedRulesCommonRuleSet` | OWASP core (XSS, LFI, RFI) |
| `AWSManagedRulesSQLiRuleSet` | SQL injection |
| `AWSManagedRulesKnownBadInputsRuleSet` | Known exploit patterns |
| `AWSManagedRulesLinuxRuleSet` | Linux LFI patterns |
| `AWSManagedRulesBotControlRuleSet` | Bot detection/management |
| `AWSManagedRulesATPRuleSet` | Account takeover prevention |
| `AWSManagedRulesAnonymousIpList` | VPN/proxy/Tor blocking |

## Rule Statement Types
- `ManagedRuleGroupStatement` -- AWS or marketplace managed rules
- `RateBasedStatement` -- Rate limiting by IP (100-2B req/5min)
- `GeoMatchStatement` -- Country-based blocking
- `ByteMatchStatement` -- Custom string/header matching
- `SqliMatchStatement` -- SQL injection detection
- `XssMatchStatement` -- Cross-site scripting detection
- `RegexPatternSetReferenceStatement` -- Custom regex rules
- `IPSetReferenceStatement` -- IP allowlist/blocklist

## Rule Actions
- `Allow` -- Permit the request
- `Block` -- Reject with 403
- `Count` -- Log only (for testing rules)
- `CAPTCHA` -- Challenge with CAPTCHA
- `Challenge` -- Silent browser challenge

## External References
- AWS WAF Developer Guide: https://docs.aws.amazon.com/waf/latest/developerguide/
- Managed Rules List: https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-list.html
- Azure WAF: https://learn.microsoft.com/en-us/azure/web-application-firewall/
- Cloudflare WAF: https://developers.cloudflare.com/waf/
