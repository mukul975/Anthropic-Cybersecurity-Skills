---
name: implementing-email-security-with-dmarc-dkim-spf
description: >-
  Audit and validate email authentication configurations by checking SPF, DKIM,
  and DMARC DNS records for a domain. Uses dnspython to query TXT records,
  validates SPF syntax and lookup counts, verifies DKIM selector records,
  parses DMARC policies, and identifies misconfigurations that enable email
  spoofing. Generates remediation recommendations.
domain: cybersecurity
subdomain: security-operations
tags: [implementing, email, security, with]
version: "1.0"
author: mahipal
license: Apache-2.0
---

## Instructions

1. Install dependencies: `pip install dnspython checkdmarc`
2. Provide target domain(s) to audit.
3. Run the agent to check email security:
   - Query and validate SPF records (syntax, mechanism count, includes, redirect)
   - Check DKIM records for common selectors (google, default, selector1, selector2)
   - Parse DMARC records (policy, subdomain policy, reporting URIs, alignment)
   - Identify misconfigurations enabling spoofing
   - Generate remediation recommendations

```bash
python scripts/agent.py --domain example.com --output email_security_report.json
```

## Examples

### Email Security Audit Result
```
Domain: example.com
SPF: v=spf1 include:_spf.google.com ~all (WARN: softfail allows spoofing)
DKIM: selector1 OK, selector2 OK
DMARC: v=DMARC1; p=none; rua=mailto:dmarc@example.com (WARN: policy=none, no enforcement)
Risk: HIGH - p=none with ~all allows email spoofing
```
