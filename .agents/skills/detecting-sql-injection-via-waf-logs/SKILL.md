---
name: detecting-sql-injection-via-waf-logs
description: >-
  Analyze WAF (ModSecurity/AWS WAF/Cloudflare) logs to detect SQL injection
  attack campaigns. Parses ModSecurity audit logs and JSON WAF event logs to
  identify SQLi patterns (UNION SELECT, OR 1=1, SLEEP(), BENCHMARK()), tracks
  attack sources, correlates multi-stage injection attempts, and generates
  incident reports with OWASP classification.
domain: cybersecurity
subdomain: security-operations
tags: [detecting, sql, injection, via]
version: "1.0"
author: mahipal
license: Apache-2.0
---

## Instructions

1. Install dependencies: `pip install requests`
2. Collect WAF logs (ModSecurity audit log, AWS WAF JSON logs, or Cloudflare firewall events).
3. Run the agent to parse and analyze:
   - Detect SQLi payloads via 15+ regex patterns
   - Classify attacks by OWASP injection type (classic, blind, time-based, UNION-based)
   - Identify persistent attackers by IP clustering
   - Correlate multi-request injection campaigns
   - Calculate attack success probability based on response codes

```bash
python scripts/agent.py --log-file /var/log/modsec_audit.log --format modsecurity --output sqli_report.json
```

## Examples

### ModSecurity SQLi Detection
```
Rule 942100 triggered: SQL Injection Attack Detected via libinjection
URI: /api/users?id=1' UNION SELECT username,password FROM users--
Source IP: 203.0.113.42 (47 requests in 5 minutes)
Classification: UNION-based SQLi campaign
```
