---
name: analyzing-api-gateway-access-logs
description: 'Parses API Gateway access logs (AWS API Gateway, Kong, Nginx) to detect
  BOLA/IDOR attacks, rate limit bypass, credential scanning, and injection attempts.
  Uses pandas for statistical analysis of request patterns and anomaly detection.
  Use when investigating API abuse or building API-specific threat detection rules.

  '
domain: cybersecurity
subdomain: security-operations
tags:
- api-security
- access-log-analysis
- aws-api-gateway
- kong
- nginx
- bola-detection
- rate-limit-bypass
- security-operations
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- DE.CM-01
- RS.MA-01
- GV.OV-01
- DE.AE-02
mitre_attack:
- T1190
- T1110.004
- T1078.004
- T1119
---

# Analyzing API Gateway Access Logs


## When to Use

- When investigating security incidents that require analyzing api gateway access logs
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Prerequisites

- Familiarity with security operations concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

Parse API gateway access logs to identify attack patterns including broken object
level authorization (BOLA), excessive data exposure, and injection attempts.

```python
import pandas as pd

df = pd.read_json("api_gateway_logs.json", lines=True)
# Detect BOLA: same user accessing many different resource IDs
bola = df.groupby(["user_id", "endpoint"]).agg(
    unique_ids=("resource_id", "nunique")).reset_index()
suspicious = bola[bola["unique_ids"] > 50]
```

Key detection patterns:
1. BOLA/IDOR: sequential resource ID enumeration
2. Rate limit bypass via header manipulation
3. Credential scanning (401 surges from single source)
4. SQL/NoSQL injection in query parameters
5. Unusual HTTP methods (DELETE, PATCH) on read-only endpoints

## Examples

```python
# Detect 401 surges indicating credential scanning
auth_failures = df[df["status_code"] == 401]
scanner_ips = auth_failures.groupby("source_ip").size()
scanners = scanner_ips[scanner_ips > 100]
```
