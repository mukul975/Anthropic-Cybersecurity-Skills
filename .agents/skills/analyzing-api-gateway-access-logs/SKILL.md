---
name: analyzing-api-gateway-access-logs
description: >
  Parses API Gateway access logs (AWS API Gateway, Kong, Nginx) to detect BOLA/IDOR
  attacks, rate limit bypass, credential scanning, and injection attempts. Uses pandas
  for statistical analysis of request patterns and anomaly detection. Use when
  investigating API abuse or building API-specific threat detection rules.
domain: cybersecurity
subdomain: security-operations
tags: [analyzing, api, gateway, access]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Analyzing API Gateway Access Logs

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
