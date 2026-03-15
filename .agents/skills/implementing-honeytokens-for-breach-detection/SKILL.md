---
name: implementing-honeytokens-for-breach-detection
description: >
  Deploys canary tokens and honeytokens (fake AWS credentials, DNS canaries, document
  beacons, database records) that trigger alerts when accessed by attackers. Uses the
  Canarytokens API and custom webhook integrations for breach detection. Use when
  building deception-based early warning systems for intrusion detection.
domain: cybersecurity
subdomain: security-operations
tags: [implementing, honeytokens, for, breach]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Implementing Honeytokens for Breach Detection

## Instructions

Deploy honeytokens across critical systems to detect unauthorized access. Each token
type alerts via webhook when triggered by an attacker.

```python
import requests

# Create a DNS canary token via Canarytokens
resp = requests.post("https://canarytokens.org/generate", data={
    "type": "dns",
    "email": "soc@company.com",
    "memo": "Production DB server honeytoken",
})
token = resp.json()
print(f"DNS token: {token['hostname']}")
```

Token types to deploy:
1. AWS credential files (~/.aws/credentials) with canary keys
2. DNS tokens embedded in configuration files
3. Document beacons (Word/PDF) in sensitive file shares
4. Database honeytoken records in user tables
5. Web bugs in internal wiki/documentation pages

## Examples

```python
# Generate a fake AWS credentials file with canary token
aws_creds = f"[default]\naws_access_key_id = {canary_key_id}\naws_secret_access_key = {canary_secret}\n"
with open("/opt/backup/.aws/credentials", "w") as f:
    f.write(aws_creds)
```
