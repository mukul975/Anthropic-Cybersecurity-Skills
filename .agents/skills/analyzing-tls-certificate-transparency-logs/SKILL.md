---
name: analyzing-tls-certificate-transparency-logs
description: >
  Queries Certificate Transparency logs via crt.sh and pycrtsh to detect phishing
  domains, unauthorized certificate issuance, and shadow IT. Monitors newly issued
  certificates for typosquatting and brand impersonation using Levenshtein distance.
  Use for proactive phishing domain detection and certificate monitoring.
domain: cybersecurity
subdomain: security-operations
tags: [analyzing, tls, certificate, transparency]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Analyzing TLS Certificate Transparency Logs

## Instructions

Query crt.sh Certificate Transparency database to find certificates issued for
domains similar to your organization's brand, detecting phishing infrastructure.

```python
from pycrtsh import Crtsh

c = Crtsh()
# Search for certificates matching a domain
certs = c.search("example.com")
for cert in certs:
    print(cert["id"], cert["name_value"])

# Get full certificate details
details = c.get(certs[0]["id"], type="id")
```

Key analysis steps:
1. Query crt.sh for all certificates matching your domain pattern
2. Identify certificates with typosquatting variations (Levenshtein distance)
3. Flag certificates from unexpected CAs
4. Monitor for wildcard certificates on suspicious subdomains
5. Cross-reference with known phishing infrastructure

## Examples

```python
from pycrtsh import Crtsh
c = Crtsh()
certs = c.search("%.example.com")
for cert in certs:
    print(f"Issuer: {cert.get('issuer_name')}, Domain: {cert.get('name_value')}")
```
