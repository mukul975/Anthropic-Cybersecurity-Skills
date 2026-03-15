---
name: implementing-mtls-for-zero-trust-services
description: >
  Configures mutual TLS (mTLS) authentication between microservices using Python
  cryptography library for certificate generation and ssl module for TLS verification.
  Validates certificate chains, checks expiration, and audits mTLS deployment status.
  Use when implementing zero-trust service-to-service authentication.
domain: cybersecurity
subdomain: security-operations
tags: [implementing, mtls, for, zero]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Implementing mTLS for Zero Trust Services

## Instructions

Generate CA certificates, issue service certificates, and configure mutual TLS
verification for service-to-service authentication.

```python
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

# Generate CA key and certificate
ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
ca_cert = (x509.CertificateBuilder()
    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Internal CA")]))
    .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Internal CA")]))
    .public_key(ca_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(ca_key, hashes.SHA256()))
```

## Examples

```python
import ssl
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.load_cert_chain("client.pem", "client-key.pem")
context.load_verify_locations("ca.pem")
context.verify_mode = ssl.CERT_REQUIRED
```
