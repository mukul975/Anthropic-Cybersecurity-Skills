---
name: performing-ssl-tls-security-assessment
description: Assess SSL/TLS server configurations using the sslyze Python library to evaluate cipher suites, certificate chains,
  protocol versions, HSTS headers, and known vulnerabilities like Heartbleed and ROBOT.
domain: cybersecurity
subdomain: network-security
tags:
- network-security
- ssl
- tls
- sslyze
- certificate
- cipher-suites
- vulnerability-assessment
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- PR.IR-01
- DE.CM-01
- ID.AM-03
- PR.DS-02
---
# Performing SSL/TLS Security Assessment

## Overview

Assess SSL/TLS server configurations using sslyze, a fast Python-based scanning library. This skill covers evaluating supported protocol versions (SSLv2/3, TLS 1.0-1.3), cipher suite strength, certificate chain validation, HSTS enforcement, OCSP stapling, and scanning for known vulnerabilities including Heartbleed, ROBOT, and session renegotiation weaknesses.


## When to Use

- When validating TLS configuration of a web server, API endpoint, or load balancer during a security assessment
- When checking compliance with TLS hardening standards (PCI-DSS, NIST SP 800-52, Mozilla SSL Configuration)
- When investigating a potential certificate issue, cipher downgrade, or known TLS vulnerability on a target host
- When building automated TLS posture reports for a fleet of HTTPS servers

**Do not use** for passive network capture analysis; use Wireshark or Zeek for capturing TLS handshakes in transit.

## Prerequisites

- Python 3.9+ with `sslyze` library (`pip install sslyze`)
- Network access to target HTTPS servers on port 443 (or custom port)
- Understanding of TLS protocol versions and cipher suite classifications (IANA names vs OpenSSL names)

## Workflow

### Step 1: Configure and Run a Basic Server Scan

```python
from sslyze import Scanner, ServerScanRequest, ServerNetworkLocation
from sslyze.plugins.scan_commands import ScanCommand

# Define target
location = ServerNetworkLocation("example.com", 443)

# Queue all scan commands
request = ServerScanRequest(
    server_location=location,
    scan_commands={
        ScanCommand.CERTIFICATE_INFO,
        ScanCommand.SSL_2_0_CIPHER_SUITES,
        ScanCommand.SSL_3_0_CIPHER_SUITES,
        ScanCommand.TLS_1_0_CIPHER_SUITES,
        ScanCommand.TLS_1_1_CIPHER_SUITES,
        ScanCommand.TLS_1_2_CIPHER_SUITES,
        ScanCommand.TLS_1_3_CIPHER_SUITES,
        ScanCommand.HEARTBLEED,
        ScanCommand.ROBOT,
        ScanCommand.SESSION_RENEGOTIATION,
        ScanCommand.HTTP_HEADERS,
    },
)

scanner = Scanner()
scanner.queue_scans([request])

for result in scanner.get_results():
    print(f"Scan complete for {result.server_location.hostname}")
    if result.scan_result is None:
        print(f"  ERROR: {result.connectivity_error_trace}")
```

### Step 2: Evaluate Supported Protocol Versions

```python
from sslyze.plugins.scan_commands import ScanCommand

PROTOCOL_COMMANDS = {
    "SSLv2": ScanCommand.SSL_2_0_CIPHER_SUITES,
    "SSLv3": ScanCommand.SSL_3_0_CIPHER_SUITES,
    "TLSv1.0": ScanCommand.TLS_1_0_CIPHER_SUITES,
    "TLSv1.1": ScanCommand.TLS_1_1_CIPHER_SUITES,
    "TLSv1.2": ScanCommand.TLS_1_2_CIPHER_SUITES,
    "TLSv1.3": ScanCommand.TLS_1_3_CIPHER_SUITES,
}

INSECURE_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}
findings = []

scan_result = result.scan_result
for proto_name, command in PROTOCOL_COMMANDS.items():
    proto_result = getattr(scan_result, command.value)
    accepted = proto_result.accepted_cipher_suites
    if accepted:
        status = "FAIL" if proto_name in INSECURE_PROTOCOLS else "OK"
        findings.append({
            "protocol": proto_name,
            "status": status,
            "cipher_count": len(accepted),
            "example_cipher": accepted[0].cipher_suite.name if accepted else None,
        })
        print(f"  [{status}] {proto_name}: {len(accepted)} cipher suites accepted")
```

### Step 3: Check Certificate Chain Validity

```python
from datetime import datetime, timezone

cert_result = scan_result.certificate_info
for deployment in cert_result.certificate_deployments:
    chain = deployment.received_certificate_chain
    leaf = chain[0]

    # Extract key fields
    subject = leaf.subject.rfc4514_string()
    not_after = leaf.not_valid_after_utc
    days_remaining = (not_after - datetime.now(timezone.utc)).days
    key_size = leaf.public_key().key_size if hasattr(leaf.public_key(), "key_size") else "N/A"

    issues = []
    if days_remaining < 0:
        issues.append("EXPIRED")
    elif days_remaining < 30:
        issues.append(f"EXPIRES_SOON ({days_remaining}d)")
    if key_size != "N/A" and key_size < 2048:
        issues.append(f"WEAK_KEY ({key_size}-bit)")
    if not deployment.verified_certificate_chain:
        issues.append("CHAIN_UNTRUSTED")

    print(f"  Subject: {subject}")
    print(f"  Expires: {not_after.date()} ({days_remaining} days)")
    print(f"  Key size: {key_size} bits")
    print(f"  Issues: {issues if issues else 'None'}")
```

### Step 4: Scan for Known Vulnerabilities and HSTS

```python
# Heartbleed
hb = scan_result.heartbleed
if hb.is_vulnerable_to_heartbleed:
    print("  [CRITICAL] HEARTBLEED: Server is vulnerable")
else:
    print("  [OK] Heartbleed: Not vulnerable")

# ROBOT (Return Of Bleichenbacher's Oracle Threat)
robot = scan_result.robot
print(f"  ROBOT result: {robot.robot_result.name}")
if "VULNERABLE" in robot.robot_result.name:
    print("  [HIGH] ROBOT: Server is vulnerable to RSA decryption oracle")

# Session renegotiation
renegotiation = scan_result.session_renegotiation
if renegotiation.is_vulnerable_to_client_renegotiation_dos:
    print("  [HIGH] Client-initiated renegotiation DoS: VULNERABLE")
if not renegotiation.supports_secure_renegotiation:
    print("  [MEDIUM] Secure renegotiation (RFC 5746): NOT supported")

# HSTS header
headers = scan_result.http_headers
if headers.strict_transport_security_header:
    hsts = headers.strict_transport_security_header
    print(f"  [OK] HSTS: max-age={hsts.max_age}, includeSubDomains={hsts.include_subdomains}")
else:
    print("  [MEDIUM] HSTS: Header not present")
```

### Step 5: Generate JSON Report

```python
import json
from dataclasses import dataclass, field, asdict
from typing import List

report = {
    "target": f"{result.server_location.hostname}:{result.server_location.port}",
    "scan_time": datetime.now(timezone.utc).isoformat(),
    "protocols": findings,
    "certificate": {
        "subject": subject,
        "expires": not_after.date().isoformat(),
        "days_remaining": days_remaining,
        "key_size_bits": key_size,
        "issues": issues,
    },
    "vulnerabilities": {
        "heartbleed": hb.is_vulnerable_to_heartbleed,
        "robot": robot.robot_result.name,
        "insecure_renegotiation": renegotiation.is_vulnerable_to_client_renegotiation_dos,
        "secure_renegotiation_supported": renegotiation.supports_secure_renegotiation,
    },
    "hsts_present": headers.strict_transport_security_header is not None,
}

print(json.dumps(report, indent=2, default=str))
with open("tls_assessment_report.json", "w") as f:
    json.dump(report, f, indent=2, default=str)
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Cipher suite** | Combination of key exchange, authentication, encryption, and MAC algorithms negotiated during a TLS handshake (e.g., `TLS_AES_256_GCM_SHA384`) |
| **Heartbleed (CVE-2014-0160)** | OpenSSL memory disclosure vulnerability that leaks up to 64 KB of server memory per request; exploitable on TLS heartbeat extension |
| **ROBOT** | Return Of Bleichenbacher's Oracle Threat — allows RSA private key recovery against servers that leak timing information during RSA decryption |
| **HSTS** | HTTP Strict Transport Security header instructs browsers to connect only via HTTPS for a defined `max-age` period, preventing downgrade attacks |
| **OCSP Stapling** | Server-side mechanism to attach a cached certificate revocation status response to the TLS handshake, reducing client round-trips |
| **Forward Secrecy** | Property of key exchange (ECDHE/DHE) that ensures session keys cannot be decrypted retroactively even if the server's private key is later compromised |
| **Certificate chain** | Ordered sequence of certificates from the leaf (server) up to a trusted root CA; breaks in the chain cause browser warnings |

## Tools & Systems

- **sslyze**: Python library and CLI for fast TLS/SSL configuration scanning; supports concurrent multi-host scanning
- **testssl.sh**: Shell script alternative for TLS scanning without Python dependencies
- **OpenSSL**: Command-line toolkit for manual cipher and protocol negotiation testing (`openssl s_client`)
- **Qualys SSL Labs**: Web-based TLS grading service (A+ to F) for public-facing hosts

## Common Scenarios

### Scenario: PCI-DSS TLS Compliance Check Before Audit

**Context**: A payment processing API must disable TLS 1.0/1.1 and all export-grade ciphers before a PCI-DSS assessment. Scan all production endpoints and generate a compliance gap report.

**Approach**:
1. Build a list of target hostnames from the production load balancer config
2. Run sslyze with `TLS_1_0_CIPHER_SUITES`, `TLS_1_1_CIPHER_SUITES`, and `SSL_2_0_CIPHER_SUITES` commands on all targets
3. Flag any host accepting TLS < 1.2 as a compliance failure
4. Check for weak ciphers (RC4, DES, 3DES, EXPORT) in TLS 1.2 accepted suites
5. Verify certificate chain is valid and not expiring within 30 days
6. Output a per-host pass/fail table for the audit report

**Pitfalls**:
- sslyze may return `ServerRejectedTlsHandshake` for TLS 1.0/1.1 probes even when those protocols are disabled at a WAF — verify by testing directly against the origin server, not through the CDN
- Load balancers sometimes negotiate TLS on behalf of the backend and may accept weaker protocols independently; scan both the LB and origin

### Scenario: Verifying HSTS Deployment After Migration

**Context**: A site migrated from HTTP to HTTPS and the team needs to confirm HSTS is correctly deployed with `includeSubDomains` and `preload` directives before submitting to the browser preload list.

**Approach**:
1. Run sslyze `HTTP_HEADERS` command against the apex domain and key subdomains
2. Check `strict_transport_security_header.max_age` ≥ 31536000 (1 year, preload requirement)
3. Verify `include_subdomains` and `preload` flags are set
4. Confirm no mixed-content resources remain (out of scope for sslyze; use a browser audit)

**Pitfalls**:
- HSTS is only served over HTTPS; if the site still redirects HTTP to HTTP on some paths, the header will be absent
- CDN edge nodes may strip or modify HSTS headers; always scan with a direct connection to the origin for ground truth

## Output Format

```
TLS SECURITY ASSESSMENT REPORT
================================
Target:      example.com:443
Scan Time:   2025-10-01T14:32:00Z

PROTOCOL SUPPORT
Protocol    Status  Cipher Suites
SSLv2       [OK]    0 (rejected)
SSLv3       [OK]    0 (rejected)
TLSv1.0     [FAIL]  5 (accepted — disable for PCI-DSS)
TLSv1.1     [FAIL]  4 (accepted — disable for PCI-DSS)
TLSv1.2     [OK]    12 (accepted)
TLSv1.3     [OK]    3 (accepted)

CERTIFICATE
Subject:         CN=example.com
Expiry:          2026-03-15 (165 days)
Key Size:        2048 bits
Chain:           Trusted (DigiCert CA)
Issues:          None

VULNERABILITIES
Heartbleed:                 Not vulnerable
ROBOT:                      NOT_VULNERABLE_NO_ORACLE
Client Renegotiation DoS:   Not vulnerable
Secure Renegotiation:       Supported

HTTP HEADERS
HSTS:            Present (max-age=31536000, includeSubDomains=True)

SUMMARY
PASS: 4   FAIL: 2   CRITICAL: 0
Recommendation: Disable TLSv1.0 and TLSv1.1 to reach full compliance.
```
