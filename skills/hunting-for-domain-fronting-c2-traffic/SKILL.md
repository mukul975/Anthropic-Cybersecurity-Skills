---
name: hunting-for-domain-fronting-c2-traffic
description: Detect domain fronting C2 traffic by analyzing SNI vs HTTP Host header
  mismatches in proxy logs and TLS certificate discrepancies using pyOpenSSL for certificate
  inspection
domain: cybersecurity
subdomain: threat-hunting
tags:
- domain-fronting
- c2-detection
- tls-inspection
- proxy-logs
- pyopenssl
- threat-hunting
- network-security
version: '1.0'
author: mahipal
license: Apache-2.0
d3fend_techniques:
- Application Protocol Command Analysis
- Network Isolation
- Network Traffic Analysis
- Client-server Payload Profiling
- Network Traffic Community Deviation
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
mitre_attack:
- T1046
- T1057
- T1082
- T1083
- T1071
---

# Hunting for Domain Fronting C2 Traffic

## Overview

Domain fronting (MITRE ATT&CK T1090.004) is a technique where attackers use different domain names in the TLS SNI field and the HTTP Host header to disguise C2 traffic behind legitimate CDN-hosted domains. This skill detects domain fronting by parsing proxy/web gateway logs for SNI-Host header mismatches, analyzing TLS certificates for CDN provider identification, flagging connections where the SNI points to a high-reputation domain but the Host header targets an attacker-controlled domain, and correlating with known CDN provider IP ranges.


## When to Use

- When investigating security incidents that require hunting for domain fronting c2 traffic
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Prerequisites

- Web proxy or secure web gateway logs with SNI and Host header fields
- Python 3.8+ with pyOpenSSL and cryptography libraries
- TLS inspection enabled on proxy for Host header visibility
- CDN provider IP range lists (CloudFront, Azure CDN, Cloudflare)

## Steps

1. Parse proxy logs for connections with both SNI and Host header fields
2. Compare SNI domain against HTTP Host header for mismatches
3. Extract TLS certificate Subject and SAN fields using pyOpenSSL
4. Identify CDN-hosted connections via certificate issuer and IP ranges
5. Flag high-confidence domain fronting where SNI and Host differ on CDN IPs
6. Score alerts based on domain reputation differential
7. Generate detection report with network flow context

## Expected Output

JSON report containing detected domain fronting indicators with SNI-Host pairs, certificate details, CDN provider identification, confidence scores, and MITRE ATT&CK technique mapping.
