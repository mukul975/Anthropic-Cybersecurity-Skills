---
name: analyzing-cobalt-strike-malleable-profiles
description: >
  Parses Cobalt Strike malleable C2 profiles using pyMalleableC2 to extract beacon
  configuration, HTTP communication patterns, and sleep/jitter settings. Combines with
  JARM TLS fingerprinting to detect C2 servers on the network. Use when investigating
  suspected Cobalt Strike infrastructure or building detection signatures for C2 traffic.
domain: cybersecurity
subdomain: security-operations
tags: [analyzing, cobalt, strike, malleable]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Analyzing Cobalt Strike Malleable Profiles

## Instructions

Parse malleable C2 profiles to extract IOCs and detection opportunities using the
pyMalleableC2 library. Combine with JARM fingerprinting to identify C2 servers.

```python
from malleablec2 import Profile

# Parse a malleable profile from file
profile = Profile.from_file("amazon.profile")

# Extract global options (sleep, jitter, user-agent)
print(profile.ast.pretty())

# Access HTTP-GET block URIs and headers for network signatures
# Access HTTP-POST block for data exfiltration patterns
# Generate JARM fingerprints for known C2 infrastructure
```

Key analysis steps:
1. Parse the malleable profile to extract HTTP-GET/POST URI patterns
2. Extract User-Agent strings and custom headers for IDS signatures
3. Identify sleep time and jitter for beaconing detection thresholds
4. Scan suspect IPs with JARM to match known C2 fingerprint hashes
5. Cross-reference extracted IOCs with network traffic logs

## Examples

```python
# Parse profile and extract detection indicators
from malleablec2 import Profile
p = Profile.from_file("cobaltstrike.profile")
print(p)  # Reconstructed source

# JARM scan a suspect C2 server
import subprocess
result = subprocess.run(
    ["python3", "jarm.py", "suspect-server.com"],
    capture_output=True, text=True
)
print(result.stdout)
# Compare fingerprint against known CS JARM hashes
```
