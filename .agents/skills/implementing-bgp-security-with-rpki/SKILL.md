---
name: implementing-bgp-security-with-rpki
description: Implement BGP route origin validation using RPKI with Route Origin Authorizations, RPKI-to-Router protocol, and ROV policies on Cisco and Juniper routers to prevent route hijacking.
domain: cybersecurity
subdomain: network-security
tags: [bgp, rpki, route-origin-validation, rov, roa, route-hijacking, internet-routing, bgp-security, prefix-hijack]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Implementing BGP Security with RPKI

## Overview

Resource Public Key Infrastructure (RPKI) provides cryptographic validation of BGP route origins to prevent route hijacking and accidental route leaks. RPKI enables network operators to create Route Origin Authorizations (ROAs) that declare which Autonomous Systems (ASes) are authorized to originate specific IP prefixes. BGP routers validate received route announcements against RPKI data through Route Origin Validation (ROV), rejecting routes with invalid origins. This skill covers creating ROAs through Regional Internet Registries (RIRs), deploying RPKI validator software, configuring ROV on Cisco IOS-XE and Juniper Junos routers, and implementing BGP filtering policies based on RPKI validation state.

## Prerequisites

- IP address space allocated from an RIR (ARIN, RIPE, APNIC, AFRINIC, LACNIC)
- RIR member portal access for ROA creation
- BGP routers (Cisco IOS-XE 16.x+, Juniper Junos 12.2+, or similar)
- Linux server for RPKI validator/cache (Routinator, FORT, or OctoRPKI)
- Understanding of BGP routing and AS path concepts

## Core Concepts

### RPKI Architecture

```
┌──────────────────────────────────────────────┐
│           Regional Internet Registries        │
│    (ARIN, RIPE, APNIC, AFRINIC, LACNIC)      │
│                                               │
│  ┌─────────────────────────────────────────┐  │
│  │  Trust Anchor (Root CA Certificate)      │  │
│  │  ├── CA Certificate (ISP/Organization)   │  │
│  │  │   ├── ROA: AS64512 → 198.51.100.0/24 │  │
│  │  │   └── ROA: AS64512 → 2001:db8::/32   │  │
│  │  └── CA Certificate (Another Org)        │  │
│  │      └── ROA: AS64513 → 203.0.113.0/24  │  │
│  └─────────────────────────────────────────┘  │
└──────────────────────────────────────────────┘
                     │ rsync/RRDP
                     ▼
         ┌──────────────────────┐
         │  RPKI Validator/Cache │  (Routinator, FORT, OctoRPKI)
         │  Validates ROAs       │
         │  Serves VRPs to RTR   │
         └──────────────────────┘
                     │ RTR Protocol (TCP 8323)
                     ▼
         ┌──────────────────────┐
         │  BGP Router           │
         │  Performs ROV          │
         │  Applies policy:      │
         │   Valid → Accept      │
         │   Invalid → Reject    │
         │   NotFound → Accept   │
         └──────────────────────┘
```

### RPKI Validation States

| State | Meaning | Recommended Action |
|-------|---------|-------------------|
| **Valid** | ROA exists, origin AS and prefix match | Accept route (prefer) |
| **Invalid** | ROA exists, but origin AS or prefix length mismatch | Reject route |
| **NotFound** | No ROA covers this prefix | Accept (but lower preference) |

### Route Origin Authorization (ROA)

A ROA is a signed object that states:
- **Prefix**: The IP address range (e.g., 198.51.100.0/24)
- **Origin AS**: The AS authorized to originate this prefix (e.g., AS64512)
- **Max Length**: Maximum prefix length that can be announced (e.g., /24)

## Implementation Steps

### Step 1: Create ROAs at Your RIR

**ARIN (North America):**
1. Log into ARIN Online portal
2. Navigate to Routing Security > Route Origin Authorizations
3. Create ROA:
   - Prefix: 198.51.100.0/24
   - Origin AS: AS64512
   - Max Length: /24 (set equal to prefix length to prevent sub-prefix hijacking)
4. Sign and submit

**RIPE NCC (Europe):**
1. Log into RIPE NCC LIR Portal
2. Navigate to Certification (RPKI) > ROAs
3. Create ROA with prefix, origin AS, and max prefix length

### Step 2: Deploy RPKI Validator (Routinator)

```bash
# Install Routinator on Ubuntu
sudo apt install -y routinator

# Or install via Cargo (Rust)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
cargo install routinator

# Initialize Routinator (accept TALs)
routinator init --accept-arin-rpa

# Start Routinator in RTR server mode
routinator server \
  --rtr 0.0.0.0:8323 \
  --http 0.0.0.0:8080 \
  --refresh 600 \
  --retry 60 \
  --expire 7200

# Run as systemd service
cat > /etc/systemd/system/routinator.service << 'SYSTEMD'
[Unit]
Description=Routinator RPKI Validator
After=network.target

[Service]
Type=simple
User=routinator
ExecStart=/usr/bin/routinator server --rtr 0.0.0.0:8323 --http 0.0.0.0:8080
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SYSTEMD

sudo systemctl enable routinator
sudo systemctl start routinator

# Verify Routinator is serving data
curl http://localhost:8080/api/v1/status
curl http://localhost:8080/api/v1/validity/AS64512/198.51.100.0/24

# View Validated ROA Payloads (VRPs)
routinator vrps --format json | head -50
```

### Step 3: Configure ROV on Cisco IOS-XE

```
! Configure RPKI cache server connection
router bgp 64512
 bgp rpki server tcp 10.0.5.50 port 8323 refresh 600

! Verify RPKI session
show bgp rpki server
show bgp rpki table

! Create route-map for RPKI-based filtering
route-map RPKI-FILTER permit 10
 match rpki valid
 set local-preference 200

route-map RPKI-FILTER permit 20
 match rpki not-found
 set local-preference 100

route-map RPKI-FILTER deny 30
 match rpki invalid

! Apply to BGP neighbors
router bgp 64512
 address-family ipv4 unicast
  neighbor 198.51.100.1 route-map RPKI-FILTER in
  neighbor 203.0.113.1 route-map RPKI-FILTER in

 address-family ipv6 unicast
  neighbor 2001:db8::1 route-map RPKI-FILTER in

! Verify ROV operation
show bgp ipv4 unicast rpki validation
show bgp ipv4 unicast 198.51.100.0/24
show ip bgp rpki table
show ip bgp neighbors 198.51.100.1 rpki state
```

### Step 4: Configure ROV on Juniper Junos

```
# Configure RPKI cache connection
set routing-options validation group RPKI-VALIDATORS session 10.0.5.50 port 8323
set routing-options validation group RPKI-VALIDATORS session 10.0.5.50 refresh-time 600
set routing-options validation group RPKI-VALIDATORS session 10.0.5.50 hold-time 7200
set routing-options validation group RPKI-VALIDATORS session 10.0.5.50 record-lifetime 7200

# Create validation policy
set policy-options policy-statement RPKI-POLICY term valid from validation-database valid
set policy-options policy-statement RPKI-POLICY term valid then validation-state valid
set policy-options policy-statement RPKI-POLICY term valid then local-preference 200
set policy-options policy-statement RPKI-POLICY term valid then accept

set policy-options policy-statement RPKI-POLICY term invalid from validation-database invalid
set policy-options policy-statement RPKI-POLICY term invalid then validation-state invalid
set policy-options policy-statement RPKI-POLICY term invalid then reject

set policy-options policy-statement RPKI-POLICY term unknown from validation-database unknown
set policy-options policy-statement RPKI-POLICY term unknown then validation-state unknown
set policy-options policy-statement RPKI-POLICY term unknown then local-preference 100
set policy-options policy-statement RPKI-POLICY term unknown then accept

# Apply to BGP peers
set protocols bgp group TRANSIT import RPKI-POLICY
set protocols bgp group PEERS import RPKI-POLICY

# Verify
show validation session
show validation database
show validation statistics
show route validation-state invalid
```

### Step 5: Monitor RPKI Deployment

```python
#!/usr/bin/env python3
"""Monitor RPKI ROV deployment health and coverage statistics."""

import json
import sys
import urllib.request


class RPKIMonitor:
    def __init__(self, routinator_url: str = "http://localhost:8080"):
        self.routinator_url = routinator_url

    def get_status(self) -> dict:
        """Get Routinator server status."""
        url = f"{self.routinator_url}/api/v1/status"
        try:
            with urllib.request.urlopen(url) as resp:
                return json.loads(resp.read())
        except Exception as e:
            print(f"Error connecting to Routinator: {e}")
            return {}

    def check_validity(self, asn: int, prefix: str) -> dict:
        """Check RPKI validity of a prefix/origin pair."""
        url = f"{self.routinator_url}/api/v1/validity/AS{asn}/{prefix}"
        try:
            with urllib.request.urlopen(url) as resp:
                return json.loads(resp.read())
        except Exception as e:
            return {"error": str(e)}

    def get_vrp_count(self) -> int:
        """Get total number of Validated ROA Payloads."""
        status = self.get_status()
        return status.get("vrpsCount", 0)

    def report(self, prefixes_to_check: list):
        """Generate RPKI monitoring report."""
        status = self.get_status()

        print(f"\n{'='*60}")
        print("RPKI MONITORING REPORT")
        print(f"{'='*60}")
        print(f"\nRoutinator Status:")
        print(f"  Version: {status.get('version', 'Unknown')}")
        print(f"  VRPs Total: {status.get('vrpsCount', 'N/A')}")
        print(f"  Last Update: {status.get('lastUpdateDone', 'N/A')}")

        if prefixes_to_check:
            print(f"\nPrefix Validity Checks:")
            for asn, prefix in prefixes_to_check:
                result = self.check_validity(asn, prefix)
                validity = result.get("validated_route", {}).get(
                    "validity", {}).get("state", "error")
                print(f"  AS{asn} -> {prefix}: {validity.upper()}")


if __name__ == "__main__":
    monitor = RPKIMonitor()

    # Check own prefixes
    own_prefixes = [
        (64512, "198.51.100.0/24"),
    ]

    monitor.report(own_prefixes)
```

## Best Practices

- **Create ROAs for All Prefixes** - Sign ROAs for every prefix your organization announces
- **Max Length = Prefix Length** - Set max-length equal to announced prefix length to prevent sub-prefix hijacking
- **Dual Validator** - Run two independent RPKI validators for redundancy
- **Soft Policy First** - Start with logging RPKI-invalid routes before dropping them
- **Monitor ROA Expiry** - Set alerts for ROA certificates approaching expiration
- **Coordinate with Upstreams** - Notify transit providers about your RPKI deployment
- **Test with Looking Glass** - Verify your ROAs are visible using public RPKI validators

## References

- [RPKI Documentation](https://rpki.readthedocs.io/en/latest/)
- [Cloudflare RPKI Blog](https://blog.cloudflare.com/rpki/)
- [NLnet Labs Routinator](https://www.nlnetlabs.nl/projects/rpki/routinator/)
- [RIPE NCC RPKI Dashboard](https://rpki.ripe.net/)
- [RFC 6480 - RPKI Architecture](https://www.rfc-editor.org/rfc/rfc6480)
- [RFC 6811 - BGP Origin AS Validation](https://www.rfc-editor.org/rfc/rfc6811)
