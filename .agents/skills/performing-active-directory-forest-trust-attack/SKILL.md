---
name: performing-active-directory-forest-trust-attack
description: Enumerate and audit Active Directory forest trust relationships using impacket for SID filtering analysis, trust key extraction, cross-forest SID history abuse detection, and inter-realm Kerberos ticket assessment.
domain: cybersecurity
subdomain: red-team
tags: [active-directory, forest-trust, impacket, SID-filtering, kerberos, red-team, trust-enumeration]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing Active Directory Forest Trust Attack

## Overview

Active Directory forest trusts enable authentication across organizational boundaries but introduce attack surface if misconfigured. This skill uses impacket to enumerate trust relationships, analyze SID filtering configuration, detect SID history abuse vectors, perform cross-forest SID lookups via LSA/LSAT RPC calls, and assess inter-realm Kerberos ticket configurations for trust ticket forgery risks.

## Prerequisites

- Python 3.9+ with `impacket`, `ldap3`
- Domain credentials with read access to AD trust objects
- Network access to Domain Controllers (ports 389, 445, 88)
- Authorized penetration testing engagement or lab environment

## Steps

1. Enumerate forest trust relationships via LDAP trusted domain objects
2. Query trust attributes and SID filtering status for each trust
3. Perform SID lookups across trust boundaries using LsarLookupNames3
4. Enumerate foreign security principals in trusted domains
5. Check for SID history on cross-forest accounts
6. Assess trust direction and transitivity for lateral movement paths
7. Generate trust security audit report with risk findings

## Expected Output

- JSON report listing all trust relationships, SID filtering status, foreign principals, trust direction/transitivity, and risk assessment
- Cross-forest attack path analysis with remediation recommendations
