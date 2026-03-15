---
name: performing-osint-with-spiderfoot
description: Automate OSINT collection using SpiderFoot REST API and CLI for target profiling, module-based reconnaissance, and structured result analysis across 200+ data sources
domain: cybersecurity
subdomain: threat-intelligence
tags:
  - osint
  - spiderfoot
  - reconnaissance
  - threat-intelligence
  - attack-surface
  - target-profiling
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing OSINT with SpiderFoot

## Overview

SpiderFoot is an open-source OSINT automation tool with 200+ modules that integrates with data sources for threat intelligence and attack surface mapping. This skill uses the SpiderFoot REST API and CLI (sf.py/spiderfoot-cli) to create and manage scans, select modules by use case (footprint, investigate, passive), parse structured results for domains, IPs, email addresses, leaked credentials, and DNS records, and generate target intelligence profiles.

## Prerequisites

- SpiderFoot 4.0+ installed or SpiderFoot HX cloud account
- Python 3.8+ with requests library
- SpiderFoot server running on default port 5001
- Optional: API keys for VirusTotal, Shodan, HaveIBeenPwned modules

## Steps

1. Connect to SpiderFoot REST API or use CLI interface
2. Create a new scan with target specification (domain, IP, email, name)
3. Select scan modules by use case (all, footprint, investigate, passive)
4. Monitor scan progress via API polling
5. Retrieve and parse scan results by data element type
6. Extract key findings: subdomains, IPs, emails, leaked credentials
7. Generate structured OSINT intelligence report

## Expected Output

JSON report containing OSINT findings organized by data type (domains, IPs, emails, credentials, DNS records), module source attribution, and target profile summary with risk indicators.
