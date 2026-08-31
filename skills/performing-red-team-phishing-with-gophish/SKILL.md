---
name: performing-red-team-phishing-with-gophish
description: Automates GoPhish phishing simulation campaigns using the Python gophish library, creating email templates with tracking pixels, configuring SMTP sending profiles, building target groups from CSV, launching campaigns, and analyzing open rates, click rates, and credential submission statistics. Use when scripting a repeatable authorized phishing simulation or red-team security-awareness assessment via the GoPhish API and Python library. Do not use for GoPhish web admin panel setup and manual awareness campaign reporting - use performing-phishing-simulation-with-gophish.
domain: cybersecurity
subdomain: security-operations
tags:
- red-teaming
- phishing-simulation
- gophish
- social-engineering
- campaign-automation
- security-awareness
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- DE.CM-01
- RS.MA-01
- GV.OV-01
- DE.AE-02
mitre_attack:
- T1078
- T1190
- T1059
- T1003
- T1110
mitre_f3:
  version: '1.1'
  tactics:
  - resource-development
  - reconnaissance
  - initial-access
  techniques:
  - id: T1598
    name: Phishing for Information
    tactic: reconnaissance
    source: attack
  - id: T1660
    name: Phishing
    tactic: initial-access
    source: attack
  - id: F1020.002
    name: 'Create Fake Materials: Fake Website'
    tactic: resource-development
    source: f3
  - id: T1583.001
    name: 'Acquire Infrastructure: Domains'
    tactic: resource-development
    source: attack
  - id: F1006.002
    name: 'Account Takeover: Exposed Login Credential'
    tactic: initial-access
    source: f3
---


## When to Use

- When conducting security assessments that involve performing red team phishing with gophish
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Prerequisites

- Familiarity with security operations concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

1. Install dependencies: `pip install gophish requests`
2. Deploy GoPhish server and obtain an API key from Settings.
3. Use the Python gophish library to automate campaign setup:
   - Create email templates with HTML body and tracking
   - Configure SMTP sending profiles
   - Import target groups from CSV
   - Create landing pages for credential capture
   - Launch and monitor campaigns
4. Analyze campaign results: opens, clicks, submitted data, reported.

```bash
# For authorized penetration testing and lab environments only
python scripts/agent.py --gophish-url https://localhost:3333 --api-key <key> --campaign-name "Q1 Awareness" --output phishing_report.json
```

## Examples

### Create Campaign via API
```python
from gophish import Gophish
from gophish.models import Campaign, Template, Group, SMTP, Page
api = Gophish("api_key", host="https://localhost:3333", verify=False)  # Self-signed cert on localhost lab
campaign = Campaign(name="Q1 Test", groups=[Group(name="Sales Team")],
    template=Template(name="IT Password Reset"), smtp=SMTP(name="Internal SMTP"),
    page=Page(name="Credential Page"))
api.campaigns.post(campaign)
```
