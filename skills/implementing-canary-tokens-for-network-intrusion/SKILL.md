---
name: implementing-canary-tokens-for-network-intrusion
description: 'Deploys DNS, HTTP, and AWS API key canary tokens across network infrastructure
  to detect unauthorized access and lateral movement. Integrates with webhook alerting
  (Slack, Teams, email, generic HTTP) for real-time intrusion notifications. Provides
  automated token generation, placement strategies, and monitoring for enterprise
  network environments. Use when building deception-based network intrusion detection
  with Canarytokens.org and Thinkst Canary platforms.

  '
domain: cybersecurity
subdomain: security-operations
tags:
- canary-tokens
- intrusion-detection
- deception
- network-security
- honeytokens
- breach-detection
version: '1.0'
author: mukul975
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
- T1021
- T1550
---

# Implementing Canary Tokens for Network Intrusion Detection

## When to Use

- When deploying deception-based tripwires across network infrastructure to detect intrusions
- When building early warning systems that alert on unauthorized access to sensitive resources
- When planting fake AWS credentials, DNS beacons, or HTTP tokens to catch attackers during lateral movement
- When integrating canary token alerts with SOC workflows via Slack, Microsoft Teams, or SIEM webhooks
- When complementing traditional IDS/IPS with zero-false-positive deception technology

## Prerequisites

- Python 3.8+ with `requests` library installed
- Network access to canarytokens.org API (or self-hosted Canarytokens instance)
- Webhook endpoint for alert delivery (Slack, Teams, email, or generic HTTP)
- For Thinkst Canary enterprise: valid console domain and API auth token
- Administrative access to target systems where tokens will be planted
- Appropriate authorization for all deployment activities

## Core Concepts

### What Are Canary Tokens?

Canary tokens are digital tripwires -- resources that should never be accessed during normal
operations. When an attacker interacts with a canary token, it immediately triggers an alert
with near-zero false positives. Unlike signature-based detection, canary tokens detect
attackers by their behavior (accessing bait resources) rather than matching known patterns.

### Token Types for Network Intrusion Detection

| Token Type | Trigger Mechanism | Best Placement | Detection Scenario |
|------------|-------------------|----------------|-------------------|
| DNS Token | DNS resolution of FQDN | Config files, scripts, internal docs | Attacker reads configs during recon |
| HTTP Token | HTTP GET to unique URL | Internal wikis, bookmark files, HTML | Attacker browses internal resources |
| AWS API Key | AWS API call with fake creds | `.aws/credentials`, env files, repos | Attacker tests found credentials |
| Cloned Site | Visit to cloned page | Internal portals, admin panels | Attacker accesses cloned services |
| SVN Token | SVN checkout | Repository configs | Attacker clones repositories |
| SQL Server | Database login attempt | Connection strings, config files | Attacker attempts DB access |

### Alert Flow Architecture

```
[Attacker Action] --> [Token Triggered] --> [Canarytokens Server]
                                                    |
                                            [Webhook POST]
                                                    |
                          +-------------------------+-------------------------+
                          |                         |                         |
                    [Slack Alert]           [Email Alert]             [SIEM Ingestion]
                          |                         |                         |
                    [SOC Analyst]           [On-Call Page]           [Correlation Rule]
```

## Instructions

### Step 1: Generate DNS Canary Tokens

DNS tokens are the most versatile -- they trigger on any DNS resolution, even from
air-gapped networks with only DNS egress. The token is an FQDN that, when resolved,
alerts the token owner.

```python
import requests

# Create DNS canary token via Canarytokens.org
response = requests.post("https://canarytokens.org/generate", data={
    "type": "dns",
    "email": "soc@company.com",
    "memo": "Production database server - /etc/app/db.conf",
    "webhook_url": "https://hooks.slack.com/services/T.../B.../xxx"
}, timeout=15)

token_data = response.json()
dns_hostname = token_data["hostname"]
# Example: abc123def456.canarytokens.com
```

Plant DNS tokens in locations attackers commonly inspect:
- `/etc/hosts` entries pointing to the canary FQDN
- Application configuration files (`database_host`, `backup_server`)
- SSH config files (`~/.ssh/config`) with canary hostnames
- Internal DNS zone files as decoy A records
- CI/CD pipeline environment variables

### Step 2: Deploy HTTP Canary Tokens

HTTP tokens generate a unique URL that triggers on any HTTP request. They reveal the
source IP, User-Agent, and other HTTP headers of the requester.

```python
# Create HTTP token
response = requests.post("https://canarytokens.org/generate", data={
    "type": "http",
    "email": "soc@company.com",
    "memo": "Internal wiki - IT admin passwords page",
    "webhook_url": "https://hooks.slack.com/services/T.../B.../xxx"
}, timeout=15)

http_url = response.json()["url"]
# Embed in internal HTML pages, documents, or bookmark files
```

Placement strategies for HTTP tokens:
- Hidden `<img>` tags in internal wiki pages with sensitive titles
- URL shortener redirects in shared bookmark collections
- Links in internal documentation labeled "admin credentials" or "VPN configs"
- `.url` or `.webloc` shortcut files in network shares
- Browser bookmark exports in user profile backups

### Step 3: Create AWS API Key Tokens

AWS key tokens are among the highest-fidelity canary tokens. They generate real-looking
AWS access keys that trigger an alert whenever anyone attempts to use them against any
AWS API endpoint.

```python
# Create AWS API key canary token
response = requests.post("https://canarytokens.org/generate", data={
    "type": "aws_keys",
    "email": "soc@company.com",
    "memo": "DevOps jump box - /home/deploy/.aws/credentials",
    "webhook_url": "https://hooks.slack.com/services/T.../B.../xxx"
}, timeout=15)

aws_token = response.json()
access_key_id = aws_token["access_key_id"]
secret_access_key = aws_token["secret_access_key"]
```

Deploy the fake credentials:
```ini
# Place in ~/.aws/credentials on honeypot or jump servers
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region = us-east-1

# Also plant in:
# - .env files in code repositories
# - Docker environment configurations
# - Terraform state files (decoy)
# - Jenkins/CI credential stores
```

### Step 4: Configure Webhook Alert Integration

Set up real-time alerting to your SOC through multiple channels:

```python
# Slack webhook integration
def send_slack_alert(webhook_url, alert_data):
    """Forward canary token alert to Slack channel."""
    payload = {
        "text": f":rotating_light: *Canary Token Triggered*",
        "attachments": [{
            "color": "#FF0000",
            "fields": [
                {"title": "Token Memo", "value": alert_data.get("memo", "Unknown"), "short": True},
                {"title": "Source IP", "value": alert_data.get("src_ip", "Unknown"), "short": True},
                {"title": "Token Type", "value": alert_data.get("channel", "Unknown"), "short": True},
                {"title": "Triggered At", "value": alert_data.get("time", "Unknown"), "short": True},
            ],
            "footer": "Canarytokens Alert System",
        }]
    }
    requests.post(webhook_url, json=payload, timeout=10)
```

```python
# Generic webhook receiver (Flask) for SIEM ingestion
from flask import Flask, request, jsonify
import json, logging

app = Flask(__name__)
logging.basicConfig(filename="/var/log/canary_alerts.json", level=logging.INFO)

@app.route("/canary-webhook", methods=["POST"])
def receive_alert():
    alert = request.json or request.form.to_dict()
    logging.info(json.dumps({
        "event_type": "canarytoken_triggered",
        "memo": alert.get("memo"),
        "src_ip": alert.get("src_ip"),
        "token_type": alert.get("channel"),
        "time": alert.get("time"),
        "manage_url": alert.get("manage_url"),
        "additional_data": alert.get("additional_data", {}),
    }))
    return jsonify({"status": "received"}), 200
```

### Step 5: Enterprise Deployment with Thinkst Canary API

For organizations using Thinkst Canary, leverage the API for mass deployment and
centralized management:

```python
import canarytools

# Connect to Thinkst Canary console
console = canarytools.Console(
    domain="yourcompany",
    api_key="your_api_auth_token"
)

# Create tokens programmatically at scale
token_types = {
    "dns": "DNS beacon in config files",
    "aws-id": "AWS credentials on jump servers",
    "http": "Web bug in internal documentation",
    "doc-msword": "Word document in finance share",
    "slack-api": "Fake Slack bot token in source code",
}

for kind, memo in token_types.items():
    result = console.tokens.create(memo=memo, kind=kind)
    print(f"[+] Created {kind} token: {result}")

# Monitor for triggered alerts
alerts = console.tokens.alerts()
for alert in alerts:
    print(f"[ALERT] {alert.memo} triggered from {alert.src_ip}")
```

### Step 6: Token Placement Strategy by Network Zone

**DMZ / Public-Facing:**
- HTTP tokens in admin panel login pages (hidden image tag)
- DNS tokens in web server configuration files
- AWS keys in `.env` files on staging servers

**Internal Network / Corporate:**
- DNS tokens in Active Directory Group Policy scripts
- AWS keys in developer workstation backup directories
- HTTP tokens in internal SharePoint/Confluence pages titled "Emergency Credentials"
- Word document tokens in network shares (`\\fileserver\IT\passwords.docx`)

**Production / Data Center:**
- DNS tokens in database configuration files
- AWS keys in CI/CD environment variables
- SQL Server tokens in connection strings on application servers
- SVN/Git tokens in repository configuration files

**Cloud Infrastructure:**
- AWS key tokens in S3 bucket policies (decoy)
- DNS tokens in CloudFormation/Terraform templates
- HTTP tokens in Lambda function environment variables
- Cloned-site tokens mimicking cloud admin consoles

## Examples

### Full Deployment Script

```python
# Deploy a comprehensive canary token network
python scripts/agent.py --action full_deploy \
    --email soc@company.com \
    --webhook https://hooks.slack.com/services/T.../B.../xxx \
    --output deployment_report.json
```

### Monitor Triggered Tokens

```python
# Check for triggered alerts
python scripts/agent.py --action monitor \
    --console-domain yourcompany \
    --api-key YOUR_AUTH_TOKEN
```

### Generate Token Inventory

```python
# Create inventory of all deployed tokens
python scripts/agent.py --action inventory \
    --output token_inventory.json
```

## Validation Checklist

- [ ] DNS tokens resolve correctly and generate alerts within 60 seconds
- [ ] HTTP tokens return a valid response and log source IP
- [ ] AWS key tokens trigger alerts when used with `aws sts get-caller-identity`
- [ ] Webhook alerts arrive in Slack/Teams/SIEM within acceptable latency
- [ ] Token memo fields contain sufficient context for SOC triage
- [ ] Deployment locations are documented in token inventory
- [ ] Alert escalation procedures are defined and tested
- [ ] Tokens do not interfere with legitimate operations
- [ ] Self-hosted Canarytokens instance (if used) is hardened and monitored
- [ ] Token rotation schedule is established (quarterly recommended)

## References

- Canarytokens Documentation: https://docs.canarytokens.org/guide/
- Thinkst Canary Platform: https://canary.tools/
- Thinkst Canary API: https://docs.canary.tools/canarytokens/actions.html
- Canarytokens Open Source: https://github.com/thinkst/canarytokens
- Zeltser Honeytoken Setup Guide: https://zeltser.com/honeytokens-canarytokens-setup/
- Grafana Canary Token Case Study: https://grafana.com/blog/2025/08/25/canary-tokens-learn-all-about-the-unsung-heroes-of-security-at-grafana-labs/
- AWS Infrastructure Canarytoken: https://blog.thinkst.com/2025/09/introducing-the-aws-infrastructure-canarytoken.html
