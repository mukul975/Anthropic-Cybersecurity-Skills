---
name: implementing-soar-playbook-for-phishing
description: Automate phishing incident response using Splunk SOAR REST API to create containers, add artifacts, and trigger playbooks
domain: cybersecurity
subdomain: security-operations
tags: [soar, splunk-phantom, phishing, incident-response]
mitre_attack: ["T1566", "T1204", "T1534", "T1598"]
version: "1.0"
author: mahipal
license: Apache-2.0
---


# Implementing SOAR Playbook for Phishing

## Overview

This skill implements a phishing incident response workflow using the Splunk SOAR (formerly Phantom) REST API. When a suspected phishing email is reported, the agent parses email headers and body, creates a SOAR container representing the incident, attaches artifacts containing indicators of compromise (sender address, URLs, IP addresses, file hashes), triggers an automated investigation playbook, and polls for action results.

Splunk SOAR orchestrates and automates security operations through playbooks that chain together investigative and response actions. The REST API at `/rest/container`, `/rest/artifact`, and `/rest/playbook_run` enables programmatic incident creation and automation triggering from external tools, email gateways, and SIEM alerts.


## When to Use

- When deploying or configuring implementing soar playbook for phishing capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Prerequisites

- Python 3.9 or later with `requests` and `email` modules
- Splunk SOAR instance (Cloud or On-Premises) with REST API access
- SOAR API token with permissions to create containers and trigger playbooks
- Network connectivity to SOAR instance on port 443
- A configured phishing investigation playbook in SOAR

## Steps

1. **Parse the phishing email**: Read the email file (.eml format) and extract headers including From, To, Subject, Reply-To, Return-Path, Received, Message-ID, X-Mailer, and authentication results (SPF, DKIM, DMARC). Extract URLs and IP addresses from the email body.

2. **Authenticate to SOAR REST API**: Use the API token in the `ph-auth-token` header to authenticate all REST API requests to the SOAR instance.

3. **Create a container**: POST to `/rest/container` with the incident label, name, description, severity, and status. The container represents the phishing incident and receives a container ID in the response.

4. **Add email header artifacts**: POST to `/rest/artifact` with `container_id` and CEF (Common Event Format) fields containing sender address (`fromAddress`), recipient (`toAddress`), subject, originating IP (`sourceAddress`), and Message-ID. Set `run_automation` to False for all but the last artifact.

5. **Add URL artifacts**: For each URL extracted from the email body, create an artifact with CEF field `requestURL` and type `url`. These artifacts feed into URL reputation checks in the playbook.

6. **Trigger the playbook**: POST to `/rest/playbook_run` with the playbook ID or name and the container ID. This initiates the automated investigation workflow.

7. **Poll action results**: GET `/rest/action_run` filtered by container ID to monitor playbook progress. Poll until all actions reach a terminal state (success, failed, or cancelled).

8. **Compile response report**: Aggregate playbook action results into a summary report with verdicts from URL reputation, domain reputation, IP geolocation, and email header analysis.

## Expected Output

```json
{
  "incident": {
    "container_id": 1542,
    "status": "new",
    "severity": "high",
    "artifacts_created": 5
  },
  "playbook": {
    "name": "phishing_investigate",
    "run_id": 892,
    "status": "success",
    "actions_completed": 8
  },
  "verdict": "malicious",
  "indicators": {
    "sender_domain_reputation": "malicious",
    "urls_flagged": 2,
    "spf_result": "fail",
    "dkim_result": "fail"
  }
}
```
