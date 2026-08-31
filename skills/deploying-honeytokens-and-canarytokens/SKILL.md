---
name: deploying-honeytokens-and-canarytokens
description: 'Plants Canarytokens-based decoy artifacts (honey credentials, DNS tokens, web-bug URLs, AWS keys, documents, kubeconfigs) using Thinkst''s open-source Canarytokens project and alerts via email or webhook when a token is touched. Use when standing up high-fidelity intrusion detection in low-telemetry areas like file shares or credential stores, or to catch credential dumping and data-theft staging. Do not use for a general honeytoken breach-detection program not tied to the Canarytokens project - use implementing-honeytokens-for-breach-detection.'
domain: cybersecurity
subdomain: deception-technology
tags:
- deception-technology
- canarytokens
- honeytokens
- breach-detection
- threat-detection
- d3fend
- decoy-credentials
- intrusion-detection
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- DE.CM-01
mitre_attack:
- T1556
---
# Deploying Honeytokens and Canarytokens

> **Authorized Use Only:** Deception assets described here are defensive controls deployed inside your own environment. Deploying tokens, decoy credentials, or honeypots on infrastructure you do not own or administer, or using them to entrap third parties, may violate computer-misuse and privacy law. Deploy only on assets you own or are explicitly authorized to instrument, and route all alert data through approved monitoring channels.

## Overview

Honeytokens (a.k.a. canarytokens) are decoy artifacts — credentials, files, URLs, API keys, DNS names, database connection strings, documents — that have no legitimate operational use. Because no authorized user or process should ever touch them, **any** interaction is a high-fidelity signal of an intrusion, insider misuse, or reconnaissance. Unlike signature- or anomaly-based detection, honeytokens generate near-zero false positives: the alert *is* the compromise.

Thinkst's open-source **Canarytokens** project (https://canarytokens.org and the self-hostable `thinkst/canarytokens-docker`) generates dozens of token types that "phone home" when triggered: an HTTP/web-bug URL that fires on GET, an AWS API key that fires when used against AWS, an MS Word/PDF document that fires on open, a DNS token that fires on resolution, a Slack API token, a Kubernetes `kubeconfig`, an Azure login certificate, a `log4shell` payload, and more. Each token is bound to a unique `memo` (so you know *where* it was planted) plus an alert channel (email and/or webhook).

This skill maps to MITRE D3FEND's **Decoy File (D3-DF)**, **Decoy User Credential (D3-DUC)**, and **Honeytoken** techniques. From an ATT&CK perspective, a triggered honey credential most commonly evidences adversary attempts to abuse or modify authentication material (**T1556 – Modify Authentication Process** and related credential-access activity), giving the SOC an early, unambiguous tripwire deep inside the kill chain — typically after initial access but before lateral movement completes.

## When to Use

- When you need high-fidelity intrusion detection in segments where traditional telemetry is sparse (file shares, password vaults, code repos, cloud accounts).
- When validating that an attacker who reaches a "crown-jewel" host or document store is detected, not just blocked at the perimeter.
- When seeding decoy credentials into LSASS-reachable memory, browser stores, `.aws/credentials`, or password managers to catch credential dumping and reuse.
- When instrumenting documents, repos, or wikis to catch data theft and ransomware staging.
- When building a MITRE D3FEND-aligned deception layer as part of a defense-in-depth or zero-trust program.

## Prerequisites

- Docker Engine and Docker Compose v2 for self-hosting (`docker compose version`).
- A registered domain you control plus DNS delegation for DNS-based tokens (NS records pointing at your switchboard host).
- A public IPv4 address reachable on 80/443 (HTTP tokens) and 53/udp (DNS tokens).
- An SMTP relay or Mailgun account, and/or a Slack/Teams/generic webhook URL for alert delivery.
- Python 3.8+ for the helper script:
  ```bash
  python3 -m pip install requests
  ```
- For quick use with no hosting, an account-free token from the public service at https://canarytokens.org.

## Objectives

- Stand up a self-hosted Canarytokens instance (or use the public service) with working alerting.
- Generate the major token types (HTTP, DNS, AWS key, MS Word/PDF, Slack, kubeconfig) with descriptive memos.
- Plant decoy credentials and decoy files in realistic, monitored locations.
- Validate that each token fires and that alerts reach the SOC channel.
- Catalogue deployed tokens and map them to MITRE D3FEND/ATT&CK for coverage tracking.

## MITRE ATT&CK Mapping

| ID | Official Technique Name | Relevance |
|----|------------------------|-----------|
| T1556 | Modify Authentication Process | A triggered honey credential reveals an adversary harvesting/abusing authentication material; the decoy provides a detection tripwire for credential abuse activity. |

**Related MITRE D3FEND defensive techniques** (the offensive counter-mapping for this control):

| D3FEND ID | Technique | Role |
|-----------|-----------|------|
| D3-DF | Decoy File | Canary documents, fake configs, decoy archives placed and monitored. |
| D3-DUC | Decoy User Credential | Honey credentials (AWS keys, AD accounts, kubeconfig) integrated with a monitored decoy asset. |
| D3-DO | Decoy Object | Umbrella for honeytokens/canarytokens as monitored decoy artifacts. |

## Workflow

### 1. Deploy a self-hosted Canarytokens switchboard
Clone the official Docker repo and create the two environment files from their distributed templates:
```bash
git clone https://github.com/thinkst/canarytokens-docker
cd canarytokens-docker
cp switchboard.env.dist switchboard.env
cp frontend.env.dist frontend.env
```
Set the core variables. In `frontend.env`:
```ini
CANARY_DOMAINS=canary.example.com          # general-purpose token domains (comma-separated)
CANARY_NXDOMAINS=nx.example.com            # domains reserved for PDF/DNS tokens
CANARY_PUBLIC_IP=203.0.113.10              # public IP of this host
```
In `switchboard.env`:
```ini
CANARY_PUBLIC_DOMAIN=canary.example.com
CANARY_MAILGUN_DOMAIN_NAME=mg.example.com
CANARY_MAILGUN_API_KEY=key-xxxxxxxxxxxxxxxx
CANARY_ALERT_EMAIL_FROM_ADDRESS=canary@example.com
CANARY_ALERT_EMAIL_FROM_DISPLAY=Canarytokens
CANARY_ALERT_EMAIL_SUBJECT=Canarytoken Triggered
# WireGuard token seed:
# dd bs=32 count=1 if=/dev/urandom 2>/dev/null | base64
CANARY_WG_PRIVATE_KEY_SEED=<base64-seed>
```

### 2. Bring the stack up
```bash
docker compose up -d
# HTTPS with automatic Let's Encrypt certs (after editing certbot.env):
# docker compose -f docker-compose-letsencrypt.yml up -d
docker compose ps
docker compose logs -f frontend
```
The frontend (token generator UI) is now served on your `CANARY_PUBLIC_DOMAIN`; the switchboard listens on 80/443 and 53/udp to receive triggers.

### 3. Generate an HTTP (web-bug) token via the API
Both the public service and a self-hosted frontend expose a `POST /generate` endpoint. Create an HTTP token that fires on any GET:
```bash
curl -s https://canarytokens.org/generate \
  -F 'type=http' \
  -F 'email=soc@example.com' \
  -F 'memo=Internal wiki - IT admin passwords page' \
  -F 'webhook_url=https://hooks.slack.com/services/T000/B000/XXXX'
# Response JSON includes: token, auth, hostname, url, url_components
```
The returned `url` is the trip-wire link; place it where only an intruder would find it (a fake bookmark, a hidden link in a wiki page, an email signature).

### 4. Generate a cloud credential (AWS API key) honeytoken
```bash
curl -s https://canarytokens.org/generate \
  -F 'type=aws_keys' \
  -F 'email=soc@example.com' \
  -F 'memo=Decoy AWS keys - jenkins build host /root/.aws/credentials'
# Response contains access_key_id and secret_access_key plus a downloadable
# credentials file via /download?token=<token>&auth=<auth>&fmt=aws_keys
```
Drop the keys into a plausible `~/.aws/credentials` on a monitored host. Any `sts:GetCallerIdentity` or other AWS call using them triggers an alert with the source IP and user agent.

### 5. Generate a document token (MS Word / PDF) for data-theft detection
```bash
# MS Word
curl -s https://canarytokens.org/generate \
  -F 'type=msword' \
  -F 'email=soc@example.com' \
  -F 'memo=Q4-Layoffs-DRAFT.docx on FILESERVER01\\HR$' \
  -o token-meta.json
# Download the weaponized document:
curl -s "https://canarytokens.org/download?fmt=msword&token=<token>&auth=<auth>" -o Q4-Layoffs-DRAFT.docx
```
For PDFs use `type=adobe_pdf`. The document phones home when opened (DNS/HTTP callback), exposing the reader's IP.

### 6. Plant a DNS token for resolver-level tripwires
```bash
curl -s https://canarytokens.org/generate \
  -F 'type=dns' \
  -F 'email=soc@example.com' \
  -F 'memo=DNS canary referenced in backup script comments'
# Response 'hostname' is a unique FQDN; any resolution of it fires an alert.
```
Embed the hostname in scripts, configs, or `/etc/hosts` comments. Because resolution alone triggers it, DNS tokens catch reconnaissance even when egress HTTP is blocked.

### 7. Generate infrastructure tokens (Slack, kubeconfig, Azure)
```bash
# Slack API token canary (fires when the fake token is used against Slack)
curl -s https://canarytokens.org/generate -F 'type=slack_api' \
  -F 'email=soc@example.com' -F 'memo=Decoy Slack bot token in repo .env'

# Kubeconfig canary (fires when used against the kube API)
curl -s https://canarytokens.org/generate -F 'type=kubeconfig' \
  -F 'email=soc@example.com' -F 'memo=Decoy kubeconfig in /home/deploy/.kube/config'
```
Commit decoy `.env` / `kubeconfig` files only to repos and hosts you instrument, never to public repos.

### 8. Plant Active Directory honey credentials (decoy user)
Create a non-privileged-looking but never-used AD account whose authentication is alerted on. Set a SPN so it appears Kerberoastable bait, and forward Event ID 4768/4769/4625 for it to your SIEM:
```powershell
New-ADUser -Name "svc_backup_legacy" -SamAccountName "svc_backup_legacy" `
  -AccountPassword (ConvertTo-SecureString 'C0mpl3xDecoy!2026' -AsPlainText -Force) `
  -Enabled $true -Description "Legacy backup service (do not use)"
Set-ADUser svc_backup_legacy -ServicePrincipalNames @{Add="MSSQLSvc/decoy.example.com:1433"}
```
Add a Windows audit ACL/SACL or a SIEM correlation rule so any 4768/4769 for `svc_backup_legacy` pages the SOC — no legitimate logon should ever occur.

### 9. Validate and catalogue
Trigger each token from a controlled host and confirm the alert lands:
```bash
# HTTP token
curl -s "https://canary.example.com/<token-url>" >/dev/null
# DNS token
dig +short <unique-hostname>
# AWS key token
AWS_ACCESS_KEY_ID=<id> AWS_SECRET_ACCESS_KEY=<secret> aws sts get-caller-identity
```
Record each deployed token (type, memo, location, alert channel, D3FEND mapping) in an inventory. Use the helper script below to bulk-generate and export this inventory as JSON.

## Tools and Resources

| Tool / Resource | Purpose | Link |
|-----------------|---------|------|
| Canarytokens (public) | Free hosted token generation | https://canarytokens.org |
| canarytokens-docker | Self-hosted switchboard + frontend | https://github.com/thinkst/canarytokens-docker |
| canarytokens (core) | Source for the token engine | https://github.com/thinkst/canarytokens |
| Canarytokens docs | Per-token-type usage guides | https://docs.canarytokens.org |
| MITRE D3FEND | Defensive technique taxonomy (D3-DF, D3-DUC) | https://d3fend.mitre.org |
| MITRE ATT&CK T1556 | Modify Authentication Process | https://attack.mitre.org/techniques/T1556/ |

## Token Type Reference

| `type` value | Token | Fires when |
|--------------|-------|-----------|
| `http` | Web-bug URL | URL is requested (GET) |
| `dns` | DNS name | Hostname is resolved |
| `aws_keys` | AWS API key | Keys used against AWS |
| `msword` / `adobe_pdf` | Office/PDF document | Document is opened |
| `slack_api` | Slack API token | Token used against Slack |
| `kubeconfig` | Kubernetes config | Used against the kube API |
| `azure_id` | Azure login certificate | Cert used to authenticate to Azure |
| `qr_code` | QR code | Encoded URL is requested |
| `web_image` | Image web-bug | Image is loaded |
| `log4shell` | Log4j JNDI string | Vulnerable logger evaluates it |
| `cmd` | Sensitive command (Windows) | Process/command is executed |

## Validation Criteria

- [ ] Self-hosted switchboard (or public service) deployed and reachable on 80/443 and 53/udp.
- [ ] Alert channel (email and/or webhook) configured and test alert received.
- [ ] At least one each of HTTP, DNS, cloud-credential, and document tokens generated with descriptive memos.
- [ ] Decoy credentials planted in realistic, monitored locations (no production secrets co-located).
- [ ] AD honey account created with SACL/SIEM rule firing on any authentication.
- [ ] Each token validated by a controlled trigger; alert confirmed end-to-end.
- [ ] Token inventory exported (type, memo, location, alert channel, D3-DF/D3-DUC mapping).
- [ ] No tokens committed to public repositories or planted on out-of-scope systems.
