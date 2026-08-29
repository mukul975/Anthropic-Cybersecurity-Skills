---
name: deploying-cloud-deception-with-decoy-resources
description: 'Deploy cloud-native deception across AWS, Azure, and GCP using decoy (honey) resources whose only purpose is to generate a high-fidelity alert the instant an attacker touches them - canary IAM access keys, permission-less decoy users/roles/service principals, honey object-storage buckets, and decoy secrets in Secrets Manager, Key Vault, or Secret Manager. Wires detection through CloudTrail + EventBridge, Azure Sentinel + Defender, and GCP Cloud Audit Logs so any use of a decoy is routed to the SOC with near-zero false positives. Use when protecting cloud accounts and data stores, extending on-prem honeypots to cloud coverage, seeding fake AWS keys to catch credential theft and code-leak exposure, or detecting cloud reconnaissance and lateral movement. Do not use for on-prem network honeypots or a general deception program rollout - use performing-deception-technology-deployment.'
domain: cybersecurity
subdomain: deception-technology
tags:
- cloud-deception
- aws
- azure
- gcp
- canary-token
- honeytoken
- cloudtrail
- breach-detection
version: "1.0"
author: andrewibrah
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.CM-06
- DE.AE-02
- ID.RA-01
- RS.MA-01
mitre_attack:
- T1078
- T1552
- T1580
- T1530
- T1619
---

# Deploying Cloud Deception with Decoy Resources

## When to Use

- When cloud accounts (AWS/Azure/GCP) hold crown-jewel data or infrastructure and you need a tripwire that fires the moment an attacker who has gained access starts to operate.
- When the only deception in place is on-prem honeypots, leaving the cloud control plane uninstrumented.
- When seeding fake credentials to catch credential theft, accidental code-repo leaks, or secrets exposed in build pipelines.
- When detecting cloud reconnaissance (enumeration of IAM, storage, or secrets) and lateral movement that legitimate users would never perform.
- When you want detections that survive into incident response with strong fidelity — a touch on a decoy resource almost always means malicious or unauthorized activity.

This is the cloud counterpart to on-prem honeypot/honeytoken/canary-token deployment skills. For program strategy and how these Activities map to adversary engagement goals, use `designing-adversary-engagement-with-mitre-engage`.

## Prerequisites

- Cloud admin/IAM permissions to create decoy principals, storage, secrets, and detection wiring, ideally in a dedicated deployment role with least privilege.
- Cloud audit logging already enabled: **AWS CloudTrail** (multi-region, with management and relevant data events), **Azure Activity log + Microsoft Entra audit/sign-in logs**, **GCP Cloud Audit Logs (Admin Activity always on; Data Access enabled where needed)**.
- A SIEM/alert sink: SNS topic, Microsoft Sentinel workspace, or GCP Pub/Sub + Monitoring, with routing to the SOC.
- A naming and tagging convention that is plausible to an attacker but unambiguous to defenders internally (e.g., realistic names, plus an internal `deception=true` tag/label kept out of attacker-visible metadata).
- **Decoy principals must be permission-less (explicit deny-all).** The value is the alert, never the access. A decoy that grants real privilege is a liability, not a control.

## Workflow

### 1. Decide what to mimic
Pick decoys that match how *your* attackers operate: leaked AWS keys (credential theft), an "admin" S3 bucket (data discovery), a `prod-db-password` secret (secrets harvesting), a privileged-looking service account (cloud lateral movement). Place credential decoys where harvesting tools look: env files, CI variables, code comments, an internal wiki.

### 2A. AWS — canary access keys on a permission-less user
Create a decoy IAM user with an explicit deny-all policy, then issue an access key to plant:
```bash
aws iam create-user --user-name svc-backup-prod --tags Key=deception,Value=true
aws iam put-user-policy --user-name svc-backup-prod \
  --policy-name deny-all \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'
aws iam create-access-key --user-name svc-backup-prod   # plant the returned AccessKeyId/Secret
```
Any use of this key appears in CloudTrail (even denied calls, which still log `AccessDenied`). Wire an EventBridge rule on CloudTrail to alert:
```bash
aws events put-rule --name decoy-key-used \
  --event-pattern '{"detail":{"userIdentity":{"userName":["svc-backup-prod"]}}}'
aws events put-targets --rule decoy-key-used \
  --targets "Id"="1","Arn"="arn:aws:sns:us-east-1:111111111111:soc-deception-alerts"
```

### 2B. AWS — honey S3 bucket
Create a believable bucket, enable object-level data events, and alert on any read/list:
```bash
aws s3api create-bucket --bucket acme-prod-db-backups-2026 --region us-east-1
aws s3api put-bucket-tagging --bucket acme-prod-db-backups-2026 \
  --tagging 'TagSet=[{Key=deception,Value=true}]'
# Ensure CloudTrail captures S3 data events for this bucket, then alert on GetObject/ListBucket
aws events put-rule --name decoy-bucket-access \
  --event-pattern '{"detail":{"eventSource":["s3.amazonaws.com"],"requestParameters":{"bucketName":["acme-prod-db-backups-2026"]}}}'
```

### 2C. AWS — decoy secret
```bash
aws secretsmanager create-secret --name prod/db/master-password \
  --secret-string '{"username":"dbadmin","password":"DECOY-DO-NOT-USE"}' \
  --tags Key=deception,Value=true
# Alert on GetSecretValue for this secret via EventBridge -> SNS
```

### 3A. Azure — honeytoken watchlist + decoy service principal
Microsoft Sentinel natively supports honeytokens via a **Watchlist** of the `HoneyTokens` template; tagged decoy accounts/secrets raise analytics alerts on use. Create a permission-less decoy app registration / service principal, then add its identifiers to the HoneyTokens watchlist and enable the related analytics rules. Microsoft Defender for Cloud and Entra ID Protection surface anomalous sign-ins to the decoy identity.

### 3B. Azure — honey storage + Key Vault decoy secret
Create a decoy Storage account and Key Vault, enable diagnostic logging to the Sentinel workspace, store a decoy secret, and write an analytics rule that fires on any data-plane read of the decoy resources.

### 4A. GCP — decoy service account + honey GCS bucket
Create a service account with no role bindings (permission-less), generate a key to plant, and alert on its use via Cloud Audit Logs:
```bash
gcloud iam service-accounts create svc-billing-export \
  --display-name="billing-export"
gcloud iam service-accounts keys create decoy-key.json \
  --iam-account=svc-billing-export@PROJECT.iam.gserviceaccount.com   # plant this key
gsutil mb -b on gs://acme-finance-exports-2026
```
Create a log-based metric + alerting policy in Cloud Monitoring that triggers on any audit-log entry where the principal is the decoy service account or the resource is the honey bucket.

### 5. Centralize and de-duplicate
Route all clouds' decoy alerts to one SOC pipeline. Tag each alert as DECEPTION/high-fidelity so it bypasses normal noise filtering and triggers an IR playbook rather than a triage queue.

### 6. Validate (red-team the decoys)
Have an authorized tester use each decoy (read the bucket, call with the key, fetch the secret) and confirm an alert lands end-to-end within target latency. A decoy you have not tested is assumed broken.

### 7. Maintain realism and rotate
Refresh decoy names, secrets, and pocket-litter periodically so they age with the real environment. Track every decoy in an inventory so they are never mistaken for real assets during audits or cleanups.

## Key Concepts

| Concept | Definition |
|---|---|
| Decoy / honey resource | A cloud object created solely to be touched by an attacker; no legitimate user has any reason to use it. |
| Canary access key | A planted credential whose use generates an audit-log event; carries deny-all permissions. |
| High-fidelity alert | A near-zero-false-positive signal because legitimate workflows never reference the decoy. |
| Permission-less principal | A decoy IAM user/role/service principal/service account with explicit deny-all or no role bindings. |
| Data event | Cloud audit logging of object/data-plane access (e.g., S3 GetObject), required to detect storage decoys. |
| Pocket litter | Plausible supporting artifacts (fake configs, env files, wiki entries) that make a decoy credible. |
| Decoy inventory | The authoritative internal record distinguishing decoys from real assets. |

## Tools & Systems

- **AWS** — IAM (decoy users/roles), S3 (honey buckets, data events), Secrets Manager / SSM Parameter Store (decoy secrets), CloudTrail, EventBridge, SNS/Lambda, GuardDuty (correlate anomalous use).
- **Azure** — Microsoft Entra ID (decoy app registrations / service principals), Storage / Key Vault decoys, **Microsoft Sentinel HoneyTokens watchlist** and analytics rules, Microsoft Defender for Cloud, Entra ID Protection.
- **GCP** — IAM service accounts (decoys), Cloud Storage (honey buckets), Secret Manager (decoy secrets), Cloud Audit Logs, log-based metrics + Cloud Monitoring alerting, Pub/Sub.
- **Open-source / managed honeytoken systems** — Canarytokens (https://canarytokens.org offers AWS API key tokens), Thinkst Canary, SpaceSiren / SpaceCrab (self-hosted AWS honey-token frameworks).
- **SIEM/SOAR** — to centralize alerts across clouds and drive an IR playbook on any decoy hit.

## Common Scenarios

- **Credential-theft / code-leak detection.** Plant a canary AWS key in CI variables, an env file, and a private repo. Any external use (even from a leaked public push) fires within minutes.
- **Crown-jewel data store.** Stand up a honey "backups" bucket next to the real one; attackers enumerating storage hit the decoy first and reveal themselves.
- **Cloud lateral movement.** A permission-less decoy service principal that "looks" privileged catches adversaries assuming roles during pivoting.
- **Secrets harvesting.** Decoy entries in Secrets Manager / Key Vault / Secret Manager detect tools scraping the secrets store.
- **Migrating from on-prem-only deception.** Mirror the existing on-prem decoy strategy into the cloud control plane so coverage follows workloads.

## Output Format

Produce a **Cloud Deception Deployment Record** using `assets/template.md`, containing:

1. **Decoy inventory** — per decoy: cloud, type, plausible name, real placement location of any planted credential, internal `deception` tag/label, owner.
2. **Detection wiring** — per decoy: audit-log source → rule/pattern → alert sink → IR playbook reference, with the target alert latency.
3. **Least-privilege proof** — evidence each decoy principal is deny-all / no-role-binding.
4. **Validation results** — date tested, who tested, end-to-end latency observed, pass/fail.
5. **Maintenance plan** — rotation cadence and review owner.

Use `scripts/process.py` to render the deployment record and a per-decoy detection checklist from a decoy-inventory JSON, and to flag decoys missing detection wiring or validation.
