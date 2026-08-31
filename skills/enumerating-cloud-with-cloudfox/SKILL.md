---
name: enumerating-cloud-with-cloudfox
description: Run CloudFox's read-only Describe/List/Get enumeration (all-checks, role-trusts, secrets, endpoints, and permissions commands) to map AWS and Azure attack paths and surface exploitable misconfigurations, including mapping sts:AssumeRole trust relationships for lateral-movement and privilege-escalation planning. Use when you have just obtained a cloud credential and need read-only situational awareness, exposed resources and secrets, or attack-path mapping. Do not use for actively executing and validating AWS privilege-escalation paths - use performing-aws-privilege-escalation-assessment.
domain: cybersecurity
subdomain: cloud-security
tags:
- cloudfox
- aws
- azure
- cloud-pentest
- attack-paths
- situational-awareness
- enumeration
- offensive-security
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- ID.AM-03
mitre_attack:
- T1526
---
# Enumerating Cloud with CloudFox

> **Legal Notice:** This skill is for authorized cloud penetration testing and assessment only. CloudFox makes read/describe API calls against the cloud account whose credentials you supply. Run it ONLY against accounts you own or are authorized to test under a signed scope. Although CloudFox is read-only by design, the enumeration it performs is reconnaissance against a live environment and must be in scope.

## Overview

CloudFox is an open-source command-line tool from Bishop Fox that helps penetration testers and red teamers gain *situational awareness* in unfamiliar cloud environments. Where tools like ScoutSuite focus on a defender-style configuration audit, CloudFox is built from the attacker's perspective: it answers questions like "what are the most attackable secrets, endpoints, and instances in this account, and what can the identity I just compromised actually reach?" It is read-only — it only performs `Describe`/`List`/`Get` style calls — and writes its findings to per-command CSV/TXT/loot files plus a combined report directory, so output can be triaged offline.

CloudFox covers AWS most deeply (30+ commands) and supports Azure. The workhorse is `cloudfox aws all-checks`, which runs the full battery of enumeration commands with sensible defaults: inventory, internet-reachable `endpoints`, EC2 `instances` (with IPs and instance-profile roles), `iam-simulator` and `permissions` for IAM analysis, `principals`, `secrets` from Secrets Manager/SSM, `buckets`, `role-trusts` (which identities can assume which roles — a core attack-path primitive), `access-keys`, `route53`, `ecr`, `lambda`, and more. CloudFox also emits ready-to-run command suggestions (e.g. `aws s3 ls` lines, `aws ssm start-session` lines) in its "loot" files so an operator can pivot immediately.

This skill covers installing CloudFox, authenticating to AWS and Azure, running targeted and full enumeration, interpreting the high-value outputs (role-trusts, secrets, endpoints), and feeding the results into attack-path planning. Source: github.com/BishopFox/cloudfox.

## When to Use

- Establishing situational awareness immediately after compromising a cloud credential
- Quickly identifying internet-exposed endpoints, instances, and exposed secrets
- Mapping `sts:AssumeRole` trust relationships to plan lateral movement / privesc
- Triaging an unfamiliar AWS or Azure account during an authorized assessment
- Producing attacker-centric inventory artifacts that complement a defensive audit

## Prerequisites

- CloudFox installed:
  ```bash
  # Homebrew
  brew install cloudfox
  # Go (1.21+)
  go install github.com/BishopFox/cloudfox@latest
  # or download a release binary from GitHub and chmod +x
  ```
- Valid cloud credentials in scope:
  ```bash
  # AWS — configure a named profile and verify
  aws configure --profile assess
  aws sts get-caller-identity --profile assess

  # Azure
  az login
  az account show
  ```
- A signed authorization / Rules of Engagement defining the in-scope accounts
- `awscli` (AWS) and/or `azure-cli` (Azure) installed for credential setup and follow-up

## Objectives

- Install CloudFox and confirm cloud credentials
- Run full and targeted enumeration across AWS and Azure
- Identify internet-reachable endpoints, instances, and exposed secrets
- Enumerate IAM principals, permissions, and role-trust attack paths
- Triage CloudFox loot files for immediate pivot commands
- Export findings to a structured output directory for reporting

## MITRE ATT&CK Mapping

| ID | Name | Use in this skill |
|----|------|-------------------|
| T1526 | Cloud Service Discovery | CloudFox enumerates the available cloud services and resources in an account |
| T1580 | Cloud Infrastructure Discovery | `inventory`, `instances`, `buckets` map the infrastructure footprint |
| T1087.004 | Account Discovery: Cloud Account | `principals`, `access-keys` enumerate cloud identities |
| T1069.003 | Permission Groups Discovery: Cloud Groups | `permissions`, `iam-simulator`, `role-trusts` reveal entitlements |
| T1538 | Cloud Service Dashboard | Aggregated situational-awareness reporting across services |

## Workflow

### 1. Confirm the identity and run all AWS checks
```bash
aws sts get-caller-identity --profile assess
cloudfox aws --profile assess all-checks -o ./loot
```

### 2. Inventory the account footprint
```bash
cloudfox aws --profile assess inventory
```

### 3. Find internet-reachable endpoints and exposed instances
```bash
cloudfox aws --profile assess endpoints
cloudfox aws --profile assess instances
```

### 4. Enumerate IAM principals, permissions, and role-trust attack paths
`role-trusts` is the key lateral-movement primitive — it shows who can assume what.
```bash
cloudfox aws --profile assess principals
cloudfox aws --profile assess permissions
cloudfox aws --profile assess role-trusts
cloudfox aws --profile assess access-keys
```

### 5. Hunt for exposed secrets
```bash
cloudfox aws --profile assess secrets
```

### 6. Enumerate storage, registries, and serverless
```bash
cloudfox aws --profile assess buckets
cloudfox aws --profile assess ecr
cloudfox aws --profile assess lambda
cloudfox aws --profile assess route53
```

### 7. Use IAM simulator to confirm what a principal can do
```bash
cloudfox aws --profile assess iam-simulator
```

### 8. Enumerate Azure
CloudFox Azure works against the subscriptions the `az` session can see.
```bash
cloudfox azure inventory --outdir ./azure-loot
cloudfox azure rbac
cloudfox azure storage
cloudfox azure vms
```

### 9. Triage the loot
CloudFox writes per-command CSV/TXT plus a `loot` directory of pivot commands.
```bash
ls -R ./loot/cloudfox-output/
# Loot files contain ready-to-run follow-ups, e.g. aws s3 ls / ssm start-session lines
```
See `scripts/agent.py` to run a curated set of commands and summarize output files.

## Tools and Resources

| Resource | Purpose | Link |
|----------|---------|------|
| CloudFox GitHub | Source, releases, full command list | https://github.com/BishopFox/cloudfox |
| CloudFox docs/wiki | Per-command output explanations | https://github.com/BishopFox/cloudfox/wiki |
| Bishop Fox CloudFox blog | Design and usage walkthrough | https://bishopfox.com/blog/introducing-cloudfox |
| AWS CLI reference | Follow-up exploitation commands | https://docs.aws.amazon.com/cli/latest/reference/ |
| Pacu | Active exploitation after enumeration | https://github.com/RhinoSecurityLabs/pacu |

## OPSEC and Detection Considerations

CloudFox is read-only, but its enumeration is far from silent. Each command issues
many `Describe*`/`List*`/`Get*` API calls in a short burst, which is highly visible
to defenders:

- **CloudTrail** records every read call. A spike of `iam:ListUsers`, `iam:ListRoles`,
  `secretsmanager:ListSecrets`, `ec2:DescribeInstances`, and `sts:GetCallerIdentity`
  from one principal within seconds is a strong enumeration signal.
- **GuardDuty** finding types such as `Discovery:IAMUser/AnomalousBehavior` and
  `Discovery:S3/MaliciousIPCaller` can fire on this burst pattern.
- Defenders should baseline normal API-call rates per principal and alert on
  enumeration bursts, especially from new IPs/ASNs or newly created credentials.

For an authorized assessment, document the source IP and timestamp of CloudFox runs
so the blue team can correlate, and prefer running from an in-scope, attributable host.

## Recommended Operator Workflow

1. Run `all-checks` once to populate the full output directory.
2. Open `role-trusts` first — it reveals the assume-role graph for lateral movement.
3. Cross-reference `secrets` and `env-vars` for credentials that unlock new principals.
4. Use `endpoints` + `instances` to map externally reachable attack surface.
5. Feed confirmed assume-role / privesc candidates into Pacu for active exploitation.

## High-Value Command Reference

| Command | Why it matters |
|---------|----------------|
| `all-checks` | Runs the full enumeration battery with defaults |
| `role-trusts` | Maps assume-role paths — core for lateral movement/privesc |
| `endpoints` | Surfaces internet-reachable attack surface |
| `secrets` | Exposes credentials in Secrets Manager / SSM |
| `permissions` | Lists effective IAM permissions per principal |
| `instances` | EC2 with IPs and attached instance-profile roles |
| `access-keys` | Active access keys (potential credential targets) |

## Validation Criteria

- [ ] CloudFox installed and runs `cloudfox aws --help`
- [ ] Cloud credentials confirmed via `sts get-caller-identity` / `az account show`
- [ ] `all-checks` completed and output directory populated
- [ ] Internet-reachable endpoints and instances identified
- [ ] IAM principals, permissions, and role-trusts enumerated
- [ ] Exposed secrets located and documented
- [ ] Azure enumeration run (if Azure in scope)
- [ ] Loot files triaged for pivot opportunities
- [ ] Findings exported to a structured directory for reporting
- [ ] Enumeration confirmed to stay within authorized scope
