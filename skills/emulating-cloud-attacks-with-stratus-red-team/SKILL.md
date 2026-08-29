---
name: emulating-cloud-attacks-with-stratus-red-team
description: Install and run Stratus Red Team to detonate granular, MITRE ATT&CK-mapped AWS, Azure, GCP, and Kubernetes attack techniques through their warmup-detonate-revert-cleanup lifecycle, then verify the telemetry they generate against detections like CloudTrail, GuardDuty, Microsoft Sentinel, GCP SCC, and Falco. Use when validating that cloud detections fire or generating repeatable attacker telemetry for a purple-team exercise with Stratus Red Team. Do not use for running a broad multi-domain purple-team exercise end to end - use performing-purple-team-exercise.
domain: cybersecurity
subdomain: cloud-security
tags:
- stratus-red-team
- adversary-emulation
- cloud-security
- detection-validation
- purple-team
- aws
- mitre-attack
- threat-detection
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- DE.CM-01
mitre_attack:
- T1078
---
# Emulating Cloud Attacks with Stratus Red Team

> **Legal Notice:** This skill is for authorized security testing and detection-validation purposes only. Stratus Red Team spins up and modifies real cloud infrastructure in the account whose credentials you supply. Only run it in accounts you own or are explicitly authorized to test. Always `cleanup` afterwards to avoid orphaned, billable, or insecure resources. Unauthorized use against systems you do not control is illegal.

## Overview

Stratus Red Team is an open-source "Atomic Red Team for the cloud," maintained by Datadog. It is a self-contained Go binary that programmatically *detonates* granular, well-documented offensive techniques against AWS, Azure, GCP, and Kubernetes, then lets you cleanly revert and remove everything it created. Unlike a full exploitation framework, Stratus is purpose-built for **detection engineering and purple teaming**: each technique maps to a MITRE ATT&CK tactic and ships with a precise description of the cloud API calls it generates, so a blue team can confirm whether their CloudTrail/GuardDuty/Sentinel/Falco detections actually fire.

Every technique has a deterministic lifecycle. Stratus first provisions any prerequisite infrastructure with embedded Terraform (the **warmup** phase), then performs the malicious actions (**detonate**), optionally **revert**s the side effects so you can detonate again, and finally **cleanup**s the prerequisite infrastructure. Because the prerequisites and the attack are decoupled, you can iterate on a detection by detonating the same technique repeatedly without re-provisioning. The tool uses your standard cloud SDK credential chain (AWS profiles/env vars, `az login`, GCP ADC, kubeconfig), so it operates with exactly the permissions of the identity you authenticate as.

This skill covers installing Stratus, listing and filtering the technique catalog, running the full warmup-detonate-revert-cleanup lifecycle, mapping detonations to the telemetry they produce, and wiring the results into a detection-validation workflow. Source: github.com/DataDog/stratus-red-team and stratus-red-team.cloud official documentation.

## When to Use

- Validating that a new or existing cloud detection rule (CloudTrail, GuardDuty, Microsoft Sentinel, GCP SCC, Falco) actually triggers on real attacker activity
- Building a repeatable purple-team exercise for cloud TTPs without writing bespoke attack scripts
- Generating realistic, MITRE-mapped telemetry to test SIEM ingestion and alert routing
- Measuring detection coverage of a cloud environment against a known catalog of techniques
- Onboarding analysts with safe, reversible hands-on cloud attack simulations

## Prerequisites

- Stratus Red Team binary (Go 1.23+ to build from source, or Homebrew/Docker):
  ```bash
  # Go install
  go install -v github.com/datadog/stratus-red-team/v2/cmd/stratus@latest

  # Homebrew
  brew tap datadog/stratus-red-team https://github.com/DataDog/stratus-red-team
  brew install datadog/stratus-red-team/stratus-red-team

  # Docker
  docker run --rm -v $HOME/.stratus-red-team/:/root/.stratus-red-team/ \
    -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN \
    ghcr.io/datadog/stratus-red-team list
  ```
- Authenticated cloud credentials for the target provider:
  ```bash
  # AWS — verify identity before detonating
  export AWS_PROFILE=stratus-lab
  aws sts get-caller-identity

  # Azure
  az login

  # GCP
  gcloud auth application-default login

  # Kubernetes
  kubectl config current-context
  ```
- A dedicated, non-production lab account or subscription (techniques create real resources)
- Terraform is embedded; no separate install is required, but outbound HTTPS to download provider plugins on first warmup is needed

## Objectives

- Install Stratus Red Team and confirm the target cloud identity
- Enumerate and filter techniques by platform and MITRE ATT&CK tactic
- Execute the warmup -> detonate -> revert -> cleanup lifecycle safely
- Map each detonation to the cloud API calls and log sources it generates
- Validate detection rules against the produced telemetry and track coverage
- Guarantee no residual infrastructure remains after testing

## MITRE ATT&CK Mapping

| ID | Name | Use in this skill |
|----|------|-------------------|
| T1078 | Valid Accounts | Emulation runs as a valid cloud identity; many techniques abuse legitimate credentials/API access |
| T1078.004 | Valid Accounts: Cloud Accounts | e.g. `aws.credential-access.ec2-steal-instance-credentials` produces cloud-account abuse telemetry |
| T1580 | Cloud Infrastructure Discovery | Discovery-tactic techniques such as `aws.discovery.*` |
| T1530 | Data from Cloud Storage | Exfiltration techniques such as `aws.exfiltration.ec2-share-ebs-snapshot` |
| T1098 | Account Manipulation | Persistence techniques such as `aws.persistence.iam-create-admin-user` |

## Workflow

### 1. Confirm identity and list the technique catalog
Always confirm which account you are about to attack, then browse the catalog.
```bash
aws sts get-caller-identity
stratus list
# Filter to a single platform
stratus list --platform aws
# Filter by MITRE ATT&CK tactic
stratus list --mitre-attack-tactic credential-access
```

### 2. Inspect a specific technique before running it
Read exactly what a technique will do and which detonation/telemetry it produces.
```bash
stratus show aws.credential-access.ec2-steal-instance-credentials
```

### 3. Warm up prerequisite infrastructure
Provision the prerequisites with embedded Terraform without performing the attack yet.
```bash
stratus warmup aws.credential-access.ec2-steal-instance-credentials
stratus status
```

### 4. Detonate the technique
Execute the malicious actions; this is what your detections must catch. Warmup is implicit if not already done.
```bash
stratus detonate aws.credential-access.ec2-steal-instance-credentials
# Detonate and force a re-warmup in one step
stratus detonate aws.persistence.iam-create-admin-user --force
```

### 5. Inspect status and the telemetry generated
Check lifecycle state, then pull the corresponding control-plane logs to confirm the attack landed.
```bash
stratus status
# Pull recent CloudTrail events to verify the detonation
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey \
  --max-results 10
```

### 6. Validate the detection
Confirm your SIEM/detection fired. Example: query Athena/CloudTrail or check GuardDuty findings.
```bash
aws guardduty list-findings --detector-id "$DETECTOR_ID" \
  --finding-criteria '{"Criterion":{"updatedAt":{"GreaterThanOrEqual":'"$(date -d '-1 hour' +%s)"'000}}}'
```

### 7. Revert side effects to re-detonate
Undo the detonation while keeping prerequisites so you can iterate on a detection.
```bash
stratus revert aws.credential-access.ec2-steal-instance-credentials
stratus detonate aws.credential-access.ec2-steal-instance-credentials   # run again
```

### 8. Clean up all infrastructure
Tear down everything a technique created. Always finish here.
```bash
stratus cleanup aws.credential-access.ec2-steal-instance-credentials
# Nuke everything Stratus ever provisioned in this account
stratus cleanup --all
stratus status   # confirm COLD state for all techniques
```

### 9. Drive it programmatically for coverage runs
Loop over a tactic to measure detection coverage, then clean up. See `scripts/agent.py`.
```bash
python scripts/agent.py --platform aws --tactic credential-access --detonate --cleanup
```

## Tools and Resources

| Resource | Purpose | Link |
|----------|---------|------|
| Stratus Red Team GitHub | Source, releases, technique source | https://github.com/DataDog/stratus-red-team |
| Stratus Red Team docs | Technique catalog and lifecycle reference | https://stratus-red-team.cloud |
| Attack technique list | Full per-platform technique IDs | https://stratus-red-team.cloud/attack-techniques/list/ |
| MITRE ATT&CK Cloud | Tactic/technique reference for mapping | https://attack.mitre.org/matrices/enterprise/cloud/ |
| Atomic Red Team | Complementary endpoint emulation | https://github.com/redcanaryco/atomic-red-team |

## Detection-Validation Mapping

For purple-team value, pair each detonation with the telemetry and detection it should trigger:

| Technique | Expected telemetry | Detection to validate |
|-----------|--------------------|-----------------------|
| `aws.credential-access.ec2-steal-instance-credentials` | CloudTrail use of role creds from a non-EC2 IP | GuardDuty `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` |
| `aws.persistence.iam-create-admin-user` | `CreateUser` + `AttachUserPolicy` (AdministratorAccess) | CloudTrail/Sentinel rule on admin-policy attach |
| `aws.exfiltration.ec2-share-ebs-snapshot` | `ModifySnapshotAttribute` sharing to external account | GuardDuty `Exfiltration:EC2/...` / custom rule |
| `aws.discovery.ec2-enumerate-from-instance` | Burst of `Describe*` from instance role | Enumeration-burst detection |

After detonation, confirm the alert fired end-to-end (source -> SIEM -> ticket). If it
did not, you have found a coverage gap; document it before cleaning up.

## Cost and Safety Notes

- Some techniques provision billable resources (EC2 instances, EBS snapshots). Always
  run `stratus cleanup --all` and verify `stratus status` returns COLD.
- Never run Stratus with production credentials; use a dedicated lab account/subscription.
- The state directory `~/.stratus-red-team/` holds Terraform state — preserve it until
  cleanup completes, or you may strand resources.

## Lifecycle State Reference

| State | Meaning |
|-------|---------|
| COLD | No prerequisites provisioned; nothing to clean up |
| WARM | Prerequisites provisioned but not yet detonated |
| DETONATED | Attack actions performed; side effects present |

## Validation Criteria

- [ ] Stratus installed and `stratus list` returns the technique catalog
- [ ] Target cloud identity confirmed via `sts get-caller-identity` / equivalent
- [ ] Technique inspected with `stratus show` before detonation
- [ ] Warmup completed and status shows WARM
- [ ] Detonation completed and status shows DETONATED
- [ ] Generated telemetry located in CloudTrail/GuardDuty/SIEM
- [ ] Detection rule confirmed to fire (or coverage gap documented)
- [ ] Technique reverted and re-detonated to confirm repeatability
- [ ] `stratus cleanup --all` run and status returns COLD for every technique
- [ ] No orphaned billable resources remain in the account
