---
name: detecting-supply-chain-attacks-in-ci-cd
description: 'Scans GitHub Actions workflows and CI/CD pipeline configurations for
  supply chain attack vectors including unpinned actions, script injection via expressions,
  dependency confusion, and secrets exposure. Uses PyGithub and YAML parsing for automated
  audit. Use when hardening CI/CD pipelines or investigating compromised build systems.

  '
domain: cybersecurity
subdomain: security-operations
tags:
- supply-chain-security
- ci-cd-security
- github-actions
- pipeline-security
- dependency-pinning
- devsecops
version: '1.0'
author: mahipal
license: Apache-2.0
atlas_techniques:
- AML.T0010
- AML.T0104
nist_ai_rmf:
- GOVERN-5.2
- MAP-1.6
- MANAGE-2.2
nist_csf:
- DE.CM-01
- RS.MA-01
- GV.OV-01
- DE.AE-02
mitre_attack:
- T1195.002
- T1195.001
- T1199
- T1554
---

# Detecting Supply Chain Attacks in CI/CD


## When to Use

- When investigating security incidents that require detecting supply chain attacks in ci cd
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Prerequisites

- Familiarity with security operations concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

Scan CI/CD workflow files for supply chain risks by parsing GitHub Actions YAML,
checking for unpinned dependencies, script injection vectors, and secrets exposure.

```python
import yaml
from pathlib import Path

for wf in Path(".github/workflows").glob("*.yml"):
    with open(wf) as f:
        workflow = yaml.safe_load(f)
    for job_name, job in workflow.get("jobs", {}).items():
        for step in job.get("steps", []):
            uses = step.get("uses", "")
            if uses and "@" in uses and not uses.split("@")[1].startswith("sha"):
                print(f"Unpinned action: {uses} in {wf.name}")
```

Key supply chain risks:
1. Unpinned GitHub Actions (using @main instead of SHA)
2. Script injection via ${{ github.event }} expressions
3. Overly permissive GITHUB_TOKEN permissions
4. Third-party actions with write access to repo
5. Dependency confusion via public/private package name collision

## Examples

```python
# Check for script injection in run steps
for step in job.get("steps", []):
    run_cmd = step.get("run", "")
    if "${{" in run_cmd and "github.event" in run_cmd:
        print(f"Script injection risk: {run_cmd[:80]}")
```
