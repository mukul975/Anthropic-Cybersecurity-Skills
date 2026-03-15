---
name: securing-github-actions-workflows
description: >
  This skill covers hardening GitHub Actions workflows against supply chain attacks,
  credential theft, and privilege escalation. It addresses pinning actions to SHA digests,
  minimizing GITHUB_TOKEN permissions, protecting secrets from exfiltration, preventing
  script injection in workflow expressions, and implementing required reviewers for
  workflow changes.
domain: cybersecurity
subdomain: devsecops
tags: [devsecops, cicd, github-actions, supply-chain, workflow-security, secure-sdlc]
version: 1.0.0
author: mahipal
license: Apache-2.0
---

# Securing GitHub Actions Workflows

## When to Use

- When GitHub Actions is the CI/CD platform and workflows need hardening against supply chain attacks
- When workflows handle secrets, deploy to production, or have elevated permissions
- When preventing script injection via untrusted PR titles, branch names, or commit messages
- When requiring audit trails and approval gates for workflow modifications
- When third-party actions pose supply chain risk through mutable version tags

**Do not use** for securing other CI/CD platforms (see platform-specific hardening guides), for application vulnerability scanning (use SAST/DAST), or for secret detection in code (use Gitleaks).

## Prerequisites

- GitHub repository with GitHub Actions enabled
- GitHub organization admin access for organization-level settings
- Understanding of GitHub Actions workflow syntax and events

## Workflow

### Step 1: Pin Actions to SHA Digests

```yaml
# INSECURE: Mutable tag can be overwritten by attacker
- uses: actions/checkout@v4

# SECURE: Pinned to immutable SHA digest
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1

# Use Dependabot to auto-update pinned SHAs
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    commit-message:
      prefix: "ci"
```

### Step 2: Minimize GITHUB_TOKEN Permissions

```yaml
# Set restrictive default permissions at workflow level
name: CI Pipeline
permissions: {}  # Start with no permissions

on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read  # Only what's needed
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

  deploy:
    runs-on: ubuntu-latest
    needs: build
    if: github.ref == 'refs/heads/main'
    permissions:
      contents: read
      deployments: write
      id-token: write  # For OIDC-based cloud auth
    steps:
      - name: Deploy
        run: echo "deploying"
```

### Step 3: Prevent Script Injection

```yaml
# VULNERABLE: User-controlled input in run step
- run: echo "PR title is ${{ github.event.pull_request.title }}"

# SECURE: Use environment variable (properly escaped by shell)
- name: Process PR
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
    PR_BODY: ${{ github.event.pull_request.body }}
  run: |
    echo "PR title is ${PR_TITLE}"
    echo "PR body is ${PR_BODY}"

# SECURE: Use actions/github-script for complex operations
- uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea
  with:
    script: |
      const title = context.payload.pull_request.title;
      console.log(`PR title: ${title}`);
```

### Step 4: Secure Fork Pull Request Handling

```yaml
# DANGEROUS: pull_request_target runs with base repo permissions
# on: pull_request_target  # AVOID unless absolutely necessary

# SAFE: pull_request runs in fork context with limited permissions
on:
  pull_request:
    branches: [main]

# If pull_request_target is required, never checkout PR code:
on:
  pull_request_target:
    types: [labeled]

jobs:
  safe-job:
    if: contains(github.event.pull_request.labels.*.name, 'safe-to-test')
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      # NEVER do: actions/checkout with ref: ${{ github.event.pull_request.head.sha }}
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
        # This checks out the BASE branch, not the PR
```

### Step 5: Protect Secrets and Environment Variables

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production  # Requires approval
    steps:
      - name: Deploy with secret
        env:
          # Secrets are masked in logs automatically
          DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}
        run: |
          # Never echo secrets
          # echo "$DEPLOY_KEY"  # BAD
          deploy-tool --key-file <(echo "$DEPLOY_KEY")

      - name: Audit secret access
        run: |
          # Log that secret was used without exposing it
          echo "::notice::Deploy key accessed for production deployment"
```

### Step 6: Implement Workflow Change Controls

```yaml
# Require CODEOWNERS approval for workflow changes
# .github/CODEOWNERS
.github/workflows/ @security-team @platform-team
.github/actions/ @security-team @platform-team

# Organization settings:
# 1. Settings > Actions > General > Fork PR policies
#    - Require approval for first-time contributors
#    - Require approval for all outside collaborators
# 2. Settings > Actions > General > Workflow permissions
#    - Read repository contents and packages permissions
#    - Do NOT allow GitHub Actions to create and approve PRs
```

## Key Concepts

| Term | Definition |
|------|------------|
| SHA Pinning | Referencing GitHub Actions by their immutable commit SHA instead of mutable version tags |
| Script Injection | Attack where untrusted input (PR title, branch name) is interpolated into shell commands |
| GITHUB_TOKEN | Automatically generated token with configurable permissions scoped to the current repository |
| pull_request_target | Dangerous event trigger that runs in the base repo context with full permissions on fork PRs |
| Environment Protection | GitHub feature requiring manual approval before jobs accessing an environment can run |
| CODEOWNERS | File defining required reviewers for specific paths including workflow files |
| OIDC Federation | Using GitHub's OIDC token to authenticate to cloud providers without storing long-lived credentials |

## Tools & Systems

- **Dependabot**: Automated dependency updater that keeps pinned action SHAs current
- **StepSecurity Harden Runner**: GitHub Action that monitors and restricts outbound network calls from workflows
- **actionlint**: Linter for GitHub Actions workflow files that detects security issues
- **allstar**: GitHub App by OpenSSF that enforces security policies on repositories
- **scorecard**: OpenSSF tool that evaluates supply chain security practices including CI/CD

## Common Scenarios

### Scenario: Preventing Supply Chain Attack via Compromised Third-Party Action

**Context**: A widely-used GitHub Action is compromised and its v3 tag is updated to include credential-stealing code. Repositories using `@v3` automatically pull the malicious version.

**Approach**:
1. Pin all actions to SHA digests immediately across all repositories
2. Configure Dependabot for github-actions ecosystem to manage SHA updates
3. Restrict GITHUB_TOKEN permissions so even compromised actions have minimal access
4. Add StepSecurity harden-runner to detect anomalous outbound network calls
5. Review all third-party actions and replace unnecessary ones with inline scripts
6. Require CODEOWNERS approval for any changes to .github/workflows/

**Pitfalls**: SHA pinning without Dependabot means missing legitimate security updates to actions. Overly restrictive permissions can break legitimate workflows. Using `pull_request_target` for label-based gating still exposes secrets if the workflow checks out PR code.

## Output Format

```
GitHub Actions Security Audit
================================
Repository: org/web-application
Date: 2026-02-23

WORKFLOW ANALYSIS:
  Total workflows: 8
  Total action references: 34

SHA PINNING:
  [FAIL] 12/34 actions use mutable tags instead of SHA digests
  - .github/workflows/ci.yml: actions/setup-node@v4
  - .github/workflows/deploy.yml: aws-actions/configure-aws-credentials@v4

PERMISSIONS:
  [FAIL] 3/8 workflows have no explicit permissions (inherit default)
  [WARN] 1/8 workflows request write-all permissions

SCRIPT INJECTION:
  [FAIL] 2 workflow steps interpolate user input directly
  - .github/workflows/pr-check.yml:23: ${{ github.event.pull_request.title }}

SECRETS:
  [PASS] No secrets exposed in workflow logs
  [PASS] All production deployments use environment protection

SCORE: 6/10 (Remediate 5 HIGH findings)
```
