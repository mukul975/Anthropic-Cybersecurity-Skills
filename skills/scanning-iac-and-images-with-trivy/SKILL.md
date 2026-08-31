---
name: scanning-iac-and-images-with-trivy
description: Scans container images, Infrastructure-as-Code (Terraform, CloudFormation, Kubernetes manifests, Dockerfile, Helm), filesystems, git repos, and SBOMs with Trivy's vuln, misconfig, secret, and license scanners. Use when building a CI/CD security gate that scans images before push, IaC before apply, or SBOMs for supply-chain weaknesses, and fails the build on policy violations. Do not use for Trivy scanning limited to container images alone - use performing-container-security-scanning-with-trivy.
domain: cybersecurity
subdomain: devsecops
tags:
- devsecops
- trivy
- container-security
- vulnerability-scanning
- iac-security
- sbom
- ci-cd
- misconfiguration
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- ID.RA-01
mitre_attack:
- T1525
---
# Scanning IaC and Images with Trivy

## Overview

Trivy (by Aqua Security) is a comprehensive, open-source security scanner that finds vulnerabilities (CVEs), misconfigurations (IaC), secrets, software licenses, and software supply-chain weaknesses across a wide range of targets: container images, filesystems, Git repositories, virtual machine images, Kubernetes clusters, and SBOM documents. It is widely adopted as a "shift-left" gate in CI/CD pipelines because it is fast, runs as a single static binary, requires no agent, and supports machine-readable output formats (JSON, SARIF, CycloneDX, SPDX) for integration with code-scanning dashboards.

Trivy bundles four primary scanners that can be toggled with `--scanners`:

- **vuln** — OS package and language-dependency vulnerability detection (CVE matching against the Trivy vulnerability DB).
- **misconfig** — Infrastructure-as-Code and configuration misconfiguration detection (Terraform, CloudFormation, Kubernetes manifests, Dockerfile, Helm) using built-in and custom Rego policies.
- **secret** — Hard-coded secret/credential detection (API keys, tokens, private keys).
- **license** — Software license identification and policy enforcement.

This skill covers building a Trivy-based scanning workflow that gates a CI/CD pipeline: scanning images before push, scanning IaC before apply, generating and re-scanning SBOMs, and failing builds on policy violations. Detecting these weaknesses defends against the MITRE ATT&CK technique **T1525 (Implant Internal Image)**, where adversaries plant malicious or vulnerable images in a registry to be deployed across the environment.

## When to Use

- When integrating vulnerability and misconfiguration scanning into a CI/CD pipeline as a quality/security gate before images are pushed or infrastructure is applied.
- When auditing container images in a registry for known CVEs prior to deployment.
- When validating Terraform, CloudFormation, Kubernetes, Dockerfile, or Helm IaC for security misconfigurations.
- When generating an SBOM (CycloneDX/SPDX) for supply-chain transparency and later re-scanning that SBOM for newly disclosed CVEs.
- When scanning a running Kubernetes cluster for vulnerable workloads and misconfigured RBAC/resources.
- When enforcing license compliance policy on dependencies.

## Prerequisites

- A Linux/macOS/Windows host or CI runner with network access to download the Trivy vulnerability database.
- Docker (optional) if scanning local images by name or using the containerized Trivy.
- Install Trivy (Aqua Security official methods):

```bash
# Debian/Ubuntu (APT repository)
sudo apt-get install -y wget gnupg
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" | sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install -y trivy

# RHEL/CentOS (YUM repository), macOS (Homebrew), and install script
brew install trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin

# Containerized usage (no install)
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:latest image python:3.10-alpine

# Verify
trivy --version
```

- For air-gapped or rate-limited environments, pre-download the DB with `trivy image --download-db-only` and the Java/policy bundles as needed.

## Objectives

- Scan a container image for OS and language vulnerabilities and fail the build above a severity threshold.
- Scan IaC (Terraform/Kubernetes/Dockerfile) for misconfigurations.
- Detect hard-coded secrets in a repository or filesystem.
- Generate a CycloneDX or SPDX SBOM and re-scan it for vulnerabilities.
- Emit SARIF for GitHub code scanning and JSON for programmatic gating.
- Wire Trivy into a CI/CD pipeline with `--exit-code` to enforce policy.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Relevance |
|--------------|------|--------|-----------|
| T1525 | Implant Internal Image | Persistence | Trivy detects vulnerable or malicious images/layers and embedded secrets before they are implanted in a registry and propagated to running workloads. |

## Workflow

### 1. Scan a container image for vulnerabilities

Run a vulnerability-only scan of a registry image, restricting to high/critical findings and ignoring CVEs with no available fix:

```bash
trivy image \
  --scanners vuln \
  --severity HIGH,CRITICAL \
  --ignore-unfixed \
  --format table \
  python:3.10-alpine
```

Scan an image saved as a tarball (useful when the image is built but not yet pushed):

```bash
docker save myorg/app:1.4.0 -o app.tar
trivy image --input app.tar --severity CRITICAL --format json --output app-vulns.json
```

### 2. Enable multiple scanners on an image

Run vulnerability, misconfiguration, secret, and license scanners together:

```bash
trivy image \
  --scanners vuln,misconfig,secret,license \
  --severity MEDIUM,HIGH,CRITICAL \
  myorg/app:1.4.0
```

Scan the image's embedded config (Dockerfile-equivalent build history and history secrets):

```bash
trivy image --image-config-scanners misconfig,secret myorg/app:1.4.0
```

### 3. Scan Infrastructure-as-Code (misconfiguration)

Scan a directory of Terraform / Kubernetes / Dockerfile / Helm / CloudFormation for misconfigurations using the `config` target:

```bash
# Scan a Terraform / IaC directory
trivy config \
  --severity HIGH,CRITICAL \
  --format table \
  ./infra

# Scan with custom Rego policies and a specific policy namespace
trivy config \
  --config-policy ./policies \
  --policy-namespaces user \
  ./infra
```

Alternatively use the `fs` (filesystem) target with the misconfig scanner explicitly:

```bash
trivy fs --scanners misconfig,secret --severity HIGH,CRITICAL ./infra
```

### 4. Scan a repository and detect secrets

Scan a local working tree (or remote repo) for vulnerabilities in lockfiles and hard-coded secrets:

```bash
# Local filesystem (dependencies + secrets)
trivy fs --scanners vuln,secret --severity HIGH,CRITICAL .

# Remote Git repository
trivy repository --scanners vuln,secret https://github.com/myorg/myrepo
```

### 5. Generate and re-scan an SBOM

Produce a CycloneDX SBOM from an image, then scan the SBOM itself for vulnerabilities (so a stored SBOM can be re-evaluated as new CVEs are disclosed):

```bash
# Generate CycloneDX SBOM
trivy image --format cyclonedx --output sbom.cdx.json myorg/app:1.4.0

# Generate SPDX SBOM
trivy image --format spdx-json --output sbom.spdx.json myorg/app:1.4.0

# Re-scan the SBOM for vulnerabilities later
trivy sbom --severity HIGH,CRITICAL sbom.cdx.json
```

### 6. Emit SARIF for code-scanning dashboards

Produce SARIF for GitHub Advanced Security / code scanning ingestion:

```bash
trivy image \
  --format sarif \
  --output trivy-results.sarif \
  --severity HIGH,CRITICAL \
  myorg/app:1.4.0
```

### 7. Gate the CI/CD pipeline with exit codes

Use `--exit-code 1` so the pipeline step fails when findings at or above the chosen severity are present. Separate the "report everything" run (exit 0) from the "enforce" run (exit 1):

```bash
# 1) Informational report (never fails the build)
trivy image --severity LOW,MEDIUM,HIGH,CRITICAL --exit-code 0 --format table myorg/app:1.4.0

# 2) Enforcement gate (fails build on HIGH/CRITICAL with a fix available)
trivy image \
  --severity HIGH,CRITICAL \
  --ignore-unfixed \
  --exit-code 1 \
  --format json --output gate.json \
  myorg/app:1.4.0
```

Example GitHub Actions step using the official action:

```yaml
- name: Run Trivy image scan (gate)
  uses: aquasecurity/trivy-action@master
  with:
    image-ref: 'myorg/app:1.4.0'
    format: 'sarif'
    output: 'trivy-results.sarif'
    severity: 'HIGH,CRITICAL'
    ignore-unfixed: true
    exit-code: '1'
```

### 8. Manage false positives and the DB

Suppress accepted-risk findings with a `.trivyignore` file and keep the DB current:

```bash
# .trivyignore — one CVE/AVD/secret rule ID per line
echo "CVE-2023-12345" >> .trivyignore
echo "AVD-AWS-0089"   >> .trivyignore

# Refresh DBs explicitly (useful for caching layers in CI)
trivy image --download-db-only
trivy image --download-java-db-only

# Scan a Kubernetes cluster (summary report)
trivy k8s --report summary --severity HIGH,CRITICAL cluster
```

## Tools and Resources

| Tool / Resource | Purpose | Link |
|------------------|---------|------|
| Trivy | Core scanner CLI | https://github.com/aquasecurity/trivy |
| Trivy Documentation | Official docs (targets, scanners, flags) | https://trivy.dev/latest/docs/ |
| trivy-action | GitHub Actions integration | https://github.com/aquasecurity/trivy-action |
| Trivy Operator | In-cluster Kubernetes continuous scanning | https://github.com/aquasecurity/trivy-operator |
| Trivy vulnerability DB | OSS vulnerability data source | https://github.com/aquasecurity/trivy-db |
| CycloneDX | SBOM standard emitted by Trivy | https://cyclonedx.org/ |

## Validation Criteria

- [ ] Trivy installed and `trivy --version` reports a valid version.
- [ ] Container image scanned for vulnerabilities with severity filtering applied.
- [ ] Image scanned with multiple scanners (vuln, misconfig, secret, license).
- [ ] IaC directory scanned with `trivy config` and misconfigurations reviewed.
- [ ] Secret scanning run against the repository.
- [ ] CycloneDX/SPDX SBOM generated and successfully re-scanned with `trivy sbom`.
- [ ] SARIF output produced for the code-scanning dashboard.
- [ ] CI/CD gate fails the build on HIGH/CRITICAL findings via `--exit-code 1`.
- [ ] `.trivyignore` configured for accepted-risk findings with documented justification.
