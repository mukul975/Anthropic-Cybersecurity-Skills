---
name: scanning-docker-images-with-trivy
description: Trivy is a comprehensive open-source vulnerability scanner by Aqua Security that detects vulnerabilities in OS packages, language-specific dependencies, misconfigurations, secrets, and license violati
domain: cybersecurity
subdomain: container-security
tags: [containers, docker, security, trivy, vulnerability-scanning]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Scanning Docker Images with Trivy

## Overview

Trivy is a comprehensive open-source vulnerability scanner by Aqua Security that detects vulnerabilities in OS packages, language-specific dependencies, misconfigurations, secrets, and license violations within container images. It integrates into CI/CD pipelines and supports multiple output formats including SARIF, CycloneDX, and SPDX.

## Prerequisites

- Docker Engine 20.10+
- Trivy v0.50+ installed
- Internet access for vulnerability database updates
- Container registry credentials (for private registries)

## Core Concepts

### Scanner Types

| Scanner | Flag | Detects |
|---------|------|---------|
| Vulnerability | `--scanners vuln` | CVEs in OS packages and libraries |
| Misconfiguration | `--scanners misconfig` | Dockerfile/K8s manifest misconfigs |
| Secret | `--scanners secret` | Hardcoded passwords, API keys, tokens |
| License | `--scanners license` | Software license compliance issues |

### Severity Levels

- **CRITICAL**: CVSS 9.0-10.0 - Immediate action required
- **HIGH**: CVSS 7.0-8.9 - Fix before production deployment
- **MEDIUM**: CVSS 4.0-6.9 - Plan remediation
- **LOW**: CVSS 0.1-3.9 - Accept or fix opportunistically
- **UNKNOWN**: Unscored - Evaluate manually

### Vulnerability Database

Trivy uses multiple vulnerability databases:
- NVD (National Vulnerability Database)
- Red Hat Security Data
- Alpine SecDB
- Debian Security Tracker
- Ubuntu CVE Tracker
- Amazon Linux Security Center
- GitHub Advisory Database

## Implementation Steps

### Step 1: Install Trivy

```bash
# Linux (apt)
sudo apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update && sudo apt-get install trivy

# macOS
brew install trivy

# Docker
docker pull aquasecurity/trivy:latest
```

### Step 2: Basic Image Scanning

```bash
# Scan a public image
trivy image python:3.12-slim

# Scan with severity filter
trivy image --severity CRITICAL,HIGH nginx:latest

# Ignore unfixed vulnerabilities
trivy image --ignore-unfixed alpine:3.19

# Scan local image
docker build -t myapp:latest .
trivy image myapp:latest

# Scan from tar archive
docker save myapp:latest -o myapp.tar
trivy image --input myapp.tar
```

### Step 3: Advanced Scanning Options

```bash
# All scanners (vuln + misconfig + secret + license)
trivy image --scanners vuln,misconfig,secret,license myapp:latest

# Generate SBOM in CycloneDX format
trivy image --format cyclonedx --output sbom.cdx.json myapp:latest

# Generate SBOM in SPDX format
trivy image --format spdx-json --output sbom.spdx.json myapp:latest

# JSON output for programmatic processing
trivy image --format json --output results.json myapp:latest

# SARIF output for GitHub Security tab
trivy image --format sarif --output results.sarif myapp:latest

# Template-based output
trivy image --format template --template "@contrib/html.tpl" --output report.html myapp:latest

# Scan specific layers only
trivy image --list-all-pkgs myapp:latest
```

### Step 4: Scanning Kubernetes Manifests

```bash
# Scan Dockerfile for misconfigurations
trivy config Dockerfile

# Scan Kubernetes manifests
trivy config k8s-deployment.yaml

# Scan Helm charts
trivy config ./helm-chart/

# Scan Terraform files
trivy config ./terraform/
```

### Step 5: CI/CD Integration

```yaml
# GitHub Actions
name: Trivy Container Scan
on: push

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build image
        run: docker build -t myapp:${{ github.sha }} .

      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: myapp:${{ github.sha }}
          format: sarif
          output: trivy-results.sarif
          severity: CRITICAL,HIGH
          exit-code: 1

      - name: Upload Trivy scan results
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: trivy-results.sarif

      - name: Generate SBOM
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: myapp:${{ github.sha }}
          format: cyclonedx
          output: sbom.cdx.json
```

```yaml
# GitLab CI
trivy-scan:
  stage: security
  image:
    name: aquasecurity/trivy:latest
    entrypoint: [""]
  script:
    - trivy image --exit-code 1 --severity CRITICAL,HIGH
        --format json --output gl-container-scanning-report.json
        $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
  artifacts:
    reports:
      container_scanning: gl-container-scanning-report.json
```

### Step 6: Policy Enforcement with .trivyignore

```bash
# .trivyignore - Ignore specific CVEs with expiry
# Accepted risk: low-impact vulnerability in dev dependency
CVE-2023-12345 exp:2025-06-01

# False positive: not exploitable in our configuration
CVE-2024-67890

# Vendor will not fix
CVE-2023-11111
```

### Step 7: Scan Private Registry Images

```bash
# Docker Hub (uses ~/.docker/config.json)
trivy image myregistry.azurecr.io/myapp:latest

# ECR
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <account>.dkr.ecr.us-east-1.amazonaws.com
trivy image <account>.dkr.ecr.us-east-1.amazonaws.com/myapp:latest

# GCR
trivy image gcr.io/my-project/myapp:latest

# With explicit credentials
TRIVY_USERNAME=user TRIVY_PASSWORD=pass trivy image registry.example.com/myapp:latest
```

## Validation Commands

```bash
# Verify Trivy installation
trivy version

# Update vulnerability database
trivy image --download-db-only

# Quick scan with table output
trivy image --severity CRITICAL python:3.12

# Verify no CRITICAL vulnerabilities
trivy image --exit-code 1 --severity CRITICAL myapp:latest
echo "Exit code: $?"  # 0 = no vulns, 1 = vulns found
```

## References

- [Trivy Documentation](https://trivy.dev/docs/)
- [Trivy GitHub Repository](https://github.com/aquasecurity/trivy)
- [Trivy GitHub Action](https://github.com/aquasecurity/trivy-action)
- [Aqua Security - Trivy Scanner Guide](https://www.aquasec.com/products/trivy/)
