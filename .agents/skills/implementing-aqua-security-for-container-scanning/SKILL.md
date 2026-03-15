---
name: implementing-aqua-security-for-container-scanning
description: Deploy Aqua Security's Trivy scanner to detect vulnerabilities, misconfigurations, secrets, and license issues in container images across CI/CD pipelines and registries.
domain: cybersecurity
subdomain: devsecops
tags: [aqua-security, trivy, container-scanning, vulnerability-scanning, sbom, image-security, supply-chain]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Implementing Aqua Security for Container Scanning

## Overview

Aqua Security provides Trivy, the world's most popular open-source universal security scanner, designed to find vulnerabilities, misconfigurations, secrets, SBOM data, and license issues in containers, Kubernetes, code repositories, and cloud environments. Trivy covers OS packages (Alpine, Debian, Ubuntu, RHEL, etc.) and language-specific dependencies (npm, pip, Maven, Go modules, Cargo, etc.) with vulnerability databases sourced from NVD, vendor advisories, and GitHub Security Advisories. The enterprise Aqua Platform extends Trivy with centralized policy management, runtime protection, and compliance reporting.

## Prerequisites

- Docker installed for local image scanning
- CI/CD platform (GitHub Actions, GitLab CI, Jenkins, etc.)
- Container registry access (Docker Hub, ECR, GCR, ACR, Harbor)
- Trivy CLI (`trivy`) or Trivy Operator for Kubernetes
- Aqua Platform license for enterprise features (optional)

## Core Scanning Capabilities

### Image Vulnerability Scanning

Trivy scans container images layer by layer, identifying CVEs in OS packages and application dependencies. It supports scanning local images, remote registry images, and tar archives.

```bash
# Scan a remote image
trivy image python:3.11-slim

# Scan with severity filter
trivy image --severity HIGH,CRITICAL nginx:latest

# Scan and fail CI if critical CVEs found
trivy image --exit-code 1 --severity CRITICAL myapp:latest

# Generate SBOM in CycloneDX format
trivy image --format cyclonedx --output sbom.json myapp:latest
```

### Filesystem and Repository Scanning

```bash
# Scan project directory for vulnerabilities in dependencies
trivy fs --scanners vuln,secret,misconfig .

# Scan a specific lockfile
trivy fs --scanners vuln package-lock.json

# Scan git repository
trivy repo https://github.com/org/project
```

### Kubernetes Scanning with Trivy Operator

The Trivy Operator runs inside a Kubernetes cluster and continuously scans workloads:

```bash
# Install Trivy Operator via Helm
helm repo add aqua https://aquasecurity.github.io/helm-charts/
helm repo update
helm install trivy-operator aqua/trivy-operator \
  --namespace trivy-system \
  --create-namespace \
  --set trivy.severity="HIGH,CRITICAL" \
  --set operator.scanJobTimeout="5m"
```

The operator creates VulnerabilityReport and ConfigAuditReport custom resources for each workload.

### IaC Misconfiguration Scanning

```bash
# Scan Terraform files
trivy config --severity HIGH,CRITICAL ./terraform/

# Scan Dockerfile for misconfigurations
trivy config Dockerfile

# Scan Kubernetes manifests
trivy config ./k8s-manifests/
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Container Security Scan
on:
  push:
    branches: [main]
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build Docker image
        run: docker build -t myapp:${{ github.sha }} .

      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'myapp:${{ github.sha }}'
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH'
          exit-code: '1'

      - name: Upload Trivy scan results to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: 'trivy-results.sarif'
```

### GitLab CI

```yaml
container_scanning:
  stage: security
  image:
    name: aquasec/trivy:latest
    entrypoint: [""]
  variables:
    FULL_IMAGE_NAME: $CI_REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA
  script:
    - trivy image --exit-code 0 --format template --template "@/contrib/gitlab.tpl"
      --output gl-container-scanning-report.json $FULL_IMAGE_NAME
    - trivy image --exit-code 1 --severity CRITICAL $FULL_IMAGE_NAME
  artifacts:
    reports:
      container_scanning: gl-container-scanning-report.json
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh 'docker build -t myapp:${BUILD_NUMBER} .'
            }
        }
        stage('Security Scan') {
            steps {
                sh '''
                    trivy image --exit-code 1 \
                      --severity HIGH,CRITICAL \
                      --format json \
                      --output trivy-report.json \
                      myapp:${BUILD_NUMBER}
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'trivy-report.json'
                }
            }
        }
    }
}
```

## Policy Configuration

### Trivy Policy with OPA/Rego

Create `.trivy/policy.rego` for custom policy enforcement:

```rego
package trivy

deny[msg] {
    input.Results[_].Vulnerabilities[_].Severity == "CRITICAL"
    msg := "Critical vulnerabilities found in image"
}

deny[msg] {
    input.Results[_].Vulnerabilities[vuln]
    vuln.FixedVersion != ""
    vuln.Severity == "HIGH"
    msg := sprintf("Fixable HIGH vulnerability: %s", [vuln.VulnerabilityID])
}
```

### Ignore File Configuration

Create `.trivyignore` for accepted risks:

```
# Accepted risk: vulnerability in test dependency only
CVE-2023-12345

# Accepted until expiry date
CVE-2024-67890 exp:2025-06-01
```

## SBOM Generation and Management

```bash
# Generate CycloneDX SBOM
trivy image --format cyclonedx --output sbom-cyclonedx.json myapp:latest

# Generate SPDX SBOM
trivy image --format spdx-json --output sbom-spdx.json myapp:latest

# Scan an existing SBOM for new vulnerabilities
trivy sbom sbom-cyclonedx.json
```

## Monitoring and Reporting

| Metric | Description | Target |
|--------|-------------|--------|
| Images scanned per day | Total images passing through scanning pipeline | All production images |
| Critical CVE count | Open critical vulnerabilities across all images | 0 in production |
| Mean time to patch | Average days from CVE publication to patched image | < 7 days |
| SBOM coverage | Percentage of production images with generated SBOMs | 100% |
| Scan duration | Average time per image scan | < 2 minutes |

## References

- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [Trivy GitHub Repository](https://github.com/aquasecurity/trivy)
- [Trivy Operator for Kubernetes](https://aquasecurity.github.io/trivy-operator/)
- [Aqua Security Platform](https://www.aquasec.com/products/)
- [CycloneDX SBOM Specification](https://cyclonedx.org/specification/overview/)
