---
name: performing-container-security-scanning-with-trivy
description: Scan container images, filesystems, and Kubernetes manifests for vulnerabilities, misconfigurations, exposed secrets, and license compliance issues using Aqua Security Trivy with SBOM generation and CI/CD integration.
domain: cybersecurity
subdomain: container-security
tags: [trivy, container-security, vulnerability-scanning, sbom, docker, kubernetes, devsecops, supply-chain]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing Container Security Scanning with Trivy

## Overview

Trivy is an open-source security scanner by Aqua Security that detects vulnerabilities in OS packages and language-specific dependencies, infrastructure-as-code misconfigurations, exposed secrets, and software license issues across container images, filesystems, Git repositories, and Kubernetes clusters. Trivy generates Software Bill of Materials (SBOM) in CycloneDX and SPDX formats for supply chain transparency. This skill covers comprehensive container image scanning, CI/CD pipeline integration, Kubernetes operator deployment, and scan result triage for security operations.

## Prerequisites

- Trivy v0.50+ installed (binary, Docker, or Homebrew)
- Docker daemon access for local image scanning
- Container registry credentials for remote image scanning
- CI/CD platform (GitHub Actions, GitLab CI, Jenkins) for pipeline integration
- Kubernetes cluster for Trivy Operator deployment (optional)

## Steps

### Step 1: Scan Container Images

Run vulnerability and secret scanning against container images from local builds or remote registries. Configure severity thresholds and ignore unfixed vulnerabilities.

### Step 2: Generate SBOM

Produce CycloneDX or SPDX SBOM documents from scanned images for supply chain compliance and vulnerability tracking across the software lifecycle.

### Step 3: Scan IaC and Kubernetes Manifests

Detect misconfigurations in Dockerfiles, Kubernetes YAML, Terraform, and Helm charts using built-in policy checks aligned with CIS benchmarks.

### Step 4: Integrate into CI/CD

Add Trivy scanning as a pipeline gate that blocks builds with critical/high vulnerabilities, generates SARIF reports for GitHub Advanced Security, and produces JUnit XML for test dashboards.

## Expected Output

JSON/table report listing CVEs with severity, CVSS scores, fixed versions, affected packages, misconfiguration findings, and exposed secrets with file locations.
