# Standards Reference - Docker Image Scanning with Trivy

## NIST SP 800-190 - Application Container Security Guide

### Relevant Controls
- **Image Vulnerability Management**: Organizations should maintain a pipeline for scanning and remediating container image vulnerabilities
- **Image Provenance**: Use content trust and signing to verify image source and integrity
- **SBOM Generation**: Produce Software Bill of Materials for all container images

## CIS Docker Benchmark v1.8.0

### Section 4: Container Images and Build File
- 4.4: Ensure images are scanned and rebuilt to include security patches
- 4.5: Ensure Content trust for Docker is Enabled
- 4.8: Ensure setuid and setgid permissions are removed

## NIST SSDF (Secure Software Development Framework)

### PW.4 - Reuse Existing, Well-Secured Software
- PW.4.1: Verify third-party software components have no known vulnerabilities
- PW.4.4: Verify software components are obtained from trusted sources

### RV.1 - Identify and Confirm Vulnerabilities
- RV.1.1: Gather information from vulnerability notifications
- RV.1.2: Review, analyze, and/or test code to identify vulnerabilities

## OWASP Container Security Verification Standard

### V2: Image Security
- 2.1: Verify images are scanned for known vulnerabilities before deployment
- 2.2: Verify base images are from trusted sources
- 2.3: Verify images do not contain embedded secrets
- 2.4: Verify unnecessary packages are removed from images
- 2.5: Verify images use minimal base (distroless/Alpine)

## Executive Order 14028 - Improving the Nation's Cybersecurity

### SBOM Requirements
- Software producers must provide SBOMs for federal software
- SBOMs must follow NTIA minimum elements
- Supported formats: SPDX, CycloneDX
- Trivy supports both SPDX and CycloneDX SBOM generation

## Trivy Vulnerability Scoring

### CVSS v3.1 Severity Mapping
| Score Range | Severity | Trivy Flag |
|-------------|----------|-----------|
| 9.0 - 10.0 | CRITICAL | --severity CRITICAL |
| 7.0 - 8.9 | HIGH | --severity HIGH |
| 4.0 - 6.9 | MEDIUM | --severity MEDIUM |
| 0.1 - 3.9 | LOW | --severity LOW |
| N/A | UNKNOWN | --severity UNKNOWN |

### Vulnerability Data Sources
| Source | Coverage |
|--------|----------|
| NVD | All CVEs |
| GHSA | GitHub ecosystem packages |
| Red Hat OVAL | RHEL, CentOS |
| Debian Security Tracker | Debian |
| Ubuntu CVE Tracker | Ubuntu |
| Alpine SecDB | Alpine Linux |
| Amazon ALAS | Amazon Linux |
| SUSE OVAL | SUSE/openSUSE |
| Wolfi SecDB | Wolfi/Chainguard |
