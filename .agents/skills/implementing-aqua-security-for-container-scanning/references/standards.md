# Standards Reference for Container Scanning

## NIST SP 800-190: Application Container Security Guide

| Recommendation | Trivy Coverage |
|---------------|---------------|
| 4.1 Image vulnerabilities | CVE scanning of OS packages and app dependencies |
| 4.2 Image configuration defects | IaC misconfig scanning of Dockerfiles |
| 4.3 Embedded malware | Secret scanning detects embedded credentials |
| 4.4 Embedded cleartext secrets | Secret scanner with regex and entropy detection |
| 4.5 Use of untrusted images | Registry scanning and image provenance verification |

## CIS Docker Benchmark v1.6 Alignment

| CIS Control | Trivy Check |
|-------------|-------------|
| 4.1 Ensure image is created from a trusted base | Base image vulnerability scanning |
| 4.3 Ensure unnecessary packages are not installed | SBOM generation reveals full package inventory |
| 4.6 Add HEALTHCHECK instruction | Dockerfile misconfiguration check |
| 4.9 Ensure COPY instead of ADD | Dockerfile misconfiguration check |
| 4.10 Ensure secrets are not stored in Dockerfiles | Secret detection in filesystem scan |

## Vulnerability Database Sources

| Source | Coverage | Update Frequency |
|--------|----------|------------------|
| NVD (NIST) | All CVEs | Continuous |
| Alpine SecDB | Alpine Linux packages | Daily |
| Debian Security Tracker | Debian packages | Daily |
| Ubuntu CVE Tracker | Ubuntu packages | Daily |
| Red Hat OVAL | RHEL/CentOS packages | Daily |
| GitHub Advisory Database | Language packages | Continuous |
| Go Vulnerability Database | Go modules | Continuous |
| RustSec Advisory Database | Rust crates | Continuous |
