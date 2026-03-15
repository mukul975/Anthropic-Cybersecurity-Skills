# Aqua Security Container Scanning Workflows

## Workflow 1: CI/CD Image Gate

```
Developer commits code
       |
Docker image built in CI
       |
Trivy scans image for vulnerabilities
       |
[No Critical/High] --> Image pushed to registry
[Critical found] --> Pipeline fails, image rejected
       |
SBOM generated and stored alongside image
       |
Image tagged with scan metadata
       |
Kubernetes admission controller validates scan results
       |
Deployment proceeds only with scanned images
```

## Workflow 2: Registry Continuous Scanning

```
New image pushed to container registry
       |
Trivy Operator detects new image tag
       |
Scheduled scan triggered
       |
VulnerabilityReport CR created in cluster
       |
New CVE published in NVD
       |
Re-scan of all running images
       |
Alert generated for newly affected images
       |
Remediation ticket created automatically
```

## Workflow 3: SBOM-Based Vulnerability Tracking

```
Image scanned, SBOM generated (CycloneDX/SPDX)
       |
SBOM stored in artifact repository
       |
New CVE published
       |
SBOM re-scanned without rebuilding image
       |
Affected images identified across fleet
       |
Prioritized patching based on exposure and severity
```
