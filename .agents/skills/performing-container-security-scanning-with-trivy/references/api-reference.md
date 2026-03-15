# API Reference: Performing Container Security Scanning with Trivy

## Trivy CLI Commands

```bash
# Vulnerability + secret scan on image
trivy image --severity CRITICAL,HIGH nginx:latest

# JSON output for CI/CD integration
trivy image --format json --output results.json alpine:3.18

# Scan with all scanners
trivy image --scanners vuln,misconfig,secret,license myregistry.io/app:v1.2

# Scan Dockerfile/K8s manifests for misconfigurations
trivy config --severity CRITICAL,HIGH ./kubernetes/

# Filesystem scan (local project)
trivy fs --scanners vuln,secret ./

# Generate CycloneDX SBOM
trivy image --format cyclonedx --output sbom.json myapp:latest

# Generate SPDX SBOM
trivy image --format spdx-json --output sbom-spdx.json myapp:latest

# Scan existing SBOM for vulnerabilities
trivy sbom ./sbom.json

# Ignore unfixed vulnerabilities
trivy image --ignore-unfixed --severity CRITICAL alpine:3.18

# SARIF output for GitHub Advanced Security
trivy image --format sarif --output trivy.sarif myapp:latest
```

## Severity Levels

| Level | CVSS Score | CI Gate Default |
|-------|------------|-----------------|
| CRITICAL | 9.0 - 10.0 | Block |
| HIGH | 7.0 - 8.9 | Block |
| MEDIUM | 4.0 - 6.9 | Warn |
| LOW | 0.1 - 3.9 | Pass |

## Scanner Types

| Scanner | Flag | Targets |
|---------|------|---------|
| vuln | `--scanners vuln` | OS packages, language deps |
| misconfig | `--scanners misconfig` | Dockerfile, K8s, Terraform |
| secret | `--scanners secret` | API keys, passwords, tokens |
| license | `--scanners license` | Package license compliance |

## GitHub Actions Integration

```yaml
- name: Trivy vulnerability scan
  uses: aquasecurity/trivy-action@master
  with:
    image-ref: 'myapp:${{ github.sha }}'
    format: 'sarif'
    output: 'trivy-results.sarif'
    severity: 'CRITICAL,HIGH'
    exit-code: '1'
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No vulnerabilities found (or below threshold) |
| 1 | Vulnerabilities found matching severity filter |

## JSON Output Structure

```json
{
  "Results": [{
    "Target": "alpine:3.18 (alpine 3.18.0)",
    "Type": "alpine",
    "Vulnerabilities": [{
      "VulnerabilityID": "CVE-2023-xxxx",
      "PkgName": "openssl",
      "InstalledVersion": "3.1.0-r0",
      "FixedVersion": "3.1.1-r0",
      "Severity": "HIGH"
    }]
  }]
}
```

### References

- Trivy Documentation: https://trivy.dev/docs/latest/
- Trivy GitHub: https://github.com/aquasecurity/trivy
- trivy-action: https://github.com/aquasecurity/trivy-action
