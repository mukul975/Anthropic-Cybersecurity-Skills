# API Reference: Scanning Containers with Trivy in CI/CD

## Trivy CLI Commands

| Command | Description |
|---------|-------------|
| `trivy image <ref>` | Scan container image for vulnerabilities |
| `trivy config <path>` | Scan Dockerfiles/IaC for misconfigurations |
| `trivy fs <path>` | Scan filesystem for vulnerabilities |
| `trivy sbom <file>` | Scan existing SBOM for vulnerabilities |
| `trivy image --format sarif` | SARIF output for GitHub Security |
| `trivy image --format cyclonedx` | CycloneDX SBOM generation |
| `trivy image --exit-code 1` | Non-zero exit on findings |

## Scan Options

| Flag | Description |
|------|-------------|
| `--severity CRITICAL,HIGH` | Filter by severity level |
| `--ignore-unfixed` | Skip CVEs without patches |
| `--scanners vuln,misconfig,secret` | Select scanner types |
| `--format json/sarif/cyclonedx` | Output format |
| `--exit-code 1` | Fail pipeline on findings |
| `--skip-db-update` | Use cached vulnerability DB |
| `--cache-dir <path>` | Set database cache directory |

## CI/CD Integration

| Platform | Method |
|----------|--------|
| GitHub Actions | `aquasecurity/trivy-action@v0.28.0` |
| GitLab CI | `aquasec/trivy:latest` Docker image |
| Jenkins | Trivy CLI in pipeline script |
| Azure DevOps | Trivy CLI task |

## Quality Gate Severities

| Level | CVSS Range | Default Gate Action |
|-------|-----------|-------------------|
| CRITICAL | 9.0 - 10.0 | Block deployment |
| HIGH | 7.0 - 8.9 | Block deployment |
| MEDIUM | 4.0 - 6.9 | Warn |
| LOW | 0.1 - 3.9 | Allow |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `subprocess` | stdlib | Execute trivy CLI |
| `json` | stdlib | Parse scan results |
| `pathlib` | stdlib | Output file management |

## References

- Trivy Documentation: https://trivy.dev/docs/
- Trivy GitHub Action: https://github.com/aquasecurity/trivy-action
- Trivy GitHub: https://github.com/aquasecurity/trivy
