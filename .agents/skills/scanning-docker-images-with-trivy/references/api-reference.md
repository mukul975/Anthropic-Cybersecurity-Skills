# API Reference: Scanning Docker Images with Trivy

## Trivy Scanner Types

| Scanner | Flag | Detects |
|---------|------|---------|
| Vulnerability | `--scanners vuln` | CVEs in OS packages and libraries |
| Misconfiguration | `--scanners misconfig` | Dockerfile/K8s misconfigs |
| Secret | `--scanners secret` | Hardcoded passwords, API keys |
| License | `--scanners license` | License compliance issues |

## Core Commands

| Command | Description |
|---------|-------------|
| `trivy image <ref>` | Scan Docker image |
| `trivy image --input <tar>` | Scan saved tar archive |
| `trivy image --format json` | JSON output |
| `trivy image --format sarif` | SARIF for GitHub Security |
| `trivy image --format cyclonedx` | CycloneDX SBOM |
| `trivy image --format spdx-json` | SPDX SBOM |
| `trivy image --exit-code 1 --severity CRITICAL` | Fail on critical |
| `trivy image --list-all-pkgs` | List all detected packages |

## Vulnerability Database Sources

| Source | Coverage |
|--------|----------|
| NVD | All ecosystems |
| GitHub Advisory Database | Open source packages |
| Alpine SecDB | Alpine Linux |
| Debian Security Tracker | Debian packages |
| Red Hat Security Data | RHEL/CentOS |
| Ubuntu CVE Tracker | Ubuntu packages |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `subprocess` | stdlib | Execute trivy CLI |
| `json` | stdlib | Parse scan results |
| `pathlib` | stdlib | File path handling |

## References

- Trivy Documentation: https://trivy.dev/docs/
- Trivy GitHub: https://github.com/aquasecurity/trivy
- Aqua Security: https://www.aquasec.com/products/trivy/
