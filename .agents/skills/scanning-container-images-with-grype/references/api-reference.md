# API Reference: Scanning Container Images with Grype

## Grype CLI Commands

| Command | Description |
|---------|-------------|
| `grype <image>` | Scan a container image |
| `grype <image> -o json` | JSON output for parsing |
| `grype <image> -o sarif` | SARIF output for GitHub Security |
| `grype <image> --fail-on critical` | Exit non-zero on severity |
| `grype <image> --only-fixed` | Show only fixable vulns |
| `grype sbom:<file>` | Scan a pre-generated SBOM |
| `grype dir:<path>` | Scan a local directory |
| `grype db status` | Check vulnerability DB status |
| `grype db update` | Update vulnerability database |

## Input Sources

| Source | Syntax | Description |
|--------|--------|-------------|
| Registry | `grype nginx:latest` | Pull from registry |
| Docker daemon | `grype docker:myapp:1.0` | Local Docker image |
| Archive | `grype docker-archive:image.tar` | Saved tar archive |
| OCI dir | `grype oci-dir:path/` | OCI layout directory |
| SBOM | `grype sbom:bom.json` | CycloneDX/SPDX SBOM |
| Directory | `grype dir:/path/` | Filesystem scan |

## Severity Levels

| Level | CVSS Range | Action |
|-------|-----------|--------|
| Critical | 9.0 - 10.0 | Immediate remediation |
| High | 7.0 - 8.9 | Fix before deployment |
| Medium | 4.0 - 6.9 | Plan remediation |
| Low | 0.1 - 3.9 | Accept or fix later |
| Negligible | 0.0 | Informational |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `subprocess` | stdlib | Execute grype CLI |
| `json` | stdlib | Parse JSON output |
| `pathlib` | stdlib | File path handling |

## References

- Grype GitHub: https://github.com/anchore/grype
- Anchore Scan Action: https://github.com/anchore/scan-action
- Syft SBOM Generator: https://github.com/anchore/syft
