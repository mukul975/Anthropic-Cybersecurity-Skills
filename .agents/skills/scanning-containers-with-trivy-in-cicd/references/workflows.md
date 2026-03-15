# Workflow Reference: Container Scanning with Trivy in CI/CD

## Container Security Scanning Pipeline

```
Source Code Push
       │
       ▼
┌──────────────────┐
│ Build Docker      │
│ Image             │
└──────┬───────────┘
       │
       ├──────────────────────┐
       ▼                      ▼
┌──────────────┐    ┌──────────────┐
│ Trivy Image  │    │ Trivy Config │
│ Vuln Scan    │    │ Misconfig    │
└──────┬───────┘    └──────┬───────┘
       │                    │
       ▼                    ▼
┌──────────────┐    ┌──────────────┐
│ SARIF/JSON   │    │ Table/JSON   │
│ Output       │    │ Output       │
└──────┬───────┘    └──────┬───────┘
       │                    │
       └──────────┬─────────┘
                  ▼
       ┌──────────────────┐
       │ Quality Gate     │
       │ Evaluation       │
       └──────┬───────────┘
              │
    ┌─────────┴──────────┐
    ▼                    ▼
 PASS: Push to         FAIL: Block
 Registry + Tag        + Alert Team
       │
       ▼
┌──────────────┐
│ Generate     │
│ SBOM + Sign  │
└──────────────┘
```

## Trivy Scan Types Reference

### Image Scanning
```bash
# Full scan (OS + language packages)
trivy image --severity CRITICAL,HIGH --exit-code 1 myimage:tag

# OS packages only
trivy image --vuln-type os myimage:tag

# Language-specific packages only
trivy image --vuln-type library myimage:tag

# From Docker archive
trivy image --input image.tar
```

### Filesystem Scanning
```bash
# Scan project directory for vulnerable dependencies
trivy fs --severity HIGH,CRITICAL /path/to/project

# Scan specific lockfile
trivy fs --severity HIGH,CRITICAL requirements.txt
```

### Repository Scanning
```bash
# Scan remote git repository
trivy repo https://github.com/org/repo

# Scan specific branch
trivy repo --branch develop https://github.com/org/repo
```

### Configuration Scanning
```bash
# Scan Dockerfile and Kubernetes manifests
trivy config .

# Scan Terraform files
trivy config --tf-vars terraform.tfvars ./terraform/

# Scan Helm charts
trivy config ./charts/myapp/
```

## Output Format Options

| Format | Use Case | Flag |
|--------|----------|------|
| table | Human-readable terminal output | `--format table` |
| json | Programmatic processing and storage | `--format json` |
| sarif | GitHub Security tab upload | `--format sarif` |
| cyclonedx | SBOM generation (CycloneDX) | `--format cyclonedx` |
| spdx-json | SBOM generation (SPDX) | `--format spdx-json` |
| template | Custom report format | `--format template --template @template.tpl` |
| cosign-vuln | Cosign attestation format | `--format cosign-vuln` |

## Severity Threshold Matrix

| Environment | Block On | Ignore Unfixed | Rationale |
|-------------|----------|----------------|-----------|
| Development | CRITICAL | Yes | Fast feedback, focus on worst issues |
| Staging | CRITICAL, HIGH | Yes | Catch more issues before production |
| Production | CRITICAL, HIGH | No | Full visibility even for unfixed CVEs |
| Compliance | ALL | No | Complete audit trail required |

## Database Management

### Database Update Strategy
```bash
# Download DB only (for caching)
trivy image --download-db-only --cache-dir /shared/trivy-cache

# Skip DB update (use cached)
trivy image --skip-db-update --cache-dir /shared/trivy-cache myimage:tag

# Java DB for JAR scanning
trivy image --download-java-db-only --cache-dir /shared/trivy-cache
```

### Cache Locations
- Default: `~/.cache/trivy/`
- CI override: `TRIVY_CACHE_DIR=/tmp/trivy-cache`
- GitHub Actions: Use `actions/cache` with key based on date
