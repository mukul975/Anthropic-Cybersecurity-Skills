# API Reference: Securing Container Registry Images

## Trivy CLI
```bash
trivy image [OPTIONS] IMAGE
```
| Flag | Description |
|------|-------------|
| `--severity` | Filter by severity: CRITICAL,HIGH,MEDIUM,LOW |
| `--format` | Output format: table, json, sarif, spdx-json |
| `--exit-code 1` | Exit with code 1 if vulnerabilities found |
| `--scanners` | Scanner types: vuln, misconfig, secret |
| `--output FILE` | Write results to file |

## Cosign CLI
| Command | Description |
|---------|-------------|
| `cosign sign --key KEY IMAGE` | Sign an image with a private key |
| `cosign verify --key KEY IMAGE` | Verify image signature |
| `cosign generate-key-pair` | Generate signing key pair |
| `cosign attest --predicate FILE IMAGE` | Attach signed attestation |
| `cosign attach sbom --sbom FILE IMAGE` | Attach SBOM to image |

## Syft CLI (SBOM Generation)
```bash
syft IMAGE -o FORMAT > output.json
```
Formats: `spdx-json`, `cyclonedx-json`, `table`, `json`

## boto3 ECR Client

| Method | Description |
|--------|-------------|
| `describe_repositories()` | Get repository config (scan settings, mutability) |
| `put_image_scanning_configuration()` | Enable/disable scan on push |
| `put_image_tag_mutability()` | Set tag immutability (MUTABLE/IMMUTABLE) |
| `put_lifecycle_policy()` | Set image cleanup rules |
| `describe_image_scan_findings()` | Get scan results for an image |
| `list_images()` | List images (filter by tagged/untagged) |
| `get_lifecycle_policy()` | Get current lifecycle policy |

### ECR Scan Findings Structure
```python
{
    "findingSeverityCounts": {"CRITICAL": 2, "HIGH": 5},
    "findings": [
        {"name": "CVE-2024-xxxx", "severity": "CRITICAL", "uri": "..."}
    ]
}
```

## References
- Trivy docs: https://aquasecurity.github.io/trivy/
- Cosign docs: https://docs.sigstore.dev/cosign/overview/
- Syft docs: https://github.com/anchore/syft
- ECR API: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ecr.html
