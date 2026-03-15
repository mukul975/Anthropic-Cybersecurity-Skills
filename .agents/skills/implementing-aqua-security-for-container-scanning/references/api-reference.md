# API Reference: Container Image Vulnerability Scanner (Trivy)

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| trivy CLI | >=0.50 | Container image scanning (invoked via subprocess) |

## CLI Usage

```bash
python scripts/agent.py \
  --images nginx:latest alpine:3.19 myapp:v1.2 \
  --severity CRITICAL,HIGH \
  --sbom \
  --output-dir /reports/ \
  --output trivy_report.json
```

## Functions

### `check_trivy_installed() -> bool`
Verifies Trivy CLI is available in PATH by running `trivy --version`.

### `scan_image(image, severity, ignore_unfixed) -> dict`
Runs `trivy image --format json --severity CRITICAL,HIGH <image>`. Returns parsed JSON output.

### `scan_image_misconfig(image) -> dict`
Runs `trivy image --scanners misconfig` to detect Dockerfile and config issues.

### `scan_image_secrets(image) -> dict`
Runs `trivy image --scanners secret` to find embedded secrets in image layers.

### `generate_sbom(image, output_path) -> bool`
Runs `trivy image --format cyclonedx` to produce CycloneDX SBOM.

### `parse_vuln_results(scan_data) -> list`
Extracts vulnerability details from Trivy JSON: VulnerabilityID, PkgName, InstalledVersion, FixedVersion, Severity.

### `compute_summary(vulns) -> dict`
Counts vulnerabilities by severity level (CRITICAL/HIGH/MEDIUM/LOW) and fixable count.

### `scan_multiple_images(images, severity) -> dict`
Orchestrates scanning of multiple images and aggregates results.

## Trivy CLI Commands Used

| Command | Purpose |
|---------|---------|
| `trivy image --format json` | Vulnerability scan with JSON output |
| `trivy image --scanners misconfig` | Misconfiguration detection |
| `trivy image --scanners secret` | Secret detection in layers |
| `trivy image --format cyclonedx` | SBOM generation |

## Output Schema

```json
{
  "images": [{"image": "nginx:latest", "summary": {"CRITICAL": 2, "HIGH": 5, "fixable": 4}}],
  "overall_summary": {"CRITICAL": 2, "HIGH": 5, "total": 7}
}
```
