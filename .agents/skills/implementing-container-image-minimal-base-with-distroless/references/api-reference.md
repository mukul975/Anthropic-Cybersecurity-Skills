# API Reference: Distroless Container Image Analysis Agent

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| trivy CLI | >=0.50 | Container vulnerability scanning (subprocess) |
| docker CLI | >=24.0 | Image inspection and property checks (subprocess) |

## CLI Usage

```bash
python scripts/agent.py \
  --images gcr.io/distroless/static-debian12 python:3.12-slim \
  --compare python:3.12 gcr.io/distroless/python3-debian12 \
  --output-dir /reports/
```

## Functions

### `run_trivy_scan(image) -> dict`
Runs `trivy image --format json --severity CRITICAL,HIGH,MEDIUM`.

### `get_image_size(image) -> int`
Runs `docker inspect --format {{.Size}}` for byte count.

### `count_vulns_by_severity(scan_data) -> dict`
Parses Trivy JSON Results for CRITICAL/HIGH/MEDIUM/LOW counts.

### `compare_images(base_image, distroless_image) -> dict`
Scans both images, computes size and vulnerability reduction percentages.

### `check_distroless_properties(image) -> dict`
Tests for shell access and package manager presence via `docker run`.

### `generate_report(images, distroless_pairs) -> dict`
Full analysis with individual scans, comparisons, and summary.

## Distroless Properties Checked

| Property | Check Method |
|----------|-------------|
| Shell access | `docker run --entrypoint "" image sh -c "echo"` |
| Package manager | `docker run --entrypoint "" image which apt/apk/yum` |

## Output Schema

```json
{
  "summary": {"images_scanned": 4, "minimal_images": 2},
  "comparisons": [{"size_reduction_pct": 82.3, "vuln_reduction_pct": 95.0}],
  "image_scans": [{"image": "gcr.io/distroless/static", "is_minimal": true}]
}
```
