# API Reference: SSRF Vulnerability Assessment Agent

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| requests | >=2.28 | HTTP client for sending SSRF payloads |

## CLI Usage

```bash
python scripts/agent.py \
  --url https://target.example.com/api/fetch-url \
  --param url \
  --auth "Bearer TOKEN" \
  --output ssrf_report.json
```

## Functions

### `test_ssrf_endpoint(target_url, param_name, payload_url, method, auth_header) -> dict`
Sends a single SSRF payload and checks the response for success indicators.

### `test_cloud_metadata(target_url, param_name, auth_header) -> list`
Tests SSRF against AWS IMDSv1, GCP, Azure, and DigitalOcean metadata endpoints.

### `test_localhost_bypasses(target_url, param_name, auth_header) -> list`
Tests 9 localhost encoding bypasses: octal, hex, decimal, IPv6, short form, wildcard DNS.

### `test_protocol_schemes(target_url, param_name, auth_header) -> list`
Tests `file://`, `dict://`, and `gopher://` protocol handlers.

### `scan_internal_ports(target_url, param_name, internal_ip, ports, auth_header) -> list`
Uses SSRF to probe internal ports (22, 80, 3306, 5432, 6379, 8080, 9200).

### `run_assessment(target_url, param_name, auth_header) -> dict`
Orchestrates all SSRF tests and compiles findings.

## Cloud Metadata Endpoints

| Provider | URL |
|----------|-----|
| AWS IMDSv1 | `http://169.254.169.254/latest/meta-data/` |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` |
| Azure | `http://169.254.169.254/metadata/instance` |
| DigitalOcean | `http://169.254.169.254/metadata/v1/` |

## Output Schema

```json
{
  "target": "https://target.example.com/api/fetch-url",
  "parameter": "url",
  "cloud_metadata_tests": [{"cloud_provider": "aws_imdsv1", "status_code": 200}],
  "findings": ["CRITICAL: Cloud metadata accessible via 1 endpoints"]
}
```
