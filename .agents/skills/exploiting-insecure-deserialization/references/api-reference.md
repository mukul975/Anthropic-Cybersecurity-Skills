# API Reference: Insecure Deserialization Detection Agent

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| requests | >=2.28 | HTTP requests for scanning cookies and responses |
| pickle | stdlib | Python pickle payload generation for testing |

## CLI Usage

```bash
python scripts/agent.py --url https://target.example.com/dashboard \
  --callback oob.attacker.com --output deser_report.json
```

## Functions

### `detect_serialization_format(data) -> str`
Identifies serialization format from a string: `java_serialized`, `dotnet_viewstate`, `php_serialized`, `python_pickle`.

### `scan_cookies(url, session) -> list`
Fetches the URL and checks each response cookie value for serialization markers.

### `scan_response_body(url, method, data) -> list`
Scans the HTTP response body for Java Base64 (`rO0AB`), PHP serialized objects, and `__VIEWSTATE` fields.

### `test_java_deserialization(url, cookie_name, callback_host) -> dict`
Injects a URLDNS-style probe into a cookie to trigger DNS callback on deserialization.

### `test_php_deserialization(url, param_name) -> dict`
Sends PHP serialized object payloads attempting role escalation.

### `test_python_pickle(url, param_name, callback_host) -> dict`
Generates a pickle payload with `__reduce__` that triggers a DNS lookup for OOB detection.

### `run_assessment(url, callback_host) -> dict`
Orchestrates cookie and body scanning.

## Serialization Markers

| Format | Magic / Prefix | Example |
|--------|---------------|---------|
| Java binary | `\xac\xed\x00\x05` | Raw bytes |
| Java Base64 | `rO0AB` | Base64-encoded |
| .NET ViewState | `/wE` | `__VIEWSTATE` hidden field |
| PHP | `O:4:`, `a:2:` | Object/array notation |
| Python pickle | `\x80` (protocol byte) | Base64-encoded |

## Output Schema

```json
{
  "target": "https://target.example.com/",
  "serialized_data_found": 2,
  "cookie_findings": [{"name": "session", "format": "java_serialized"}],
  "formats_detected": ["java_serialized"]
}
```
