# API Reference: HTTP Request Smuggling Detection Agent

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| requests | >=2.28 | Architecture fingerprinting via HTTP headers |
| socket/ssl | stdlib | Raw HTTP request construction for smuggling probes |

## CLI Usage

```bash
python scripts/agent.py --url https://target.example.com/ --output smuggling.json
```

## Functions

### `identify_architecture(url) -> dict`
Sends a GET request and inspects `Server`, `Via`, `X-Served-By`, `CF-Ray` headers to identify proxy/CDN chain.

### `send_raw_request(host, port, request_bytes, use_ssl, timeout) -> tuple`
Low-level socket send for crafting ambiguous HTTP requests. Returns `(response_bytes, elapsed_seconds, error)`.

### `test_clte_detection(host, port, use_ssl) -> dict`
Sends a CL.TE probe with mismatched `Content-Length` and incomplete chunked body. A response delay >5s suggests vulnerability.

### `test_tecl_detection(host, port, use_ssl) -> dict`
Sends a TE.CL probe. Back-end reading `Content-Length` receives extra data that becomes the next request prefix.

### `test_te_te_detection(host, port, use_ssl) -> dict`
Tests 5 `Transfer-Encoding` header obfuscation variants to detect differential parsing.

### `run_assessment(url) -> dict`
Orchestrates all tests and compiles results.

## Smuggling Types

| Type | Front-End Uses | Back-End Uses | Detection |
|------|---------------|---------------|-----------|
| CL.TE | Content-Length | Transfer-Encoding | Time delay on incomplete chunk |
| TE.CL | Transfer-Encoding | Content-Length | Extra data becomes next request |
| TE.TE | Transfer-Encoding | Transfer-Encoding | Obfuscated TE header parsed differently |

## Output Schema

```json
{
  "target": "https://target.example.com/",
  "architecture": {"server": "nginx", "cdn": "Cloudflare"},
  "tests": {"CL.TE": {"likely_vulnerable": false}, ...},
  "summary": {"clte_vulnerable": false, "tecl_vulnerable": false}
}
```
