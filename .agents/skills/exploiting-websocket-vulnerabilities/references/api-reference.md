# API Reference: WebSocket Vulnerability Assessment Agent

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| websockets | >=11.0 | Async WebSocket client for connection and message testing |
| requests | >=2.28 | HTTP-level WebSocket handshake inspection |

## CLI Usage

```bash
python scripts/agent.py \
  --url wss://target.example.com/ws \
  --cookie "session=abc123" \
  --output ws_report.json
```

## Functions

### `discover_ws_endpoints(base_url) -> list`
Probes 9 common WebSocket paths with upgrade headers to find endpoints.

### `test_origin_validation(ws_url, cookie) -> dict`
Sends WebSocket upgrade requests with evil Origin headers. Acceptance indicates CSWSH risk.

### `test_no_auth_connect(ws_url) -> dict` (async)
Attempts WebSocket connection without any authentication tokens.

### `test_message_injection(ws_url, cookie) -> list` (async)
Sends 6 injection payloads (SQLi, XSS, SSTI, path traversal, command injection) and checks responses.

### `test_idor_channels(ws_url, cookie, channel_ids) -> list` (async)
Subscribes to channels 1-5 to test for IDOR in channel access.

### `test_rate_limiting(ws_url, cookie, count) -> dict` (async)
Sends 100 rapid messages and checks if the connection is throttled or closed.

### `run_assessment(ws_url, cookie) -> dict`
Orchestrates all tests and compiles findings.

## websockets Library Usage

| Method | Purpose |
|--------|---------|
| `websockets.connect(url, extra_headers)` | Async context manager for WS connection |
| `ws.send(data)` | Send a text frame |
| `ws.recv()` | Receive next frame |
| `asyncio.wait_for(ws.recv(), timeout)` | Receive with timeout |

## Output Schema

```json
{
  "target": "wss://target.example.com/ws",
  "origin_validation": {"cswsh_vulnerable": true},
  "unauthenticated_access": {"connected": false},
  "injection_tests": [{"payload": {"query": "' OR 1=1--"}, "suspicious": true}],
  "rate_limiting": {"rate_limited": false},
  "findings": ["HIGH: Cross-Site WebSocket Hijacking possible"]
}
```
