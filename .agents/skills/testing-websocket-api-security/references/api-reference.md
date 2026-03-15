# API Reference: Testing WebSocket API Security

## WebSocket Attack Surface

| Attack | Severity | Description |
|--------|----------|-------------|
| CSWSH | Critical | Cross-Site WebSocket Hijacking via Origin |
| No authentication | High | Connection without credentials accepted |
| Channel auth bypass | High | Subscribe to privileged channels |
| Injection via messages | Medium | SQL/XSS/command injection in payloads |
| Message flooding | Medium | DoS through rapid message sending |
| Prototype pollution | Medium | `__proto__` payload in JSON messages |

## WebSocket Handshake Headers

| Header | Direction | Purpose |
|--------|-----------|---------|
| Upgrade: websocket | Request | Protocol upgrade request |
| Connection: Upgrade | Request | Connection type change |
| Sec-WebSocket-Key | Request | Client nonce for handshake |
| Sec-WebSocket-Version | Request | Protocol version (13) |
| Sec-WebSocket-Accept | Response | Server handshake confirmation |
| Origin | Request | CSWSH validation target |

## Injection Payload Categories

| Category | Example |
|----------|---------|
| Admin action | `{"action":"admin","data":"test"}` |
| Path traversal | `{"channel":"../admin"}` |
| XSS | `<script>alert(1)</script>` |
| SQLi | `' OR 1=1 --` |
| Prototype pollution | `{"__proto__":{"isAdmin":true}}` |
| Oversized message | 100KB+ payload |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `websockets` | >=10.0 | Async WebSocket client |
| `asyncio` | stdlib | Async event loop |
| `requests` | >=2.28 | HTTP upgrade header check |
| `json` | stdlib | Message/report serialization |

## References

- OWASP WebSocket Testing: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets
- PortSwigger WebSocket: https://portswigger.net/web-security/websockets
- RFC 6455: https://www.rfc-editor.org/rfc/rfc6455
