# API Reference: Mobile Traffic Interception with Burp Suite

## HAR (HTTP Archive) Format

### Structure
```json
{"log": {"entries": [{"request": {"method": "GET", "url": "https://...",
  "headers": [{"name": "Authorization", "value": "Bearer ..."}],
  "postData": {"text": "..."}},
  "response": {"status": 200, "headers": [...],
  "content": {"text": "..."}}}]}}
```

### Key HAR Fields
| Field | Description |
|-------|-------------|
| `request.url` | Full request URL |
| `request.method` | HTTP method |
| `request.headers` | Request headers array |
| `request.postData.text` | POST body content |
| `response.status` | HTTP status code |
| `response.content.text` | Response body |

## Burp Suite Proxy Setup for Mobile
1. Set proxy listener: `127.0.0.1:8080`
2. Configure device WiFi proxy to Burp IP:8080
3. Install Burp CA: `http://burp/cert`
4. Export traffic as HAR: Proxy > HTTP History > Save Items

## mitmproxy Alternative
```bash
mitmproxy --mode regular --listen-port 8080
mitmdump -w output.flow --set flow_detail=3
# Convert to HAR:
mitmproxy2har output.flow > capture.har
```

## Certificate Pinning Bypass
| Platform | Tool |
|----------|------|
| Android | Frida + objection (`objection explore --startup-command 'android sslpinning disable'`) |
| iOS | SSL Kill Switch 2 (Cydia) |

## Sensitive Data Patterns
| Type | Regex Pattern |
|------|---------------|
| Email | `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}` |
| Credit Card | `\b(?:4\d{3}|5[1-5]\d{2})\d{12}\b` |
| JWT | `eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+` |

## References
- Burp Suite: https://portswigger.net/burp/documentation
- HAR spec: https://w3c.github.io/web-performance/specs/HAR/Overview.html
- mitmproxy: https://docs.mitmproxy.org/stable/
