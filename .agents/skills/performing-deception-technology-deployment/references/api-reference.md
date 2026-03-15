# API Reference: Performing Deception Technology Deployment

## Canary Tokens API (canarytokens.org)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/generate` | POST | Generate a new canary token (DNS, HTTP, file) |
| `/history` | GET | Retrieve alert history for a token |
| `/manage` | GET | List all deployed tokens |

## Thinkst Canary API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/canarytokens/create` | POST | Create a new canarytoken |
| `/api/v1/incidents/all` | GET | List all triggered incidents |
| `/api/v1/device/list` | GET | List deployed Canary devices |

## Honeypot Components (stdlib)

| Module | Description |
|--------|-------------|
| `http.server.HTTPServer` | HTTP honeypot listener |
| `socketserver.TCPServer` | Generic TCP honeypot |
| `secrets.token_hex()` | Generate unique token IDs |
| `hashlib.sha256()` | Hash canary file content for integrity |

## Key Libraries

- **secrets** (stdlib): Cryptographically secure token generation
- **http.server** (stdlib): HTTP honeypot server implementation
- **socket** (stdlib): TCP/UDP honeypot listeners
- **hashlib** (stdlib): File integrity hashing for canary files
- **threading** (stdlib): Run honeypot services in background threads

## Honeytoken Types

| Type | Deployment | Alert Trigger |
|------|------------|---------------|
| Credential | AD, LSASS, config files | Any authentication attempt |
| Canary File | Network shares, endpoints | File open/read access |
| DNS Token | Documents, scripts | DNS resolution |
| AWS Key | Code repos, config files | AWS API call with key |
| HTTP Token | Documents, emails | HTTP GET request |

## Configuration

| Variable | Description |
|----------|-------------|
| `CANARY_API_KEY` | Thinkst Canary API key |
| `CANARY_DOMAIN` | Canary DNS domain for token callbacks |
| `HONEYPOT_PORT` | Port for HTTP honeypot listener |

## References

- [Canarytokens.org](https://canarytokens.org/)
- [Thinkst Canary](https://canary.tools/)
- [MITRE ATT&CK D3FEND - Decoy](https://d3fend.mitre.org/technique/d3f:Decoy/)
- [OpenCanary](https://github.com/thinkst/opencanary)
