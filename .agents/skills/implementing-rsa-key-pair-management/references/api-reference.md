# API Reference: RSA key pair lifecycle management audit

## API Details
rsa.generate_private_key(), key.public_key(), serialization PEM/DER, key strength 2048/4096

## Installation
```bash
pip install cryptography
```

## Libraries

| Library | Use |
|---------|-----|
| `cryptography` | cryptography client/SDK |

## Authentication

| Method | Header |
|--------|--------|
| Bearer Token | `Authorization: Bearer <token>` |
| API Key | `X-API-Key: <key>` |

## Output Format
```json
{"timestamp": "ISO-8601", "findings": [], "risk_level": "HIGH"}
```
