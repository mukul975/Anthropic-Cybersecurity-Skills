# API Reference: Palo Alto Networks NGFW (PAN-OS)

## PAN-OS XML API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/?type=keygen` | GET | Generate API key |
| `/api/?type=config&action=get` | GET | Get configuration |
| `/api/?type=config&action=set` | GET | Set configuration |
| `/api/?type=op` | POST | Operational commands |

## Authentication
```
GET https://<fw>/api/?type=keygen&user=admin&password=admin
```

## Configuration XPaths

| XPath | Description |
|-------|-------------|
| `/config/devices/.../vsys/.../rulebase/security/rules` | Security rules |
| `/config/devices/.../vsys/.../profiles` | Security profiles |
| `/config/devices/.../deviceconfig/system` | System config |

## pan-python Library

```bash
pip install pan-python
```
| Method | Description |
|--------|-------------|
| `pan.xapi.PanXapi(hostname, api_key)` | Create API client |
| `xapi.get(xpath)` | Get config element |
| `xapi.set(xpath, element)` | Set config element |

## Key Libraries

| Library | Use |
|---------|-----|
| `requests` | REST API calls |
| `pan-python` | PAN-OS SDK |
| `xml.etree` | XML response parsing |
