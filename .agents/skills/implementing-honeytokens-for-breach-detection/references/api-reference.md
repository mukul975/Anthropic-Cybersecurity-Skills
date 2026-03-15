# API Reference: Implementing Honeytokens for Breach Detection

## Canarytokens.org API

```python
import requests

# Create DNS canary token
resp = requests.post("https://canarytokens.org/generate", data={
    "type": "dns",
    "email": "soc@company.com",
    "memo": "Prod DB honeytoken",
    "webhook_url": "https://hooks.slack.com/...",  # optional
})
token = resp.json()  # {"hostname": "xxx.canarytokens.com", ...}

# Available token types
# dns, web_image, aws_keys, cloned_web, doc_msword,
# slack_api, svn, sql_server, qr_code
```

## Token Deployment Locations

| Type | Location | Trigger |
|------|----------|---------|
| AWS keys | `~/.aws/credentials` | Key used in API call |
| DNS | Config files, code | DNS resolution |
| Web image | Wiki, docs, shares | Image HTTP request |
| Document | File shares | Document opened |
| Database | User/config tables | Record queried |

## Webhook Alert Payload

```json
{
  "manage_url": "https://canarytokens.org/manage?...",
  "memo": "Production honeytoken",
  "additional_data": {
    "src_ip": "203.0.113.50",
    "useragent": "..."
  },
  "channel": "DNS",
  "time": "2025-01-15 14:23:00"
}
```

## Thinkst Canary API (Enterprise)

```python
# List triggered tokens
resp = requests.get("https://console.canary.tools/api/v1/canarytokens/alerts",
    params={"auth_token": "<api_key>"})
```

### References

- Canarytokens: https://canarytokens.org/
- Thinkst Canary: https://canary.tools/
- LOLBAS honeytoken guide: https://zeltser.com/honeytokens-canarytokens-setup/
