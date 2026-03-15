# API Reference: Implementing Mimecast Targeted Attack Protection

## Mimecast API Authentication

```python
import requests
headers = {"Authorization": "MC access_key:secret_key",
           "x-mc-app-id": "app-id"}
resp = requests.post("https://us-api.mimecast.com/api/ttp/url/get-logs",
                     headers=headers, json={"data": [{"from": "2024-01-01"}]})
```

## TTP API Endpoints

| Endpoint | Description |
|----------|-------------|
| `/api/ttp/url/get-logs` | URL Protection logs |
| `/api/ttp/attachment/get-logs` | Attachment sandbox logs |
| `/api/ttp/impersonation/get-logs` | Impersonation detections |

## URL Protection Actions

| Action | Description |
|--------|-------------|
| allow | URL permitted |
| block | URL blocked (malicious) |
| warn | User warned before click |
| sandbox | Deferred for sandbox analysis |

## Attachment Sandbox Results

| Result | Severity |
|--------|----------|
| safe | INFO |
| suspicious | MEDIUM |
| malicious | CRITICAL |
| sandbox_timeout | HIGH |

## Impersonation Types

| Type | Description |
|------|-------------|
| Internal | Employee name spoofing |
| External | Vendor/partner spoofing |
| Domain | Similar domain detection |

### References

- Mimecast API: https://developer.services.mimecast.com/
- TTP URL Protection: https://developer.services.mimecast.com/docs/threatsintel/1/routes/ttp/url/get-logs/post
