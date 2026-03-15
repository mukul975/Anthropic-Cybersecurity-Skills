# API Reference: Implementing Email Sandboxing with Proofpoint

## Proofpoint TAP SIEM API

```python
import requests
resp = requests.get(
    "https://tap-api-v2.proofpoint.com/v2/siem/all",
    auth=(principal, secret),
    params={"sinceSeconds": 3600, "format": "json"})
data = resp.json()
# Keys: messagesDelivered, messagesBlocked, clicksPermitted, clicksBlocked
```

## TAP API Endpoints

| Endpoint | Description |
|----------|-------------|
| `/v2/siem/all` | All threat events |
| `/v2/siem/messages/blocked` | Blocked messages only |
| `/v2/siem/messages/delivered` | Delivered threats |
| `/v2/siem/clicks/blocked` | Blocked URL clicks |
| `/v2/siem/clicks/permitted` | Permitted URL clicks |

## Threat Categories

| Category | Description | Severity |
|----------|-------------|----------|
| Malware | Malicious attachment | CRITICAL |
| Phish | Credential harvesting | HIGH |
| Impostor | BEC/spoofing | HIGH |
| Spam | Unsolicited | LOW |

## URL Defense Configuration

```json
{
  "url_defense": {
    "rewrite_all_urls": true,
    "real_time_scanning": true,
    "sandbox_detonation": true,
    "click_time_protection": true
  }
}
```

## Splunk Integration

```spl
index=proofpoint sourcetype=tap:siem
| where classification="malicious"
| stats count by sender, threatType, subject
```

### References

- Proofpoint TAP API: https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation
- Proofpoint Email Protection: https://www.proofpoint.com/us/products/email-security-and-protection
