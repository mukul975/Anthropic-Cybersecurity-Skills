# Adversary-in-the-Middle (AiTM) Phishing Detection - API Reference

## AiTM Attack Overview

AiTM phishing uses a reverse proxy between the victim and legitimate login page to intercept session cookies in real-time, bypassing MFA. Common frameworks: Evilginx2, Modlishka, Muraena.

**Attack Chain:**
1. Victim clicks phishing link
2. Reverse proxy forwards request to real login page
3. Victim enters credentials and completes MFA
4. Proxy captures session cookie
5. Attacker replays session cookie from different location

## Azure AD / Entra ID Sign-In Logs

### Export via Microsoft Graph API
```
GET https://graph.microsoft.com/v1.0/auditLogs/signIns
```

### Key Fields

| Field | Type | Description |
|-------|------|-------------|
| `userPrincipalName` | string | User email |
| `createdDateTime` | ISO-8601 | Sign-in timestamp |
| `ipAddress` | string | Source IP address |
| `location.latitude` | float | Geo-location latitude |
| `location.longitude` | float | Geo-location longitude |
| `deviceDetail.displayName` | string | Device name |
| `correlationId` | string | Session correlation ID |
| `userAgent` | string | Browser user agent |

## Detection Methods

### Impossible Travel
Calculates Haversine great-circle distance between consecutive logins. If `distance / time > 900 km/h` (commercial flight speed) and distance > 100km, flags as suspicious.

### Suspicious Inbox Rules
AiTM attackers commonly create rules to:
- Forward emails to external address (`forwardTo`, `redirectTo`)
- Delete incoming emails (`moveToDeletedItems`, `permanentDelete`)
- Auto-read messages (`markAsRead`)
- Filter on keywords: invoice, payment, wire, bank, password

### Token Replay Detection
Multiple IPs and devices in a short timeframe for the same user session indicates stolen session token replay.

## Inbox Rules Format

```json
[
  {
    "displayName": "rule1",
    "mailboxOwner": "user@example.com",
    "actions": {"forwardTo": [{"emailAddress": {"address": "attacker@evil.com"}}]},
    "conditions": {"subjectContains": ["invoice", "payment"]},
    "createdDateTime": "2024-01-15T10:00:00Z"
  }
]
```

## Haversine Formula

```python
from math import radians, cos, sin, asin, sqrt
def haversine_km(lat1, lon1, lat2, lon2):
    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
    dlat, dlon = lat2 - lat1, lon2 - lon1
    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    return 2 * 6371 * asin(sqrt(a))
```

## Output Schema

```json
{
  "report": "aitm_phishing_detection",
  "total_sign_ins_analyzed": 5000,
  "total_findings": 8,
  "severity_summary": {"critical": 3, "high": 5},
  "findings": [{"type": "impossible_travel", "severity": "critical"}]
}
```

## CLI Usage

```bash
python agent.py --logs signin_logs.json --inbox-rules rules.json --output report.json
```
