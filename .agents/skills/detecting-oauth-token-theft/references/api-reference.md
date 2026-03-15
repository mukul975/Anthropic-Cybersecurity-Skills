# API Reference: Detecting OAuth Token Theft

## Microsoft Graph Sign-In Logs
```bash
# Query sign-in logs
curl -H "Authorization: Bearer $MS_TOKEN" \
  "https://graph.microsoft.com/v1.0/auditLogs/signIns?\$filter=createdDateTime ge 2025-01-01&\$top=100"
```

### Sign-In Event Fields
| Field | Description |
|-------|------------|
| userPrincipalName | User email/UPN |
| ipAddress | Source IP address |
| location.city | Geo city |
| location.geoCoordinates | Lat/lon |
| deviceDetail.deviceId | Device identifier |
| resourceDisplayName | Target resource |
| status.errorCode | 0 = success |
| riskState | none, confirmedCompromised, remediated |

## Okta System Log API
```bash
# Query events
curl -H "Authorization: SSWS $OKTA_TOKEN" \
  "https://your-org.okta.com/api/v1/logs?filter=eventType eq \"user.session.start\"&since=2025-01-01"
```

## Detection Logic
| Detection | Method |
|-----------|--------|
| Impossible travel | Haversine distance / time > 900 km/h |
| Token replay | Same user, 3+ IPs within 5 min window |
| New device | Device ID not in known device inventory |
| Suspicious scopes | 2+ sensitive OAuth scopes requested |

## Sensitive OAuth Scopes (Microsoft)
| Scope | Risk |
|-------|------|
| Mail.ReadWrite | Email access |
| Mail.Send | Send-as capability |
| Files.ReadWrite.All | Full file access |
| Directory.ReadWrite.All | AD modification |
| Application.ReadWrite.All | App registration |

## MITRE ATT&CK Mapping
| Technique | Description |
|-----------|------------|
| T1528 | Steal Application Access Token |
| T1550.001 | Application Access Token reuse |
| T1078.004 | Cloud Accounts |
