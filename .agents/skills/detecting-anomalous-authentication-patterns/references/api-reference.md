# Authentication Anomaly Detection API Reference

## Azure AD Sign-In Logs (Microsoft Graph)

```bash
# Query sign-in logs
GET https://graph.microsoft.com/v1.0/auditLogs/signIns?$filter=createdDateTime ge 2024-01-01
Authorization: Bearer <token>

# Risky sign-ins
GET https://graph.microsoft.com/v1.0/identityProtection/riskyUsers
```

## Okta System Log API

```bash
# Query authentication events
curl "https://your-org.okta.com/api/v1/logs?filter=eventType+eq+%22user.session.start%22&since=2024-01-01" \
  -H "Authorization: SSWS <api_token>"

# Filter failed logins
curl "https://your-org.okta.com/api/v1/logs?filter=outcome.result+eq+%22FAILURE%22" \
  -H "Authorization: SSWS <api_token>"
```

## Windows Event IDs for Auth Monitoring

| Event ID | Description |
|----------|-------------|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4648 | Logon with explicit credentials |
| 4672 | Special privileges assigned |
| 4768 | Kerberos TGT request |
| 4769 | Kerberos service ticket request |
| 4771 | Kerberos pre-auth failed |
| 4776 | NTLM credential validation |

## Splunk SPL Detection Queries

```spl
# Brute force detection
index=auth result="failure"
| bin _time span=10m
| stats count by user src_ip _time
| where count >= 10

# Password spray detection
index=auth result="failure"
| bin _time span=30m
| stats dc(user) as targets count by src_ip _time
| where targets >= 10

# Impossible travel
index=auth result="success"
| iplocation src_ip
| sort user _time
| streamstats last(lat) as prev_lat last(lon) as prev_lon last(_time) as prev_time by user
| eval dist=6371*2*asin(sqrt(pow(sin((lat-prev_lat)*pi()/360),2)+cos(prev_lat*pi()/180)*cos(lat*pi()/180)*pow(sin((lon-prev_lon)*pi()/360),2)))
| eval speed=dist/((_time-prev_time)/3600)
| where speed > 900 AND dist > 100
```

## GeoIP with MaxMind (Python)

```python
import geoip2.database
reader = geoip2.database.Reader('/opt/geoip/GeoLite2-City.mmdb')
response = reader.city('203.0.113.50')
print(response.city.name, response.location.latitude, response.location.longitude)
reader.close()
```

## Isolation Forest (scikit-learn)

```python
from sklearn.ensemble import IsolationForest
model = IsolationForest(n_estimators=200, contamination=0.01, random_state=42)
model.fit(X)
predictions = model.predict(X)  # -1 = anomaly, 1 = normal
scores = model.score_samples(X)  # lower = more anomalous
```
