# QRadar SIEM API Reference

## QRadar REST API Base

```
Base URL: https://<qradar_host>/api/
Auth Header: SEC: <api_token>
Content-Type: application/json
```

## AQL (Ariel Query Language)

```sql
-- Search events by offense
SELECT DATEFORMAT(startTime, 'yyyy-MM-dd HH:mm:ss') AS event_time,
       sourceIP, destinationIP, username,
       QIDNAME(qid) AS event_name
FROM events
WHERE INOFFENSE(12345)
ORDER BY startTime ASC LIMIT 500

-- Brute force detection
SELECT sourceIP, COUNT(*) AS failures
FROM events
WHERE QIDNAME(qid) ILIKE '%Authentication Fail%'
  AND startTime > NOW() - 3600000
GROUP BY sourceIP HAVING COUNT(*) > 10

-- Cross-source correlation (events + flows)
SELECT e.sourceIP, e.destinationIP, f.sourceBytes
FROM events e LEFT JOIN flows f
  ON e.sourceIP = f.sourceIP AND e.destinationIP = f.destinationIP
WHERE e.category = 'Authentication'
```

## Offense Management API

```bash
# List open offenses
curl -s "https://qradar/api/siem/offenses?filter=status%3DOPEN" -H "SEC: $TOKEN"

# Get offense details
curl -s "https://qradar/api/siem/offenses/12345" -H "SEC: $TOKEN"

# Close offense
curl -X POST "https://qradar/api/siem/offenses/12345?closing_reason_id=1&status=CLOSED" \
  -H "SEC: $TOKEN"

# Add note to offense
curl -X POST "https://qradar/api/siem/offenses/12345/notes" \
  -H "SEC: $TOKEN" -H "Content-Type: application/json" \
  -d '{"note_text": "Investigation completed"}'
```

## Reference Data API

```bash
# Create reference set
curl -X POST "https://qradar/api/reference_data/sets" \
  -H "SEC: $TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"Watchlist_IPs","element_type":"IP","timeout_type":"LAST_SEEN","time_to_live":"30 days"}'

# Add value to set
curl -X POST "https://qradar/api/reference_data/sets/Watchlist_IPs?value=10.0.5.100" \
  -H "SEC: $TOKEN"

# Get set contents
curl -s "https://qradar/api/reference_data/sets/Watchlist_IPs" -H "SEC: $TOKEN"
```

## AQL Functions

| Function | Description |
|----------|-------------|
| `QIDNAME(qid)` | Resolve QID to event name |
| `LOGSOURCENAME(id)` | Resolve log source ID to name |
| `INOFFENSE(id)` | Filter events belonging to offense |
| `DATEFORMAT(ts, fmt)` | Format timestamp |
| `NOW()` | Current time in milliseconds |
| `CATEGORYNAME(cat)` | Resolve category ID to name |
