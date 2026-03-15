# API Reference: Analyzing API Gateway Access Logs

## AWS API Gateway Log Fields

```json
{
  "requestId": "abc-123",
  "ip": "203.0.113.50",
  "httpMethod": "GET",
  "resourcePath": "/api/users/{id}",
  "status": 200,
  "requestTime": "2025-03-15T14:00:00Z",
  "responseLength": 1024
}
```

## Pandas Log Analysis

```python
import pandas as pd

df = pd.read_json("access_logs.json", lines=True)

# BOLA detection
df.groupby("user_id")["resource_id"].nunique()

# Auth failure surge
df[df["status_code"] == 401].groupby("source_ip").size()

# Request velocity
df.set_index("timestamp").resample("1min").size()
```

## OWASP API Top 10 Patterns

| Risk | Detection Pattern |
|------|-------------------|
| BOLA (API1) | User accessing > 50 unique resource IDs |
| Broken Auth (API2) | > 100 401/403 from single IP |
| Excessive Data (API3) | Response size > 10x average |
| Rate Limit (API4) | > 100 req/min from single IP |
| BFLA (API5) | DELETE/PUT on read-only endpoints |
| Injection (API8) | SQL/NoSQL patterns in params |

## Injection Regex Patterns

```python
sql = r"union\s+select|drop\s+table|'\s*or\s+'1'"
nosql = r"\$ne|\$gt|\$regex|\$where"
xss = r"<script|javascript:|onerror="
path_traversal = r"\.\./\.\./|/etc/passwd"
```

### References

- OWASP API Security Top 10: https://owasp.org/API-Security/
- AWS API Gateway logging: https://docs.aws.amazon.com/apigateway/latest/developerguide/
- pandas: https://pandas.pydata.org/docs/
