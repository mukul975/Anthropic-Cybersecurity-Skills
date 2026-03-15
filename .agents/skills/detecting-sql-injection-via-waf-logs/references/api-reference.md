# API Reference: SQL Injection Detection via WAF Logs

## ModSecurity Audit Log Sections
| Section | Content |
|---------|---------|
| A | Audit log header (timestamp, transaction ID) |
| B | Request headers (method, URI, HTTP version) |
| C | Request body |
| E | Response body |
| F | Response headers |
| H | Audit log trailer (rule matches, actions) |

## OWASP CRS SQLi Rules (942xxx)
| Rule ID | Description |
|---------|-------------|
| 942100 | SQL Injection via libinjection |
| 942110 | SQL Injection (common keywords) |
| 942120 | SQL Injection operator detected |
| 942130 | SQL Injection tautology |
| 942150 | SQL Injection function detected |
| 942160 | Blind SQLi (sleep/benchmark) |
| 942170 | UNION query injection |
| 942190 | MSSQL code execution |
| 942200 | MySQL comment obfuscation |
| 942210 | Chained SQL injection |
| 942280 | PostgreSQL/MSSQL sleep |
| 942290 | MongoDB injection |

## SQL Injection Types
| Type | Pattern | Severity |
|------|---------|----------|
| UNION-based | `UNION SELECT` | Critical |
| Time-based blind | `SLEEP()`, `BENCHMARK()`, `WAITFOR DELAY` | Critical |
| Error-based | `EXTRACTVALUE()`, `UPDATEXML()` | High |
| Tautology | `OR 1=1`, `AND 1=1` | High |
| Stacked query | `'; DROP TABLE` | Critical |
| Schema enum | `INFORMATION_SCHEMA` | High |
| File access | `LOAD_FILE()`, `INTO OUTFILE` | Critical |

## AWS WAF Log Format (JSON)
```json
{
  "httpRequest": {
    "clientIp": "203.0.113.42",
    "uri": "/api/users",
    "args": "id=1' OR 1=1--",
    "httpMethod": "GET"
  },
  "action": "BLOCK",
  "ruleGroupList": [{"ruleId": "SQLi_BODY"}]
}
```

## Campaign Detection Logic
- Group requests by source IP
- Flag IPs with >= 5 SQLi attempts as campaigns
- IPs with > 20 requests classified as automated tooling
- Multiple attack types from same IP = multi-stage campaign

## MITRE ATT&CK
- T1190 - Exploit Public-Facing Application
