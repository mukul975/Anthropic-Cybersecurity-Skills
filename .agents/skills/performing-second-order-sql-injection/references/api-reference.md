# Second-Order SQL Injection - API Reference

## Attack Overview

Second-order SQL injection occurs when user-supplied data is stored in a database and later incorporated into SQL queries without sanitization. Unlike first-order SQLi, the injection payload is not executed at the point of input but at a secondary execution point.

**Attack Flow:**
1. Attacker submits payload via input form (e.g., username registration)
2. Application safely stores the payload in database (parameterized INSERT)
3. Application later retrieves the stored value
4. Stored value is concatenated into a new SQL query without sanitization
5. Injection executes at the secondary query point

## SQL Injection Patterns

| Pattern | Example | Risk |
|---------|---------|------|
| UNION SELECT | `' UNION SELECT password FROM users--` | Data exfiltration |
| Tautology | `' OR 1=1--` | Authentication bypass |
| Stacked queries | `'; DROP TABLE users--` | Data destruction |
| Time-based blind | `'; WAITFOR DELAY '0:0:5'--` | Data extraction |
| Error-based | `' AND CONVERT(int, @@version)--` | Information disclosure |

## Code Sink Patterns (Vulnerable Code)

### Python (dangerous)
```python
cursor.execute(f"SELECT * FROM orders WHERE user='{username}'")
cursor.execute("SELECT * FROM orders WHERE user='%s'" % username)
```

### Python (safe - parameterized)
```python
cursor.execute("SELECT * FROM orders WHERE user=%s", (username,))
```

### PHP (dangerous)
```php
$query = "SELECT * FROM orders WHERE user='" . $username . "'";
```

## Database Dump Format

The agent expects JSON format for database analysis:
```json
{
  "users": [
    {"id": 1, "username": "admin", "email": "admin@example.com"},
    {"id": 2, "username": "' UNION SELECT 1,2,3--", "email": "test@test.com"}
  ],
  "comments": [
    {"id": 1, "body": "Normal comment"},
    {"id": 2, "body": "'; DROP TABLE users--"}
  ]
}
```

## Data Flow Tracing

The agent correlates stored payloads with code sinks by matching table/column names referenced in source code queries against tables containing injection payloads.

## Prevention

- Use parameterized queries (prepared statements) everywhere
- Apply output encoding when using stored data in queries
- Implement stored procedure-based data access
- Use an ORM that auto-parameterizes queries
- Validate data on both input AND retrieval from database

## Output Schema

```json
{
  "report": "second_order_sql_injection",
  "total_findings": 15,
  "stored_payloads": 5,
  "code_sinks": 8,
  "confirmed_attack_paths": 2,
  "findings": [{"type": "confirmed_attack_path", "severity": "critical"}]
}
```

## CLI Usage

```bash
python agent.py --db-dump database.json --source /app/src --output report.json
```
