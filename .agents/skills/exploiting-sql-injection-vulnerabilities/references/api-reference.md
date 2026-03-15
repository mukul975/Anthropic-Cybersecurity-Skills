# API Reference: SQL Injection Detection Agent

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| requests | >=2.28 | HTTP client for injection payload delivery |

## CLI Usage

```bash
python scripts/agent.py \
  --url "https://target.example.com/products" \
  --param id --method GET \
  --output sqli_report.json
```

## Functions

### `detect_error_based(url, param, method, headers) -> dict`
Injects `'` and matches response against SQL error patterns for MySQL, PostgreSQL, MSSQL, Oracle, SQLite.

### `detect_boolean_based(url, param, method, headers) -> dict`
Compares response lengths for `AND 1=1` (true) vs `AND 1=2` (false) against a baseline.

### `detect_time_based(url, param, method, headers, delay) -> dict`
Tests `SLEEP()`, `pg_sleep()`, and `WAITFOR DELAY` payloads. Measures response time against target delay.

### `detect_union_columns(url, param, method, headers, max_cols) -> dict`
Increments `ORDER BY N` until error to determine column count for UNION injection.

### `fingerprint_database(url, param, method, headers) -> dict`
Tries `@@version` and `version()` via UNION SELECT to identify the database engine.

### `run_assessment(url, param, method) -> dict`
Runs all detection techniques and compiles findings.

## SQL Error Signatures

| Database | Pattern |
|----------|---------|
| MySQL | `SQL syntax.*MySQL`, `Warning.*mysql_` |
| PostgreSQL | `ERROR:\s+syntax error`, `PSQLException` |
| MSSQL | `SQL Server.*Driver`, `SQLServerException` |
| Oracle | `ORA-\d{5}` |
| SQLite | `SQLite\.Exception` |

## Output Schema

```json
{
  "target": "https://target.example.com/products",
  "parameter": "id",
  "injectable": true,
  "error_based": {"injectable": true, "database": "mysql"},
  "boolean_based": {"injectable": true},
  "time_based": {"injectable": false},
  "findings": ["CRITICAL: Error-based SQLi confirmed (DB: mysql)"]
}
```
