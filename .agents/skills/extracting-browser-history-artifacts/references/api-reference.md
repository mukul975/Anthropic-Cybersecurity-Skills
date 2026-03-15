# API Reference: Browser History Extraction Agent

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| sqlite3 | stdlib | Query Chrome/Firefox SQLite databases |
| csv | stdlib | Export results to CSV format |

## CLI Usage

```bash
python scripts/agent.py \
  --chrome-dir "/mnt/evidence/Users/suspect/AppData/Local/Google/Chrome/User Data/Default" \
  --firefox-dir "/mnt/evidence/Users/suspect/AppData/Roaming/Mozilla/Firefox/Profiles/abc.default" \
  --output-dir /cases/analysis/ \
  --output browser_report.json
```

## Functions

### `chrome_time_to_utc(chrome_ts) -> str`
Converts Chrome/WebKit timestamp (microseconds since 1601-01-01) to ISO-8601 UTC string.

### `firefox_time_to_utc(ff_ts) -> str`
Converts Firefox timestamp (microseconds since Unix epoch) to ISO-8601 UTC string.

### `extract_chrome_history(db_path, limit) -> list`
Queries the `urls` table from Chrome's `History` SQLite DB. Returns URL, title, last_visit, visit_count.

### `extract_chrome_downloads(db_path, limit) -> list`
Queries the `downloads` table for file path, source URL, size, timestamps, and danger type.

### `extract_chrome_cookies(db_path, limit) -> list`
Queries the `cookies` table. Note: cookie values are DPAPI-encrypted on Windows.

### `extract_firefox_history(db_path, limit) -> list`
Queries `moz_places` JOIN `moz_historyvisits` from Firefox `places.sqlite`.

### `extract_firefox_cookies(db_path, limit) -> list`
Queries `moz_cookies` from Firefox `cookies.sqlite`.

### `export_to_csv(data, output_path)`
Writes list of dicts to CSV with headers.

### `generate_report(chrome_dir, firefox_dir, output_dir) -> dict`
Orchestrates extraction from both browsers and exports CSVs.

## Browser Database Locations (Windows)

| Browser | Path |
|---------|------|
| Chrome | `%LOCALAPPDATA%\Google\Chrome\User Data\Default\History` |
| Edge | `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\History` |
| Firefox | `%APPDATA%\Mozilla\Firefox\Profiles\*.default\places.sqlite` |

## Timestamp Formats

| Browser | Epoch | Unit |
|---------|-------|------|
| Chrome/Edge | 1601-01-01 | Microseconds |
| Firefox | 1970-01-01 | Microseconds |
