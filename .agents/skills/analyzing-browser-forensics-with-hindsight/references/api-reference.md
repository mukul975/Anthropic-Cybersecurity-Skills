# API Reference: Browser Forensics with Hindsight

## Hindsight CLI

### Syntax
```bash
hindsight.py -i <profile_path>                  # Analyze Chrome profile
hindsight.py -i <path> -o <output_dir>          # Save results
hindsight.py -i <path> -f xlsx                  # Export as Excel
hindsight.py -i <path> -f sqlite                # Export as SQLite
hindsight.py -i <path> -b <browser_type>        # Specify browser type
```

### Browser Types
| Flag | Browser |
|------|---------|
| `Chrome` | Google Chrome |
| `Edge` | Microsoft Edge (Chromium) |
| `Brave` | Brave Browser |
| `Opera` | Opera (Chromium) |

### Output Artifacts
| Table | Description |
|-------|-------------|
| `urls` | Browsing history with visit counts |
| `downloads` | File downloads with source URLs |
| `cookies` | Cookie values, domains, expiry |
| `autofill` | Form autofill entries |
| `bookmarks` | Saved bookmarks |
| `preferences` | Browser configuration |
| `local_storage` | Site local storage data |
| `login_data` | Saved credential metadata |
| `extensions` | Installed extensions with permissions |

## Chrome SQLite Databases

### History Database
```sql
-- Browsing history
SELECT u.url, u.title, v.visit_time, v.transition
FROM visits v JOIN urls u ON v.url = u.id
ORDER BY v.visit_time DESC;

-- Downloads
SELECT target_path, tab_url, total_bytes, start_time, danger_type, mime_type
FROM downloads ORDER BY start_time DESC;
```

### Cookies Database
```sql
SELECT host_key, name, value, creation_utc, expires_utc, is_secure, is_httponly
FROM cookies ORDER BY creation_utc DESC;
```

### Web Data Database (Autofill)
```sql
SELECT name, value, count, date_created, date_last_used
FROM autofill ORDER BY date_last_used DESC;
```

## Chrome Timestamp Conversion

### Format
Microseconds since January 1, 1601 (Windows FILETIME base)

### Python Conversion
```python
import datetime
def chrome_to_datetime(chrome_time):
    epoch = datetime.datetime(1601, 1, 1)
    return epoch + datetime.timedelta(microseconds=chrome_time)
```

## Browser Profile Paths

| OS | Browser | Default Path |
|----|---------|-------------|
| Windows | Chrome | `%LOCALAPPDATA%\Google\Chrome\User Data\Default` |
| Windows | Edge | `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default` |
| Linux | Chrome | `~/.config/google-chrome/Default` |
| macOS | Chrome | `~/Library/Application Support/Google/Chrome/Default` |

## Transition Types (visit_transition & 0xFF)
| Value | Type | Description |
|-------|------|-------------|
| 0 | LINK | Clicked a link |
| 1 | TYPED | Typed URL in address bar |
| 2 | AUTO_BOOKMARK | Via bookmark |
| 3 | AUTO_SUBFRAME | Subframe navigation |
| 5 | GENERATED | Generated (e.g., search) |
| 7 | FORM_SUBMIT | Form submission |
| 8 | RELOAD | Page reload |
