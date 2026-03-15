---
name: extracting-browser-history-artifacts
description: Extract and analyze browser history, cookies, cache, downloads, and bookmarks from Chrome, Firefox, and Edge for forensic evidence of user web activity.
domain: cybersecurity
subdomain: digital-forensics
tags: [forensics, browser-forensics, chrome, firefox, edge, web-history, artifact-extraction]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Extracting Browser History Artifacts

## When to Use
- When investigating user web activity as part of a forensic examination
- During insider threat investigations to establish patterns of data exfiltration
- When tracing user visits to malicious or policy-violating websites
- For correlating browser activity with other forensic artifacts and timelines
- When investigating phishing attacks to identify which links were clicked

## Prerequisites
- Forensic image or access to user profile directories
- SQLite3 for querying browser databases
- Hindsight, BrowsingHistoryView, or DB Browser for SQLite
- Knowledge of browser artifact file locations per OS
- Python 3 with sqlite3 module for automated extraction
- Understanding of Chrome, Firefox, and Edge storage formats

## Workflow

### Step 1: Locate Browser Artifact Files

```bash
# Mount forensic image
mount -o ro,loop,offset=$((2048*512)) /cases/case-2024-001/images/evidence.dd /mnt/evidence

# Chrome artifact locations (Windows)
CHROME_WIN="/mnt/evidence/Users/suspect/AppData/Local/Google/Chrome/User Data/Default"
# Key files: History, Cookies, Login Data, Web Data, Bookmarks, Preferences,
#            Cache/, GPUCache/, Local Storage/, Session Storage/, IndexedDB/

# Firefox artifact locations (Windows)
FIREFOX_WIN="/mnt/evidence/Users/suspect/AppData/Roaming/Mozilla/Firefox/Profiles/*.default-release"
# Key files: places.sqlite, cookies.sqlite, formhistory.sqlite, logins.json,
#            key4.db, sessionstore.jsonlz4, webappsstore.sqlite

# Edge (Chromium) artifact locations (Windows)
EDGE_WIN="/mnt/evidence/Users/suspect/AppData/Local/Microsoft/Edge/User Data/Default"

# Copy artifacts to working directory
mkdir -p /cases/case-2024-001/browser/{chrome,firefox,edge}
cp -r "$CHROME_WIN"/{History,Cookies,Downloads,"Login Data","Web Data",Bookmarks} \
   /cases/case-2024-001/browser/chrome/ 2>/dev/null
cp -r $FIREFOX_WIN/{places.sqlite,cookies.sqlite,formhistory.sqlite,logins.json} \
   /cases/case-2024-001/browser/firefox/ 2>/dev/null
cp -r "$EDGE_WIN"/{History,Cookies,Downloads} \
   /cases/case-2024-001/browser/edge/ 2>/dev/null

# Hash artifacts for integrity
find /cases/case-2024-001/browser/ -type f -exec sha256sum {} \; \
   > /cases/case-2024-001/browser/artifact_hashes.txt
```

### Step 2: Extract Chrome Browsing History and Downloads

```bash
# Query Chrome History database
sqlite3 /cases/case-2024-001/browser/chrome/History << 'SQL'
.headers on
.mode csv
.output /cases/case-2024-001/analysis/chrome_history.csv

SELECT
    urls.url,
    urls.title,
    datetime(urls.last_visit_time/1000000-11644473600, 'unixepoch') AS last_visit,
    urls.visit_count,
    urls.typed_count,
    visits.transition & 0xFF AS transition_type
FROM urls
LEFT JOIN visits ON urls.id = visits.url
ORDER BY urls.last_visit_time DESC;
SQL

# Extract Chrome downloads
sqlite3 /cases/case-2024-001/browser/chrome/History << 'SQL'
.headers on
.mode csv
.output /cases/case-2024-001/analysis/chrome_downloads.csv

SELECT
    current_path,
    tab_url AS source_url,
    total_bytes,
    datetime(start_time/1000000-11644473600, 'unixepoch') AS start_time,
    datetime(end_time/1000000-11644473600, 'unixepoch') AS end_time,
    state,
    danger_type,
    mime_type
FROM downloads
ORDER BY start_time DESC;
SQL

# Extract Chrome search terms
sqlite3 /cases/case-2024-001/browser/chrome/History << 'SQL'
.headers on
.mode csv
.output /cases/case-2024-001/analysis/chrome_searches.csv

SELECT
    term,
    urls.url,
    datetime(urls.last_visit_time/1000000-11644473600, 'unixepoch') AS search_time
FROM keyword_search_terms
JOIN urls ON keyword_search_terms.url_id = urls.id
ORDER BY urls.last_visit_time DESC;
SQL
```

### Step 3: Extract Firefox Browsing History

```bash
# Query Firefox places.sqlite for history
sqlite3 /cases/case-2024-001/browser/firefox/places.sqlite << 'SQL'
.headers on
.mode csv
.output /cases/case-2024-001/analysis/firefox_history.csv

SELECT
    moz_places.url,
    moz_places.title,
    datetime(moz_historyvisits.visit_date/1000000, 'unixepoch') AS visit_date,
    moz_places.visit_count,
    moz_historyvisits.visit_type
FROM moz_places
JOIN moz_historyvisits ON moz_places.id = moz_historyvisits.place_id
ORDER BY moz_historyvisits.visit_date DESC;
SQL

# Extract Firefox bookmarks
sqlite3 /cases/case-2024-001/browser/firefox/places.sqlite << 'SQL'
.headers on
.mode csv
.output /cases/case-2024-001/analysis/firefox_bookmarks.csv

SELECT
    moz_bookmarks.title,
    moz_places.url,
    datetime(moz_bookmarks.dateAdded/1000000, 'unixepoch') AS date_added,
    datetime(moz_bookmarks.lastModified/1000000, 'unixepoch') AS last_modified
FROM moz_bookmarks
JOIN moz_places ON moz_bookmarks.fk = moz_places.id
WHERE moz_bookmarks.type = 1
ORDER BY moz_bookmarks.dateAdded DESC;
SQL

# Extract Firefox form history (search terms, form fills)
sqlite3 /cases/case-2024-001/browser/firefox/formhistory.sqlite << 'SQL'
.headers on
.mode csv
.output /cases/case-2024-001/analysis/firefox_forms.csv

SELECT
    fieldname,
    value,
    timesUsed,
    datetime(firstUsed/1000000, 'unixepoch') AS first_used,
    datetime(lastUsed/1000000, 'unixepoch') AS last_used
FROM moz_formhistory
ORDER BY lastUsed DESC;
SQL
```

### Step 4: Extract Cookies and Stored Credentials

```bash
# Extract Chrome cookies
sqlite3 /cases/case-2024-001/browser/chrome/Cookies << 'SQL'
.headers on
.mode csv
.output /cases/case-2024-001/analysis/chrome_cookies.csv

SELECT
    host_key,
    name,
    path,
    datetime(creation_utc/1000000-11644473600, 'unixepoch') AS created,
    datetime(expires_utc/1000000-11644473600, 'unixepoch') AS expires,
    datetime(last_access_utc/1000000-11644473600, 'unixepoch') AS last_access,
    is_secure,
    is_httponly,
    is_persistent
FROM cookies
ORDER BY last_access_utc DESC;
SQL

# Extract Firefox cookies
sqlite3 /cases/case-2024-001/browser/firefox/cookies.sqlite << 'SQL'
.headers on
.mode csv
.output /cases/case-2024-001/analysis/firefox_cookies.csv

SELECT
    host,
    name,
    path,
    datetime(creationTime/1000000, 'unixepoch') AS created,
    datetime(expiry, 'unixepoch') AS expires,
    datetime(lastAccessed/1000000, 'unixepoch') AS last_access,
    isSecure,
    isHttpOnly
FROM moz_cookies
ORDER BY lastAccessed DESC;
SQL

# Note: Chrome Login Data is encrypted with DPAPI (Windows) or keychain (Mac)
# Extract stored login URLs (passwords are encrypted)
sqlite3 /cases/case-2024-001/browser/chrome/"Login Data" << 'SQL'
.headers on
.mode csv
.output /cases/case-2024-001/analysis/chrome_logins.csv

SELECT
    origin_url,
    action_url,
    username_value,
    datetime(date_created/1000000-11644473600, 'unixepoch') AS date_created,
    datetime(date_last_used/1000000-11644473600, 'unixepoch') AS date_last_used,
    times_used
FROM logins
ORDER BY date_last_used DESC;
SQL
```

### Step 5: Use Hindsight for Comprehensive Chrome Analysis

```bash
# Install Hindsight
pip install pyhindsight

# Run Hindsight against Chrome profile
hindsight -i "/cases/case-2024-001/browser/chrome/" \
   -o /cases/case-2024-001/analysis/hindsight_report \
   -f xlsx

# Hindsight automatically extracts:
# - Browsing history with timestamps
# - Downloads with source URLs
# - Cookies with decryption (where possible)
# - Cache records
# - Local Storage entries
# - Autofill data
# - Saved passwords (encrypted)
# - Preferences and extensions
# - Session/tab recovery data

# For JSONL output (easier to parse)
hindsight -i "/cases/case-2024-001/browser/chrome/" \
   -o /cases/case-2024-001/analysis/hindsight_report \
   -f jsonl
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| Chrome timestamp | Microseconds since January 1, 1601 (WebKit/Chrome epoch) |
| Firefox timestamp | Microseconds since January 1, 1970 (Unix epoch in microseconds) |
| Transition types | How a URL was accessed: typed (1), link (0), bookmark (1), redirect (5/6) |
| DPAPI encryption | Windows Data Protection API encrypting stored passwords and cookies |
| places.sqlite | Firefox combined history and bookmark database |
| SQLite WAL | Write-Ahead Log that may contain recently deleted browser records |
| Session restore | Browser data preserving open tabs across restarts |
| IndexedDB | Browser-based database that may contain web application data |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Hindsight | Comprehensive Chrome/Chromium forensic analysis tool |
| sqlite3 | Command-line SQLite database query tool |
| DB Browser for SQLite | GUI tool for browsing SQLite databases |
| BrowsingHistoryView | NirSoft tool for viewing browser history across all browsers |
| ChromeCacheView | NirSoft tool for examining Chrome cache contents |
| MZCacheView | NirSoft tool for Firefox cache analysis |
| KAPE | Automated artifact collection including browser data |
| Autopsy | Full forensic platform with browser artifact ingest modules |

## Common Scenarios

**Scenario 1: Phishing Investigation**
Extract browser history around the reported phishing timeframe, identify the phishing URL that was visited, check downloads for malicious attachments, examine cookies for session tokens that may have been stolen, correlate with email header analysis.

**Scenario 2: Data Exfiltration via Cloud Services**
Search history for cloud storage URLs (Dropbox, Google Drive, OneDrive, Mega), examine downloads and uploads, check form history for file names entered, review cookies for active cloud service sessions during the investigation period.

**Scenario 3: Policy Violation Investigation**
Extract complete browsing history for the investigation period, categorize sites visited, identify access to prohibited content categories, document timestamps and visit duration, correlate with network proxy logs for verification.

**Scenario 4: Malware Delivery Vector Analysis**
Trace the chain of redirects leading to a drive-by download, examine the downloads database for the malware payload, check cache for exploit kit landing pages, identify the initial referrer URL that started the infection chain.

## Output Format

```
Browser Forensics Summary:
  User Profile: suspect (Windows 10)
  Browsers Found: Chrome 120, Firefox 121, Edge 120

  Chrome Analysis:
    History Entries:    12,456
    Downloads:          234
    Saved Passwords:    67 sites (encrypted)
    Cookies:            3,456
    Bookmarks:          89

  Firefox Analysis:
    History Entries:    5,678
    Form Entries:       234
    Bookmarks:          45
    Cookies:            1,234

  Suspicious Findings:
    - Visited known phishing URL at 2024-01-15 14:32 UTC
    - Downloaded "invoice_update.exe" from suspicious domain
    - Cloud storage (mega.nz) accessed 15 times in 2-hour window
    - Search queries: "how to encrypt files", "secure file transfer"

  Reports:
    Chrome History:   /analysis/chrome_history.csv
    Firefox History:  /analysis/firefox_history.csv
    Full Report:      /analysis/hindsight_report.xlsx
```
