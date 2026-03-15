# Standards - Browser Forensics with Hindsight
## Tools
- Hindsight: https://github.com/obsidianforensics/hindsight
- DB Browser for SQLite: Chrome database inspection
- ChromeCacheView (NirSoft): Cache analysis
## Browser Databases
- History: URL visits, downloads, keyword searches
- Cookies: HTTP cookies per domain
- Web Data: Autofill, credit cards
- Login Data: Saved credentials (encrypted)
- Bookmarks: JSON bookmark tree
## Timestamp Formats
- Chrome/WebKit: microseconds since 1601-01-01 UTC
- Firefox/Mozilla: microseconds since Unix epoch
- Safari/Mac: seconds since 2001-01-01 UTC
