# API Reference: Web Application Scanning with Nikto

## Nikto CLI Options

| Flag | Description |
|------|-------------|
| `-h <host>` | Target hostname or IP |
| `-port <ports>` | Target ports (comma-separated) |
| `-ssl` | Force SSL/TLS connection |
| `-Format xml\|json\|csv\|htm` | Output format |
| `-output <file>` | Save results to file |
| `-Tuning <options>` | Scan tuning categories |
| `-Plugins <list>` | Specific plugins to run |
| `-maxtime <seconds>s` | Maximum scan duration |
| `-nointeractive` | Disable interactive prompts |
| `-useproxy <url>` | Use HTTP proxy |
| `-id <user:pass>` | HTTP Basic auth credentials |

## Tuning Categories

| Code | Category |
|------|----------|
| 1 | Interesting File / Seen in logs |
| 2 | Misconfiguration / Default File |
| 3 | Information Disclosure |
| 4 | Injection (XSS/Script/HTML) |
| 5 | Remote File Retrieval - Inside Web Root |
| 6 | Denial of Service |
| 7 | Remote File Retrieval - Server Wide |
| 8 | Command Execution / Remote Shell |
| 9 | SQL Injection |
| 0 | File Upload |

## XML Output Structure

| Element | Description |
|---------|-------------|
| `<niktoscan>` | Root element |
| `<scandetails>` | Scan metadata |
| `<item>` | Individual finding |
| `<item id="..." osvdbid="...">` | Finding with OSVDB reference |
| `<uri>` | Affected URI path |
| `<description>` | Finding description |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `subprocess` | stdlib | Execute Nikto CLI |
| `xml.etree.ElementTree` | stdlib | Parse Nikto XML output |
| `json` | stdlib | Report generation |

## References

- Nikto GitHub: https://github.com/sullo/nikto
- Nikto Documentation: https://cirt.net/Nikto2
- OSVDB (archived): https://vulndb.cyberriskanalytics.com/
