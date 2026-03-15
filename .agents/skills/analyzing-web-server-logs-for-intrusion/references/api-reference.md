# API Reference: Web Server Log Intrusion Analysis

## Combined Log Format (Apache/Nginx)
```
<ip> <ident> <authuser> [<date>] "<method> <uri> <proto>" <status> <size> "<referer>" "<user-agent>"
```

## Python re Module - Log Parsing
```python
import re
pattern = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<uri>\S+) (?P<proto>[^"]*)" '
    r'(?P<status>\d+) (?P<size>\S+) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)
match = pattern.match(line)
data = match.groupdict()
```

## GeoIP2 Python Library
```python
import geoip2.database
reader = geoip2.database.Reader("GeoLite2-City.mmdb")
response = reader.city("8.8.8.8")
response.country.name       # "United States"
response.city.name           # "Mountain View"
response.location.latitude   # 37.386
response.location.longitude  # -122.0838
reader.close()
```

## Attack Signature Categories
| Type | Example Pattern | Severity |
|------|----------------|----------|
| SQLi | `UNION SELECT`, `OR 1=1`, `SLEEP()` | Critical |
| LFI | `../../etc/passwd`, `php://filter` | High |
| XSS | `<script>`, `onerror=`, `javascript:` | High |
| Scanner | User-Agent: nikto, sqlmap, gobuster | Medium |
| Brute Force | >50 POST /login from same IP | High |

## Scanner User-Agent Signatures
| Tool | UA Pattern |
|------|-----------|
| Nikto | `Nikto/2.x` |
| sqlmap | `sqlmap/1.x` |
| DirBuster | `DirBuster-1.0` |
| Gobuster | `gobuster/3.x` |
| Wfuzz | `Wfuzz/3.x` |
