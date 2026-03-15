# API Reference: WAF Bypass Testing

## Encoding Bypass Techniques

| Technique | Example | Description |
|-----------|---------|-------------|
| URL Encoding | `%3Cscript%3E` | Single URL encode |
| Double Encoding | `%253Cscript%253E` | Double URL encode |
| Unicode/Fullwidth | `\uff1cscript\uff1e` | Unicode replacement |
| HTML Entities | `&#x3c;script&#x3e;` | Hex HTML entities |
| Null Byte | `%00` insertion | Terminate string parsing |
| Tab/Newline | `scr\tipt` | Whitespace insertion |

## SQLi WAF Bypass Techniques

| Technique | Payload Pattern |
|-----------|----------------|
| Inline Comment | `1'/**/OR/**/1=1--` |
| Version Comment | `1'/*!50000OR*/1=1--` |
| Case Variation | `1' oR 1=1--` |
| Hex Encoding | `0x313d31` |
| Buffer Overflow | Long padding before payload |
| Content-Type Switch | Send as `application/json` |

## HTTP Method Bypass

| Method | WAF Behavior |
|--------|-------------|
| GET/POST | Usually inspected |
| PUT/PATCH/DELETE | Often not inspected |
| OPTIONS | Typically bypasses rules |

## WAF Detection Indicators

| Response | Meaning |
|----------|---------|
| 403 Forbidden | Request blocked by WAF |
| 406 Not Acceptable | Content rejected |
| 429 Too Many Requests | Rate limited |
| Custom error page | WAF vendor-specific block |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `requests` | >=2.28 | HTTP request sending |
| `urllib.parse` | stdlib | URL encoding/double encoding |

## References

- OWASP WAF Bypass: https://owasp.org/www-community/attacks/WAF_Bypass
- PortSwigger WAF Bypass: https://portswigger.net/web-security/essential-skills/obfuscating-attacks-using-encodings
- PayloadsAllTheThings WAF: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/WAF%20Bypass
