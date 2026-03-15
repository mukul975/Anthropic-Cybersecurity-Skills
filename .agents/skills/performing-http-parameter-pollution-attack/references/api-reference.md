# API Reference — Performing HTTP Parameter Pollution Attack

## Libraries Used
- **requests**: Send HTTP requests with duplicate/encoded parameters
- **urllib.parse**: URL encoding and parameter manipulation

## CLI Interface
```
python agent.py precedence --url <target> [--param id]
python agent.py test --url <target> [--method GET|POST]
python agent.py waf --url <target> --param <name> --value <blocked_value>
```

## Core Functions

### `test_parameter_precedence(url, param_name, headers)` — Detect server parameter handling
Sends duplicate parameters to determine if server uses FIRST, LAST, BOTH, or UNKNOWN value.
Tests three value pairs to establish consistent behavior.

### `test_hpp_payloads(url, method, headers)` — Execute HPP payload suite
Three categories of payloads:
- **duplicate_param**: Basic duplicate parameter injection
- **encoding_bypass**: URL-encoded, null byte, CRLF injection
- **array_syntax**: PHP arrays, comma-separated, indexed arrays

Compares responses against baseline to detect anomalies (status/length changes).

### `test_waf_bypass(url, blocked_param, blocked_value, headers)` — Test WAF evasion
Five bypass techniques: direct, duplicate_first, duplicate_last, encoded, array syntax.
Detects if any technique passes WAF filtering (status 403/406/429 = blocked).

## Payload Categories
| Category | Count | Purpose |
|---|---|---|
| duplicate_param | 3 | Parameter precedence abuse |
| encoding_bypass | 3 | URL encoding / CRLF injection |
| array_syntax | 3 | PHP/framework array handling |

## Dependencies
```
pip install requests
```
