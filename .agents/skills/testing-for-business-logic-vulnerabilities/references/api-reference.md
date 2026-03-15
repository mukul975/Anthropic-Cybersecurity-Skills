# API Reference: Testing for Business Logic Vulnerabilities

## requests Library

### Concurrent Testing (Race Conditions)
```python
import threading

def send_request():
    resp = requests.post(url, headers=headers, json=payload)
    results.append(resp.status_code)

threads = [threading.Thread(target=send_request) for _ in range(10)]
for t in threads: t.start()
for t in threads: t.join()
```

## Business Logic Test Categories

### Price Manipulation Payloads
| Test | Payload | Expected |
|------|---------|----------|
| Negative quantity | `{"quantity": -1}` | Should reject |
| Zero price | `{"price": 0}` | Should reject |
| Float quantity | `{"quantity": 0.001}` | Should reject for physical goods |
| Integer overflow | `{"quantity": 2147483647}` | Should reject |
| Negative price | `{"price": -99.99}` | Should reject |

### Workflow Bypass Tests
1. Skip email verification -> access dashboard
2. Skip payment -> confirm order
3. Skip MFA -> access protected resources
4. Repeat one-time steps (coupon, voucher)

### Race Condition Targets
| Endpoint | Risk |
|----------|------|
| Coupon application | Applied multiple times |
| Balance transfer | Double spending |
| Reward claiming | Multiple claims |
| Inventory purchase | Overselling |

### Referral/Reward Abuse
- Self-referral with own email
- Referral code reuse across accounts
- Coupon stacking (multiple codes)
- Earn points -> cancel order -> keep points

## OWASP Category
- A04:2021 - Insecure Design
- Business logic flaws are not detectable by automated scanners

## References
- OWASP Testing Business Logic: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/
- PortSwigger Business Logic: https://portswigger.net/web-security/logic-flaws
- requests docs: https://docs.python-requests.org/
