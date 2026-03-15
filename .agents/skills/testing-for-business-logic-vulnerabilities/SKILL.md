---
name: testing-for-business-logic-vulnerabilities
description: Identifying flaws in application business logic that allow price manipulation, workflow bypass, and privilege escalation beyond what technical vulnerability scanners can detect.
domain: cybersecurity
subdomain: web-application-security
tags: [penetration-testing, business-logic, owasp, web-security, burpsuite, manual-testing]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Testing for Business Logic Vulnerabilities

## When to Use

- During authorized penetration tests when automated scanners have found few technical vulnerabilities
- When assessing e-commerce platforms for pricing, cart, and payment flow manipulations
- For testing multi-step workflows (registration, checkout, approval processes) for bypass opportunities
- When evaluating rate-limited features like vouchers, coupons, referrals, and rewards systems
- During security assessments of financial applications, voting systems, or any application with critical business rules

## Prerequisites

- **Authorization**: Written penetration testing agreement covering business logic testing
- **Burp Suite Professional**: For intercepting and modifying multi-step request flows
- **Application understanding**: Thorough knowledge of the application's intended business workflows
- **Multiple test accounts**: Accounts at different privilege levels and states
- **Browser DevTools**: For examining client-side validation logic
- **Documentation**: Business requirements or user stories describing expected behavior

## Workflow

### Step 1: Map Business Workflows and Rules

Document all critical business processes and their expected constraints.

```
# Critical business flows to map:
# 1. Registration/Onboarding flow
#    - Email verification requirements
#    - Account approval process
#    - Role assignment logic

# 2. E-commerce/Purchase flow
#    - Product selection → Cart → Checkout → Payment → Confirmation
#    - Price calculation logic
#    - Discount/coupon application
#    - Quantity limits
#    - Shipping cost calculation

# 3. Authentication/Authorization flow
#    - Login → MFA → Dashboard
#    - Password reset → Token → New password
#    - Role escalation/approval

# 4. Financial transactions
#    - Balance check → Transfer → Confirmation
#    - Withdrawal limits
#    - Currency conversion

# Document expected constraints:
# - Minimum order amounts
# - Maximum quantity per item
# - Coupon usage limits (one per user)
# - Referral reward caps
# - Withdrawal daily limits
# - Account verification requirements before certain actions
```

### Step 2: Test Price and Quantity Manipulation

Intercept and modify price, quantity, and total values in requests.

```bash
# Test negative quantity
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"product_id": 1, "quantity": -1, "price": 99.99}' \
  "https://target.example.com/api/cart/add"

# Test zero price
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"product_id": 1, "quantity": 1, "price": 0}' \
  "https://target.example.com/api/cart/add"

# Test extremely large quantity
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"product_id": 1, "quantity": 999999999}' \
  "https://target.example.com/api/cart/add"

# Test decimal/float manipulation
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"product_id": 1, "quantity": 0.001, "price": 0.01}' \
  "https://target.example.com/api/cart/add"

# Test integer overflow
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"product_id": 1, "quantity": 2147483647}' \
  "https://target.example.com/api/cart/add"

# Modify total amount directly in checkout request
# Intercept in Burp and change total from 299.99 to 0.01
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"cart_id": "abc123", "total": 0.01, "payment_method": "card"}' \
  "https://target.example.com/api/checkout"
```

### Step 3: Test Workflow Step Bypass

Attempt to skip required steps in multi-step processes.

```bash
# Skip email verification
# Instead of: Register → Verify email → Access dashboard
# Try: Register → Access dashboard directly
curl -s -H "Authorization: Bearer $UNVERIFIED_TOKEN" \
  "https://target.example.com/api/dashboard"

# Skip payment step
# Instead of: Cart → Shipping → Payment → Confirmation
# Try: Cart → Confirmation (skip payment)
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"cart_id": "abc123", "shipping_address": "123 Main St"}' \
  "https://target.example.com/api/orders/confirm"

# Skip MFA step
# Instead of: Login → MFA → Dashboard
# Try: Login → Dashboard (skip MFA)
# After successful password auth, directly access protected resources

# Skip approval process
# Instead of: Submit request → Manager approval → Access granted
# Try: Submit request → Access granted (skip approval)

# Repeat a step that should be one-time
# Apply same coupon code multiple times
for i in $(seq 1 5); do
  curl -s -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"coupon_code": "DISCOUNT50"}' \
    "https://target.example.com/api/cart/apply-coupon"
  echo "Attempt $i"
done
```

### Step 4: Test Race Conditions in Business Logic

Exploit timing windows in concurrent request processing.

```bash
# Race condition on coupon application
# Send multiple identical requests simultaneously
for i in $(seq 1 10); do
  curl -s -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"coupon_code": "ONETIME50"}' \
    "https://target.example.com/api/cart/apply-coupon" &
done
wait

# Race condition on balance transfer
# If user has $100, try to transfer $100 to two accounts simultaneously
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"to": "user_b", "amount": 100}' \
  "https://target.example.com/api/transfer" &

curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"to": "user_c", "amount": 100}' \
  "https://target.example.com/api/transfer" &
wait

# Race condition on reward claiming
# Using Burp Turbo Intruder for precise timing:
# 1. Send request to Turbo Intruder
# 2. Use race condition script template
# 3. Send 20+ requests simultaneously
# 4. Check if reward was claimed multiple times
```

### Step 5: Test Referral and Reward System Abuse

Find ways to exploit promotional features and reward mechanisms.

```bash
# Self-referral: refer your own email
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"referral_email": "myown@email.com"}' \
  "https://target.example.com/api/referrals/invite"

# Referral code reuse across multiple accounts
# Create multiple accounts and use same referral code

# Coupon stacking: apply multiple discount codes
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"coupon_codes": ["SAVE10", "WELCOME20", "VIP50"]}' \
  "https://target.example.com/api/cart/apply-coupons"

# Abuse free trial: re-register with same details
# Test if email+1@domain.com or email@domain.com bypass duplicate detection

# Gift card / credit manipulation
# Buy gift card with gift card balance (circular)
# Apply gift card with value > purchase price (get change as credit)

# Test reward point manipulation
# Earn points on order → Cancel order → Keep points
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  "https://target.example.com/api/orders/12345/cancel"
# Check if reward points from order 12345 were revoked
```

### Step 6: Test Role and Permission Logic

Assess authorization logic for privilege escalation through business processes.

```bash
# Role escalation via registration parameter
curl -s -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"Test1234!","role":"admin"}' \
  "https://target.example.com/api/auth/register"

# Organization tenant boundary testing
# User in Org A tries to access Org B resources via business workflows
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN_ORG_A" \
  -H "Content-Type: application/json" \
  -d '{"org_id": "org_b_id", "action": "view_reports"}' \
  "https://target.example.com/api/reports"

# Test for privilege retention after role downgrade
# Admin → Regular user: can they still access admin functions?
# Employee → Terminated: can they still access company resources?

# Test invitation/delegation abuse
# Invite user with higher privileges than inviter has
curl -s -X POST \
  -H "Authorization: Bearer $REGULAR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"new@test.com","role":"admin"}' \
  "https://target.example.com/api/users/invite"
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Business Logic Flaw** | A vulnerability in the application's workflow or rules that allows unintended actions |
| **Price Manipulation** | Modifying price, quantity, or total values in client-side requests |
| **Workflow Bypass** | Skipping required steps in a multi-step business process |
| **Race Condition** | Exploiting concurrent request processing to violate business constraints |
| **Privilege Escalation** | Gaining higher permissions through business process manipulation |
| **Negative Testing** | Testing with unexpected values (negative, zero, null, extreme) |
| **State Manipulation** | Changing application state in an order not intended by the business logic |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **Burp Suite Professional** | Request interception, modification, and sequence testing |
| **Burp Turbo Intruder** | High-speed request sending for race condition testing |
| **Burp Sequencer** | Token randomness analysis for predictable reference testing |
| **OWASP ZAP** | Open-source alternative for proxy-based testing |
| **Postman** | Workflow testing with collection runners and environment variables |
| **Custom scripts** | Python/bash scripts for automated business logic testing |

## Common Scenarios

### Scenario 1: Coupon Code Stacking
An e-commerce site allows applying multiple coupon codes. By stacking "WELCOME10", "SAVE20", and "VIP30", the total discount exceeds the product price, resulting in a negative balance or free order.

### Scenario 2: Race Condition on Fund Transfer
A banking application checks balance before transfer but does not lock the account. Sending two simultaneous $1000 transfers from a $1000 balance results in both succeeding, creating money from nothing.

### Scenario 3: Checkout Price Override
The checkout flow sends the total amount in the POST body. Intercepting and changing the total from $499.99 to $0.01 results in a successful order at the manipulated price.

### Scenario 4: Password Reset Token Reuse
The password reset flow generates a one-time token but does not invalidate it after use. The same token can be used repeatedly to reset the password.

## Output Format

```
## Business Logic Vulnerability Finding

**Vulnerability**: Price Manipulation in Checkout Flow
**Severity**: Critical (CVSS 9.1)
**Location**: POST /api/checkout - `total` parameter
**OWASP Category**: A04:2021 - Insecure Design

### Reproduction Steps
1. Add item to cart (price: $499.99)
2. Proceed to checkout
3. Intercept POST /api/checkout request in Burp
4. Modify "total" from 499.99 to 0.01
5. Forward the request; order completes at $0.01

### Business Rules Violated
| Rule | Expected | Actual |
|------|----------|--------|
| Server-side price calculation | Total computed server-side | Client-submitted total accepted |
| Coupon single use | One coupon per order | Same coupon applied 5 times |
| Negative quantity check | Quantity >= 1 | Quantity -1 accepted (credit issued) |
| Race condition on transfer | Balance checked atomically | Dual transfer exceeded balance |

### Impact
- Financial loss: orders processed at attacker-controlled prices
- Inventory loss: products shipped for $0.01
- Reward abuse: unlimited referral credits via self-referral
- Double-spending via race condition on transfers

### Recommendation
1. Perform all price calculations server-side; never trust client-submitted totals
2. Implement server-side validation for quantity (positive integers only)
3. Use database-level locks or atomic transactions for financial operations
4. Implement idempotency keys to prevent duplicate transaction processing
5. Rate-limit and log coupon applications, referral submissions, and transfers
```
