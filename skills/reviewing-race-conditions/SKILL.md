---
name: reviewing-race-conditions
description: >-
  Detect Race Conditions and Time-of-Check to Time-of-Use (TOCTOU) vulnerabilities. 
  Targets endpoints managing limited resources (coupons, wallet balances, inventory, 
  state transitions) by sending highly concurrent requests to bypass check-then-act 
  business logic boundaries.
domain: cybersecurity
subdomain: web-application-security
tags: [race-condition, toctou, concurrency, business-logic]
mitre_attack: [T1190, T1499]
version: "1.0"
author: Victor
license: Apache-2.0
---

# Reviewing Race Conditions

## When to Use

- When an endpoint performs a "check-then-act" operation on a finite or stateful resource.
- Scenarios: Coupon redemption (limit 1 per user), Wallet balance deductions, Flash sales / Inventory decrements, One-time token usage (OTP, invitation codes).
- State Machine changes: Changing an order from `pending` to `paid` or `canceled`.

## Prerequisites

- An interception proxy with concurrent sending capabilities (Burp Suite Professional's Intruder or Turbo Intruder, ZAP).
- The ability to send HTTP/2 Single-Packet Attacks (to eliminate network jitter).
- Controlled test accounts or sentinel resources. **Critical**: Do not run race conditions against real production inventory or financial balances unless using a dedicated test sentinel account, as the effects (negative balances, overselling) are permanent.

## Workflow

### Step 1: Target Identification
Identify the non-atomic check-then-act sequence:
1. **Check**: The server verifies a precondition (e.g., "Does the user have >= $10?").
2. **Act**: The server mutates the state (e.g., "Deduct $10 from wallet").

### Step 2: Baseline Execution
1. Perform the operation normally once to establish the baseline response and confirm the precondition and postcondition.
2. Determine the limit (e.g., the wallet has exactly $10 left).

### Step 3: Concurrent Exploitation
Send multiple requests simultaneously. The goal is to get multiple requests to pass the "Check" phase before any of them complete the "Act" phase.
- **Strategy 1: Simple Concurrency**: Use a script or Intruder to fire 10-20 requests simultaneously.
- **Strategy 2: HTTP/2 Single Packet Attack (SPA)**: If the server supports HTTP/2, use Burp's Turbo Intruder to pack 20 requests into a single TCP packet. This ensures they arrive at the server at the exact same microsecond, maximizing the chance of triggering the race condition.

### Step 4: Verification
Count the number of HTTP 200 OK responses. However, a 200 OK does *not* confirm a race condition by itself (it could be idempotent).
You must verify the backend state:
- Check the wallet balance: Is it negative?
- Check the inventory: Were 5 items bought when only 1 was in stock?
- Check the coupon list: Was the "limit 1" coupon applied 3 times?

### Verification and Validation Phase
1. Establish target environment baseline and identify endpoint parameters.
2. Execute realistic detection payload to evaluate vulnerability exposure:

```bash
for i in {1..5}; do
  curl -s -X POST "https://target.example.com/api/v1/coupon/claim" \
       -H "Authorization: Bearer test_token" \
       -d '{"coupon_code": "DISCOUNT100"}' &
done
wait
```

3. Analyze HTTP response status, reflected headers, and execution timing to confirm finding.

## Key Concepts

| Term | Definition |
|------|------------|
| **Race Condition (TOCTOU)** | A flaw occurring when the timing or ordering of events affects a program's correctness. Specifically, Time-of-Check to Time-of-Use occurs when a resource's state changes between the time it is checked and the time it is used. |
| **Atomic Operation** | An operation that completes in a single step relative to other threads. If the check and act are atomic (e.g., using a database `SELECT ... FOR UPDATE` row lock), the race condition is prevented. |
| **HTTP/2 Single Packet Attack** | A technique that places multiple HTTP requests into a single TCP packet, allowing them to be processed by the server at the exact same moment, bypassing network jitter. |

## Tools & Systems

- Burp Suite Professional / Community Edition
- Standard web browsers and interception proxies.

## Common Scenarios

### Scenario: False Positive - Idempotent Endpoints
**Context**: You fire 10 concurrent requests to an endpoint that sets an order status to `CANCELED`. All 10 return 200 OK.
**Analysis**: The backend query might just be `UPDATE orders SET status = 'CANCELED' WHERE id = 1`. Running this 10 times is safe because the end state is the same.
**Action**: Verify if the action caused an unintended side effect (e.g., did the system issue 10 separate refund transactions?). If not, it's just idempotent, not a vulnerability.

### Scenario: The Negative Balance
**Context**: A user has $50. An item costs $50. You send 5 concurrent purchase requests.
**Analysis**: The backend uses application-level logic: `if (user.balance >= 50) { user.balance = user.balance - 50; }`.
**Action**: If 3 requests win the race, the user will own 3 items, and their balance will be -$100. This confirms a critical vulnerability.

## Output Format

Document confirmed vulnerabilities with proof of the unexpected state mutation:

```json
{
  "id": "race-001",
  "title": "Race Condition in Wallet Deduction leading to Negative Balance",
  "severity": "critical",
  "cwe": "CWE-362",
  "endpoint": "POST /api/v1/wallet/purchase",
  "status": "confirmed",
  "evidence": {
    "attack_method": "HTTP/2 Single-Packet Attack (15 concurrent requests)",
    "execution_proof": "The test account started with a $100 balance. By sending 15 concurrent purchase requests for a $100 item, 3 requests succeeded simultaneously. The account now owns 3 items, and the wallet balance is -$200, proving the check-then-act sequence is non-atomic."
  },
  "description": "The purchase endpoint is vulnerable to a Time-of-Check to Time-of-Use (TOCTOU) race condition. The application verifies the user's balance in application memory before updating the database without a row lock, allowing concurrent requests to overdraw the account."
}
```
