# API Reference: Implementing API Rate Limiting and Throttling

## Token Bucket Algorithm

```python
import time
class TokenBucket:
    def __init__(self, capacity, refill_rate):
        self.capacity = capacity
        self.tokens = capacity
        self.refill_rate = refill_rate  # tokens/sec
        self.last_refill = time.time()

    def allow(self):
        now = time.time()
        self.tokens = min(self.capacity,
            self.tokens + (now - self.last_refill) * self.refill_rate)
        self.last_refill = now
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False
```

## Redis Sliding Window

```python
import redis, time
r = redis.Redis()
def check_rate(client_id, window=60, limit=100):
    key = f"rl:{client_id}"
    now = time.time()
    pipe = r.pipeline()
    pipe.zremrangebyscore(key, 0, now - window)
    pipe.zadd(key, {str(now): now})
    pipe.zcard(key)
    pipe.expire(key, window)
    _, _, count, _ = pipe.execute()
    return count <= limit
```

## HTTP 429 Response Headers

| Header | Value | Description |
|--------|-------|-------------|
| `Retry-After` | `30` | Seconds until retry |
| `X-RateLimit-Limit` | `100` | Max requests |
| `X-RateLimit-Remaining` | `0` | Remaining requests |
| `X-RateLimit-Reset` | epoch | Reset timestamp |

## Kong Rate Limiting Plugin

```bash
curl -X POST http://localhost:8001/services/{id}/plugins \
  -d "name=rate-limiting" \
  -d "config.minute=100" \
  -d "config.policy=redis" \
  -d "config.redis_host=redis"
```

### References

- Redis Rate Limiting: https://redis.io/glossary/rate-limiting/
- IETF RateLimit Headers: https://datatracker.ietf.org/doc/draft-ietf-httpapi-ratelimit-headers/
- Kong Rate Limiting: https://docs.konghq.com/hub/kong-inc/rate-limiting/
