# API Reference: Implementing API Abuse Detection with Rate Limiting

## Redis Token Bucket (Python)

```python
import redis, time
r = redis.Redis()

# Lua-based atomic token bucket
lua = """
local tokens = tonumber(redis.call('HGET', KEYS[1], 'tokens') or ARGV[1])
local last = tonumber(redis.call('HGET', KEYS[1], 'last') or ARGV[3])
local elapsed = ARGV[3] - last
tokens = math.min(tonumber(ARGV[1]), tokens + elapsed * tonumber(ARGV[2]))
if tokens >= 1 then
    tokens = tokens - 1
    redis.call('HMSET', KEYS[1], 'tokens', tokens, 'last', ARGV[3])
    return 1
end
return 0
"""
allowed = r.eval(lua, 1, f"rl:{client_ip}", max_tokens, refill_rate, time.time())
```

## Rate Limit Response Headers

| Header | Description |
|--------|-------------|
| `X-RateLimit-Limit` | Maximum requests allowed |
| `X-RateLimit-Remaining` | Requests remaining |
| `X-RateLimit-Reset` | Unix timestamp when limit resets |
| `Retry-After` | Seconds until client can retry |

## NGINX Rate Limiting

```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
location /api/ {
    limit_req zone=api burst=20 nodelay;
    limit_req_status 429;
}
```

## Abuse Detection Thresholds

| Attack Type | Indicator | Threshold |
|-------------|-----------|-----------|
| Brute Force | Auth failures/IP | > 10 in 5 min |
| Credential Stuffing | Unique users/IP | > 20 |
| API Scraping | Requests/IP | > 500/hr |
| Rate Bypass | User-Agent rotation | > 10 unique UAs |

## Flask-Limiter

```python
from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
limiter = Limiter(get_remote_address, app=app, default_limits=["100/minute"])

@app.route("/api/login")
@limiter.limit("5/minute")
def login():
    pass
```

### References

- Redis Rate Limiting: https://redis.io/glossary/rate-limiting/
- Flask-Limiter: https://flask-limiter.readthedocs.io/
- IETF RateLimit Headers: https://datatracker.ietf.org/doc/draft-ietf-httpapi-ratelimit-headers/
