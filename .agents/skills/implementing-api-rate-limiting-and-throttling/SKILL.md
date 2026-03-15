---
name: implementing-api-rate-limiting-and-throttling
description: >
  Implements API rate limiting and throttling controls using token bucket, sliding window,
  and fixed window algorithms to protect against brute force attacks, credential stuffing,
  resource exhaustion, and API abuse. The engineer configures per-user, per-IP, and per-endpoint
  rate limits using Redis-backed counters, API gateway plugins, or application middleware,
  and implements proper HTTP 429 responses with Retry-After headers. Activates for requests
  involving rate limiting implementation, API throttling setup, request quota management,
  or API abuse prevention.
domain: cybersecurity
subdomain: api-security
tags: [api-security, rate-limiting, throttling, redis, token-bucket, abuse-prevention]
version: 1.0.0
author: mahipal
license: Apache-2.0
---
# Implementing API Rate Limiting and Throttling

## When to Use

- Protecting authentication endpoints against brute force and credential stuffing attacks
- Preventing API abuse and resource exhaustion from automated scripts and bots
- Implementing fair usage quotas for different API consumer tiers (free, premium, enterprise)
- Defending against denial-of-service attacks at the application layer
- Meeting compliance requirements that mandate API abuse prevention controls

**Do not use** rate limiting as the sole defense against attacks. Combine with authentication, authorization, and WAF rules.

## Prerequisites

- Redis 6.0+ for distributed rate limit counters (or in-memory for single-instance deployments)
- API framework (Express.js, FastAPI, Spring Boot, or Django REST Framework)
- Monitoring system for rate limit metrics (Prometheus, CloudWatch, Datadog)
- Understanding of the API's normal traffic patterns and peak usage
- Load testing tool (k6, Gatling, or Locust) for validating rate limit behavior

## Workflow

### Step 1: Rate Limiting Strategy Design

Define rate limits per endpoint category and user tier:

```python
# Rate limit configuration
RATE_LIMITS = {
    # Authentication endpoints (most restrictive)
    "auth": {
        "login": {"requests": 5, "window_seconds": 60, "by": "ip"},
        "register": {"requests": 3, "window_seconds": 300, "by": "ip"},
        "forgot_password": {"requests": 3, "window_seconds": 3600, "by": "ip"},
        "verify_mfa": {"requests": 5, "window_seconds": 300, "by": "user"},
    },
    # Standard API endpoints
    "api": {
        "free": {"requests": 60, "window_seconds": 60, "by": "user"},
        "premium": {"requests": 300, "window_seconds": 60, "by": "user"},
        "enterprise": {"requests": 1000, "window_seconds": 60, "by": "user"},
    },
    # Resource-intensive endpoints
    "expensive": {
        "search": {"requests": 10, "window_seconds": 60, "by": "user"},
        "export": {"requests": 5, "window_seconds": 3600, "by": "user"},
        "bulk_import": {"requests": 2, "window_seconds": 3600, "by": "user"},
    },
    # Global limits
    "global": {
        "per_ip": {"requests": 1000, "window_seconds": 60, "by": "ip"},
        "per_user": {"requests": 5000, "window_seconds": 3600, "by": "user"},
    },
}
```

### Step 2: Sliding Window Rate Limiter (Redis)

```python
import redis
import time
import hashlib
from functools import wraps
from flask import Flask, request, jsonify, g

app = Flask(__name__)
redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)

class SlidingWindowRateLimiter:
    """Sliding window rate limiter using Redis sorted sets."""

    def __init__(self, redis_conn):
        self.redis = redis_conn

    def is_allowed(self, key, max_requests, window_seconds):
        """Check if request is allowed and record it."""
        now = time.time()
        window_start = now - window_seconds
        pipe = self.redis.pipeline()

        # Remove expired entries
        pipe.zremrangebyscore(key, 0, window_start)
        # Count requests in current window
        pipe.zcard(key)
        # Add current request
        pipe.zadd(key, {f"{now}:{hashlib.md5(str(now).encode()).hexdigest()[:8]}": now})
        # Set TTL on the key
        pipe.expire(key, window_seconds + 1)

        results = pipe.execute()
        current_count = results[1]

        if current_count >= max_requests:
            # Calculate retry-after
            oldest = self.redis.zrange(key, 0, 0, withscores=True)
            if oldest:
                retry_after = int(oldest[0][1] + window_seconds - now) + 1
            else:
                retry_after = window_seconds
            return False, current_count, max_requests, retry_after

        return True, current_count + 1, max_requests, 0

rate_limiter = SlidingWindowRateLimiter(redis_client)

def rate_limit(max_requests, window_seconds, key_func=None):
    """Decorator for rate limiting API endpoints."""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # Determine the rate limit key
            if key_func:
                identifier = key_func()
            elif hasattr(g, 'user_id'):
                identifier = f"user:{g.user_id}"
            else:
                identifier = f"ip:{request.remote_addr}"

            key = f"ratelimit:{request.endpoint}:{identifier}"
            allowed, current, limit, retry_after = rate_limiter.is_allowed(
                key, max_requests, window_seconds)

            # Always set rate limit headers
            headers = {
                "X-RateLimit-Limit": str(limit),
                "X-RateLimit-Remaining": str(max(0, limit - current)),
                "X-RateLimit-Reset": str(int(time.time()) + window_seconds),
            }

            if not allowed:
                headers["Retry-After"] = str(retry_after)
                response = jsonify({
                    "error": "rate_limit_exceeded",
                    "message": "Too many requests. Please try again later.",
                    "retry_after": retry_after
                })
                response.status_code = 429
                for h, v in headers.items():
                    response.headers[h] = v
                return response

            response = f(*args, **kwargs)
            for h, v in headers.items():
                response.headers[h] = v
            return response
        return wrapped
    return decorator

# Apply rate limiting to endpoints
@app.route('/api/v1/auth/login', methods=['POST'])
@rate_limit(max_requests=5, window_seconds=60,
            key_func=lambda: f"ip:{request.remote_addr}")
def login():
    # Login logic
    return jsonify({"message": "Login successful"})

@app.route('/api/v1/users/me', methods=['GET'])
@rate_limit(max_requests=60, window_seconds=60)
def get_profile():
    # Profile logic
    return jsonify({"user": "data"})

@app.route('/api/v1/search', methods=['GET'])
@rate_limit(max_requests=10, window_seconds=60)
def search():
    # Search logic
    return jsonify({"results": []})
```

### Step 3: Token Bucket Rate Limiter

```python
import redis
import time

class TokenBucketRateLimiter:
    """Token bucket rate limiter allowing burst traffic within limits."""

    def __init__(self, redis_conn):
        self.redis = redis_conn

    def is_allowed(self, key, max_tokens, refill_rate, refill_interval=1):
        """
        Token bucket algorithm:
        - max_tokens: Maximum burst capacity
        - refill_rate: Tokens added per refill_interval
        - refill_interval: Seconds between refills
        """
        now = time.time()
        bucket_key = f"tb:{key}"

        # Lua script for atomic token bucket operation
        lua_script = """
        local key = KEYS[1]
        local max_tokens = tonumber(ARGV[1])
        local refill_rate = tonumber(ARGV[2])
        local refill_interval = tonumber(ARGV[3])
        local now = tonumber(ARGV[4])

        local bucket = redis.call('hmget', key, 'tokens', 'last_refill')
        local tokens = tonumber(bucket[1])
        local last_refill = tonumber(bucket[2])

        if tokens == nil then
            tokens = max_tokens
            last_refill = now
        end

        -- Refill tokens
        local elapsed = now - last_refill
        local refills = math.floor(elapsed / refill_interval)
        if refills > 0 then
            tokens = math.min(max_tokens, tokens + (refills * refill_rate))
            last_refill = last_refill + (refills * refill_interval)
        end

        local allowed = 0
        if tokens >= 1 then
            tokens = tokens - 1
            allowed = 1
        end

        redis.call('hmset', key, 'tokens', tokens, 'last_refill', last_refill)
        redis.call('expire', key, math.ceil(max_tokens / refill_rate * refill_interval) + 10)

        return {allowed, tokens, max_tokens}
        """

        result = self.redis.eval(lua_script, 1, bucket_key,
                                  max_tokens, refill_rate, refill_interval, now)
        allowed = bool(result[0])
        remaining = int(result[1])
        limit = int(result[2])

        return allowed, remaining, limit
```

### Step 4: Tiered Rate Limiting with User Plans

```python
from enum import Enum

class UserTier(Enum):
    FREE = "free"
    PREMIUM = "premium"
    ENTERPRISE = "enterprise"

TIER_LIMITS = {
    UserTier.FREE: {
        "default": (60, 60),          # 60 req/min
        "search": (10, 60),           # 10 req/min
        "export": (5, 3600),          # 5 req/hour
        "daily_total": (1000, 86400), # 1000 req/day
    },
    UserTier.PREMIUM: {
        "default": (300, 60),
        "search": (50, 60),
        "export": (20, 3600),
        "daily_total": (10000, 86400),
    },
    UserTier.ENTERPRISE: {
        "default": (1000, 60),
        "search": (200, 60),
        "export": (100, 3600),
        "daily_total": (100000, 86400),
    },
}

def get_rate_limit_for_request(user_tier, endpoint_category="default"):
    """Get rate limit configuration based on user tier and endpoint."""
    tier_config = TIER_LIMITS.get(user_tier, TIER_LIMITS[UserTier.FREE])
    limit_config = tier_config.get(endpoint_category, tier_config["default"])
    return limit_config  # (max_requests, window_seconds)

class TieredRateLimitMiddleware:
    """Middleware that applies rate limits based on user subscription tier."""

    def __init__(self, app, redis_conn):
        self.app = app
        self.limiter = SlidingWindowRateLimiter(redis_conn)

    def __call__(self, environ, start_response):
        # Extract user info from request
        user_id = environ.get("HTTP_X_USER_ID")
        user_tier = UserTier(environ.get("HTTP_X_USER_TIER", "free"))
        endpoint = environ.get("PATH_INFO", "/")

        # Determine endpoint category
        category = "default"
        if "/search" in endpoint:
            category = "search"
        elif "/export" in endpoint:
            category = "export"

        max_requests, window = get_rate_limit_for_request(user_tier, category)
        key = f"tiered:{user_id or environ.get('REMOTE_ADDR')}:{category}"

        allowed, current, limit, retry_after = self.limiter.is_allowed(
            key, max_requests, window)

        if not allowed:
            status = "429 Too Many Requests"
            headers = [
                ("Content-Type", "application/json"),
                ("Retry-After", str(retry_after)),
                ("X-RateLimit-Limit", str(limit)),
                ("X-RateLimit-Remaining", "0"),
            ]
            start_response(status, headers)
            body = f'{{"error":"rate_limit_exceeded","retry_after":{retry_after},"tier":"{user_tier.value}"}}'
            return [body.encode()]

        return self.app(environ, start_response)
```

### Step 5: Distributed Rate Limiting for Microservices

```python
# Centralized rate limiting service using Redis Cluster
import redis
from redis.cluster import RedisCluster

class DistributedRateLimiter:
    """Rate limiter for microservice architectures using Redis Cluster."""

    def __init__(self):
        self.redis = RedisCluster(
            startup_nodes=[
                {"host": "redis-node-1", "port": 6379},
                {"host": "redis-node-2", "port": 6379},
                {"host": "redis-node-3", "port": 6379},
            ],
            decode_responses=True
        )

    def check_and_increment(self, service_name, user_id, endpoint,
                             max_requests, window_seconds):
        """Atomic check-and-increment using Redis Lua script."""
        key = f"rl:{{{service_name}}}:{user_id}:{endpoint}"

        # Lua script ensures atomicity across the check and increment
        lua_script = """
        local key = KEYS[1]
        local max_requests = tonumber(ARGV[1])
        local window = tonumber(ARGV[2])
        local now = tonumber(ARGV[3])
        local window_start = now - window

        -- Remove old entries
        redis.call('zremrangebyscore', key, '-inf', window_start)

        -- Count current entries
        local count = redis.call('zcard', key)

        if count >= max_requests then
            -- Get oldest entry for retry-after calculation
            local oldest = redis.call('zrange', key, 0, 0, 'WITHSCORES')
            local retry_after = 0
            if #oldest > 0 then
                retry_after = math.ceil(tonumber(oldest[2]) + window - now)
            end
            return {0, count, retry_after}
        end

        -- Add new entry
        redis.call('zadd', key, now, now .. ':' .. math.random(100000))
        redis.call('expire', key, window + 1)

        return {1, count + 1, 0}
        """

        result = self.redis.eval(lua_script, 1, key,
                                  max_requests, window_seconds, time.time())
        return {
            "allowed": bool(result[0]),
            "current": int(result[1]),
            "retry_after": int(result[2]),
        }
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Sliding Window** | Rate limiting algorithm that tracks requests in a rolling time window, providing smoother rate enforcement than fixed windows |
| **Token Bucket** | Algorithm where tokens are added at a fixed rate and consumed per request, allowing controlled bursts up to the bucket capacity |
| **Fixed Window** | Simplest rate limiting where requests are counted per fixed time window (e.g., per minute), susceptible to burst at window boundaries |
| **429 Too Many Requests** | HTTP status code indicating the client has exceeded the rate limit, accompanied by Retry-After header |
| **Retry-After Header** | HTTP response header telling the client how many seconds to wait before retrying, essential for well-behaved API clients |
| **Distributed Rate Limiting** | Rate limiting across multiple server instances using shared state (Redis, Memcached) to maintain accurate global counters |

## Tools & Systems

- **Redis**: In-memory data store used for distributed rate limit counters with atomic operations via Lua scripts
- **Kong Rate Limiting Plugin**: API gateway plugin supporting fixed-window and sliding-window rate limiting with Redis backend
- **express-rate-limit**: Express.js middleware for simple rate limiting with Redis, Memcached, or in-memory stores
- **Flask-Limiter**: Flask extension for rate limiting with support for multiple backends and configurable limits per endpoint
- **Envoy Rate Limit Service**: Centralized rate limiting service for Envoy-based service mesh architectures

## Common Scenarios

### Scenario: Implementing Rate Limiting for a Public API

**Context**: A company launches a public API with free, premium, and enterprise tiers. The API must protect against abuse while providing fair access to paying customers. The API runs on 6 instances behind an AWS ALB.

**Approach**:
1. Deploy Redis Cluster (3 nodes) for distributed rate limit state
2. Implement sliding window rate limiter using Redis sorted sets with Lua scripts for atomicity
3. Configure per-tier limits: Free (60 req/min), Premium (300 req/min), Enterprise (1000 req/min)
4. Add stricter limits on authentication endpoints (5 req/min per IP) regardless of tier
5. Implement resource-intensive endpoint limits (search: 10 req/min free, export: 5 req/hour)
6. Set rate limit response headers on every response (X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset)
7. Return 429 with Retry-After header and JSON error body when limits are exceeded
8. Set up Prometheus metrics for rate limit hits and CloudWatch alarms for unusual patterns

**Pitfalls**:
- Using in-memory rate limiting without shared state across instances, allowing limit bypass by hitting different servers
- Not implementing rate limiting on authentication endpoints separately from general API limits
- Using fixed windows that allow burst at window boundaries (2x the limit in a short period)
- Not including rate limit headers on successful responses, giving clients no visibility into their quota
- Trusting X-Forwarded-For for IP identification without validating it against the load balancer

## Output Format

```
## Rate Limiting Implementation Report

**API**: Public API v2
**Algorithm**: Sliding Window (Redis Sorted Sets)
**Backend**: Redis Cluster (3 nodes)
**Deployment**: 6 API instances behind AWS ALB

### Rate Limit Configuration

| Tier | Default | Search | Export | Auth (per IP) |
|------|---------|--------|--------|---------------|
| Free | 60/min | 10/min | 5/hour | 5/min |
| Premium | 300/min | 50/min | 20/hour | 5/min |
| Enterprise | 1000/min | 200/min | 100/hour | 10/min |

### Validation Results (k6 load test)

- Free tier: Rate limited at 61st request (correct)
- Premium tier: Rate limited at 301st request (correct)
- Cross-instance: Rate limiting consistent across all 6 instances
- Redis failover: Rate limiting degrades gracefully (allows traffic) when Redis is unreachable
- Retry-After header: Accurate within 1 second of actual reset time
- Response overhead: < 2ms added latency per request for rate limit check
```
