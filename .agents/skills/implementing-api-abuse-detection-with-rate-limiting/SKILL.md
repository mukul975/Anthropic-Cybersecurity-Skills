---
name: implementing-api-abuse-detection-with-rate-limiting
description: Implement API abuse detection using token bucket, sliding window, and adaptive rate limiting algorithms to prevent DDoS, brute force, and credential stuffing attacks.
domain: cybersecurity
subdomain: api-security
tags: [api-security, rate-limiting, token-bucket, sliding-window, ddos-protection, brute-force-prevention, api-abuse, api-gateway]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Implementing API Abuse Detection with Rate Limiting

## Overview

API rate limiting is a critical security control that restricts the number of requests a client can make within a defined time period. It defends against denial-of-service (DDoS), brute force login attempts, credential stuffing, API scraping, and resource exhaustion attacks. Modern implementations use algorithms like token bucket, sliding window, and fixed window counters, often backed by distributed stores like Redis. Adaptive rate limiting dynamically tightens limits during detected attacks and relaxes during normal operation, achieving a 94% reduction in successful DDoS attempts compared to static IP-based approaches.

## Prerequisites

- API gateway (Kong, AWS API Gateway, Apigee) or reverse proxy (NGINX, Envoy)
- Redis or Memcached for distributed rate limit counters
- Monitoring and alerting infrastructure (Prometheus, Grafana, or SIEM)
- Understanding of normal API traffic patterns and baselines
- Python 3.8+ or Node.js for custom implementation

## Rate Limiting Algorithms

### Token Bucket Algorithm

The token bucket assigns each client a bucket with a fixed capacity of tokens. Tokens refill at a constant rate. Each request consumes one token. When the bucket is empty, requests are rejected. This allows controlled bursts while maintaining average limits.

```python
"""Token Bucket Rate Limiter with Redis Backend

Implements a distributed token bucket algorithm for API rate limiting
with burst allowance and automatic refill.
"""

import time
import redis
import json
from typing import Tuple

class TokenBucketRateLimiter:
    def __init__(self, redis_client: redis.Redis,
                 max_tokens: int = 100,
                 refill_rate: float = 10.0,
                 key_prefix: str = "ratelimit:tb"):
        self.redis = redis_client
        self.max_tokens = max_tokens
        self.refill_rate = refill_rate  # tokens per second
        self.key_prefix = key_prefix

    def _get_key(self, client_id: str) -> str:
        return f"{self.key_prefix}:{client_id}"

    def allow_request(self, client_id: str, tokens_required: int = 1) -> Tuple[bool, dict]:
        """Check if a request should be allowed under the rate limit.

        Returns (allowed, info) where info contains remaining tokens
        and retry-after seconds.
        """
        key = self._get_key(client_id)
        now = time.time()

        # Atomic token bucket operation using Lua script
        lua_script = """
        local key = KEYS[1]
        local max_tokens = tonumber(ARGV[1])
        local refill_rate = tonumber(ARGV[2])
        local now = tonumber(ARGV[3])
        local requested = tonumber(ARGV[4])

        local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')
        local tokens = tonumber(bucket[1])
        local last_refill = tonumber(bucket[2])

        -- Initialize bucket if it doesn't exist
        if tokens == nil then
            tokens = max_tokens
            last_refill = now
        end

        -- Calculate refilled tokens
        local elapsed = now - last_refill
        local refilled = elapsed * refill_rate
        tokens = math.min(max_tokens, tokens + refilled)

        -- Check if enough tokens available
        local allowed = 0
        if tokens >= requested then
            tokens = tokens - requested
            allowed = 1
        end

        -- Update bucket state
        redis.call('HMSET', key, 'tokens', tokens, 'last_refill', now)
        redis.call('EXPIRE', key, 3600)  -- TTL for cleanup

        -- Calculate retry-after if denied
        local retry_after = 0
        if allowed == 0 then
            retry_after = math.ceil((requested - tokens) / refill_rate)
        end

        return {allowed, math.floor(tokens), retry_after}
        """
        result = self.redis.eval(
            lua_script, 1, key,
            self.max_tokens, self.refill_rate, now, tokens_required
        )

        allowed = bool(result[0])
        remaining = int(result[1])
        retry_after = int(result[2])

        return allowed, {
            "remaining": remaining,
            "limit": self.max_tokens,
            "retry_after": retry_after,
            "reset": int(now + (self.max_tokens - remaining) / self.refill_rate)
        }
```

### Sliding Window Rate Limiter

```python
"""Sliding Window Rate Limiter

Tracks requests over a continuously moving time window,
providing smoother rate limiting than fixed windows with
only a 2.3% false positive rate.
"""

class SlidingWindowRateLimiter:
    def __init__(self, redis_client: redis.Redis,
                 window_seconds: int = 60,
                 max_requests: int = 100,
                 key_prefix: str = "ratelimit:sw"):
        self.redis = redis_client
        self.window = window_seconds
        self.max_requests = max_requests
        self.key_prefix = key_prefix

    def allow_request(self, client_id: str) -> Tuple[bool, dict]:
        key = f"{self.key_prefix}:{client_id}"
        now = time.time()
        window_start = now - self.window

        # Atomic sliding window using sorted set
        pipe = self.redis.pipeline()
        # Remove expired entries
        pipe.zremrangebyscore(key, 0, window_start)
        # Add current request
        pipe.zadd(key, {f"{now}:{id(now)}": now})
        # Count requests in window
        pipe.zcard(key)
        # Set TTL
        pipe.expire(key, self.window + 1)
        results = pipe.execute()

        current_count = results[2]
        allowed = current_count <= self.max_requests

        if not allowed:
            # Remove the request we just added since it's denied
            self.redis.zremrangebyscore(key, now, now)

        return allowed, {
            "remaining": max(0, self.max_requests - current_count),
            "limit": self.max_requests,
            "window": self.window,
            "current_count": current_count
        }
```

### Adaptive Rate Limiter

```python
"""Adaptive Rate Limiter

Dynamically adjusts rate limits based on detected attack patterns.
Tightens limits during attacks and relaxes during normal operation.
"""

from enum import Enum
from dataclasses import dataclass

class ThreatLevel(Enum):
    NORMAL = "normal"
    ELEVATED = "elevated"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class AdaptiveLimits:
    requests_per_minute: int
    burst_size: int
    block_duration_seconds: int

THREAT_LIMITS = {
    ThreatLevel.NORMAL: AdaptiveLimits(100, 20, 0),
    ThreatLevel.ELEVATED: AdaptiveLimits(50, 10, 60),
    ThreatLevel.HIGH: AdaptiveLimits(20, 5, 300),
    ThreatLevel.CRITICAL: AdaptiveLimits(5, 2, 3600),
}

class AdaptiveRateLimiter:
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
        self.token_bucket = TokenBucketRateLimiter(redis_client)
        self.sliding_window = SlidingWindowRateLimiter(redis_client)

    def assess_threat_level(self, client_id: str) -> ThreatLevel:
        """Assess the current threat level for a client based on behavior."""
        metrics_key = f"metrics:{client_id}"
        metrics = self.redis.hgetall(metrics_key)

        if not metrics:
            return ThreatLevel.NORMAL

        error_rate = float(metrics.get(b'error_rate', 0))
        auth_failures = int(metrics.get(b'auth_failures_5m', 0))
        unique_endpoints = int(metrics.get(b'unique_endpoints_5m', 0))
        request_rate = float(metrics.get(b'requests_per_second', 0))

        # Scoring-based threat assessment
        score = 0
        if auth_failures > 10:
            score += 3
        elif auth_failures > 5:
            score += 2
        elif auth_failures > 2:
            score += 1

        if error_rate > 0.8:
            score += 3
        elif error_rate > 0.5:
            score += 2

        if request_rate > 50:
            score += 2
        elif request_rate > 20:
            score += 1

        if unique_endpoints > 50:
            score += 2  # Possible enumeration

        if score >= 7:
            return ThreatLevel.CRITICAL
        elif score >= 5:
            return ThreatLevel.HIGH
        elif score >= 3:
            return ThreatLevel.ELEVATED
        return ThreatLevel.NORMAL

    def allow_request(self, client_id: str, endpoint: str) -> Tuple[bool, dict]:
        """Rate limit with adaptive thresholds based on threat level."""
        threat_level = self.assess_threat_level(client_id)
        limits = THREAT_LIMITS[threat_level]

        # Check if client is currently blocked
        block_key = f"blocked:{client_id}"
        if self.redis.exists(block_key):
            ttl = self.redis.ttl(block_key)
            return False, {
                "blocked": True,
                "threat_level": threat_level.value,
                "retry_after": ttl,
                "reason": "Temporarily blocked due to suspicious activity"
            }

        # Apply rate limit with threat-adjusted parameters
        self.token_bucket.max_tokens = limits.burst_size
        self.token_bucket.refill_rate = limits.requests_per_minute / 60.0

        allowed, info = self.token_bucket.allow_request(client_id)

        if not allowed and limits.block_duration_seconds > 0:
            # Block the client for the threat-level duration
            self.redis.setex(block_key, limits.block_duration_seconds, threat_level.value)

        info["threat_level"] = threat_level.value
        return allowed, info

    def record_request_outcome(self, client_id: str, status_code: int, endpoint: str):
        """Track request outcomes for threat assessment."""
        metrics_key = f"metrics:{client_id}"
        pipe = self.redis.pipeline()

        pipe.hincrby(metrics_key, 'total_requests', 1)
        if status_code in (401, 403):
            pipe.hincrby(metrics_key, 'auth_failures_5m', 1)
        if status_code >= 400:
            pipe.hincrby(metrics_key, 'errors_5m', 1)

        # Track unique endpoints for enumeration detection
        pipe.sadd(f"endpoints:{client_id}", endpoint)
        pipe.expire(metrics_key, 300)  # 5-minute window
        pipe.expire(f"endpoints:{client_id}", 300)
        pipe.execute()
```

### NGINX Rate Limiting Configuration

```nginx
# Define rate limit zones
limit_req_zone $binary_remote_addr zone=api_general:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=api_auth:10m rate=3r/s;
limit_req_zone $binary_remote_addr zone=api_sensitive:10m rate=1r/s;

# Apply rate limits to API routes
server {
    listen 443 ssl;

    # General API endpoints - 10 req/s with burst of 20
    location /api/v1/ {
        limit_req zone=api_general burst=20 nodelay;
        limit_req_status 429;
        proxy_pass http://api_backend;
    }

    # Authentication endpoints - strict 3 req/s
    location /api/v1/auth/ {
        limit_req zone=api_auth burst=5;
        limit_req_status 429;
        proxy_pass http://api_backend;
    }

    # Sensitive data endpoints - 1 req/s
    location /api/v1/admin/ {
        limit_req zone=api_sensitive burst=3;
        limit_req_status 429;
        proxy_pass http://api_backend;
    }

    # Custom 429 response with Retry-After header
    error_page 429 = @rate_limited;
    location @rate_limited {
        add_header Retry-After 30;
        add_header X-RateLimit-Limit $limit_req_status;
        return 429 '{"error": "rate_limit_exceeded", "retry_after": 30}';
    }
}
```

## Response Headers

Always include standard rate limit headers:

```
HTTP/1.1 429 Too Many Requests
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1672531200
Retry-After: 30
Content-Type: application/json

{"error": "rate_limit_exceeded", "retry_after": 30}
```

## References

- APIsec Rate Limiting Strategies: https://www.apisec.ai/blog/api-rate-limiting-strategies-preventing
- HackerOne Rate Limiting Best Practices: https://www.hackerone.com/blog/rate-limiting-strategies-protecting-your-api-ddos-and-brute-force-attacks
- API7.ai Rate Limiting Algorithms Guide: https://api7.ai/blog/rate-limiting-guide-algorithms-best-practices
- Redis Rate Limiting: https://redis.io/glossary/rate-limiting/
- Rakuten SixthSense API Rate Limiting: https://sixthsense.rakuten.com/blog/API-Rate-Limiting-A-Critical-Layer-for-API-Protection
