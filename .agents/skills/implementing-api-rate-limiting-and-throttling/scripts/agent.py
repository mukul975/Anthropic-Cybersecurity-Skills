#!/usr/bin/env python3
"""Agent for implementing and testing API rate limiting and throttling."""

import json
import argparse
import time
from datetime import datetime
from collections import defaultdict, Counter


class TokenBucket:
    """In-memory token bucket rate limiter."""
    def __init__(self, max_tokens=100, refill_rate=10.0):
        self.max_tokens = max_tokens
        self.refill_rate = refill_rate
        self.buckets = {}

    def allow(self, client_id):
        now = time.time()
        if client_id not in self.buckets:
            self.buckets[client_id] = {"tokens": self.max_tokens, "last": now}
        bucket = self.buckets[client_id]
        elapsed = now - bucket["last"]
        bucket["tokens"] = min(self.max_tokens, bucket["tokens"] + elapsed * self.refill_rate)
        bucket["last"] = now
        if bucket["tokens"] >= 1:
            bucket["tokens"] -= 1
            return True, {"remaining": int(bucket["tokens"]), "limit": self.max_tokens}
        return False, {"remaining": 0, "retry_after": round((1 - bucket["tokens"]) / self.refill_rate, 2)}


class SlidingWindow:
    """In-memory sliding window rate limiter."""
    def __init__(self, window_seconds=60, max_requests=100):
        self.window = window_seconds
        self.max_requests = max_requests
        self.requests = defaultdict(list)

    def allow(self, client_id):
        now = time.time()
        cutoff = now - self.window
        self.requests[client_id] = [t for t in self.requests[client_id] if t > cutoff]
        current = len(self.requests[client_id])
        if current < self.max_requests:
            self.requests[client_id].append(now)
            return True, {"remaining": self.max_requests - current - 1, "window": self.window}
        return False, {"remaining": 0, "retry_after": round(self.requests[client_id][0] - cutoff, 2)}


def analyze_rate_limit_effectiveness(log_path):
    """Analyze API logs to assess rate limiting effectiveness."""
    ip_requests = Counter()
    ip_429s = Counter()
    endpoint_load = Counter()
    with open(log_path) as f:
        for line in f:
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            ip = entry.get("client_ip", entry.get("ip", ""))
            status = int(entry.get("status_code", entry.get("status", 0)))
            endpoint = entry.get("path", entry.get("endpoint", ""))
            ip_requests[ip] += 1
            if status == 429:
                ip_429s[ip] += 1
            endpoint_load[endpoint] += 1
    findings = []
    for ip, total in ip_requests.most_common(20):
        rate_limited = ip_429s.get(ip, 0)
        if total > 1000 and rate_limited == 0:
            findings.append({
                "ip": ip, "total_requests": total, "rate_limited": 0,
                "issue": "high_volume_not_rate_limited", "severity": "HIGH",
            })
        elif rate_limited > 0 and rate_limited < total * 0.1:
            findings.append({
                "ip": ip, "total_requests": total, "rate_limited": rate_limited,
                "issue": "rate_limit_too_permissive", "severity": "MEDIUM",
            })
    return findings


def simulate_rate_limit_test(algorithm="token_bucket", requests_count=200, rate=10):
    """Simulate rate limiting to test configuration."""
    if algorithm == "token_bucket":
        limiter = TokenBucket(max_tokens=rate, refill_rate=rate / 60.0)
    else:
        limiter = SlidingWindow(window_seconds=60, max_requests=rate)
    allowed = 0
    denied = 0
    for i in range(requests_count):
        ok, _ = limiter.allow("test_client")
        if ok:
            allowed += 1
        else:
            denied += 1
    return {
        "algorithm": algorithm, "total_requests": requests_count,
        "allowed": allowed, "denied": denied,
        "effective_rate": round(allowed / requests_count * 100, 1),
    }


def generate_rate_limit_recommendations(log_path):
    """Generate rate limit recommendations from traffic patterns."""
    ip_rpm = defaultdict(int)
    endpoint_rpm = defaultdict(int)
    with open(log_path) as f:
        for line in f:
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            ip = entry.get("client_ip", "")
            endpoint = entry.get("path", "")
            ip_rpm[ip] += 1
            endpoint_rpm[endpoint] += 1
    ip_values = sorted(ip_rpm.values())
    p95 = ip_values[int(len(ip_values) * 0.95)] if ip_values else 100
    p99 = ip_values[int(len(ip_values) * 0.99)] if ip_values else 200
    return {
        "global_rate_limit": p99 * 2,
        "per_ip_limit": p95 * 2,
        "auth_endpoint_limit": max(10, p95 // 10),
        "p95_requests_per_ip": p95,
        "p99_requests_per_ip": p99,
    }


def main():
    parser = argparse.ArgumentParser(description="API Rate Limiting Agent")
    parser.add_argument("--action", choices=[
        "analyze", "simulate", "recommend", "full"
    ], default="full")
    parser.add_argument("--log", help="API access log (JSON lines)")
    parser.add_argument("--algorithm", choices=["token_bucket", "sliding_window"],
                        default="token_bucket")
    parser.add_argument("--output", default="rate_limiting_report.json")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "findings": {}}

    if args.action in ("analyze", "full") and args.log:
        f = analyze_rate_limit_effectiveness(args.log)
        report["findings"]["effectiveness"] = f
        print(f"[+] Rate limit issues: {len(f)}")

    if args.action in ("simulate", "full"):
        result = simulate_rate_limit_test(args.algorithm)
        report["findings"]["simulation"] = result
        print(f"[+] Simulation: {result['allowed']}/{result['total_requests']} allowed")

    if args.action in ("recommend", "full") and args.log:
        recs = generate_rate_limit_recommendations(args.log)
        report["findings"]["recommendations"] = recs
        print(f"[+] Recommended per-IP limit: {recs['per_ip_limit']}")

    with open(args.output, "w") as fout:
        json.dump(report, fout, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
