---
name: detecting-api-enumeration-attacks
description: Detect and prevent API enumeration attacks including BOLA and IDOR exploitation by monitoring sequential identifier access patterns and authorization failures.
domain: cybersecurity
subdomain: api-security
tags: [api-security, enumeration, bola, idor, broken-object-level-authorization, owasp-api-top-10, access-control, rate-limiting]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Detecting API Enumeration Attacks

## Overview

API enumeration attacks occur when attackers systematically probe API endpoints with sequential or predictable identifiers to discover and access unauthorized resources. Broken Object Level Authorization (BOLA), ranked as API1:2023 in the OWASP API Security Top 10, is the most critical API vulnerability. Attackers manipulate object identifiers (user IDs, order numbers, account references) in API requests to bypass authorization and access other users' data. Detection requires monitoring for patterns of rapid sequential access attempts, authorization failures, and abnormal API usage behavior.

## Prerequisites

- API gateway or reverse proxy with logging enabled (Kong, AWS API Gateway, Apigee)
- SIEM platform (Splunk, Elastic SIEM, or Microsoft Sentinel)
- Access to API server logs with request details
- Web Application Firewall (WAF) with API protection capabilities
- Understanding of the API's authorization model and object identifier schemes

## Attack Patterns to Detect

### 1. Sequential ID Enumeration

Attackers iterate through numeric or predictable identifiers:

```
GET /api/v1/users/1001 -> 200 OK
GET /api/v1/users/1002 -> 200 OK
GET /api/v1/users/1003 -> 403 Forbidden
GET /api/v1/users/1004 -> 200 OK
GET /api/v1/users/1005 -> 200 OK
...
```

**Detection Indicators:**
- Rapid sequential requests to the same endpoint with incrementing IDs
- Mix of 200/403/401 responses from same source
- Request rate exceeding normal user behavior
- Access to resources outside authenticated user's scope

### 2. UUID/GUID Enumeration

Even non-sequential identifiers can be enumerated if leaked through other endpoints:

```
# Attacker first harvests UUIDs from a list endpoint
GET /api/v1/posts?page=1  -> Returns post objects with author UUIDs

# Then uses those UUIDs to access restricted user data
GET /api/v1/users/a3f2c1e4-... -> Private user profile
GET /api/v1/users/b7d9e8f1-... -> Private user profile
```

### 3. Parameter Tampering Enumeration

```
# Authenticated as user_id=100, attempting to access other users' orders
GET /api/v1/orders?user_id=101
GET /api/v1/orders?user_id=102
GET /api/v1/orders?user_id=103
```

## Detection Rules

### Splunk Detection Queries

```spl
# Detect sequential ID enumeration on API endpoints
index=api_logs sourcetype=api_access
| rex field=uri_path "(?<endpoint>/api/v\d+/\w+/)(?<object_id>\d+)"
| stats count as request_count,
        dc(object_id) as unique_ids,
        values(status_code) as status_codes,
        min(_time) as first_seen,
        max(_time) as last_seen
  by src_ip, endpoint, user_session
| eval time_span = last_seen - first_seen
| eval requests_per_second = request_count / max(time_span, 1)
| where unique_ids > 20 AND requests_per_second > 2
| eval severity = case(
    unique_ids > 100, "critical",
    unique_ids > 50, "high",
    unique_ids > 20, "medium",
    1==1, "low"
  )
| sort - unique_ids
| table src_ip, endpoint, unique_ids, request_count, requests_per_second,
        status_codes, severity

# Detect BOLA via authorization failure patterns
index=api_logs sourcetype=api_access status_code IN (401, 403)
| bin _time span=5m
| stats count as failure_count,
        dc(uri_path) as unique_paths,
        values(uri_path) as attempted_paths
  by _time, src_ip, user_id
| where failure_count > 10
| eval attack_type = if(unique_paths > 5, "enumeration", "brute_force")
```

### Elastic SIEM Detection Rules

```json
{
  "rule": {
    "name": "API Object Enumeration Detection",
    "description": "Detects rapid sequential access to API objects with mixed authorization results",
    "type": "threshold",
    "index": ["api-access-*"],
    "query": {
      "bool": {
        "must": [
          { "regexp": { "url.path": "/api/v[0-9]+/[a-z]+/[0-9]+" } }
        ],
        "should": [
          { "term": { "http.response.status_code": 200 } },
          { "term": { "http.response.status_code": 403 } },
          { "term": { "http.response.status_code": 401 } }
        ]
      }
    },
    "threshold": {
      "field": ["source.ip"],
      "value": 50,
      "cardinality": [
        { "field": "url.path", "value": 20 }
      ]
    },
    "schedule": { "interval": "5m" },
    "severity": "high",
    "risk_score": 73,
    "tags": ["OWASP-API1", "BOLA", "Enumeration"]
  }
}
```

### Custom Detection Script

```python
#!/usr/bin/env python3
"""API Enumeration Attack Detector

Analyzes API access logs to detect enumeration patterns
including BOLA, IDOR, and sequential ID probing.
"""

import re
import sys
import json
from collections import defaultdict
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import List, Dict, Optional

@dataclass
class AccessRecord:
    timestamp: datetime
    source_ip: str
    user_id: Optional[str]
    method: str
    path: str
    status_code: int
    object_id: Optional[str] = None

@dataclass
class EnumerationAlert:
    source_ip: str
    user_id: Optional[str]
    endpoint_pattern: str
    unique_object_ids: int
    total_requests: int
    time_window_seconds: float
    requests_per_second: float
    auth_failure_ratio: float
    severity: str
    attack_type: str
    sample_ids: List[str] = field(default_factory=list)

class EnumerationDetector:
    # Regex patterns for extracting object IDs from API paths
    ID_PATTERNS = [
        re.compile(r'/api/v\d+/(\w+)/(\d+)'),           # Numeric IDs
        re.compile(r'/api/v\d+/(\w+)/([a-f0-9\-]{36})'), # UUIDs
        re.compile(r'/api/v\d+/(\w+)/([a-zA-Z0-9]{20,})'), # Long alphanumeric IDs
    ]

    def __init__(self, time_window_minutes: int = 5,
                 min_unique_ids: int = 15,
                 max_requests_per_second: float = 5.0):
        self.time_window = timedelta(minutes=time_window_minutes)
        self.min_unique_ids = min_unique_ids
        self.max_rps = max_requests_per_second
        self.access_log: List[AccessRecord] = []

    def parse_log_line(self, line: str) -> Optional[AccessRecord]:
        """Parse a common log format line into an AccessRecord."""
        log_pattern = re.compile(
            r'(?P<ip>[\d.]+)\s+\S+\s+(?P<user>\S+)\s+'
            r'\[(?P<time>[^\]]+)\]\s+'
            r'"(?P<method>\w+)\s+(?P<path>\S+)\s+\S+"\s+'
            r'(?P<status>\d+)'
        )
        match = log_pattern.match(line)
        if not match:
            return None

        path = match.group('path')
        object_id = None
        for pattern in self.ID_PATTERNS:
            id_match = pattern.search(path)
            if id_match:
                object_id = id_match.group(2)
                break

        return AccessRecord(
            timestamp=datetime.strptime(match.group('time'), '%d/%b/%Y:%H:%M:%S %z'),
            source_ip=match.group('ip'),
            user_id=match.group('user') if match.group('user') != '-' else None,
            method=match.group('method'),
            path=path,
            status_code=int(match.group('status')),
            object_id=object_id
        )

    def analyze(self, records: List[AccessRecord]) -> List[EnumerationAlert]:
        """Analyze access records for enumeration patterns."""
        alerts = []

        # Group by source IP and endpoint pattern
        grouped = defaultdict(list)
        for record in records:
            if record.object_id:
                # Normalize endpoint by removing the specific object ID
                endpoint = re.sub(r'/[a-f0-9\-]{36}', '/{id}',
                         re.sub(r'/\d+', '/{id}', record.path))
                key = (record.source_ip, record.user_id, endpoint)
                grouped[key].append(record)

        for (src_ip, user_id, endpoint), records_group in grouped.items():
            if len(records_group) < self.min_unique_ids:
                continue

            # Sort by timestamp
            records_group.sort(key=lambda r: r.timestamp)

            # Analyze time windows
            window_start = 0
            for window_start in range(len(records_group)):
                window_records = []
                for r in records_group[window_start:]:
                    if r.timestamp - records_group[window_start].timestamp <= self.time_window:
                        window_records.append(r)

                unique_ids = set(r.object_id for r in window_records)
                if len(unique_ids) < self.min_unique_ids:
                    continue

                time_span = (window_records[-1].timestamp -
                           window_records[0].timestamp).total_seconds()
                rps = len(window_records) / max(time_span, 1)

                auth_failures = sum(1 for r in window_records
                                   if r.status_code in (401, 403))
                failure_ratio = auth_failures / len(window_records)

                # Determine severity
                if len(unique_ids) > 100:
                    severity = "critical"
                elif len(unique_ids) > 50 or failure_ratio > 0.5:
                    severity = "high"
                elif len(unique_ids) > 20:
                    severity = "medium"
                else:
                    severity = "low"

                # Determine attack type
                ids_list = sorted([r.object_id for r in window_records
                                  if r.object_id and r.object_id.isdigit()])
                is_sequential = self._check_sequential(ids_list)
                attack_type = "sequential_enumeration" if is_sequential else "random_enumeration"

                alert = EnumerationAlert(
                    source_ip=src_ip,
                    user_id=user_id,
                    endpoint_pattern=endpoint,
                    unique_object_ids=len(unique_ids),
                    total_requests=len(window_records),
                    time_window_seconds=time_span,
                    requests_per_second=round(rps, 2),
                    auth_failure_ratio=round(failure_ratio, 2),
                    severity=severity,
                    attack_type=attack_type,
                    sample_ids=list(unique_ids)[:10]
                )
                alerts.append(alert)
                break  # One alert per group

        return alerts

    def _check_sequential(self, ids: List[str]) -> bool:
        """Check if numeric IDs follow a sequential pattern."""
        if len(ids) < 5:
            return False
        try:
            numeric_ids = sorted(int(i) for i in ids)
            sequential_count = sum(
                1 for i in range(1, len(numeric_ids))
                if numeric_ids[i] - numeric_ids[i-1] <= 2
            )
            return sequential_count / len(numeric_ids) > 0.7
        except ValueError:
            return False


def main():
    detector = EnumerationDetector(
        time_window_minutes=5,
        min_unique_ids=15
    )

    log_file = sys.argv[1] if len(sys.argv) > 1 else "/var/log/api/access.log"
    records = []
    with open(log_file, 'r') as f:
        for line in f:
            record = detector.parse_log_line(line.strip())
            if record:
                records.append(record)

    alerts = detector.analyze(records)

    if alerts:
        print(f"\n[!] {len(alerts)} enumeration attack(s) detected:\n")
        for alert in alerts:
            print(f"  Source IP: {alert.source_ip}")
            print(f"  User ID: {alert.user_id}")
            print(f"  Endpoint: {alert.endpoint_pattern}")
            print(f"  Unique IDs Accessed: {alert.unique_object_ids}")
            print(f"  Requests/sec: {alert.requests_per_second}")
            print(f"  Auth Failure Ratio: {alert.auth_failure_ratio}")
            print(f"  Attack Type: {alert.attack_type}")
            print(f"  Severity: {alert.severity.upper()}")
            print(f"  Sample IDs: {alert.sample_ids}")
            print()
    else:
        print("[+] No enumeration attacks detected.")


if __name__ == "__main__":
    main()
```

## Prevention Controls

### Server-Side Authorization Enforcement

```python
# Always validate object ownership at the data layer
def get_user_order(request, order_id):
    order = Order.objects.get(id=order_id)
    if order.user_id != request.user.id:
        raise PermissionDenied("Not authorized to access this order")
    return order
```

### Use Unpredictable Identifiers

```python
import uuid

# Use UUIDs instead of sequential integers
class Order(Model):
    id = UUIDField(default=uuid.uuid4, primary_key=True)
```

### Implement Rate Limiting Per Endpoint

```yaml
# Kong rate limiting per API route
plugins:
  - name: rate-limiting
    config:
      minute: 30
      policy: redis
      limit_by: credential
```

## References

- OWASP API1:2023 Broken Object Level Authorization: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
- Traceable.ai BOLA Deep Dive: https://www.traceable.ai/blog-post/a-deep-dive-on-the-most-critical-api-vulnerability----bola-broken-object-level-authorization
- Cequence BOLA Prevention: https://www.cequence.ai/solutions/bola-and-enumeration-attack-prevention/
- Cloudflare API Shield BOLA Detection: https://community.cloudflare.com/t/api-shield-new-bola-vulnerability-detection-for-api-shield/883021
- Sycope IDOR Detection via HTTP Traffic Analysis: https://www.sycope.com/post/idor-vulnerability-how-to-detect-an-attack-on-web-applications-through-http-traffic-analysis
