---
name: detecting-shadow-api-endpoints
description: Discover and inventory shadow API endpoints that operate outside documented specifications using traffic analysis, code scanning, and API discovery platforms.
domain: cybersecurity
subdomain: api-security
tags: [api-security, shadow-apis, api-discovery, undocumented-apis, zombie-apis, api-inventory, attack-surface-management, api-governance]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Detecting Shadow API Endpoints

## Overview

Shadow APIs are API endpoints operating within an organization's environment that are not tracked, documented, or secured. They emerge from rapid development cycles, forgotten test environments, deprecated API versions left running, third-party integrations, or developer side projects deployed without governance. Shadow APIs bypass authentication and monitoring controls, creating hidden entry points for attackers. Studies show that up to 30% of API endpoints in large organizations are undocumented, making shadow API detection a critical component of API security posture management.

## Prerequisites

- API gateway or reverse proxy with traffic logging (Kong, AWS API Gateway, Envoy)
- Network traffic capture capability (packet broker, port mirroring)
- Access to source code repositories and CI/CD pipeline configurations
- Cloud provider access for configuration scanning (AWS, GCP, Azure)
- API documentation inventory (OpenAPI specs, Swagger docs)
- Python 3.8+ for custom discovery tooling

## Detection Methods

### 1. Traffic Analysis and Comparison

Compare live API traffic against documented OpenAPI specifications to identify undocumented endpoints:

```python
#!/usr/bin/env python3
"""Shadow API Endpoint Detector

Compares observed API traffic patterns against documented
OpenAPI specifications to identify undocumented (shadow) endpoints.
"""

import json
import re
import yaml
import sys
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, field

@dataclass
class DiscoveredEndpoint:
    method: str
    path_pattern: str
    first_seen: str
    last_seen: str
    request_count: int
    source_ips: Set[str] = field(default_factory=set)
    status_codes: Set[int] = field(default_factory=set)
    has_auth_header: bool = False
    documented: bool = False

class ShadowAPIDetector:
    # Common patterns for parameterized path segments
    PARAM_PATTERNS = [
        (re.compile(r'/\d+'), '/{id}'),
        (re.compile(r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'), '/{uuid}'),
        (re.compile(r'/[a-zA-Z0-9]{20,40}'), '/{token}'),
    ]

    def __init__(self):
        self.documented_endpoints: Set[Tuple[str, str]] = set()
        self.discovered_endpoints: Dict[Tuple[str, str], DiscoveredEndpoint] = {}

    def load_openapi_spec(self, spec_path: str):
        """Load documented endpoints from OpenAPI specification."""
        with open(spec_path, 'r') as f:
            if spec_path.endswith('.json'):
                spec = json.load(f)
            else:
                spec = yaml.safe_load(f)

        paths = spec.get('paths', {})
        for path, methods in paths.items():
            # Normalize OpenAPI path parameters
            normalized_path = re.sub(r'\{[^}]+\}', '{id}', path)
            for method in methods:
                if method.upper() in ('GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'):
                    self.documented_endpoints.add((method.upper(), normalized_path))

        print(f"Loaded {len(self.documented_endpoints)} documented endpoints from {spec_path}")

    def normalize_path(self, path: str) -> str:
        """Normalize an observed path by replacing dynamic segments with placeholders."""
        # Remove query string
        path = path.split('?')[0]

        for pattern, replacement in self.PARAM_PATTERNS:
            path = pattern.sub(replacement, path)

        return path

    def process_access_log(self, log_file: str, log_format: str = "common"):
        """Process API access logs to discover endpoints."""
        patterns = {
            "common": re.compile(
                r'(?P<ip>[\d.]+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
                r'"(?P<method>\w+)\s+(?P<path>\S+)\s+\S+"\s+(?P<status>\d+)'
            ),
            "json": None  # Handle JSON logs separately
        }

        with open(log_file, 'r') as f:
            for line in f:
                if log_format == "json":
                    try:
                        entry = json.loads(line)
                        method = entry.get('method', entry.get('http_method', ''))
                        path = entry.get('path', entry.get('uri', ''))
                        status = int(entry.get('status', entry.get('status_code', 0)))
                        ip = entry.get('remote_addr', entry.get('client_ip', ''))
                        timestamp = entry.get('timestamp', entry.get('@timestamp', ''))
                        has_auth = bool(entry.get('authorization', entry.get('auth_header', '')))
                    except json.JSONDecodeError:
                        continue
                else:
                    match = patterns[log_format].match(line)
                    if not match:
                        continue
                    method = match.group('method')
                    path = match.group('path')
                    status = int(match.group('status'))
                    ip = match.group('ip')
                    timestamp = match.group('time')
                    has_auth = 'Authorization' in line

                # Only process API paths
                if not path.startswith('/api') and not path.startswith('/v'):
                    continue

                normalized = self.normalize_path(path)
                key = (method.upper(), normalized)

                if key not in self.discovered_endpoints:
                    self.discovered_endpoints[key] = DiscoveredEndpoint(
                        method=method.upper(),
                        path_pattern=normalized,
                        first_seen=timestamp,
                        last_seen=timestamp,
                        request_count=0,
                        documented=(key in self.documented_endpoints)
                    )

                endpoint = self.discovered_endpoints[key]
                endpoint.request_count += 1
                endpoint.last_seen = timestamp
                endpoint.source_ips.add(ip)
                endpoint.status_codes.add(status)
                if has_auth:
                    endpoint.has_auth_header = True

    def identify_shadow_apis(self) -> List[DiscoveredEndpoint]:
        """Identify endpoints that are not in the documented specification."""
        shadows = []
        for key, endpoint in self.discovered_endpoints.items():
            if not endpoint.documented:
                shadows.append(endpoint)

        # Sort by request count descending (most active shadows first)
        shadows.sort(key=lambda e: e.request_count, reverse=True)
        return shadows

    def classify_risk(self, endpoint: DiscoveredEndpoint) -> str:
        """Classify the risk level of a shadow endpoint."""
        risk_score = 0

        # No authentication observed
        if not endpoint.has_auth_header:
            risk_score += 3

        # High traffic volume
        if endpoint.request_count > 1000:
            risk_score += 2
        elif endpoint.request_count > 100:
            risk_score += 1

        # Multiple source IPs (wider exposure)
        if len(endpoint.source_ips) > 10:
            risk_score += 2

        # Successful responses (endpoint is functional)
        if 200 in endpoint.status_codes or 201 in endpoint.status_codes:
            risk_score += 1

        # Write operations are higher risk
        if endpoint.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
            risk_score += 2

        # Sensitive path patterns
        sensitive_patterns = ['admin', 'internal', 'debug', 'test', 'backup',
                            'config', 'health', 'metrics', 'graphql', 'console']
        for pattern in sensitive_patterns:
            if pattern in endpoint.path_pattern.lower():
                risk_score += 3
                break

        if risk_score >= 8:
            return "CRITICAL"
        elif risk_score >= 5:
            return "HIGH"
        elif risk_score >= 3:
            return "MEDIUM"
        return "LOW"

    def generate_report(self) -> dict:
        """Generate a comprehensive shadow API discovery report."""
        shadows = self.identify_shadow_apis()
        total_documented = len(self.documented_endpoints)
        total_discovered = len(self.discovered_endpoints)

        report = {
            "scan_date": datetime.now().isoformat(),
            "summary": {
                "documented_endpoints": total_documented,
                "total_discovered_endpoints": total_discovered,
                "shadow_endpoints": len(shadows),
                "shadow_ratio": f"{len(shadows)/max(total_discovered,1)*100:.1f}%",
            },
            "shadow_endpoints": []
        }

        for endpoint in shadows:
            risk = self.classify_risk(endpoint)
            report["shadow_endpoints"].append({
                "method": endpoint.method,
                "path": endpoint.path_pattern,
                "risk_level": risk,
                "request_count": endpoint.request_count,
                "unique_sources": len(endpoint.source_ips),
                "authenticated": endpoint.has_auth_header,
                "status_codes": sorted(endpoint.status_codes),
                "first_seen": endpoint.first_seen,
                "last_seen": endpoint.last_seen,
            })

        return report


def main():
    detector = ShadowAPIDetector()

    # Load documented API specifications
    spec_files = sys.argv[1:] if len(sys.argv) > 1 else ["openapi.yaml"]
    for spec in spec_files:
        if spec.endswith(('.yaml', '.yml', '.json')):
            detector.load_openapi_spec(spec)

    # Process access logs
    detector.process_access_log("/var/log/api/access.log")

    report = detector.generate_report()

    print(f"\n{'='*60}")
    print(f"SHADOW API DISCOVERY REPORT")
    print(f"{'='*60}")
    print(f"Documented: {report['summary']['documented_endpoints']}")
    print(f"Discovered: {report['summary']['total_discovered_endpoints']}")
    print(f"Shadow: {report['summary']['shadow_endpoints']} ({report['summary']['shadow_ratio']})")
    print()

    for ep in report["shadow_endpoints"]:
        risk_marker = {"CRITICAL": "[!!!]", "HIGH": "[!!]", "MEDIUM": "[!]", "LOW": "[.]"}
        print(f"  {risk_marker.get(ep['risk_level'], '[?]')} {ep['method']} {ep['path']}")
        print(f"      Risk: {ep['risk_level']} | Requests: {ep['request_count']} | Auth: {ep['authenticated']}")

    # Save full report
    with open("shadow_api_report.json", "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\nFull report saved to shadow_api_report.json")


if __name__ == "__main__":
    main()
```

### 2. Cloud Configuration Scanning

```bash
# AWS: Discover API Gateway endpoints not in documentation
aws apigateway get-rest-apis --query 'items[*].[name,id]' --output table

# List all routes for each API
aws apigatewayv2 get-apis --query 'Items[*].[Name,ApiId,ProtocolType]' --output table

# AWS Lambda function URLs (potential shadow APIs)
aws lambda list-function-url-configs --function-name "*" 2>/dev/null

# Find ALB listener rules routing to undocumented backends
aws elbv2 describe-rules --listener-arn $LISTENER_ARN \
  --query 'Rules[*].[Priority,Conditions[0].Values[0],Actions[0].TargetGroupArn]'
```

### 3. Source Code Repository Mining

```bash
# Search for undocumented route definitions in source code
# Express.js routes
grep -rn "app\.\(get\|post\|put\|delete\|patch\)" --include="*.js" --include="*.ts" src/

# Flask/Django routes
grep -rn "@app\.route\|@api\.route\|path(" --include="*.py" src/

# Spring Boot endpoints
grep -rn "@\(Get\|Post\|Put\|Delete\|Patch\)Mapping\|@RequestMapping" --include="*.java" src/

# Compare found routes against OpenAPI specification
diff <(grep -roh "'/api/[^']*'" src/ | sort -u) \
     <(yq '.paths | keys[]' openapi.yaml | sort -u)
```

## Prevention and Governance

### API Registration Gateway Policy

```yaml
# Kong plugin configuration - reject unregistered routes
plugins:
  - name: request-validator
    config:
      allowed_content_types:
        - application/json
      body_schema: null
  - name: pre-function
    config:
      access:
        - |
          -- Block requests to unregistered endpoints
          local registered = kong.cache:get("registered_endpoints")
          local path = kong.request.get_path()
          local method = kong.request.get_method()
          local key = method .. ":" .. path
          if not registered[key] then
            kong.log.warn("Shadow API access attempt: ", key)
            return kong.response.exit(404, {error = "Endpoint not registered"})
          end
```

## References

- APIsec Shadow API Best Practices: https://www.apisec.ai/blog/secure-your-shadow-apis-best-practices-for-api-discovery
- Wiz Shadow API Guide: https://www.wiz.io/academy/api-security/shadow-api
- Checkmarx Shadow and Zombie APIs: https://checkmarx.com/learn/api-security/shadow-zombie-apis-undocumented-api-vulnerabilities-threaten-security-posture/
- Treblle Shadow API Tools: https://treblle.com/blog/top-tools-for-detecting-shadow-apis-and-how-treblle-differs
- SecureLayer7 Shadow APIs: https://blog.securelayer7.net/shadow-apis-explained-risks-detection-and-prevention/
