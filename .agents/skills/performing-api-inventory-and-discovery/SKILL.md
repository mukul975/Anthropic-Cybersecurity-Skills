---
name: performing-api-inventory-and-discovery
description: >
  Performs API inventory and discovery to identify all API endpoints in an organization's
  environment including documented, undocumented, shadow, zombie, and deprecated APIs. The
  tester uses passive traffic analysis, active scanning, DNS enumeration, JavaScript analysis,
  and cloud resource inventory to build a comprehensive API catalog. Maps to OWASP API9:2023
  Improper Inventory Management. Activates for requests involving API discovery, shadow API
  detection, API inventory audit, or attack surface mapping.
domain: cybersecurity
subdomain: api-security
tags: [api-security, owasp, api-discovery, shadow-api, inventory, attack-surface]
version: 1.0.0
author: mahipal
license: Apache-2.0
---
# Performing API Inventory and Discovery

## When to Use

- Mapping the complete API attack surface of an organization before a security assessment
- Identifying shadow APIs deployed by development teams without security review
- Discovering deprecated or zombie API versions that remain accessible but unmaintained
- Finding undocumented API endpoints exposed through mobile applications, SPAs, or microservices
- Building an API inventory for compliance requirements (PCI-DSS, SOC2, GDPR)

**Do not use** without written authorization. API discovery involves scanning network infrastructure and analyzing traffic.

## Prerequisites

- Written authorization specifying the target domains and network ranges
- Passive traffic capture capability (network tap, proxy, or cloud traffic mirroring)
- Active scanning tools: Amass, subfinder, httpx, and nuclei
- JavaScript analysis tools: LinkFinder, JS-Miner, or custom parsers
- Access to cloud console (AWS, Azure, GCP) for API gateway inventory
- Burp Suite Professional for passive API endpoint discovery

## Workflow

### Step 1: Passive API Discovery from Traffic Analysis

```python
import re
import json
from collections import defaultdict

# Parse HAR file from browser developer tools or proxy
def analyze_har_for_apis(har_file_path):
    """Extract API endpoints from HTTP Archive (HAR) file."""
    with open(har_file_path) as f:
        har = json.load(f)

    api_endpoints = defaultdict(lambda: {
        "methods": set(), "content_types": set(),
        "auth_types": set(), "count": 0
    })

    for entry in har["log"]["entries"]:
        url = entry["request"]["url"]
        method = entry["request"]["method"]

        # Identify API patterns
        api_patterns = [
            r'/api/', r'/v\d+/', r'/graphql', r'/rest/',
            r'/ws/', r'/rpc/', r'/grpc', r'/json',
        ]

        if any(re.search(p, url) for p in api_patterns):
            # Normalize the URL (remove query params and IDs)
            normalized = re.sub(r'\?.*$', '', url)
            normalized = re.sub(r'/\d+(/|$)', '/{id}\\1', normalized)
            normalized = re.sub(
                r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
                '/{uuid}', normalized)

            ep = api_endpoints[normalized]
            ep["methods"].add(method)
            ep["count"] += 1

            # Detect authentication type
            for header in entry["request"]["headers"]:
                name = header["name"].lower()
                if name == "authorization":
                    if "bearer" in header["value"].lower():
                        ep["auth_types"].add("Bearer/JWT")
                    elif "basic" in header["value"].lower():
                        ep["auth_types"].add("Basic")
                elif name == "x-api-key":
                    ep["auth_types"].add("API Key")

            # Detect content type
            content_type = next(
                (h["value"] for h in entry["request"]["headers"]
                 if h["name"].lower() == "content-type"), None)
            if content_type:
                ep["content_types"].add(content_type.split(";")[0])

    print(f"Discovered {len(api_endpoints)} unique API endpoints:\n")
    for url, info in sorted(api_endpoints.items()):
        methods = ", ".join(sorted(info["methods"]))
        auth = ", ".join(info["auth_types"]) or "None"
        print(f"  [{methods}] {url}")
        print(f"    Auth: {auth} | Requests: {info['count']}")

    return api_endpoints
```

### Step 2: Active API Endpoint Discovery

```bash
# DNS enumeration for API subdomains
amass enum -d example.com -o amass_results.txt
subfinder -d example.com -o subfinder_results.txt

# Filter for API-related subdomains
grep -iE '(api|rest|graphql|ws|gateway|backend|internal|staging|dev|v1|v2)' \
    amass_results.txt subfinder_results.txt | sort -u > api_subdomains.txt

# Check which subdomains are alive
cat api_subdomains.txt | httpx -status-code -content-length -title \
    -tech-detect -o live_apis.txt

# Probe common API paths on each live subdomain
cat api_subdomains.txt | while read domain; do
    for path in /api /api/v1 /api/v2 /graphql /swagger.json /openapi.json \
                /api-docs /docs /health /status /metrics /actuator; do
        curl -s -o /dev/null -w "%{http_code} %{url_effective}\n" \
            "https://${domain}${path}" 2>/dev/null | grep -v "^404"
    done
done
```

```python
import requests
import concurrent.futures

def discover_api_endpoints(base_domains):
    """Actively probe for API endpoints across discovered domains."""

    # Common API paths to test
    API_PATHS = [
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/graphql", "/gql", "/query",
        "/rest", "/json", "/rpc",
        "/swagger.json", "/swagger/v1/swagger.json",
        "/openapi.json", "/openapi.yaml", "/api-docs",
        "/docs", "/redoc", "/explorer",
        "/.well-known/openid-configuration",
        "/health", "/healthz", "/ready",
        "/status", "/info", "/version",
        "/metrics", "/prometheus",
        "/actuator", "/actuator/health", "/actuator/info",
        "/admin", "/admin/api", "/internal",
        "/debug", "/debug/vars", "/debug/pprof",
        "/ws", "/websocket", "/socket.io",
        "/grpc", "/twirp",
    ]

    discovered = []

    def check_endpoint(domain, path):
        for scheme in ["https", "http"]:
            url = f"{scheme}://{domain}{path}"
            try:
                resp = requests.get(url, timeout=5, allow_redirects=False,
                                  verify=False)
                if resp.status_code not in (404, 502, 503):
                    return {
                        "url": url,
                        "status": resp.status_code,
                        "content_type": resp.headers.get("Content-Type", ""),
                        "server": resp.headers.get("Server", ""),
                        "size": len(resp.content),
                    }
            except requests.exceptions.RequestException:
                pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {}
        for domain in base_domains:
            for path in API_PATHS:
                future = executor.submit(check_endpoint, domain, path)
                futures[future] = (domain, path)

        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                discovered.append(result)
                print(f"  [FOUND] {result['url']} -> {result['status']} ({result['content_type']})")

    return discovered
```

### Step 3: JavaScript Source Analysis for API Endpoints

```python
import re
import requests

def extract_apis_from_javascript(js_urls):
    """Extract API endpoints from JavaScript source files."""
    api_pattern = re.compile(
        r'''(?:['"`])((?:/api/|/v[0-9]+/|/graphql|/rest/)[^'"`\s<>{}]+)(?:['"`])''',
        re.IGNORECASE
    )
    url_pattern = re.compile(
        r'''(?:['"`])(https?://[a-zA-Z0-9._-]+(?:\.[a-zA-Z]{2,})+(?:/[^'"`\s<>{}]*)?)(?:['"`])'''
    )
    fetch_pattern = re.compile(
        r'''(?:fetch|axios|ajax|XMLHttpRequest|\.get|\.post|\.put|\.delete|\.patch)\s*\(\s*(?:['"`])([^'"`]+)'''
    )

    all_endpoints = set()

    for js_url in js_urls:
        try:
            resp = requests.get(js_url, timeout=10)
            content = resp.text

            # Extract relative API paths
            for match in api_pattern.findall(content):
                all_endpoints.add(("relative", match))

            # Extract absolute URLs
            for match in url_pattern.findall(content):
                if any(kw in match.lower() for kw in ["/api", "/v1", "/v2", "graphql"]):
                    all_endpoints.add(("absolute", match))

            # Extract from fetch/axios calls
            for match in fetch_pattern.findall(content):
                all_endpoints.add(("fetch", match))

        except requests.exceptions.RequestException:
            pass

    print(f"\nAPI endpoints discovered from JavaScript ({len(all_endpoints)}):")
    for source, endpoint in sorted(all_endpoints):
        print(f"  [{source}] {endpoint}")

    return all_endpoints

# Find JavaScript files from the target domain
def find_js_files(domain):
    """Discover JavaScript files from a web application."""
    resp = requests.get(f"https://{domain}", timeout=10)
    js_files = re.findall(r'src=["\']([^"\']+\.js[^"\']*)', resp.text)
    full_urls = []
    for js in js_files:
        if js.startswith("http"):
            full_urls.append(js)
        elif js.startswith("//"):
            full_urls.append(f"https:{js}")
        elif js.startswith("/"):
            full_urls.append(f"https://{domain}{js}")
    return full_urls
```

### Step 4: Cloud API Gateway Inventory

```python
import boto3

def inventory_aws_apis():
    """Inventory all APIs in AWS API Gateway."""
    apigw = boto3.client('apigateway')
    apigwv2 = boto3.client('apigatewayv2')

    apis = []

    # REST APIs (API Gateway v1)
    rest_apis = apigw.get_rest_apis()
    for api in rest_apis['items']:
        resources = apigw.get_resources(restApiId=api['id'])
        stages = apigw.get_stages(restApiId=api['id'])

        for stage in stages['item']:
            for resource in resources['items']:
                for method in resource.get('resourceMethods', {}).keys():
                    apis.append({
                        "type": "REST",
                        "name": api['name'],
                        "stage": stage['stageName'],
                        "path": resource['path'],
                        "method": method,
                        "url": f"https://{api['id']}.execute-api.{boto3.session.Session().region_name}.amazonaws.com/{stage['stageName']}{resource['path']}",
                        "created": str(api.get('createdDate', '')),
                    })

    # HTTP APIs (API Gateway v2)
    http_apis = apigwv2.get_apis()
    for api in http_apis['Items']:
        routes = apigwv2.get_routes(ApiId=api['ApiId'])
        stages = apigwv2.get_stages(ApiId=api['ApiId'])

        for route in routes['Items']:
            apis.append({
                "type": "HTTP",
                "name": api['Name'],
                "route": route['RouteKey'],
                "api_id": api['ApiId'],
                "protocol": api['ProtocolType'],
            })

    print(f"\nAWS API Inventory ({len(apis)} endpoints):")
    for api in apis:
        print(f"  [{api['type']}] {api.get('name')} - {api.get('method', '')} {api.get('path', api.get('route', ''))}")

    return apis
```

### Step 5: API Version and Shadow API Detection

```python
def detect_shadow_and_zombie_apis(discovered_endpoints, documented_endpoints):
    """Compare discovered APIs against documented inventory."""

    # Normalize endpoints for comparison
    def normalize(ep):
        ep = re.sub(r'/v\d+/', '/vX/', ep)
        ep = re.sub(r'/\d+', '/{id}', ep)
        return ep.lower().rstrip('/')

    documented_normalized = {normalize(ep) for ep in documented_endpoints}

    shadow_apis = []  # Discovered but not documented
    zombie_apis = []  # Old versions still accessible

    for ep in discovered_endpoints:
        normalized = normalize(ep["url"])

        if normalized not in documented_normalized:
            # Check if it is an old version of a documented API
            if re.search(r'/v[0-9]+/', ep["url"]):
                zombie_apis.append(ep)
            else:
                shadow_apis.append(ep)

    print(f"\nShadow APIs (undocumented): {len(shadow_apis)}")
    for api in shadow_apis:
        print(f"  [SHADOW] {api['url']} -> {api['status']}")

    print(f"\nZombie APIs (deprecated versions): {len(zombie_apis)}")
    for api in zombie_apis:
        print(f"  [ZOMBIE] {api['url']} -> {api['status']}")

    # Check if zombie APIs lack security controls
    for api in zombie_apis:
        resp = requests.get(api["url"], timeout=5)
        if resp.status_code not in (401, 403):
            print(f"  [CRITICAL] Zombie API accessible without auth: {api['url']}")

    return shadow_apis, zombie_apis
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Shadow API** | An API deployed by a development team without going through the official API management or security review process |
| **Zombie API** | A deprecated or old API version that remains accessible and running but is no longer maintained or monitored |
| **API Inventory** | A comprehensive catalog of all APIs in an organization including endpoint URLs, owners, versions, authentication methods, and data classifications |
| **Improper Inventory Management** | OWASP API9:2023 - failure to maintain an accurate API inventory, leading to unmonitored and unprotected API endpoints |
| **Attack Surface** | The total set of API endpoints, methods, and parameters that an attacker can potentially interact with |
| **API Sprawl** | The uncontrolled proliferation of APIs in an organization, often resulting from microservice adoption without centralized governance |

## Tools & Systems

- **Amass**: OWASP tool for attack surface mapping through DNS enumeration, web scraping, and API discovery
- **httpx**: Fast HTTP probing tool for validating discovered domains and identifying live API endpoints
- **nuclei**: Template-based scanner for detecting exposed API documentation, debug endpoints, and misconfigured services
- **Swagger UI Detector**: Tool for finding exposed Swagger/OpenAPI documentation endpoints across the organization
- **Akto**: API security platform that discovers APIs through traffic analysis and maintains an automated inventory

## Common Scenarios

### Scenario: Enterprise API Attack Surface Assessment

**Context**: A large enterprise has 200+ development teams using microservices. The security team suspects many undocumented APIs are exposed to the internet. A comprehensive API inventory is needed for a security audit.

**Approach**:
1. DNS enumeration discovers 340 subdomains, 45 contain API-related keywords (api, rest, gateway, backend)
2. Active probing of all subdomains with API path wordlist discovers 127 live API endpoints
3. JavaScript analysis of the main web application reveals 34 API endpoints, 8 of which point to undocumented internal services
4. AWS API Gateway inventory shows 67 REST APIs and 23 HTTP APIs across 12 accounts
5. Cross-referencing against the official API catalog: 31 shadow APIs (undocumented), 14 zombie APIs (deprecated versions)
6. 3 zombie APIs have no authentication, exposing customer data through endpoints that were supposed to be decommissioned
7. 2 shadow APIs expose internal admin functions to the internet without authorization

**Pitfalls**:
- Only checking documented API endpoints and missing shadow APIs deployed outside the API gateway
- Not scanning JavaScript bundles where frontend applications hardcode API endpoint URLs
- Missing APIs behind non-standard ports or subpaths
- Not checking for multiple API versions where older versions may lack security controls
- Assuming all APIs go through the API gateway when some may be directly exposed

## Output Format

```
## API Inventory and Discovery Report

**Organization**: Example Corp
**Assessment Date**: 2024-12-15
**Domains Scanned**: 340

### Summary

| Category | Count |
|----------|-------|
| Total APIs Discovered | 127 |
| Documented APIs | 82 |
| Shadow APIs (undocumented) | 31 |
| Zombie APIs (deprecated) | 14 |
| APIs Without Authentication | 8 |
| APIs Exposing Sensitive Data | 5 |

### Critical Findings

1. **Zombie API**: api-v1.example.com/api/v1/users - Deprecated in 2022,
   still accessible, no authentication required, returns full user data
2. **Shadow API**: internal-tools.example.com/api/admin - Admin functions
   exposed to internet without authorization
3. **Exposed Documentation**: 12 Swagger UI instances accessible publicly,
   revealing full API schema and endpoint details
```
