# API Reference: Shadow API Endpoint Detection

## OpenAPI 3.0 Specification Structure

### Loading Paths
```json
{
  "openapi": "3.0.0",
  "paths": {
    "/api/users": {
      "get": { "summary": "List users" },
      "post": { "summary": "Create user" }
    },
    "/api/users/{id}": {
      "get": { "summary": "Get user by ID" }
    }
  }
}
```

### Key Fields
| Field | Description |
|-------|-------------|
| `paths` | Map of URL paths to operations |
| `servers[].url` | Base URL for the API |
| `components.securitySchemes` | Authentication methods |

## Web Access Log Formats

### Apache/Nginx Combined Log
```
127.0.0.1 - frank [10/Oct/2024:13:55:36 -0700] "GET /api/users HTTP/1.1" 200 2326
```

### Regex Pattern
```python
r'(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d+)\s+(\d+)'
```

| Group | Content |
|-------|---------|
| 1 | Client IP |
| 2 | Timestamp |
| 3 | HTTP Method |
| 4 | Request Path |
| 5 | Status Code |
| 6 | Response Size |

## Path Normalization Patterns

### ID replacement
```python
re.sub(r'/\d+', '/{id}', path)                    # /users/123 -> /users/{id}
re.sub(r'/[0-9a-f]{24,}', '/{id}', path)          # MongoDB ObjectId
re.sub(r'/[0-9a-f-]{36}', '/{uuid}', path)        # UUID v4
```

## OWASP API Security Top 10 (2023)

| # | Risk | Relevance to Shadow APIs |
|---|------|--------------------------|
| API1 | Broken Object Level Auth | Shadow endpoints may lack auth |
| API2 | Broken Authentication | Undocumented auth bypass |
| API5 | Broken Function Level Auth | Admin endpoints exposed |
| API9 | Improper Inventory Management | Core shadow API risk |

## Akamai API Discovery

### List discovered APIs
```http
GET https://cloud.akamai.com/api-gateway/v1/apis/discovered
Authorization: Bearer {token}
```

## AWS API Gateway — Export API
```bash
aws apigateway get-export \
    --rest-api-id abc123 \
    --stage-name prod \
    --export-type oas30 \
    exported-api.json
```

## Burp Suite Enterprise — API Scan
```http
POST https://burp-enterprise/api/v1/scans
Content-Type: application/json

{
  "scan_type": "api_discovery",
  "target_url": "https://api.example.com",
  "openapi_spec": "https://api.example.com/openapi.json"
}
```
