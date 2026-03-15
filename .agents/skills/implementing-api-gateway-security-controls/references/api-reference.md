# API Reference: Implementing API Gateway Security Controls

## AWS API Gateway (boto3)

```python
import boto3
client = boto3.client("apigateway")
apis = client.get_rest_apis()["items"]
method = client.get_method(restApiId=api_id, resourceId=res_id, httpMethod="GET")
# Check: authorizationType, apiKeyRequired, requestValidatorId
stages = client.get_stages(restApiId=api_id)["item"]
# Check: accessLogSettings, methodSettings throttling
```

## Kong Admin API

```bash
# List services and their plugins
curl http://localhost:8001/services
curl http://localhost:8001/services/{id}/plugins

# Enable rate limiting
curl -X POST http://localhost:8001/services/{id}/plugins \
  -d "name=rate-limiting" -d "config.minute=100"

# Enable JWT auth
curl -X POST http://localhost:8001/services/{id}/plugins \
  -d "name=jwt"
```

## Security Controls Checklist

| Control | Gateway | Severity if Missing |
|---------|---------|---------------------|
| Authentication (JWT/OAuth) | All | CRITICAL |
| Rate Limiting | All | HIGH |
| Request Validation | All | MEDIUM |
| Access Logging | All | HIGH |
| TLS/mTLS | All | CRITICAL |
| CORS Policy | All | MEDIUM |
| IP Restriction | All | LOW |

## NGINX Gateway Security

```nginx
location /api/ {
    limit_req zone=api burst=20 nodelay;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_pass http://backend;
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
}
```

### References

- AWS API Gateway: https://docs.aws.amazon.com/apigateway/
- Kong Gateway: https://docs.konghq.com/gateway/
- Azure APIM: https://learn.microsoft.com/en-us/azure/api-management/
