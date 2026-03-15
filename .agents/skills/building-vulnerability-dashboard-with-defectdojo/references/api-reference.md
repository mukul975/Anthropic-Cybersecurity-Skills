# API Reference: Vulnerability Dashboard with DefectDojo

## Authentication
```bash
# Token-based auth
curl -H "Authorization: Token $DEFECTDOJO_TOKEN" \
  "http://localhost:8080/api/v2/findings/"
```

## Core Endpoints
| Method | Endpoint | Description |
|--------|----------|------------|
| GET | /api/v2/findings/ | List vulnerability findings |
| GET | /api/v2/products/ | List products |
| GET | /api/v2/engagements/ | List engagements |
| GET | /api/v2/tests/ | List tests |
| POST | /api/v2/import-scan/ | Import scanner results |
| POST | /api/v2/reimport-scan/ | Re-import/update results |

## Finding Query Parameters
| Parameter | Type | Description |
|-----------|------|------------|
| severity | string | Critical, High, Medium, Low, Info |
| active | boolean | Only active findings |
| verified | boolean | Only verified findings |
| duplicate | boolean | Include duplicates |
| product | integer | Filter by product ID |
| limit | integer | Results per page |
| offset | integer | Pagination offset |

## Import Scan
```bash
curl -X POST "http://localhost:8080/api/v2/import-scan/" \
  -H "Authorization: Token $TOKEN" \
  -F "product=1" \
  -F "engagement=1" \
  -F "scan_type=Nessus Scan" \
  -F "file=@nessus_export.csv" \
  -F "active=true" \
  -F "verified=false"
```

## Supported Scan Types (partial)
| Scanner | scan_type Value |
|---------|----------------|
| Nessus | Nessus Scan |
| Qualys | Qualys Scan |
| Burp Suite | Burp REST API |
| OWASP ZAP | ZAP Scan |
| Trivy | Trivy Scan |
| Snyk | Snyk Scan |
| Semgrep | Semgrep JSON Report |
| Nuclei | Nuclei Scan |
| Checkov | Checkov Scan |
| SARIF | SARIF |

## Python Client
```python
import requests

class DefectDojoClient:
    def __init__(self, url, token):
        self.url = url.rstrip("/")
        self.headers = {"Authorization": "Token " + token}

    def get_findings(self, **params):
        return requests.get(
            f"{self.url}/api/v2/findings/",
            headers=self.headers, params=params
        ).json()
```
