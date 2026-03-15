# API Reference: SSRF Vulnerability Testing

## Cloud Metadata Endpoints
| Cloud | URL | Headers |
|-------|-----|---------|
| AWS IMDSv1 | `http://169.254.169.254/latest/meta-data/` | None |
| AWS IMDSv2 | `http://169.254.169.254/latest/api/token` | `X-aws-ec2-metadata-token-ttl-seconds: 21600` |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` | `Metadata-Flavor: Google` |
| Azure | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` | `Metadata: true` |

## IP Encoding Bypass Techniques
| Technique | 169.254.169.254 Encoded |
|-----------|------------------------|
| Decimal | `2852039166` |
| Hex | `0xa9fea9fe` |
| Octal | `0251.0376.0251.0376` |
| IPv6 mapped | `[::ffff:169.254.169.254]` |
| Shortened | `169.254.169.254` -> `0` (localhost) |

## Python requests
```python
import requests
resp = requests.get(url, timeout=10, allow_redirects=False, verify=False)
resp.status_code   # HTTP status
resp.text          # Response body
len(resp.content)  # Response size
resp.headers       # Response headers
```

## SSRF Impact Levels
| Access | Impact | Severity |
|--------|--------|----------|
| Cloud metadata credentials | Full account compromise | Critical |
| Internal service access | Lateral movement | High |
| Local file read (file://) | Information disclosure | High |
| Internal port scan | Reconnaissance | Medium |

## MITRE ATT&CK
- T1190 - Exploit Public-Facing Application
- T1552.005 - Cloud Instance Metadata API
