# API Reference: OWASP ZAP DAST Pipeline Integration

## ZAP Docker Scan Scripts

### Baseline Scan (Passive Only)
```bash
docker run --rm -v $(pwd):/zap/wrk zaproxy/zap-stable \
  zap-baseline.py -t https://target.com -J report.json -I
```

### Full Scan (Active + Passive)
```bash
docker run --rm -v $(pwd):/zap/wrk zaproxy/zap-stable \
  zap-full-scan.py -t https://target.com -J report.json -m 5 -I
```

### API Scan (OpenAPI/Swagger)
```bash
docker run --rm -v $(pwd):/zap/wrk zaproxy/zap-stable \
  zap-api-scan.py -t https://target.com/openapi.json -f openapi -J report.json
```

### Return Codes
| Code | Meaning |
|------|---------|
| 0 | No alerts above threshold |
| 1 | Warnings found |
| 2 | Failures found |

### Common Flags
| Flag | Description |
|------|-------------|
| `-t` | Target URL |
| `-J` | JSON report filename |
| `-m` | Max scan duration in minutes |
| `-I` | Do not return failure on warnings |
| `-f` | API spec format (`openapi`, `soap`) |
| `-r` | HTML report filename |
| `-c` | Config file for rule tuning |

## ZAP JSON Report Structure
```json
{"site": [{"alerts": [{"name": "...", "riskdesc": "High (Medium)",
  "cweid": "79", "count": 3, "solution": "..."}]}]}
```

### Risk Levels
| Level | Action |
|-------|--------|
| High | Block deployment |
| Medium | Require review |
| Low | Track as tech debt |
| Informational | Log only |

## References
- ZAP Docker: https://www.zaproxy.org/docs/docker/
- ZAP Automation: https://www.zaproxy.org/docs/automate/
