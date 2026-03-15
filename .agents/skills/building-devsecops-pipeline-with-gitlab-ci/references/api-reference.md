# API Reference: GitLab CI DevSecOps Pipeline

## GitLab Security Templates
| Template | Stage |
|----------|-------|
| `Security/SAST.gitlab-ci.yml` | Static analysis |
| `Security/DAST.gitlab-ci.yml` | Dynamic testing |
| `Security/Dependency-Scanning.gitlab-ci.yml` | Dependency audit |
| `Security/Container-Scanning.gitlab-ci.yml` | Container scan |
| `Security/Secret-Detection.gitlab-ci.yml` | Secret detection |
| `Security/IaC-Scanning.gitlab-ci.yml` | IaC security |

## .gitlab-ci.yml Structure
```yaml
include:
  - template: Security/SAST.gitlab-ci.yml
  - template: Security/Secret-Detection.gitlab-ci.yml
stages:
  - build
  - test
  - security
  - deploy
variables:
  SECURE_LOG_LEVEL: info
```

## GitLab CI Lint API
```
POST /api/v4/projects/:id/ci/lint
PRIVATE-TOKEN: your-token
Body: {"content": "yaml-string"}
```

## Security Variables
| Variable | Description |
|----------|-------------|
| `SAST_DEFAULT_ANALYZERS` | Comma-separated analyzer list |
| `SAST_EXCLUDED_ANALYZERS` | Analyzers to skip |
| `CS_IMAGE` | Container image to scan |
| `DAST_WEBSITE` | Target URL for DAST |
| `SECRET_DETECTION_HISTORIC_SCAN` | Scan full history |

## Vulnerability Report API
```
GET /api/v4/projects/:id/vulnerability_findings
```

## Security Scanning Tools
| Tool | Type | Language |
|------|------|----------|
| Semgrep | SAST | Multi-language |
| Bandit | SAST | Python |
| Trivy | Container | Container images |
| Gitleaks | Secret | Git history |
| KICS | IaC | Terraform/CloudFormation |
| ZAP | DAST | Web applications |
