# GitLab DevSecOps Pipeline Implementation Template

## Pipeline Security Scanner Checklist

| Scanner | Enabled | Template Included | Threshold Set | Blocking |
|---------|---------|-------------------|---------------|----------|
| SAST | [ ] | [ ] | Severity: _____ | [ ] |
| DAST | [ ] | [ ] | Severity: _____ | [ ] |
| Container Scanning | [ ] | [ ] | Severity: _____ | [ ] |
| Dependency Scanning | [ ] | [ ] | Severity: _____ | [ ] |
| Secret Detection | [ ] | [ ] | N/A | [ ] |
| License Scanning | [ ] | [ ] | Policy: _____ | [ ] |

## Security Policy Configuration

| Policy Type | Name | Scope | Enforcement |
|-------------|------|-------|-------------|
| Scan Execution | | [ ] All branches [ ] Default only | [ ] Required |
| MR Approval | | Severity trigger: _____ | Approvers: _____ |

## Environment-Specific DAST Targets

| Environment | URL | Auth Method | Scan Type | Schedule |
|-------------|-----|-------------|-----------|----------|
| Staging | | [ ] None [ ] Token [ ] Cookie | [ ] Passive [ ] Full | |
| Pre-production | | [ ] None [ ] Token [ ] Cookie | [ ] Passive [ ] Full | |

## Vulnerability SLA Targets

| Severity | Detection to Triage | Triage to Fix | Total SLA |
|----------|--------------------|--------------|-----------|
| Critical | 4 hours | 24 hours | 48 hours |
| High | 24 hours | 5 days | 7 days |
| Medium | 48 hours | 14 days | 30 days |
| Low | 1 week | 30 days | 90 days |
