# Container Image Scan Policy Template

## Scan Policy Configuration

### Severity Thresholds

| Environment | Block On | Alert On | Accept |
|-------------|----------|----------|--------|
| Production | Critical, High | Medium | Low, Negligible |
| Staging | Critical | High, Medium | Low, Negligible |
| Development | None | Critical, High | Medium, Low, Negligible |

### Scan Triggers

- [ ] On image build (CI pipeline)
- [ ] On image push to registry
- [ ] Before deployment to production
- [ ] Scheduled weekly rescan of deployed images
- [ ] On new vulnerability database update

### Image Inventory

| Image | Registry | Tag Policy | Last Scanned | Status |
|-------|----------|------------|--------------|--------|
| `app/frontend` | ghcr.io | Immutable digest | YYYY-MM-DD | Pass/Fail |
| `app/backend` | ghcr.io | Immutable digest | YYYY-MM-DD | Pass/Fail |
| `app/worker` | ghcr.io | Immutable digest | YYYY-MM-DD | Pass/Fail |

## Grype Configuration Template

```yaml
# .grype.yaml - Place in repository root
check-for-app-update: false
fail-on-severity: "high"
output: "json"
scope: "squashed"
quiet: false

ignore:
  # Template: Add accepted risks below
  # - vulnerability: CVE-YYYY-NNNNN
  #   reason: "Justification for accepting this risk"
  #   expires: "YYYY-MM-DD"  # Optional expiration for risk acceptance

db:
  auto-update: true
  cache-dir: "/tmp/grype-db"
  max-allowed-built-age: 120h

match:
  java:
    using-cpes: true
  python:
    using-cpes: true
  javascript:
    using-cpes: false
  stock:
    using-cpes: true
```

## Risk Acceptance Form

### Vulnerability Risk Acceptance

| Field | Value |
|-------|-------|
| CVE ID | |
| Severity | |
| Affected Package | |
| Image(s) Affected | |
| Justification | |
| Compensating Controls | |
| Approved By | |
| Approval Date | |
| Expiration Date | |

## Remediation SLA

| Severity | Remediation Timeline | Escalation |
|----------|---------------------|------------|
| Critical | 24 hours | Security Lead + Engineering VP |
| High | 7 days | Security Lead |
| Medium | 30 days | Team Lead |
| Low | 90 days | Tracked in backlog |
| Negligible | Best effort | No escalation |
