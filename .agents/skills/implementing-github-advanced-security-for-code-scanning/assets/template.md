# GHAS Code Scanning Implementation Template

## Organization Security Configuration

| Setting | Value | Notes |
|---------|-------|-------|
| Organization | `_______________` | |
| GHAS License Seats | `_______________` | Active committers |
| Default Query Suite | [ ] default [ ] security-extended [ ] security-and-quality | |
| Branch Protection Enabled | [ ] Yes [ ] No | |
| Secret Scanning Enabled | [ ] Yes [ ] No | |
| Push Protection Enabled | [ ] Yes [ ] No | |
| Dependabot Enabled | [ ] Yes [ ] No | |

## Repository Enablement Tracker

| Repository | Languages | Setup Type | Scanning Active | Open Alerts | Date Enabled |
|------------|-----------|------------|-----------------|-------------|--------------|
| | | [ ] Default [ ] Advanced | [ ] Yes [ ] No | | |
| | | [ ] Default [ ] Advanced | [ ] Yes [ ] No | | |
| | | [ ] Default [ ] Advanced | [ ] Yes [ ] No | | |

## Custom Query Pack Registry

| Pack Name | Version | Description | Target Languages |
|-----------|---------|-------------|------------------|
| | | | |

## Alert Severity Gate Configuration

| Environment | Block on Critical | Block on High | Block on Medium | Block on Low |
|-------------|-------------------|---------------|-----------------|--------------|
| Production (main) | [x] Yes | [x] Yes | [ ] Yes | [ ] No |
| Staging (develop) | [x] Yes | [ ] Yes | [ ] No | [ ] No |
| Feature branches | [x] Yes | [ ] Yes | [ ] No | [ ] No |

## Secret Scanning Custom Patterns

| Pattern Name | Regex | Description | Alert Enabled | Push Protection |
|--------------|-------|-------------|---------------|-----------------|
| | | | [ ] Yes [ ] No | [ ] Yes [ ] No |

## Weekly Security Review Checklist

- [ ] Review new critical and high severity alerts
- [ ] Check alert dismissal reasons for quality
- [ ] Verify new repositories have scanning enabled
- [ ] Review Dependabot alerts and merge security updates
- [ ] Check secret scanning alerts for exposed credentials
- [ ] Update security overview dashboard metrics
- [ ] Review MTTR trends and identify bottlenecks

## Escalation Matrix

| Alert Severity | Response SLA | Escalation Contact | Action Required |
|----------------|-------------|--------------------|-----------------|
| Critical | 24 hours | Security Lead | Immediate remediation, potential incident |
| High | 72 hours | Team Lead | Prioritize in current sprint |
| Medium | 2 weeks | Developer | Schedule for next sprint |
| Low | 30 days | Developer | Add to backlog |
