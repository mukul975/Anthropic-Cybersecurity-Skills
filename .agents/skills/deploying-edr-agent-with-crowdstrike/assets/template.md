# CrowdStrike Falcon EDR Deployment Template

## Deployment Information

| Field | Value |
|-------|-------|
| Falcon Tenant | |
| Customer ID (CID) | |
| Sensor Version | |
| Deployment Tool | SCCM / Intune / GPO / Ansible / Manual |
| Target Environment | Production / Staging / Dev |
| Deployment Date | |
| Deployment Lead | |

## Pre-Deployment Checklist

- [ ] Falcon Console access verified with Administrator role
- [ ] CID obtained from Sensor downloads page
- [ ] Sensor installer downloaded for all target OS platforms
- [ ] Network connectivity verified: endpoints can reach ts01-b.cloudsink.net:443
- [ ] Proxy configuration documented (if applicable)
- [ ] Prevention policies created for each endpoint group
- [ ] Sensor update policy configured (auto-update or pinned version)
- [ ] Existing AV/EDR removal plan documented
- [ ] Exclusion list prepared for known LOB applications
- [ ] Change management ticket approved

## Deployment Scope

| Endpoint Group | Count | OS | Policy | Deployment Phase |
|---------------|-------|-----|--------|-----------------|
| Workstations | | Windows 11 | WS-Prevention-L1 | Phase 1 |
| Standard Servers | | Windows Server 2022 | SRV-Prevention | Phase 2 |
| Linux Servers | | Ubuntu 22.04 | LNX-Prevention | Phase 2 |
| macOS Endpoints | | macOS Ventura | MAC-Prevention | Phase 3 |
| Critical Servers | | Mixed | CRIT-Prevention | Phase 4 |

## Policy Configuration

### Prevention Policy Settings

| Setting | Workstations | Servers | Critical |
|---------|-------------|---------|----------|
| Cloud ML | Aggressive | Moderate | Aggressive |
| Sensor ML | Moderate | Cautious | Moderate |
| On Write | Enabled | Enabled | Enabled |
| Script-based Execution | Enabled | Enabled | Enabled |
| Ransomware Protection | Enabled | Enabled | Enabled |
| Exploit Protection | Enabled | Enabled | Enabled |

### Exclusions Applied

| Path/Process | Reason | Policy Group | Approved By |
|-------------|--------|-------------|-------------|
| | | | |

## Post-Deployment Validation

- [ ] All target endpoints show "Online" in Falcon Console
- [ ] Correct prevention policy applied to each host group
- [ ] Test detection generated with CsTestDetect and visible in console
- [ ] No RFM (Reduced Functionality Mode) hosts
- [ ] No critical application performance degradation reported
- [ ] SIEM integration receiving events
- [ ] RTR access verified for IR team

## Deployment Metrics

| Metric | Target | Actual |
|--------|--------|--------|
| Coverage (% of endpoints with sensor) | 100% | |
| Online rate | >98% | |
| Sensor version compliance | >95% same version | |
| Policy assignment accuracy | 100% | |
| Mean time to deploy (per phase) | <5 business days | |

## Issues and Remediation

| Issue | Affected Hosts | Root Cause | Resolution | Status |
|-------|---------------|------------|-----------|--------|
| | | | | |

## Sign-Off

| Role | Name | Date |
|------|------|------|
| Security Engineer | | |
| IT Operations | | |
| SOC Manager | | |
