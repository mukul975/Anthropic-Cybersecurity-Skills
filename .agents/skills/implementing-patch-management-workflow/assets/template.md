# Patch Management Report Template

## Patch Cycle Summary
| Field | Value |
|-------|-------|
| Patch Cycle | [Month Year] |
| Deployment Window | [Start] to [End] |
| Patches Deployed | [N] security, [N] critical, [N] feature |

## Compliance Metrics
| Metric | Value | Target | Status |
|--------|-------|--------|--------|
| Overall Compliance | [%] | 95% | [Met/Not Met] |
| Critical Patch Compliance | [%] | 100% | [Met/Not Met] |
| Mean Time to Patch (Critical) | [N days] | 48 hours | [Met/Not Met] |
| Mean Time to Patch (High) | [N days] | 7 days | [Met/Not Met] |
| Rollback Rate | [%] | <2% | [Met/Not Met] |

## Deployment Results by Ring
| Ring | Hosts | Success | Failed | Rollback | Duration |
|------|-------|---------|--------|----------|----------|
| Ring 0 (Lab) | [N] | [N] | [N] | [N] | [Nh] |
| Ring 1 (Pilot) | [N] | [N] | [N] | [N] | [Nh] |
| Ring 2 (General) | [N] | [N] | [N] | [N] | [Nh] |
| Ring 3 (Critical) | [N] | [N] | [N] | [N] | [Nh] |

## Exceptions and Deferrals
| Host/Group | Patch | Reason | Approved By | Expiry |
|-----------|-------|--------|-------------|--------|
| [host] | [KB/CVE] | [reason] | [approver] | [date] |
