# Agentless Vulnerability Scan Report Template

## Scan Summary
| Field | Value |
|-------|-------|
| Scan Date | [YYYY-MM-DD] |
| Scan Method | [SSH / WinRM / Cloud Snapshot / API] |
| Total Hosts Targeted | [N] |
| Successfully Scanned | [N] |
| Failed / Unreachable | [N] |
| Total Packages Enumerated | [N] |
| Total Vulnerabilities Found | [N] |

## Host Inventory
| Hostname | IP | OS | Kernel | Packages | Vulns | Status |
|----------|----|----|--------|----------|-------|--------|
| [host] | [IP] | [OS] | [kernel] | [N] | [N] | [Success/Failed] |

## Vulnerability Summary by Severity
| Severity | Count | % | Hosts Affected |
|----------|-------|---|----------------|
| Critical | [N] | [%] | [N] |
| High | [N] | [%] | [N] |
| Medium | [N] | [%] | [N] |
| Low | [N] | [%] | [N] |

## Scan Failures
| Hostname | Error | Recommended Action |
|----------|-------|--------------------|
| [host] | [Auth failure / Timeout / Port closed] | [Fix SSH key / Open firewall / Enable WinRM] |
