# Authenticated Vulnerability Scan Report Template

## Scan Configuration
| Field | Value |
|-------|-------|
| Scan Date | [YYYY-MM-DD] |
| Scanner | [Nessus/Qualys/OpenVAS] |
| Scan Type | Authenticated (Credentialed) |
| Targets | [TARGET_RANGE] |
| Credential Types | SSH / WinRM / SMB / SNMPv3 |

## Credential Success Summary
| Protocol | Targets | Success | Failed | Rate |
|----------|---------|---------|--------|------|
| SSH | [N] | [N] | [N] | [%] |
| WinRM | [N] | [N] | [N] | [%] |
| SMB | [N] | [N] | [N] | [%] |
| SNMPv3 | [N] | [N] | [N] | [%] |
| **Total** | **[N]** | **[N]** | **[N]** | **[%]** |

## Findings Summary (Authenticated vs Unauthenticated Comparison)
| Severity | Auth Scan | Unauth Scan | Delta |
|----------|-----------|-------------|-------|
| Critical | [N] | [N] | [+N] |
| High | [N] | [N] | [+N] |
| Medium | [N] | [N] | [+N] |
| Low | [N] | [N] | [+N] |

## Authentication Failures
| Host | Protocol | Failure Reason | Remediation |
|------|----------|---------------|-------------|
| [IP] | [SSH/WinRM] | [reason] | [action] |

## Recommendations
1. **Credential Coverage**: [Current %] - Target: >95%
2. **Failed Hosts**: Investigate [N] authentication failures
3. **Privilege Gaps**: [N] hosts missing sudo/admin elevation
4. **Credential Rotation**: Next rotation due [DATE]
