# DCSync Attack Detection Hunt Template

## Hunt Metadata
| Field | Value |
|-------|-------|
| Hunt ID | TH-DCSYNC-YYYY-MM-DD-NNN |
| Analyst | |
| Date | |
| Status | [ ] In Progress / [ ] Complete |

## Hypothesis
> An adversary with elevated AD privileges is performing DCSync to extract password hashes from Active Directory by replicating directory data from a non-domain-controller machine.

## Pre-Hunt Checklist
- [ ] Event ID 4662 audit policy enabled on all DCs
- [ ] SACL configured on domain root object
- [ ] Domain controller inventory documented
- [ ] Known service accounts with replication rights documented
- [ ] Azure AD Connect accounts identified (if hybrid)

## DCSync Detection Findings

| # | Timestamp | Subject Account | Source Machine | Target DC | Replication Rights | Severity |
|---|-----------|-----------------|----------------|-----------|-------------------|----------|
| 1 | | | | | | |

## Accounts with Replication Rights Audit

| Account | Type | Rights | Legitimate | Justification |
|---------|------|--------|-----------|---------------|
| | User/Service/Computer | Get-Changes / Get-Changes-All | Yes/No | |

## Post-DCSync Impact Assessment

| Check | Status | Notes |
|-------|--------|-------|
| KRBTGT hash potentially compromised | | |
| Domain Admin hashes extracted | | |
| Service account credentials at risk | | |
| Golden Ticket creation possible | | |

## Response Actions
1. **Disable**: [Compromised accounts]
2. **Reset**: [KRBTGT password -- twice, 12 hours apart]
3. **Revoke**: [Unauthorized replication rights]
4. **Investigate**: [Source machine forensics]
5. **Monitor**: [Subsequent credential abuse attempts]
