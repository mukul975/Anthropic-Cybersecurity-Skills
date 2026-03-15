# Proofpoint Email Security Gateway Deployment Template

## Pre-Deployment Checklist
- [ ] Proofpoint license type confirmed (PPS / PoD)
- [ ] Current MX records documented
- [ ] All legitimate sending sources inventoried
- [ ] SPF record updated with Proofpoint include
- [ ] DKIM keys generated and DNS records published
- [ ] DMARC record configured in monitoring mode
- [ ] Firewall rules updated for Proofpoint IP ranges
- [ ] Microsoft 365 / Google Workspace connector configured

## Policy Configuration
| Policy | Scope | Action | Status |
|---|---|---|---|
| Anti-spam (inbound) | All users | Quarantine high confidence | |
| Anti-virus | All users | Block + notify admin | |
| Impostor detection | VIP list | Quarantine + SOC alert | |
| URL Defense | All users | Rewrite + sandbox at click | |
| Attachment Defense | All users | Sandbox suspicious types | |
| TRAP auto-pull | All users | Retract post-delivery threats | |
| DLP (outbound) | All users | Block + manager notify | |

## VIP Protection List
| Name | Title | Email | Protected |
|---|---|---|---|
| | CEO | | Yes |
| | CFO | | Yes |
| | CTO | | Yes |
| | VP Finance | | Yes |

## MX Record Migration
| Record Type | Priority | Old Value | New Value |
|---|---|---|---|
| MX | 10 | | {org}.mail.protection.proofpoint.com |

## Post-Deployment Validation
- [ ] Test inbound mail delivery through Proofpoint
- [ ] Verify message headers show Proofpoint processing
- [ ] Test URL Defense rewriting on inbound links
- [ ] Test Attachment Defense with EICAR test file
- [ ] Verify TRAP can retract delivered message
- [ ] Confirm quarantine digest notifications working
- [ ] Validate SPF/DKIM/DMARC pass for outbound mail
- [ ] Review false positive rate after 48 hours
