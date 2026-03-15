# DMARC Policy Enforcement Rollout Template

## Sending Source Inventory
| Source | Type | SPF Included | DKIM Configured | Status |
|---|---|---|---|---|
| Exchange Online | Primary mail | include:spf.protection.outlook.com | selector1/selector2 | |
| SendGrid | Transactional | include:sendgrid.net | sg._domainkey | |
| Mailchimp | Marketing | include:servers.mcsv.net | k1._domainkey | |
| Salesforce | CRM | include:_spf.salesforce.com | salesforce._domainkey | |

## DMARC Rollout Schedule
| Week | Phase | Record Change | Monitoring |
|---|---|---|---|
| 1-2 | Discovery | (no DMARC yet) | Audit sending sources |
| 3-4 | SPF/DKIM | (configure auth) | Test outbound auth |
| 5-6 | Monitor | p=none; rua=... | Daily report review |
| 7-8 | Quarantine 10% | p=quarantine; pct=10 | Check false positives |
| 9-10 | Quarantine 50% | p=quarantine; pct=50 | Validate stability |
| 11-12 | Quarantine 100% | p=quarantine; pct=100 | Confirm all passing |
| 13-14 | Reject 10% | p=reject; pct=10 | Monitor rejections |
| 15-16 | Reject 50% | p=reject; pct=50 | Near full enforcement |
| 17-20 | Reject 100% | p=reject | FULL ENFORCEMENT |

## Emergency Rollback Procedure
- [ ] Reduce pct to previous stable value OR
- [ ] Revert policy to previous level (reject->quarantine or quarantine->none)
- [ ] Investigate failing source in DMARC reports
- [ ] Fix authentication issue
- [ ] Resume rollout after confirmation

## Sign-off
| Milestone | Approved By | Date |
|---|---|---|
| SPF/DKIM configured | | |
| p=none deployed | | |
| p=quarantine 100% | | |
| p=reject 100% | | |
