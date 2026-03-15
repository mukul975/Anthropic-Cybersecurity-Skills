# Email Authentication Implementation Template

## Domain Information
- **Domain**: [example.com]
- **DNS Provider**: [Cloudflare / Route53 / GoDaddy]
- **Email Platform**: [Google Workspace / Microsoft 365 / Postfix]
- **Implementation Date**: [YYYY-MM-DD]

## Current State Assessment
| Check | Status | Record |
|---|---|---|
| SPF | Present/Missing | |
| DKIM | Present/Missing | |
| DMARC | Present/Missing | |

## Authorized Email Senders Inventory
| Service | Purpose | SPF Include | DKIM Selector |
|---|---|---|---|
| Primary MTA | Employee email | | |
| Google Workspace | Employee email | `_spf.google.com` | `google` |
| Microsoft 365 | Employee email | `spf.protection.outlook.com` | `selector1`, `selector2` |
| SendGrid | Transactional | `sendgrid.net` | `s1`, `s2` |
| Mailchimp | Marketing | `servers.mcsv.net` | `k1` |
| Amazon SES | Notifications | `amazonses.com` | Custom |
| Salesforce | CRM emails | `_spf.salesforce.com` | Custom |

## SPF Record Design
```
v=spf1 [mechanisms] [qualifier]
```

### DNS Lookup Budget (Max 10)
| # | Mechanism | Lookups |
|---|---|---|
| 1 | | |
| 2 | | |
| Total | | /10 |

## DKIM Configuration
| Selector | Key Length | Service | DNS Record |
|---|---|---|---|
| | 2048-bit | | |

## DMARC Rollout Plan
| Phase | Policy | pct | Duration | Start Date |
|---|---|---|---|---|
| 1 - Monitor | none | 100 | 4 weeks | |
| 2 - Quarantine Low | quarantine | 10 | 2 weeks | |
| 3 - Quarantine Medium | quarantine | 50 | 2 weeks | |
| 4 - Quarantine Full | quarantine | 100 | 2 weeks | |
| 5 - Reject Low | reject | 10 | 2 weeks | |
| 6 - Reject Medium | reject | 50 | 2 weeks | |
| 7 - Reject Full | reject | 100 | Ongoing | |

## DMARC Report Monitoring
- **Aggregate reports (rua)**: `mailto:dmarc-aggregate@[domain]`
- **Forensic reports (ruf)**: `mailto:dmarc-forensic@[domain]`
- **Analysis tool**: [dmarcian / Valimail / Postmark]
- **Review frequency**: Weekly during rollout, monthly after enforcement

## Validation Checklist
- [ ] SPF record validates at mxtoolbox.com/spf.aspx
- [ ] SPF DNS lookup count is under 10
- [ ] DKIM key is 2048-bit minimum
- [ ] DKIM signature verified on test email
- [ ] DMARC record validates at mxtoolbox.com/dmarc.aspx
- [ ] Aggregate reports receiving data
- [ ] All legitimate senders pass authentication
- [ ] No false positives in quarantine/reject

## Rollback Plan
If authentication causes delivery issues:
1. Change DMARC policy back to `p=none`
2. Investigate failing sources in aggregate reports
3. Update SPF/DKIM for legitimate failing senders
4. Re-start enforcement rollout at lower pct
