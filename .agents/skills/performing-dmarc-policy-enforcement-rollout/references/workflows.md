# Workflows: Performing DMARC Policy Enforcement Rollout

## Workflow 1: DMARC Phased Rollout

```
Week 1-2: Discovery
  |
  v
[Inventory all legitimate email sending sources]
  +-- Internal mail servers
  +-- Third-party SaaS (marketing, CRM, support)
  +-- Transactional email services
  +-- Application-generated email
  |
  v
Week 2-4: Foundation
  |
  v
[Configure SPF and DKIM for all sources]
  +-- Publish SPF record with all includes
  +-- Validate SPF under 10 lookup limit
  +-- Generate DKIM keys per sending source
  +-- Test outbound authentication
  |
  v
Week 4-6: Monitor
  |
  v
[Publish p=none DMARC record]
  +-- Collect aggregate reports for 2 weeks
  +-- Analyze: who is sending as your domain?
  +-- Fix alignment failures for legitimate sources
  +-- Identify unauthorized/spoofing sources
  |
  v
Week 6-12: Quarantine
  |
  v
[Move to p=quarantine with gradual pct increase]
  +-- pct=10 (2 weeks) -> check false positives
  +-- pct=25 (2 weeks) -> verify clean
  +-- pct=50 (1 week) -> validate stability
  +-- pct=100 (2 weeks) -> confirm all legitimate passes
  |
  v
Week 12-20: Reject
  |
  v
[Move to p=reject with gradual pct increase]
  +-- pct=10 (2 weeks) -> monitor rejections
  +-- pct=25 (2 weeks) -> verify no legitimate blocked
  +-- pct=50 (1 week) -> near full enforcement
  +-- pct=100 -> FULL ENFORCEMENT ACHIEVED
  |
  v
Ongoing: Maintenance
  +-- Monitor aggregate reports monthly
  +-- Update SPF/DKIM for new sending sources
  +-- Rotate DKIM keys annually
```

## Workflow 2: DMARC Report Analysis

```
Aggregate report received (daily XML)
  |
  v
[Parse report in DMARC analyzer]
  |
  v
[Categorize sending sources]
  +-- PASS: Legitimate, properly authenticated
  +-- FAIL (known): Legitimate source with auth issue -> FIX
  +-- FAIL (unknown): Unauthorized sender -> INVESTIGATE
  |
  v
[For each FAIL (known)]
  +-- Identify missing SPF include or DKIM config
  +-- Update DNS records
  +-- Wait for next report to confirm fix
  |
  v
[For each FAIL (unknown)]
  +-- Is it spoofing? -> Document for enforcement case
  +-- Is it shadow IT? -> Onboard or decommission
  +-- Is it forwarding? -> ARC chain may be needed
```

## Workflow 3: Emergency Rollback

```
Legitimate email being rejected (false positive detected)
  |
  v
[Immediate: Roll back pct or policy]
  +-- Reduce pct to previous stable level
  +-- OR roll back from reject to quarantine
  +-- OR roll back from quarantine to none
  |
  v
[Investigate root cause]
  +-- Check aggregate reports for failing source
  +-- Verify SPF/DKIM configuration for source
  +-- Check for forwarding or mailing list issues
  |
  v
[Fix and re-advance]
  +-- Correct authentication issue
  +-- Verify fix in next report cycle
  +-- Resume gradual pct advancement
```
