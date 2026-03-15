# Workflows - Log Source Onboarding in SIEM

## Onboarding Workflow

```
1. Request Received (ticket/email)
   |
   v
2. Discovery & Assessment (1-2 days)
   - Identify log format and volume
   - Assess security value vs cost
   - Check for existing parser
   |
   v
3. Planning (1 day)
   - Determine collection method
   - Plan network access
   - Estimate storage impact
   |
   v
4. Implementation (2-5 days)
   - Install/configure collector
   - Build/customize parser
   - Map to CIM fields
   |
   v
5. Validation (1-2 days)
   - Verify data flow
   - Check field extraction
   - Confirm CIM compliance
   - Test detection rules
   |
   v
6. Production Release (1 day)
   - Enable detection rules
   - Update dashboards
   - Document in CMDB
   - Notify SOC team
```

## Volume Estimation Formula

```
Daily Volume (GB) = EPS * Average Event Size (bytes) * 86400 / 1,073,741,824

Example:
  EPS = 100
  Avg Event Size = 500 bytes
  Daily Volume = 100 * 500 * 86400 / 1,073,741,824 = 4.03 GB/day
  Monthly Volume = 4.03 * 30 = 120.9 GB/month
```

## Cost-Value Assessment Matrix

| Security Value | Low Volume (<1GB/day) | Medium (1-10GB) | High (>10GB) |
|---|---|---|---|
| Critical | Must have | Must have | Evaluate ROI |
| High | Should have | Should have | Evaluate ROI |
| Medium | Nice to have | Evaluate ROI | Defer |
| Low | Defer | Defer | Reject |
