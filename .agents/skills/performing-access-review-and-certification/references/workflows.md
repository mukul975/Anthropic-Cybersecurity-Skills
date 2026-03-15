# Access Review and Certification Workflows

## Workflow 1: Quarterly Access Review Campaign

### Timeline:
- Week 1: Data collection and campaign configuration
- Week 2-4: Active review period
- Week 5: Escalation for non-responsive reviewers
- Week 6: Hard close and remediation initiation
- Week 7-8: Remediation execution and verification
- Week 8: Campaign closure and reporting

### Steps:
1. Extract entitlement data from all in-scope systems
2. Correlate with HR data for active/inactive status
3. Calculate risk scores for each user-entitlement pair
4. Assign reviewers based on reviewer model
5. Launch campaign with notifications
6. Monitor completion daily, send reminders at 50% and 75% of timeline
7. Escalate to VP level at deadline for incomplete reviews
8. Force-close with auto-revoke or manager-override at hard deadline
9. Process revocations through ticketing system
10. Verify revocations completed in target systems
11. Generate compliance report and evidence package

## Workflow 2: Triggered Access Review (Role Change)

### Steps:
1. HR system notifies of employee role change (transfer, promotion)
2. System identifies current access vs. new role entitlements
3. Birthright access for new role automatically provisioned
4. Legacy access flagged for new manager review
5. New manager certifies which legacy access to retain/revoke
6. Retained access documented with justification
7. Revoked access removed within SLA

## Workflow 3: Privileged Access Micro-Certification

### Steps:
1. Weekly extraction of privileged entitlements
2. Privileged access grouped by system owner
3. System owner reviews new privileged access grants since last certification
4. Each privileged entitlement requires explicit approval with justification
5. Non-certified privileged access auto-revoked after 48 hours
6. Results forwarded to security team for trending

## Workflow 4: SOD Violation Detection and Resolution

### Steps:
1. Define SOD rule matrix (e.g., AP create vs. AP approve)
2. Scan entitlements against SOD rules
3. Flag violations with risk level
4. Route violations to compliance team
5. Compliance team evaluates: revoke access or approve compensating control
6. If compensating control: document control, set review frequency, assign monitor
7. If revoke: process access removal and verify
