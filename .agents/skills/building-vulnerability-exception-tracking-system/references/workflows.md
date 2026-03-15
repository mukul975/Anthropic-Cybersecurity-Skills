# Workflows - Vulnerability Exception Tracking

## Workflow 1: Exception Request and Approval

### Steps
1. Asset owner identifies vulnerability that cannot be remediated within SLA
2. Owner submits exception request with justification and compensating controls
3. System validates request completeness and category-specific fields
4. System routes request to appropriate approver based on severity and category
5. Approver reviews justification and compensating controls
6. Approver approves, rejects, or requests additional information
7. If approved, exception is recorded with expiration date
8. Vulnerability status updated in scanner/DefectDojo to "exception_approved"
9. Audit log entry created with full approval chain

## Workflow 2: Daily Expiration Check

### Steps
1. Cron job queries all active exceptions with expires_at <= today + 14 days
2. For exceptions expiring within 14 days: send renewal reminder to requestor
3. For exceptions expiring within 7 days: send urgency reminder with escalation
4. For expired exceptions: update status to "expired", revert vulnerability to "open"
5. Send expiration notification to asset owner and security team
6. Regenerate SLA tracking to include re-opened findings

## Workflow 3: Quarterly Exception Review

### Steps
1. Generate report of all active exceptions grouped by category and severity
2. For each exception, verify compensating controls are still in place
3. Review if vendor patch has become available for "no_fix" exceptions
4. Re-assess risk rating based on current threat landscape
5. Escalate exceptions with changed risk profiles for re-approval
6. Update exception records with review notes and new risk ratings
7. Submit quarterly report to security governance committee

## Workflow 4: Compensating Control Validation

### Steps
1. For each active exception, extract listed compensating controls
2. Validate each control is still operational:
   - WAF rules: Query WAF API for rule status
   - Network segmentation: Verify firewall rules
   - Monitoring alerts: Confirm SIEM rules are active and triggering
3. Flag exceptions where compensating controls have degraded
4. Notify exception requestor and security team of control failures
5. If controls cannot be restored within 48 hours, revoke exception
