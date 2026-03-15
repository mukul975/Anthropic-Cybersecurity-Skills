# Just-In-Time Access Provisioning Workflows

## Workflow 1: Standard JIT Access Request

### Steps:
1. User submits access request via self-service portal
2. Request includes: target resource, duration, business justification
3. System calculates risk score based on resource sensitivity and user context
4. Risk-based routing:
   - Low risk (< 1 hr, non-privileged): Auto-approve
   - Medium risk: Route to resource owner for approval
   - High risk (privileged, production): Dual approval required
5. Approver notified via email/Slack/Teams
6. Approver reviews and approves/denies with comments
7. On approval: system provisions access with time-bound constraint
8. User notified of access grant with expiration time
9. At expiration: system automatically revokes access
10. All events logged for audit trail

## Workflow 2: Emergency JIT Access (Break-Glass)

### Steps:
1. User declares emergency and requests immediate access
2. System grants access immediately without pre-approval
3. Access limited to shorter maximum duration (e.g., 2 hours)
4. Security team notified of emergency access grant
5. User must provide justification within 24 hours
6. Manager and security team perform post-facto review
7. If review finds access unjustified: security incident opened
8. All emergency access events flagged in audit reports

## Workflow 3: Privileged Elevation with PAM Integration

### Steps:
1. User requests privilege elevation through JIT portal
2. Approval obtained per risk-based workflow
3. JIT system triggers PAM credential checkout
4. PSM session initiated with time-bound credential
5. User performs privileged operations via isolated session
6. Session recorded for audit
7. At expiration: session terminated, credential checked in, password rotated
8. JIT access record closed

## Workflow 4: Vendor/Third-Party JIT Access

### Steps:
1. Internal sponsor submits access request on behalf of vendor
2. Request includes: vendor identity, scope, duration, project reference
3. Dual approval required (sponsor manager + security)
4. Temporary account created with MFA enrollment
5. Access restricted to specified resources only
6. Network access limited to authorized segments
7. Session monitoring enabled
8. Account deactivated at expiration
9. Account deleted after 30-day retention period
