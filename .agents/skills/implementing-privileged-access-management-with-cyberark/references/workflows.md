# Privileged Access Management Workflows

## Workflow 1: Privileged Credential Checkout and Use

```
User -> PVWA -> Request Credential -> Dual Control Approval -> Vault Release -> PSM Session -> Target System
```

### Steps:
1. User authenticates to PVWA with MFA
2. User requests access to privileged account
3. If dual control enabled, request routed to approver
4. Approver reviews and approves/denies request
5. Vault releases credential through PSM
6. User connects to target via PSM (never sees password)
7. Session recorded (video, keystrokes, commands)
8. On disconnect, credential checked back in
9. If one-time password mode, CPM rotates credential immediately

## Workflow 2: Automated Credential Rotation

### Steps:
1. CPM checks rotation schedule for each platform
2. CPM connects to target system using reconciliation account
3. CPM generates new password meeting complexity requirements
4. CPM changes password on target system
5. CPM updates password in vault
6. CPM verifies new credential works on target
7. If verification fails, CPM triggers reconciliation
8. Rotation event logged to audit trail
9. SIEM alert triggered on rotation failure

## Workflow 3: Privileged Account Discovery

### Steps:
1. Configure account discovery scan targets (IP ranges, domains)
2. Discovery scanner connects to targets using scanning credentials
3. Scanner identifies privileged accounts:
   - Windows: Local admins, domain admins, service accounts
   - Linux: root, sudoers, service accounts
   - Database: DBA accounts, application accounts
   - Network: admin/enable accounts on switches/routers
4. Discovered accounts compared against vault inventory
5. Unmanaged accounts flagged for review
6. Security team reviews and prioritizes onboarding
7. Approved accounts onboarded to appropriate safes
8. CPM begins credential rotation per platform policy

## Workflow 4: Break-Glass Emergency Access

### Steps:
1. Normal vault access unavailable (outage, disaster)
2. Authorized personnel retrieve break-glass media (sealed envelope, USB)
3. Break-glass credentials used to access critical systems directly
4. All actions taken with break-glass credentials manually documented
5. When vault service restored, all break-glass credentials rotated immediately
6. Break-glass media re-sealed with new credentials
7. Incident report created documenting break-glass usage
8. All actions performed during break-glass reviewed by security team

## Workflow 5: Incident Response - Compromised Privileged Account

### Steps:
1. PTA detects anomalous privileged account behavior
2. Alert generated with risk score and indicators
3. Security analyst reviews alert in PVWA/SIEM
4. If confirmed compromise:
   a. Immediately rotate compromised credential via CPM
   b. Terminate any active PSM sessions using that account
   c. Review session recordings for malicious activity
   d. Check for lateral movement using audit logs
   e. Assess blast radius of compromised privilege level
5. Forensic analysis of session recordings
6. Post-incident review and policy updates
