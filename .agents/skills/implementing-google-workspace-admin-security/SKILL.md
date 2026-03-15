---
name: implementing-google-workspace-admin-security
description: >
  Implements comprehensive Google Workspace security hardening including admin console
  configuration, phishing-resistant MFA enforcement, DLP policies, email authentication
  (SPF/DKIM/DMARC), OAuth app control, and external sharing restrictions.
  Activates for requests involving Google Workspace hardening, G Suite security configuration,
  or cloud office security administration.
domain: cybersecurity
subdomain: identity-access-management
tags: [Google-Workspace, admin-security, MFA, DMARC, DLP, OAuth, cloud-security]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Implementing Google Workspace Admin Security

## When to Use

- Deploying or hardening a Google Workspace environment for enterprise use
- CIS benchmark compliance assessment for Google Workspace configuration
- Protecting against business email compromise (BEC) and phishing attacks targeting Google accounts
- Implementing Data Loss Prevention controls for Gmail and Google Drive
- Restricting OAuth application access and third-party integrations
- Configuring admin account security with Advanced Protection Program enrollment

**Do not use** for Microsoft 365 environments; Google Workspace has distinct admin console settings and API configurations that differ from Azure AD/Entra ID controls.

## Prerequisites

- Google Workspace Business Plus, Enterprise Standard, or Enterprise Plus license
- Super Admin access to the Google Admin Console (admin.google.com)
- DNS management access for SPF, DKIM, and DMARC record configuration
- Google Cloud Identity or Cloud Identity Premium for advanced security features
- FIDO2 security keys for super admin accounts (YubiKey 5 Series recommended)

## Workflow

### Step 1: Harden Super Admin Accounts

Secure the highest-privilege accounts in the Google Workspace tenant:

```bash
# Google Workspace Admin SDK - configure admin account security
# Using gam (Google Apps Manager) CLI tool

# List all super admin accounts for audit
gam print admins role "Super Admin" > super_admins.csv
echo "Review and minimize super admin count (recommended: 2-3 maximum)"

# Enforce Advanced Protection Program for super admins
# APP provides strongest account protections:
# - Requires FIDO2 security key for sign-in
# - Blocks third-party app access to Gmail and Drive
# - Enhanced account recovery verification
gam update user superadmin@corp.com \
    advanced_protection true

# Create dedicated break-glass admin account
gam create user breakglass-admin@corp.com \
    firstname "Break" lastname "Glass Admin" \
    password "$(openssl rand -base64 32)" \
    changepassword true \
    org "/Emergency Accounts"

# Assign super admin role to break-glass account
gam create admin breakglass-admin@corp.com "Super Admin"

# Configure admin activity alerts
# Alert Center API - create alert for admin actions
cat > admin_alert_policy.json << 'EOF'
{
  "alertPolicies": [
    {
      "name": "Super Admin Sign-In Alert",
      "conditions": {
        "eventType": "login",
        "filterCriteria": "actor.adminRole=SUPER_ADMIN"
      },
      "notifications": {
        "email": ["security-team@corp.com"],
        "webhook": "https://siem.corp.com/webhook/google-admin"
      }
    },
    {
      "name": "Admin Role Change Alert",
      "conditions": {
        "eventType": "admin_role_change"
      },
      "notifications": {
        "email": ["security-team@corp.com"]
      }
    }
  ]
}
EOF
```

### Step 2: Enforce Phishing-Resistant Multi-Factor Authentication

Configure MFA policies that eliminate phishable authentication factors:

```bash
# Enforce 2-Step Verification for all organizational units
# Using Admin SDK Directory API

# Enable 2SV enforcement for the entire organization
gam update org "/" settings \
    2sv_enforcement true \
    2sv_enrollment_grace_period 14 \
    2sv_new_user_enrollment_period 1

# Configure allowed 2SV methods - restrict to phishing-resistant only
# For high-security OUs: Security keys only
gam update org "/Executive" settings \
    2sv_allowed_methods "SECURITY_KEY_ONLY"

# For general staff: Security keys or phone prompts (no SMS/voice)
gam update org "/" settings \
    2sv_allowed_methods "SECURITY_KEY,PHONE_PROMPT" \
    2sv_disallowed_methods "SMS,VOICE_CALL,BACKUP_CODES"

# Bulk check 2SV enrollment status
gam print users \
    fields primaryEmail,isEnrolledIn2Sv,isEnforcedIn2Sv \
    query "isEnrolledIn2Sv=false" > users_without_2sv.csv

# Count users without 2SV
echo "Users without 2SV enrolled:"
wc -l < users_without_2sv.csv

# Configure context-aware access policies
# Require 2SV + managed device for sensitive apps
cat > context_aware_policy.json << 'EOF'
{
  "accessLevels": [
    {
      "name": "Managed Device Required",
      "conditions": {
        "devicePolicy": {
          "requireScreenLock": true,
          "requireAdminApproval": true,
          "allowedEncryptionStatuses": ["ENCRYPTED"],
          "requireCorpOwned": false
        },
        "requiredAccessLevels": ["VERIFIED_2SV"]
      }
    }
  ],
  "applicationPolicies": [
    {
      "applications": ["Google Drive", "Gmail", "Admin Console"],
      "accessLevel": "Managed Device Required"
    }
  ]
}
EOF
```

### Step 3: Configure Email Authentication and Anti-Phishing

Set up SPF, DKIM, DMARC and advanced phishing protections:

```bash
# Step 3a: Configure SPF record
# Add to DNS TXT record for corp.com
echo 'DNS TXT Record for SPF:'
echo 'corp.com TXT "v=spf1 include:_spf.google.com ~all"'
echo ''
echo 'After testing, change ~all to -all (hard fail) for enforcement'

# Step 3b: Generate and configure DKIM signing
# Generate 2048-bit DKIM key via Admin Console or API
gam create dkim domain corp.com selector google bitlength 2048

echo 'Add DKIM DNS TXT record:'
echo 'google._domainkey.corp.com TXT "v=DKIM1; k=rsa; p=<public_key_from_admin_console>"'

# Verify DKIM is working
gam info dkim domain corp.com

# Step 3c: Configure DMARC policy
echo 'DNS TXT Record for DMARC (start with monitoring):'
echo '_dmarc.corp.com TXT "v=DMARC1; p=none; rua=mailto:dmarc-reports@corp.com; ruf=mailto:dmarc-forensics@corp.com; pct=100; adkim=s; aspf=s"'
echo ''
echo 'After 30 days monitoring, escalate to quarantine then reject:'
echo '_dmarc.corp.com TXT "v=DMARC1; p=reject; rua=mailto:dmarc-reports@corp.com; pct=100; adkim=s; aspf=s"'

# Step 3d: Enable advanced phishing and malware protection
# Configure in Admin Console > Security > Email Safety
gam update settings email_safety \
    protect_against_domain_spoofing true \
    protect_against_employee_spoofing true \
    protect_against_inbound_spoofing true \
    protect_unauthenticated_email true \
    identify_spoofed_groups true \
    auto_move_suspicious_to_spam true

# Configure attachment security
gam update settings email_safety \
    protect_encrypted_attachments true \
    protect_anomalous_attachment_types true \
    protect_scripts_from_untrusted true \
    whitelist_sender_domains "" \
    apply_future_recommended_settings true
```

### Step 4: Implement Data Loss Prevention (DLP)

Configure DLP rules to prevent sensitive data exfiltration:

```bash
# Create DLP rules for Gmail and Drive
# Using Google Workspace DLP API

cat > dlp_rules.json << 'EOF'
{
  "dlpRules": [
    {
      "name": "PII Detection - SSN",
      "description": "Detect Social Security Numbers in outbound email and Drive sharing",
      "trigger": {
        "contentMatchers": [
          {
            "infoType": "US_SOCIAL_SECURITY_NUMBER",
            "likelihood": "LIKELY",
            "minMatchCount": 1
          }
        ],
        "scope": ["GMAIL_OUTBOUND", "DRIVE_EXTERNAL_SHARE"]
      },
      "action": {
        "blockAction": "QUARANTINE",
        "notifyAdmin": true,
        "notifyUser": true,
        "userMessage": "This message contains a Social Security Number and has been quarantined for review.",
        "auditLog": true
      }
    },
    {
      "name": "Credit Card Number Detection",
      "description": "Block credit card numbers in outbound communications",
      "trigger": {
        "contentMatchers": [
          {
            "infoType": "CREDIT_CARD_NUMBER",
            "likelihood": "LIKELY",
            "minMatchCount": 1
          }
        ],
        "scope": ["GMAIL_OUTBOUND", "DRIVE_EXTERNAL_SHARE", "CHAT"]
      },
      "action": {
        "blockAction": "BLOCK",
        "notifyAdmin": true,
        "notifyUser": true,
        "auditLog": true
      }
    },
    {
      "name": "Confidential Document Detection",
      "description": "Detect documents marked as Confidential or Internal Only",
      "trigger": {
        "contentMatchers": [
          {
            "customRegex": "(?i)(CONFIDENTIAL|INTERNAL ONLY|DO NOT DISTRIBUTE|RESTRICTED)",
            "minMatchCount": 2
          }
        ],
        "metadataMatchers": [
          {
            "driveLabels": ["Confidential", "Restricted"]
          }
        ],
        "scope": ["DRIVE_EXTERNAL_SHARE"]
      },
      "action": {
        "blockAction": "WARN",
        "requireJustification": true,
        "auditLog": true
      }
    }
  ]
}
EOF

echo "Apply DLP rules via Admin Console > Security > Data Protection"
echo "Or use the Google Workspace DLP API for programmatic deployment"
```

### Step 5: Control OAuth Applications and Third-Party Access

Restrict which third-party applications can access organizational data:

```bash
# Configure OAuth app access control
# Admin Console > Security > API Controls > App Access Control

# Block all third-party apps by default, then allowlist approved ones
gam update org "/" settings \
    third_party_app_access "BLOCKED" \
    allow_users_to_install_apps false

# Allowlist approved applications
cat > approved_apps.json << 'EOF'
{
  "allowedApps": [
    {
      "appId": "slack-app-id",
      "name": "Slack",
      "scopes": ["gmail.readonly", "calendar.readonly"],
      "approvedBy": "security-team",
      "reviewDate": "2026-01-15"
    },
    {
      "appId": "zoom-app-id",
      "name": "Zoom",
      "scopes": ["calendar.events"],
      "approvedBy": "security-team",
      "reviewDate": "2026-01-15"
    },
    {
      "appId": "salesforce-app-id",
      "name": "Salesforce",
      "scopes": ["gmail.send", "contacts.readonly"],
      "approvedBy": "security-team",
      "reviewDate": "2026-01-15"
    }
  ]
}
EOF

# Audit current OAuth tokens granted by users
gam all users print tokens > oauth_tokens_audit.csv
echo "Review oauth_tokens_audit.csv for unauthorized third-party access"

# Revoke tokens for unapproved applications
gam all users deprovision tokens \
    clientid "unapproved-app-client-id"

# Configure API scopes restriction
# Limit which API scopes third-party apps can request
gam update org "/" settings \
    api_access_restricted true \
    allowed_api_scopes "gmail.readonly,calendar.readonly,drive.readonly"
```

### Step 6: Configure External Sharing and Drive Security

Lock down data sharing controls:

```bash
# Configure Google Drive sharing restrictions
gam update org "/" settings \
    drive_sharing_outside_domain "WHITELISTED_DOMAINS" \
    drive_sharing_whitelisted_domains "partner1.com,partner2.com" \
    drive_allow_file_requests false \
    drive_shared_drive_creation "ADMIN_ONLY" \
    drive_default_link_sharing "RESTRICTED"

# Configure sharing alerts
gam create alert \
    name "External Sharing Alert" \
    type "drive_external_share" \
    condition "shared_outside_domain=true AND file_type IN ('spreadsheet','document','presentation')" \
    action "notify_admin security-team@corp.com"

# Audit current external shares
gam all users print filelist \
    fields id,name,owners,permissions \
    query "visibility='anyoneWithLink' or visibility='anyoneCanFind'" \
    > external_shares_audit.csv

echo "External shares requiring review:"
wc -l < external_shares_audit.csv

# Configure Google Groups security
gam update org "/" settings \
    groups_external_members false \
    groups_external_posting false \
    groups_creation "ADMIN_ONLY" \
    groups_allow_external_invitations false
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Advanced Protection Program (APP)** | Google's strongest account security requiring FIDO2 security keys, blocking third-party app access, and enhanced identity verification for account recovery |
| **Context-Aware Access** | Security policy framework that evaluates device posture, location, and user identity before granting access to Google Workspace applications |
| **DMARC** | Domain-based Message Authentication, Reporting and Conformance protocol that prevents email domain spoofing by validating SPF and DKIM alignment |
| **DLP Rule** | Data Loss Prevention policy that scans content in Gmail, Drive, and Chat for sensitive data patterns and triggers block, quarantine, or warn actions |
| **OAuth App Allowlisting** | Admin control restricting which third-party applications can access organizational data through Google OAuth API scopes |
| **2-Step Verification (2SV)** | Google's multi-factor authentication implementation supporting security keys, phone prompts, TOTP, and backup codes as second factors |

## Tools & Systems

- **Google Admin Console**: Web-based administration portal for managing all Google Workspace security settings, users, and organizational units
- **GAM (Google Apps Manager)**: Open-source command-line tool for bulk Google Workspace administration and automation
- **Google Workspace Alert Center**: Centralized dashboard for security alerts including suspicious login activity, DLP violations, and device compromise
- **Google BeyondCorp Enterprise**: Zero-trust access solution integrated with Google Workspace for context-aware access policies

## Common Scenarios

### Scenario: Securing a Newly Acquired Google Workspace Tenant

**Context**: Post-acquisition security audit reveals the acquired company's Google Workspace has no MFA enforcement, open external sharing, no DLP policies, and multiple unauthorized OAuth applications accessing user data.

**Approach**:
1. Immediately enforce 2SV for all super admin accounts using FIDO2 security keys
2. Reduce super admin count to 3 (primary, secondary, break-glass)
3. Deploy SPF, DKIM, and DMARC starting with monitoring mode (p=none)
4. Enable all anti-phishing and anti-spoofing settings in Email Safety
5. Audit and revoke all unauthorized OAuth application tokens
6. Set third-party app access to blocked with allowlist of approved applications
7. Restrict external Drive sharing to approved partner domains only
8. Deploy DLP rules for PII, financial data, and confidential documents
9. Enable context-aware access requiring managed devices for sensitive applications
10. Configure security alerts and SIEM integration for ongoing monitoring

**Pitfalls**:
- Enforcing MFA without enrollment grace period locks users out of accounts
- Setting DMARC to reject before monitoring period causes legitimate email delivery failures
- Blocking all OAuth apps without identifying business-critical integrations disrupts workflows
- Not auditing existing external shares before restricting sharing leaves data exposed

## Output Format

```
GOOGLE WORKSPACE SECURITY ASSESSMENT REPORT
=============================================
Tenant:            corp.com
License:           Enterprise Plus
Total Users:       3,847
Organizational Units: 12

AUTHENTICATION SECURITY
2SV Enforced:           YES (all OUs)
2SV Enrollment:         3,712 / 3,847 (96.5%)
Security Keys Only:     Executive OU (47 users)
Advanced Protection:    3 super admin accounts
Super Admin Count:      3 (within recommended limit)

EMAIL AUTHENTICATION
SPF:                    CONFIGURED (hard fail: -all)
DKIM:                   CONFIGURED (2048-bit, selector: google)
DMARC:                  ENFORCED (p=reject, 100%)
Anti-Phishing:          ALL PROTECTIONS ENABLED
Anti-Spoofing:          ENABLED (domain + employee name)

DATA PROTECTION
DLP Rules Active:       7
  PII Detection:        SSN, Credit Card, Passport
  Content Labels:       Confidential, Restricted
  Custom Patterns:      3 organization-specific rules
DLP Violations (30d):   89 (67 blocked, 22 warned)

APPLICATION CONTROL
Third-Party App Policy: BLOCKED (allowlist mode)
Approved Apps:          12
Unauthorized Tokens:    0 (all revoked)
API Scope Restrictions: ENABLED

SHARING CONTROLS
External Sharing:       RESTRICTED (allowlisted domains only)
Public Link Sharing:    DISABLED
External Group Members: DISABLED
Shared Drive Creation:  ADMIN ONLY
```
