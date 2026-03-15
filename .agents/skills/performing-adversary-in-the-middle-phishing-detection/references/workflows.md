# Workflows: AiTM Phishing Detection

## Workflow 1: AiTM Attack Detection

```
User clicks phishing link
  |
  v
[Reverse proxy serves mirrored login page]
  +-- Page loads assets from legitimate CDN
  +-- SSL cert issued for lookalike domain
  |
  v
[User enters credentials + completes MFA]
  |
  v
[Attacker captures session cookie]
  |
  v
[DETECTION POINTS]
  +-- Web proxy: Connection to newly registered domain
  +-- Azure AD: Sign-in from proxy IP (unfamiliar location)
  +-- Session: Cookie replay from different IP within minutes
  +-- Exchange: Inbox rule created post-authentication
  +-- Azure AD: New OAuth app consent
  |
  v
[Automated response]
  +-- Revoke all sessions for user
  +-- Require re-authentication with phishing-resistant MFA
  +-- Remove suspicious inbox rules
  +-- Revoke OAuth app consents
  +-- Block attacker IP at firewall
```

## Workflow 2: AiTM Incident Response

```
AiTM compromise confirmed
  |
  v
[Immediate containment (first 30 minutes)]
  +-- Revoke all user sessions and tokens
  +-- Force password reset
  +-- Remove all inbox forwarding rules
  +-- Revoke OAuth app consents granted post-compromise
  +-- Disable compromised MFA methods
  |
  v
[Investigation (next 2-4 hours)]
  +-- Review Azure AD sign-in logs for compromise timeline
  +-- Check email sent items for BEC/phishing sent from account
  +-- Review SharePoint/OneDrive access for data exfiltration
  +-- Check for lateral movement to other accounts
  +-- Identify all affected users (same phishing campaign)
  |
  v
[Remediation]
  +-- Enroll user in phishing-resistant MFA (FIDO2)
  +-- Block phishing domain at email gateway and web proxy
  +-- Retract phishing email from all mailboxes
  +-- Update Conditional Access policies
  +-- Notify all targeted users
  |
  v
[Post-incident]
  +-- Add IOCs to threat intelligence
  +-- Create SIEM detection rules for observed TTPs
  +-- Update security awareness training
  +-- Assess FIDO2 rollout for broader user population
```
