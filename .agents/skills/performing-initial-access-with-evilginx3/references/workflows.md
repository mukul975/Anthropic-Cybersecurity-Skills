# Workflows - EvilGinx3 Initial Access

## End-to-End AiTM Phishing Workflow

```
1. Reconnaissance
   ├── Identify target authentication service (M365, Google, Okta)
   ├── Analyze target MFA implementation (SMS, Authenticator, FIDO2)
   ├── Register lookalike domain with appropriate TLD
   └── Categorize domain to avoid URL filtering

2. Infrastructure Setup
   ├── Deploy VPS and configure DNS records
   ├── Install and configure EvilGinx3
   ├── Enable phishlet for target service
   ├── Verify SSL certificate provisioning
   └── Create and test lure URLs

3. Phishing Delivery
   ├── Craft pretext email with social engineering
   ├── Configure GoPhish or SMTP relay for delivery
   ├── Send phishing emails to authorized targets
   └── Monitor delivery and open rates

4. Credential and Session Capture
   ├── Monitor EvilGinx3 session dashboard
   ├── Capture credentials as victims authenticate
   ├── Capture session cookies (MFA bypass tokens)
   └── Export session data for exploitation

5. Session Hijacking
   ├── Import session cookies into attacker browser
   ├── Navigate to target service with hijacked session
   ├── Validate access to victim's account
   └── Enumerate accessible resources

6. Persistence and Escalation
   ├── Create application-specific passwords
   ├── Register attacker device in Azure AD / Entra ID
   ├── Add OAuth application consents
   └── Establish email forwarding rules for persistence

7. Reporting
   ├── Document attack chain with evidence
   ├── Record number of successful captures
   ├── Identify defensive gaps exploited
   └── Provide remediation recommendations
```

## Cookie Import Workflow

```
1. From EvilGinx3 session output, copy cookie data
2. Open browser with Cookie-Editor extension
3. Navigate to target service login page
4. Clear existing cookies for the domain
5. Import captured cookies via Cookie-Editor
6. Refresh the page to obtain authenticated session
7. Verify access to victim's account
```
