# Workflows: Implementing DMARC, DKIM, and SPF

## Workflow 1: Phased DMARC Deployment

```
Phase 1: Discovery (Weeks 1-2)
  |
  +-- Inventory all email-sending services
  +-- Identify legitimate sources (marketing, transactional, internal)
  +-- Audit current SPF/DKIM/DMARC records
  |
Phase 2: SPF Setup (Weeks 2-4)
  |
  +-- Create SPF record with all authorized senders
  +-- Start with ~all (soft fail) for monitoring
  +-- Test with email validation tools
  |
Phase 3: DKIM Setup (Weeks 3-5)
  |
  +-- Generate 2048-bit RSA key pairs per sending service
  +-- Configure DKIM signing on MTA/email service
  +-- Publish public keys in DNS
  +-- Verify signatures with test emails
  |
Phase 4: DMARC Monitor (Weeks 5-8)
  |
  +-- Deploy DMARC with p=none
  +-- Set up aggregate report (rua) processing
  +-- Monitor for 4+ weeks
  +-- Identify and fix failing legitimate sources
  |
Phase 5: DMARC Quarantine (Weeks 9-12)
  |
  +-- Move to p=quarantine at pct=10
  +-- Gradually increase pct to 100
  +-- Monitor false positives
  |
Phase 6: DMARC Reject (Weeks 13+)
  |
  +-- Move to p=reject at pct=10
  +-- Gradually increase to pct=100
  +-- Ongoing monitoring and maintenance
```

## Workflow 2: SPF Record Construction

```
START: List all email sending sources
  |
  v
[Internal mail servers] --> ip4:x.x.x.x/y
  |
  v
[Cloud email (Google/M365)] --> include:_spf.google.com / include:spf.protection.outlook.com
  |
  v
[Marketing (Mailchimp, SendGrid)] --> include:servers.mcsv.net / include:sendgrid.net
  |
  v
[Transactional (SES, Postmark)] --> include:amazonses.com / include:spf.mtasv.net
  |
  v
[CRM (Salesforce, HubSpot)] --> include:_spf.salesforce.com / include:hubs.hubspot.com
  |
  v
[Combine all mechanisms, ensure < 10 DNS lookups]
  |
  v
[Add qualifier: ~all (monitor) or -all (enforce)]
  |
  v
[Publish TXT record at domain apex]
  |
  v
[Validate: mxtoolbox.com/spf.aspx]
```

## Workflow 3: DMARC Report Analysis

```
Daily DMARC aggregate reports (XML) received
  |
  v
[Parse XML reports with process.py]
  |
  v
[Categorize results]
  |
  +-- PASS (SPF + DKIM aligned) --> No action needed
  |
  +-- FAIL (unauthorized sender)
  |     |
  |     +-- Known service missing from SPF? --> Update SPF record
  |     +-- Known service missing DKIM? --> Configure DKIM signing
  |     +-- Unknown/suspicious sender --> Likely spoofing attempt
  |           |
  |           +-- Document source IPs
  |           +-- Add to threat intelligence
  |           +-- No SPF/DKIM changes needed (DMARC working correctly)
  |
  +-- PARTIAL PASS (SPF or DKIM only)
        |
        +-- Fix the failing mechanism
        +-- Check for forwarding/mailing list issues (consider ARC)
```

## Workflow 4: Ongoing Maintenance

```
Monthly:
  - Review DMARC aggregate reports for new unauthorized sources
  - Verify all third-party senders still authorized
  - Check SPF record is under 10 DNS lookup limit

Quarterly:
  - Rotate DKIM keys (update selector)
  - Review and update authorized sender inventory
  - Test authentication with external validation tools

Annually:
  - Full audit of email authentication configuration
  - Review DMARC policy strictness
  - Update documentation
```
