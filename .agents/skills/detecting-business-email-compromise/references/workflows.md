# Workflows: Detecting Business Email Compromise

## Workflow 1: BEC Detection Pipeline

```
Inbound email arrives
  |
  v
[Check: Does display name match VIP list?]
  +-- YES + external domain --> HIGH ALERT: Possible CEO fraud
  +-- NO --> Continue standard checks
  |
  v
[Check: Financial keywords present?]
  +-- "wire transfer", "payment", "invoice", "bank details" detected
  +-- Combined with urgency: "urgent", "confidential", "today"
  +-- YES --> ELEVATED: Flag for finance team review
  |
  v
[Check: Reply-To mismatch?]
  +-- Reply-To domain differs from From domain
  +-- YES --> HIGH: Likely BEC attempt
  |
  v
[Check: Communication pattern anomaly?]
  +-- First-time sender to finance/HR staff
  +-- Unusual time of day for this sender
  +-- YES --> MEDIUM: Requires verification
  |
  v
[Decision]
  +-- BLOCK: High-confidence BEC
  +-- QUARANTINE: Moderate confidence
  +-- TAG: Warning banner for recipient
  +-- DELIVER: Low risk
```

## Workflow 2: BEC Incident Response

```
BEC attempt detected or reported
  |
  v
[Immediate actions (first 30 minutes)]
  +-- Quarantine the email
  +-- Search for similar messages to other recipients
  +-- Alert affected users not to comply with request
  |
  v
[Investigation (next 2 hours)]
  +-- Analyze email headers for true origin
  +-- Check if any user already complied (check sent folders)
  +-- If payment was made: Initiate bank recall immediately
  +-- Search for compromised accounts (forwarding rules, login anomalies)
  |
  v
[Containment]
  +-- Block sender domain/IP
  +-- If account compromised: Force password reset, revoke sessions
  +-- Remove malicious forwarding rules
  +-- Notify finance to halt pending payments
  |
  v
[Recovery]
  +-- Work with bank for fund recovery
  +-- File FBI IC3 report (ic3.gov)
  +-- Notify affected parties
  +-- Update detection rules
  +-- Targeted training for affected employees
```

## Workflow 3: Vendor Payment Change Verification

```
Vendor requests payment detail change
  |
  v
[Do NOT use contact info from the email]
  |
  v
[Look up vendor contact from existing records]
  |
  v
[Call vendor using known phone number]
  +-- Verify the payment change request is legitimate
  |
  +-- CONFIRMED --> Process change with dual authorization
  +-- NOT CONFIRMED --> Report as BEC attempt, block sender
  +-- UNABLE TO REACH --> Hold payment, escalate
```
