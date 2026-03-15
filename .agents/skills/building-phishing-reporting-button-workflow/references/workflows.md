# Workflows: Building Phishing Reporting Button Workflow

## Workflow 1: Automated Phishing Report Triage

```
User clicks "Report Phishing" button
  |
  v
[Email forwarded to reporting mailbox]
  +-- Original email preserved with full headers
  +-- Reporter identity recorded
  |
  v
[SOAR platform ingests report]
  |
  v
[Automated IOC extraction]
  +-- Extract sender address and domain
  +-- Extract all URLs from body
  +-- Extract attachment hashes (MD5, SHA256)
  +-- Parse email headers for authentication results
  |
  v
[Automated analysis (parallel)]
  +-- URLs -> VirusTotal, URLScan.io, PhishTank
  +-- Attachments -> Sandbox detonation
  +-- Sender -> Threat intelligence lookup
  +-- Headers -> SPF/DKIM/DMARC validation
  |
  v
[Classification]
  +-- CONFIRMED PHISHING: High-confidence malicious
  +-- SUSPICIOUS: Moderate indicators, needs analyst review
  +-- SPAM: Unwanted but not malicious
  +-- SIMULATION: Matches internal phishing test
  +-- CLEAN: Legitimate email, false report
  |
  v
[Automated response by classification]
  +-- PHISHING: Retract from all inboxes + block sender
  +-- SUSPICIOUS: Escalate to SOC analyst
  +-- SPAM: Move to junk for all recipients
  +-- SIMULATION: Credit reporter in training platform
  +-- CLEAN: Return to inbox
  |
  v
[Feedback to reporter]
  +-- "Thank you for reporting" (immediate)
  +-- Classification result (when complete)
  +-- Training tip (if false positive)
```

## Workflow 2: SOC Analyst Escalation

```
SOAR classifies report as SUSPICIOUS
  |
  v
[SOC analyst reviews]
  +-- Examine full email content and headers
  +-- Verify automated analysis results
  +-- Check for similar reports from other users
  |
  v
[Analyst decision]
  +-- Confirm malicious --> Trigger remediation playbook
  +-- Confirm clean --> Close and notify reporter
  +-- Need more info --> Contact reporter for context
```
