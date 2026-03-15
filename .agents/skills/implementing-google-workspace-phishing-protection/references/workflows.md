# Workflows: Google Workspace Phishing Protection

## Workflow 1: Gmail Inbound Protection Pipeline

```
Inbound email arrives at Gmail
  |
  v
[Connection-level checks]
  +-- IP reputation
  +-- SPF validation
  +-- DKIM verification
  +-- DMARC evaluation
  |
  v
[Enhanced Pre-Delivery Scanning]
  +-- Content analysis for phishing indicators
  +-- URL expansion (shortened URLs)
  +-- Image scanning for embedded phishing
  +-- NLP analysis for social engineering
  |
  v
[Attachment Protection]
  +-- File type analysis
  +-- Script detection in attachments
  +-- Encrypted attachment from untrusted sender check
  +-- Security Sandbox detonation (Enterprise)
  |
  v
[Spoofing Detection]
  +-- Domain name similarity check
  +-- Employee name impersonation check
  +-- Internal domain spoofing check
  |
  v
[Delivery decision]
  +-- DELIVER: Clean message to inbox
  +-- WARN: Deliver with yellow warning banner
  +-- SPAM: Route to spam folder
  +-- QUARANTINE: Hold for admin review
  +-- REJECT: Block delivery entirely
```

## Workflow 2: Safe Browsing URL Protection

```
User clicks URL in Gmail
  |
  v
[Enhanced Safe Browsing check]
  +-- Real-time URL reputation lookup
  +-- Check against known phishing database
  +-- Dynamic page analysis
  |
  v
[Decision]
  +-- SAFE: Allow navigation
  +-- DANGEROUS: Display full-page warning
  +-- SUSPICIOUS: Display interstitial warning
```
