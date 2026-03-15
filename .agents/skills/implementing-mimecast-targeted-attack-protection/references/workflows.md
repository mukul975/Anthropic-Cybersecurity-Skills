# Workflows: Implementing Mimecast Targeted Attack Protection

## Workflow 1: URL Protect Processing

```
Inbound email with URLs arrives
  |
  v
[Pre-delivery URL check]
  +-- Extract all URLs from body and attachments
  +-- Check against Mimecast threat intelligence
  +-- KNOWN MALICIOUS --> Hold/Block message
  +-- SUSPICIOUS --> Hold for deeper analysis
  +-- CLEAN --> Proceed to rewriting
  |
  v
[URL rewriting]
  +-- Replace original URLs with Mimecast proxy URLs
  +-- Preserve original URL in encoded format
  +-- Apply per-policy rewriting rules
  |
  v
[Message delivered to user inbox]
  |
  v
[User clicks rewritten URL]
  |
  v
[Time-of-click analysis]
  +-- Real-time page scan and sandbox
  +-- Check for credential harvesting forms
  +-- Check for malware downloads
  |
  v
[Decision]
  +-- SAFE: Redirect to original URL
  +-- MALICIOUS: Display block page
  +-- SUSPICIOUS: Display warning with proceed option
```

## Workflow 2: Attachment Protect Pipeline

```
Email with attachment arrives
  |
  v
[Static analysis]
  +-- File type identification
  +-- Signature matching
  +-- Known malware hash check
  |
  v
[Policy evaluation]
  +-- Safe File mode: Convert to safe format (PDF)
  +-- Dynamic mode: Full sandbox detonation
  +-- Bypass: Whitelisted sender/type
  |
  v
[Dynamic sandbox (if configured)]
  +-- Execute in isolated environment
  +-- Monitor for malicious behavior
  +-- Check for C2 callbacks, file drops, registry changes
  +-- Timeout: up to 7 minutes
  |
  v
[Verdict]
  +-- CLEAN: Deliver original attachment
  +-- MALICIOUS: Quarantine, notify admin
  +-- TIMEOUT: Deliver with warning or hold per policy
```

## Workflow 3: Impersonation Protect Analysis

```
Inbound email arrives
  |
  v
[Identifier check against VIP list]
  +-- Compare display name to VIP names
  +-- Check domain similarity to internal domains
  +-- Verify reply-to alignment
  +-- Check if sender is newly observed
  |
  v
[Hit scoring]
  +-- Hit 1 policy (VIP): 1+ indicator match
  +-- Hit 3 policy (Default): 3+ indicator matches
  |
  v
[Action based on hit level]
  +-- QUARANTINE: High confidence impersonation
  +-- TAG: Moderate confidence, add warning banner
  +-- LOG: Low confidence, record for analysis
  +-- DELIVER: No indicators matched
```
