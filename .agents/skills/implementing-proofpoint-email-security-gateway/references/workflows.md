# Workflows: Implementing Proofpoint Email Security Gateway

## Workflow 1: Inbound Mail Processing Pipeline

```
External sender sends email
  |
  v
[DNS MX lookup resolves to Proofpoint]
  |
  v
[Connection-level filtering]
  +-- IP reputation check (Proofpoint Nexus)
  +-- Rate limiting and connection throttling
  +-- REJECT if known-bad IP
  |
  v
[Authentication checks]
  +-- SPF validation
  +-- DKIM signature verification
  +-- DMARC policy evaluation
  +-- FAIL actions: quarantine or reject per policy
  |
  v
[Content analysis]
  +-- Anti-spam scoring (ML classifier)
  +-- Anti-virus scanning (multi-engine)
  +-- Impostor classifier (BEC detection)
  +-- NLP analysis for social engineering language
  |
  v
[URL Defense]
  +-- Extract all URLs from body and attachments
  +-- Rewrite URLs through Proofpoint proxy
  +-- Pre-delivery URL reputation check
  +-- BLOCK if known malicious
  |
  v
[Attachment Defense]
  +-- Static analysis (signatures, heuristics)
  +-- Dynamic sandbox detonation (if suspicious)
  +-- Wait for sandbox verdict (up to 7 minutes)
  +-- QUARANTINE if malicious
  |
  v
[Policy action]
  +-- DELIVER: Clean email to mailbox
  +-- TAG: Add warning banner for external/suspicious
  +-- QUARANTINE: Hold for admin/user review
  +-- REJECT: Block with NDR to sender
```

## Workflow 2: Post-Delivery Threat Response (TRAP)

```
Threat intelligence update received
  |
  v
[TRAP scans delivered messages retroactively]
  +-- URL becomes malicious after delivery
  +-- New malware signature matches delivered attachment
  |
  v
[Auto-Pull action triggered]
  +-- Move message from user inbox to quarantine
  +-- Log retraction in TRAP dashboard
  +-- Notify SOC team of post-delivery threat
  |
  v
[SOC investigation]
  +-- Review TRAP alert and threat details
  +-- Check if user clicked URL before retraction
  +-- If clicked: initiate incident response
  +-- If not clicked: close as contained
  |
  v
[Update policies]
  +-- Add sender/domain to block list if needed
  +-- Create detection rule for similar campaigns
  +-- Update TAP Dashboard threat tracking
```

## Workflow 3: Phishing Report and CLEAR Integration

```
User receives suspicious email
  |
  v
[User clicks "Report Phishing" button (Proofpoint CLEAR)]
  |
  v
[Email forwarded to Proofpoint analysis pipeline]
  +-- Automated classification (phishing/spam/clean)
  +-- URL and attachment analysis
  |
  v
[CLEAR verdict]
  +-- MALICIOUS: Auto-retract from all inboxes that received it
  +-- SPAM: Move to junk for all recipients
  +-- CLEAN: Return to inbox, thank reporter
  |
  v
[Metrics and feedback]
  +-- Track reporter accuracy rate
  +-- Update user risk score
  +-- Feed into security awareness metrics
```
