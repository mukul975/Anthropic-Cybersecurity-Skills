# Workflows: Detecting Spearphishing with Email Gateway

## Workflow 1: Multi-Layer Detection Pipeline

```
Inbound Email Arrives at Gateway
  |
  v
[Layer 1: Connection Filtering]
  +-- Check sender IP reputation
  +-- Check RBL/DNSBL blacklists
  +-- Rate limiting / throttling
  |
  v
[Layer 2: Authentication]
  +-- Verify SPF alignment
  +-- Verify DKIM signature
  +-- Evaluate DMARC policy
  +-- Check ARC headers (forwarded mail)
  |
  v
[Layer 3: Impersonation Detection]
  +-- Compare display name against VIP list
  +-- Check domain similarity (Levenshtein distance)
  +-- Evaluate sender reputation
  +-- First-time sender analysis
  |
  v
[Layer 4: Content Analysis]
  +-- NLP analysis for urgency/social engineering
  +-- Business context anomaly detection
  +-- Keyword pattern matching
  +-- Language analysis
  |
  v
[Layer 5: URL Analysis]
  +-- URL reputation check
  +-- Domain age verification
  +-- Real-time URL detonation
  +-- Redirect chain following
  +-- Visual similarity to legitimate sites
  |
  v
[Layer 6: Attachment Analysis]
  +-- File type validation
  +-- Sandbox detonation
  +-- Macro analysis
  +-- Embedded object detection
  |
  v
[Decision Engine]
  +-- Aggregate scores from all layers
  +-- Apply organizational policy
  |
  +-- DELIVER: Low risk
  +-- TAG: Add warning banner
  +-- QUARANTINE: Moderate risk
  +-- BLOCK: High risk, drop message
```

## Workflow 2: VIP Impersonation Detection

```
Email arrives with From display name matching VIP list
  |
  v
[Check: Is sending domain authorized for this VIP?]
  |
  +-- YES: Check DKIM/SPF --> If pass, deliver normally
  |
  +-- NO: Impersonation suspected
       |
       v
  [Calculate domain similarity score]
       |
       +-- Exact match (different email): CRITICAL - Block
       +-- Lookalike domain (1-2 char diff): HIGH - Quarantine
       +-- Similar but different: MEDIUM - Tag with warning
       |
       v
  [Additional checks]
       +-- Has this sender emailed before?
       +-- Is the sending infrastructure legitimate?
       +-- Does email content match typical VIP communication?
       |
       v
  [Action: Quarantine + Alert SOC + Notify recipient manager]
```

## Workflow 3: Spearphishing Response

```
Gateway detects potential spearphishing
  |
  v
[Automated Response]
  +-- Quarantine message
  +-- Generate alert in SIEM
  +-- Extract IOCs (sender, domain, URLs, hashes)
  |
  v
[SOC Analyst Review]
  +-- Review quarantined message
  +-- Analyze full headers
  +-- Investigate sending infrastructure
  +-- Check if other users received similar emails
  |
  +-- FALSE POSITIVE
  |     +-- Release from quarantine
  |     +-- Whitelist if legitimate
  |     +-- Update detection rules
  |
  +-- CONFIRMED SPEARPHISHING
        +-- Block sender domain organization-wide
        +-- Search mailboxes for similar messages (retroactive)
        +-- Auto-purge any delivered copies (ZAP)
        +-- Notify targeted users
        +-- Submit IOCs to threat intelligence
        +-- Check for any successful credential compromise
        +-- Update VIP protection list if needed
```

## Workflow 4: Gateway Tuning Cycle

```
Monthly Review
  |
  +-- Pull detection statistics from gateway
  +-- Analyze false positive rate
  +-- Analyze false negative rate (user-reported misses)
  +-- Review quarantine volumes
  |
  v
[Identify gaps]
  +-- New impersonation patterns?
  +-- New sending domains to whitelist/blacklist?
  +-- Policy thresholds too aggressive/permissive?
  |
  v
[Adjust configuration]
  +-- Update VIP protection list (new hires, departures)
  +-- Tune sensitivity thresholds
  +-- Add custom transport rules
  +-- Update URL/domain blocklists
  |
  v
[Validate changes]
  +-- Send test phishing emails
  +-- Verify legitimate mail still flows
  +-- Document changes
```
