# Workflows: Analyzing Malicious URLs with URLScan

## Workflow 1: URL Triage Pipeline

```
Suspicious URL received (from user report / email gateway / SIEM)
  |
  v
[Step 1: Defang and document URL]
  +-- Replace http with hxxp, . with [.]
  +-- Record original context (email subject, sender, timestamp)
  |
  v
[Step 2: Submit to URLScan (private visibility)]
  +-- POST to /api/v1/scan/
  +-- Wait for scan completion (poll /api/v1/result/{uuid}/)
  |
  v
[Step 3: Analyze results]
  +-- Review screenshot for brand impersonation
  +-- Check redirect chain (original URL vs final URL)
  +-- Examine DOM for login forms / credential inputs
  +-- Review network requests for suspicious endpoints
  +-- Check SSL certificate details
  |
  v
[Step 4: Classify]
  +-- Phishing (credential harvesting)
  +-- Malware delivery
  +-- Scam / fraud
  +-- Benign (false positive)
  |
  v
[Step 5: Action]
  +-- If malicious: Extract IOCs, block domain/IP, update filters
  +-- If benign: Document and close
  +-- If uncertain: Escalate for deeper analysis
```

## Workflow 2: Bulk URL Analysis

```
URL list from email gateway / threat feed
  |
  v
[Batch submit to URLScan API]
  +-- Rate limit: 2 submissions/second (free tier)
  +-- Use private visibility for sensitive URLs
  |
  v
[Collect all results]
  +-- Poll each scan UUID for completion
  +-- Download screenshots and DOM content
  |
  v
[Automated triage]
  +-- Flag: credential input forms detected
  +-- Flag: brand impersonation in screenshot
  +-- Flag: known phishing infrastructure (IP/ASN)
  +-- Flag: newly registered domains
  |
  v
[Generate report]
  +-- Categorized URL list (malicious / suspicious / clean)
  +-- IOC extract for blocking
  +-- Statistics summary
```

## Workflow 3: IOC Extraction and Enrichment

```
URLScan result available
  |
  v
[Extract from scan]
  +-- All domains contacted
  +-- All IPs contacted
  +-- SSL certificate fingerprints
  +-- JavaScript file hashes
  +-- Page resource hashes
  +-- Final redirect URL
  |
  v
[Cross-reference]
  +-- VirusTotal: domain/IP/hash reputation
  +-- PhishTank: known phishing URL database
  +-- WHOIS: domain registration details
  +-- AbuseIPDB: IP abuse reports
  +-- Google Safe Browsing: malware/phishing flags
  |
  v
[Compile IOC package]
  +-- STIX/TAXII format for TIP
  +-- CSV for firewall/proxy rules
  +-- JSON for SIEM enrichment
```
