# Workflows: Detecting QR Code Phishing

## Workflow 1: QR Code Email Detection Pipeline

```
Inbound email arrives at gateway
  |
  v
[Standard text/URL scanning]
  +-- Check text-based URLs (standard pipeline)
  +-- No malicious URLs found in text
  |
  v
[Image analysis module]
  +-- Scan all embedded images and attachments
  +-- Apply QR code detection algorithm
  +-- Check for ASCII/text-rendered QR codes
  +-- Scan PDF attachments for embedded QR codes
  |
  v
[QR code detected?]
  +-- NO --> Continue standard delivery
  +-- YES --> Extract encoded URL
  |
  v
[URL reputation and analysis]
  +-- Check URL against threat intelligence feeds
  +-- Check domain age and registration data
  +-- Submit to sandbox for real-time analysis
  +-- Check for credential harvesting indicators
  |
  v
[Decision]
  +-- MALICIOUS URL: Block email, alert SOC
  +-- SUSPICIOUS URL: Quarantine, add warning banner
  +-- UNKNOWN URL: Tag email with QR warning banner
  +-- CLEAN URL: Deliver with informational banner
```

## Workflow 2: Quishing Incident Response

```
User reports QR code phishing email
  |
  v
[Triage (15 minutes)]
  +-- Extract QR code and decode URL
  +-- Check if URL is active credential harvester
  +-- Search mailboxes for same email to other recipients
  |
  v
[Containment]
  +-- Block sender domain across email gateway
  +-- Retract email from all recipient inboxes
  +-- Block decoded URL at web proxy/firewall
  +-- If user scanned: check for credential compromise
  |
  v
[Investigation]
  +-- Did any user submit credentials on phishing page?
  +-- Check authentication logs for compromised accounts
  +-- If credentials entered: force password reset + revoke sessions
  +-- Review phishing page infrastructure
  |
  v
[Recovery and prevention]
  +-- Add QR URL pattern to detection rules
  +-- Update security awareness training
  +-- Send targeted alert to affected users
  +-- Document IOCs for threat intelligence sharing
```

## Workflow 3: Mobile QR Scanning Protection

```
User scans QR code with mobile device
  |
  v
[Mobile threat defense intercepts]
  +-- Decode QR destination URL
  +-- Check against mobile threat intelligence
  |
  v
[URL assessment]
  +-- KNOWN MALICIOUS: Block and alert user
  +-- SUSPICIOUS: Display warning, require confirmation
  +-- CREDENTIAL PAGE: Extra warning about entering passwords
  +-- CLEAN: Allow access
  |
  v
[If user proceeds to suspicious site]
  +-- Route through secure browser/VPN
  +-- Monitor for credential submission
  +-- Log URL and user action for SOC review
```
