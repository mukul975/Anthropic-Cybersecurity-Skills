# Workflows: Email Sandboxing with Proofpoint

## Workflow 1: Attachment Detonation Pipeline
```
Email with attachment arrives at Proofpoint gateway
  |
  v
[Pre-filter: Check attachment type]
  +-- Blocked types (.bat, .ps1, .vbs) --> Quarantine immediately
  +-- Detonable types --> Send to sandbox
  +-- Known safe types (.txt, .csv) --> Deliver
  |
  v
[Sandbox detonation]
  +-- Execute in multiple environments (Win10, Win11, macOS)
  +-- Monitor: file system changes, registry, network, process creation
  +-- Timeout: 60-120 seconds per environment
  |
  v
[Verdict]
  +-- MALICIOUS --> Quarantine, alert, extract IOCs
  +-- SUSPICIOUS --> Quarantine for analyst review
  +-- CLEAN --> Deliver with dynamic delivery
```

## Workflow 2: URL Defense Time-of-Click
```
Email with URL arrives
  |
  v
[URL rewritten to Proofpoint URL Defense proxy]
  |
  v
[Email delivered to user]
  |
  v
[User clicks rewritten URL]
  |
  v
[Proofpoint performs real-time analysis]
  +-- Reputation check
  +-- Content analysis
  +-- Sandbox detonation of landing page
  |
  +-- SAFE --> Redirect to original URL
  +-- MALICIOUS --> Block access, show warning page
  +-- SUSPICIOUS --> Show interstitial warning, allow proceed
```

## Workflow 3: TAP Dashboard Monitoring
```
Daily operations:
  +-- Review TAP Dashboard threat digest
  +-- Check VAP (Very Attacked People) changes
  +-- Review campaign clusters
  +-- Investigate quarantined messages
  +-- Monitor false positive rate
  |
Weekly:
  +-- Analyze threat trends
  +-- Review sandboxing effectiveness
  +-- Tune policies based on FP/FN data
  +-- Update blocked file type list
  |
Monthly:
  +-- Generate executive report from TAP
  +-- Review VAP list with HR/management
  +-- Assess ROI and threat prevention metrics
```
