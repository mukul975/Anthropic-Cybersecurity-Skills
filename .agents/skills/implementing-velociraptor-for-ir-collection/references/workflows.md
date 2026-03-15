# Velociraptor IR Collection Workflows

## Workflow 1: Rapid Triage Collection

```
START: Incident Detected - Triage Needed
  |
  v
[Identify Target Endpoints]
  |-- Search clients by hostname, IP, or label
  |-- Verify client connectivity status
  |-- Label endpoints as "investigation_targets"
  |
  v
[Launch Triage Collection]
  |-- Select triage artifact pack
  |-- Configure collection parameters
  |-- Set resource limits (CPU, bandwidth)
  |-- Launch flow on target endpoints
  |
  v
[Monitor Collection Progress]
  |-- View flow status in Velociraptor UI
  |-- Check for collection errors
  |-- Verify artifact completeness
  |
  v
[Download and Analyze Results]
  |-- Export collected data
  |-- Import into timeline tool
  |-- Begin forensic analysis
  |
  v
END: Triage Data Available for Analysis
```

## Workflow 2: Enterprise-Wide Hunt

```
START: IOC or Threat Intelligence Received
  |
  v
[Create Hunt]
  |-- Define hunt description and scope
  |-- Select target artifacts
  |-- Configure IOC-based VQL queries
  |-- Set include/exclude labels
  |
  v
[Launch Hunt]
  |-- Deploy to all matching endpoints
  |-- Offline endpoints queued for pickup
  |-- Monitor completion percentage
  |
  v
[Analyze Hunt Results]
  |-- Review matches and anomalies
  |-- Identify compromised endpoints
  |-- Label affected systems
  |
  v
[Escalate Findings]
  |-- Create detailed flows for hits
  |-- Collect additional artifacts
  |-- Feed results into IR process
  |
  v
END: Hunt Complete - Findings Documented
```

## Workflow 3: Live Incident Response

```
START: Active Compromise Detected
  |
  v
[Connect to Affected Endpoint]
  |-- Open VQL shell in Velociraptor UI
  |-- Verify system identity and status
  |
  v
[Volatile Evidence Collection]
  |-- Running processes (pslist)
  |-- Network connections (netstat)
  |-- DNS cache
  |-- Open file handles
  |-- Loaded DLLs
  |-- Memory strings (if needed)
  |
  v
[Persistence Check]
  |-- Scheduled tasks
  |-- Services
  |-- Registry autorun keys
  |-- WMI subscriptions
  |-- Startup folder items
  |
  v
[Non-Volatile Evidence]
  |-- Event logs
  |-- Prefetch files
  |-- MFT entries
  |-- Browser history
  |-- PowerShell history
  |
  v
[Containment Decision]
  |-- Enough evidence to contain?
  |-- Isolate endpoint if needed
  |-- Continue monitoring if needed
  |
  v
END: Evidence Collected - Containment Executed
```

## Workflow 4: Deployment at Scale

```
START: Velociraptor Deployment Project
  |
  v
[Server Setup]
  |-- Deploy server on dedicated host
  |-- Configure SSL certificates
  |-- Set up authentication (SSO/SAML)
  |-- Configure storage backend
  |
  v
[Client Configuration]
  |-- Generate client config from server
  |-- Repack client installers
  |-- Test on pilot group
  |
  v
[Mass Deployment]
  |-- GPO deployment (Windows)
  |-- Configuration management (Linux)
  |-- MDM deployment (macOS)
  |-- Verify connectivity
  |
  v
[Operational Configuration]
  |-- Set up monitoring artifacts
  |-- Configure event forwarding
  |-- Create standard hunt templates
  |-- Document SOPs for analysts
  |
  v
END: Velociraptor Operational at Scale
```
