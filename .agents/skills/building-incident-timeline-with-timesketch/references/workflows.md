# Timesketch Timeline Building Workflows

## Workflow 1: Evidence Processing Pipeline

```
START: Evidence Collection Complete
  |
  v
[Mount Evidence / Extract Artifacts]
  |-- Mount disk image (read-only)
  |-- Extract event logs from triage package
  |-- Collect cloud service logs
  |-- Gather network device logs
  |
  v
[Process with Plaso/log2timeline]
  |-- Select appropriate parsers
  |-- Configure filter files for scope
  |-- Run log2timeline on each source
  |-- Verify output .plaso files
  |
  v
[Import into Timesketch]
  |-- Create sketch for investigation
  |-- Upload each timeline with descriptive name
  |-- Wait for indexing to complete
  |-- Verify event counts per timeline
  |
  v
[Run Automated Analyzers]
  |-- Domain analyzer
  |-- Sigma rule analyzer
  |-- Chain of events analyzer
  |-- Feature extraction analyzer
  |
  v
[Manual Analysis and Tagging]
  |-- Search for key indicators
  |-- Tag events by attack phase
  |-- Add investigator annotations
  |-- Build investigation story
  |
  v
END: Timeline Ready for Analysis
```

## Workflow 2: Rapid Triage Timeline

```
START: Incident Detected - Quick Timeline Needed
  |
  v
[Collect Quick-Win Artifacts]
  |-- Windows Event Logs (Security, System, PowerShell)
  |-- Prefetch files
  |-- Browser history
  |-- Recent file access (NTUSER.DAT)
  |
  v
[Fast Processing]
  |-- Targeted Plaso parsers only
  |   (winevtx, prefetch, chrome_history)
  |-- Or convert logs to CSV format
  |-- Import directly into Timesketch
  |
  v
[Initial Analysis]
  |-- Search for known IOCs
  |-- Run Sigma analyzer for quick wins
  |-- Identify suspicious time periods
  |-- Tag initial findings
  |
  v
[Expand if Needed]
  |-- Add additional evidence sources
  |-- Run full parser set
  |-- Broaden search scope
  |
  v
END: Initial Triage Complete
```

## Workflow 3: Multi-Source Correlation

```
START: Multiple Evidence Sources Available
  |
  v
[Normalize Timestamps]
  |-- Ensure all sources use UTC
  |-- Account for clock skew between systems
  |-- Document any time synchronization issues
  |
  v
[Import All Sources as Separate Timelines]
  |-- Timeline 1: Endpoint logs (Plaso)
  |-- Timeline 2: Network logs (CSV)
  |-- Timeline 3: Cloud logs (JSONL)
  |-- Timeline 4: Email logs (CSV)
  |-- Timeline 5: Firewall logs (CSV)
  |
  v
[Cross-Source Correlation]
  |-- Search across all timelines simultaneously
  |-- Identify same events seen from different perspectives
  |-- Build complete picture of attacker activity
  |-- Tag correlated events with shared labels
  |
  v
[Build Attack Narrative]
  |-- Create story in Timesketch
  |-- Link saved views for each attack phase
  |-- Add context and analysis notes
  |-- Export for final report
  |
  v
END: Correlated Timeline Analysis Complete
```

## Workflow 4: Collaborative Team Investigation

```
START: Investigation Assigned to Team
  |
  v
[Sketch Setup by Lead Investigator]
  |-- Create sketch with case details
  |-- Import initial timeline data
  |-- Define investigation objectives
  |-- Assign analysis areas to team members
  |
  v
[Parallel Analysis by Team]
  |-- Analyst 1: Network traffic analysis
  |-- Analyst 2: Endpoint artifact analysis
  |-- Analyst 3: Cloud/identity analysis
  |-- Each analyst tags and annotates findings
  |
  v
[Consolidation]
  |-- Review all tagged events
  |-- Resolve conflicting findings
  |-- Build unified attack narrative
  |-- Create investigation story
  |
  v
[Quality Review]
  |-- Lead reviews complete timeline
  |-- Verify attack chain is complete
  |-- Ensure all IOCs documented
  |-- Export findings for report
  |
  v
END: Team Investigation Complete
```
