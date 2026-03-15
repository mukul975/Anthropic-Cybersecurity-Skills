# AD Compromise Investigation Workflows

## Workflow 1: Initial Triage and Scoping

```
START: AD Compromise Alert Received
  |
  v
[Determine Scope of Potential Compromise]
  |-- Single account compromised?
  |-- Multiple accounts compromised?
  |-- Domain controller compromised?
  |-- Full domain compromise suspected?
  |
  v
[Collect Initial Evidence]
  |-- Export Security event logs from all DCs
  |-- Snapshot AD replication metadata
  |-- Export current GPO configurations
  |-- Document privileged group memberships
  |
  v
[Identify Compromised Accounts]
  |-- Analyze logon events (4624/4625)
  |-- Check for pass-the-hash patterns
  |-- Review Kerberos ticket activity
  |-- Cross-reference with threat intelligence
  |
  v
[Determine Attack Timeline]
  |-- First known malicious activity
  |-- Privilege escalation events
  |-- Lateral movement chain
  |-- Data access and exfiltration
  |
  v
[Report Findings and Escalate]
```

## Workflow 2: Kerberos Attack Investigation

```
START: Suspicious Kerberos Activity Detected
  |
  v
[Analyze Event ID 4768 - TGT Requests]
  |-- Normal TGT requests from user workstations?
  |-- TGT requests from unusual sources?
  |-- Encryption type analysis (AES vs RC4)
  |
  v
[Analyze Event ID 4769 - Service Ticket Requests]
  |-- High volume from single source? --> Kerberoasting
  |-- Service tickets without prior TGT? --> Silver Ticket
  |-- Unusual service names or SPNs?
  |
  v
[Check for Golden Ticket Indicators]
  |-- TGT lifetime exceeds 10 hours?
  |-- TGT for non-existent accounts?
  |-- TGT without matching AS-REQ?
  |-- krbtgt account age analysis
  |
  v
[Determine Remediation Actions]
  |-- Kerberoasting: Reset affected service account passwords
  |-- Golden Ticket: Double-rotate krbtgt password
  |-- Silver Ticket: Reset affected service account passwords
  |-- All: Review and harden SPN configurations
  |
  v
END: Remediation Complete + Monitoring Enhanced
```

## Workflow 3: DCSync Attack Investigation

```
START: Replication from Non-DC Source Detected
  |
  v
[Verify Replication Source]
  |-- Is source a legitimate domain controller?
  |-- Check Event ID 4662 for replication rights usage
  |-- Verify account has DS-Replication-Get-Changes-All
  |
  v
[If Unauthorized Replication Detected]
  |-- Identify compromised account with replication rights
  |-- Determine which credentials were replicated
  |-- Check for Mimikatz/Impacket artifacts on source
  |
  v
[Assess Credential Exposure]
  |-- All domain password hashes potentially compromised
  |-- krbtgt hash exposure enables Golden Ticket
  |-- Service account hashes enable Silver Tickets
  |-- Trust keys enable cross-domain attacks
  |
  v
[Execute Full Credential Reset]
  |-- Double-rotate krbtgt (wait for replication)
  |-- Reset all privileged account passwords
  |-- Reset all service account passwords
  |-- Force password change for all users
  |
  v
END: Monitor for Continued Unauthorized Replication
```

## Workflow 4: Post-Compromise Remediation

```
START: Compromise Scope Determined
  |
  v
[Immediate Containment]
  |-- Disable compromised accounts
  |-- Block attacker IP addresses
  |-- Isolate compromised systems
  |-- Revoke active sessions and tokens
  |
  v
[Credential Reset Sequence]
  |-- Step 1: Reset krbtgt (first rotation)
  |-- Step 2: Wait for full AD replication
  |-- Step 3: Reset krbtgt (second rotation)
  |-- Step 4: Wait for full AD replication
  |-- Step 5: Reset all privileged accounts
  |-- Step 6: Reset all service accounts
  |-- Step 7: Force user password changes
  |
  v
[Persistence Removal]
  |-- Remove unauthorized GPO modifications
  |-- Clean AdminSDHolder ACL entries
  |-- Remove SID History entries
  |-- Revoke rogue AD CS certificates
  |-- Remove skeleton key if detected
  |-- Clean scheduled tasks and services
  |
  v
[Hardening Implementation]
  |-- Deploy tiered administration model
  |-- Enable Protected Users group
  |-- Implement PAW for admin tasks
  |-- Deploy LAPS for local admin
  |-- Configure advanced audit policies
  |
  v
END: Continuous Monitoring Established
```
