# Cloud Incident Containment Workflows

## Workflow 1: AWS Credential Compromise Response

```
START: Compromised AWS Credentials Detected
  |
  v
[Identify Scope]
  |-- Which IAM user/role is compromised?
  |-- What permissions does it have?
  |-- Review CloudTrail for unauthorized actions
  |
  v
[Immediate Containment]
  |-- Disable all access keys
  |-- Attach deny-all inline policy
  |-- Revoke active sessions (date condition)
  |-- Update role trust policy if needed
  |
  v
[Evidence Preservation]
  |-- Export CloudTrail logs to S3 with Object Lock
  |-- Snapshot any accessed resources
  |-- Document all API calls by compromised identity
  |
  v
[Impact Assessment]
  |-- What resources were accessed?
  |-- Was data exfiltrated?
  |-- Were new resources created?
  |-- Were other accounts compromised?
  |
  v
[Remediation]
  |-- Rotate all credentials
  |-- Remove unauthorized resources
  |-- Update IAM policies
  |-- Enable MFA enforcement
  |
  v
END: Containment Complete
```

## Workflow 2: Cloud VM Compromise Response

```
START: Compromised Cloud VM Detected
  |
  v
[Preserve Evidence First]
  |-- Create disk snapshot immediately
  |-- Capture instance metadata
  |-- Export relevant logs
  |
  v
[Network Isolation]
  |-- Apply quarantine security group/NSG
  |-- Remove public IP addresses
  |-- Block outbound traffic
  |-- Maintain forensic access only
  |
  v
[Assess Blast Radius]
  |-- Check lateral movement indicators
  |-- Review IAM role attached to instance
  |-- Check for data access to other services
  |
  v
[Forensic Analysis]
  |-- Mount snapshot to forensic workstation
  |-- Analyze disk for malware/tools
  |-- Review instance logs
  |
  v
[Recovery]
  |-- Rebuild from known-good image
  |-- Apply security hardening
  |-- Restore from clean backup
  |
  v
END: VM Contained and Rebuilt
```

## Workflow 3: Multi-Cloud Containment

```
START: Multi-Cloud Incident
  |
  v
[Identify Affected Cloud Platforms]
  |-- AWS accounts affected?
  |-- Azure subscriptions affected?
  |-- GCP projects affected?
  |
  v
[Parallel Containment]
  |-- AWS: SecurityHub + GuardDuty response
  |-- Azure: Defender + Sentinel playbooks
  |-- GCP: SCC + Chronicle response
  |
  v
[Cross-Cloud Credential Check]
  |-- Shared credentials between platforms?
  |-- Federated identity compromise?
  |-- Third-party integrations affected?
  |
  v
[Unified Evidence Collection]
  |-- Centralize logs from all platforms
  |-- Normalize timestamps to UTC
  |-- Build cross-cloud timeline
  |
  v
END: Multi-Cloud Containment Complete
```
