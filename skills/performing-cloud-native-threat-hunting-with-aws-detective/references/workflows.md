# AWS Detective Investigation Workflow

## Phase 1: Triage
1. Review GuardDuty HIGH/CRITICAL findings
2. Open Detective console → Finding Groups
3. Identify clustered findings pointing to same entity

## Phase 2: Entity Investigation
1. Select entity (IAM user/role, EC2, IP)
2. Review 24h behavior timeline
3. Identify unusual API calls, new geolocations, impossible travel
4. Check for privilege escalation patterns (CreateAccessKey, AttachPolicy)

## Phase 3: Scope Assessment
1. Trace lateral movement via AssumeRole chains
2. Check S3 data access patterns
3. Review VPC Flow Logs for unusual outbound connections
4. Identify all compromised credentials

## Phase 4: Correlation
1. Map findings to MITRE ATT&CK techniques
2. Build attack timeline from entity profiles
3. Identify initial access vector
4. Document indicators of compromise (IOCs)

## Phase 5: Response
1. Disable compromised credentials
2. Revoke active sessions
3. Isolate affected resources
4. Preserve evidence (CloudTrail logs, flow logs)
