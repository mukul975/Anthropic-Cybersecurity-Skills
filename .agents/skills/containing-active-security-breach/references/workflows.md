# Containing an Active Security Breach - Detailed Workflow

## Pre-Containment Decision Framework

### Containment Strategy Selection Matrix
| Factor | Low Impact | Medium Impact | High Impact |
|--------|-----------|---------------|-------------|
| Data sensitivity | Monitor and assess | Partial isolation | Full network isolation |
| Active exfiltration | Block egress IPs | Block + isolate segment | Air-gap + full isolation |
| Lateral movement | Enhanced monitoring | Segment isolation | Domain-wide lockdown |
| Business criticality | Targeted containment | Phased containment | Emergency containment with DR |
| Ransomware deployment | Isolate patient zero | Segment + block C2 | Enterprise-wide isolation |

## Step-by-Step Procedure

### Phase 1: Incident Validation (0-15 minutes)
1. Receive alert from SIEM/EDR/SOC analyst
2. Verify alert is true positive by correlating multiple data sources
3. Classify incident severity using organization's severity matrix
4. Activate incident response team based on severity level
5. Establish incident communication channel (war room or Slack/Teams channel)
6. Assign Incident Commander and document in ticketing system

### Phase 2: Scope Assessment (15-45 minutes)
1. Query SIEM for all related alerts in the past 72 hours
2. Identify all compromised hosts using EDR telemetry
3. Map network connections from compromised hosts to identify lateral movement
4. Check authentication logs for compromised account usage across systems
5. Identify affected data repositories and assess data classification
6. Document the attack timeline and current threat actor position
7. Determine the attack vector (how did they get in)

### Phase 3: Short-Term Containment (30-60 minutes)
1. **Network Level**:
   - Block attacker external IPs at perimeter firewall
   - Sinkhole C2 domains at DNS level
   - Apply ACLs to isolate compromised network segments
   - Enable enhanced packet capture on affected segments

2. **Endpoint Level**:
   - Network-contain compromised hosts via EDR
   - Disable compromised user accounts in Active Directory
   - Revoke OAuth tokens and API keys
   - Kill malicious processes identified by EDR

3. **Identity Level**:
   - Force password reset on compromised accounts
   - Disable MFA bypass methods used by attacker
   - Revoke VPN certificates for compromised users
   - Block compromised service account authentication

### Phase 4: Evidence Preservation (During Containment)
1. Capture live memory from key compromised systems before full isolation
2. Export relevant SIEM logs to secure evidence storage
3. Take forensic disk images of critical compromised systems
4. Preserve network capture data (PCAP) from affected segments
5. Screenshot active sessions and running process trees
6. Hash all evidence files and create chain of custody documentation

### Phase 5: Long-Term Containment (1-24 hours)
1. Implement network microsegmentation around affected areas
2. Deploy additional monitoring sensors in compromised zones
3. Set up honeypots to detect continued attacker activity
4. Apply temporary firewall rules with logging for affected segments
5. Enable enhanced audit logging on systems adjacent to compromise
6. Implement file integrity monitoring on critical systems
7. Set up network traffic baseline comparison

### Phase 6: Containment Verification (Ongoing)
1. Monitor for new alerts from previously compromised systems
2. Verify no new C2 communications from any internal host
3. Check for new account creation or privilege escalation attempts
4. Validate that isolated systems cannot reach external networks
5. Test that critical business services remain functional
6. Brief stakeholders on containment status and next steps

## Escalation Criteria
- Containment fails (attacker regains access): Escalate to CISO, consider external IR firm
- Business-critical systems affected: Engage business continuity team
- Data exfiltration confirmed: Engage legal and compliance teams
- Nation-state indicators: Engage FBI/CISA
- Ransomware spreading despite containment: Consider full network shutdown

## Communication Templates

### Internal Escalation (Initial)
```
SUBJECT: [SEVERITY-CRITICAL] Active Security Breach - Containment in Progress
INCIDENT ID: IR-YYYY-NNN
TIME DETECTED: YYYY-MM-DD HH:MM UTC
CURRENT STATUS: Containment in progress
AFFECTED SYSTEMS: [count] hosts, [count] accounts
INCIDENT COMMANDER: [Name]
NEXT UPDATE: [time]
```

### Status Update (During Containment)
```
SUBJECT: [UPDATE] IR-YYYY-NNN - Containment Status
CONTAINMENT STATUS: [Partial/Complete/Pending]
SYSTEMS ISOLATED: [count]
ACCOUNTS DISABLED: [count]
C2 COMMUNICATIONS: [Blocked/Active/Unknown]
BUSINESS IMPACT: [Description]
NEXT STEPS: [Actions]
NEXT UPDATE: [time]
```
