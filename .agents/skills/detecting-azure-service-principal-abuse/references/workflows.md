# Workflows - Detecting Azure Service Principal Abuse

## Detection Workflow
```
1. Log Collection → Ingest Azure AD Audit + Sign-in logs to SIEM
2. Rule Activation → Enable detection analytics for SP abuse patterns
3. Alert Triage → Validate alerts against known automation accounts
4. Investigation → Correlate credential changes with sign-in anomalies
5. Containment → Disable compromised SP, rotate credentials
6. Remediation → Remove unauthorized permissions, review ownership
```

## Investigation Workflow
```
1. Identify affected service principal (name, object ID, app ID)
2. Review recent credential changes (new secrets/certificates)
3. Check role assignments for privilege escalation
4. Analyze sign-in logs for unusual IPs/locations
5. Review application ownership chain
6. Assess blast radius of compromised permissions
7. Document findings and initiate incident response
```
