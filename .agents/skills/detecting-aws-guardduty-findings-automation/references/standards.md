# Standards - AWS GuardDuty Findings Automation

## MITRE ATT&CK Mapping
- TA0001 Initial Access: UnauthorizedAccess findings
- TA0003 Persistence: Persistence:IAMUser findings
- TA0005 Defense Evasion: Stealth findings
- TA0006 Credential Access: CredentialAccess findings
- TA0010 Exfiltration: Exfiltration findings
- TA0040 Impact: CryptoCurrency/Trojan findings

## NIST 800-53
- IR-4: Incident Handling
- IR-5: Incident Monitoring
- SI-4: System Monitoring
- AU-6: Audit Record Review

## AWS Security Best Practices
- Enable GuardDuty in all regions
- Configure multi-account with Organizations
- Publish findings every 15 minutes
- Integrate with Security Hub
