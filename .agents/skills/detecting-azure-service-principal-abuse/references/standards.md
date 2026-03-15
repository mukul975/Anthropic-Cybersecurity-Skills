# Standards - Detecting Azure Service Principal Abuse

## MITRE ATT&CK Techniques
- T1098.001: Account Manipulation - Additional Cloud Credentials
- T1078.004: Valid Accounts - Cloud Accounts
- T1087.004: Account Discovery - Cloud Account
- T1528: Steal Application Access Token
- T1550.001: Use Alternate Authentication Material - Application Access Token

## CIS Microsoft Azure Foundations Benchmark v2.1
- 1.11: Ensure that multi-factor authentication is enabled for all privileged users
- 1.14: Ensure that guest users are reviewed on a regular basis
- 1.15: Ensure that User consent for applications is set to Do not allow user consent

## Microsoft Secure Score Recommendations
- Require admin approval for unmanaged applications
- Remove unused application permissions
- Limit service principal credential lifetime
- Implement Conditional Access for workload identities
